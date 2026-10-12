#!/bin/bash
# Runs only inside the disposable CI VM (a fresh single-node NS8 leader).
set -Eeuo pipefail
# Read all input before deciding: "grep -q" exits at the first match, the
# writer then dies of SIGPIPE and pipefail reports the match as a failure.
contains() { grep -c -- "$1" >/dev/null; }
image="${1:?module image}"
step() { printf '\n=== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
wait_for() { # seconds description command...
    local seconds=$1 what=$2; shift 2
    for _ in $(seq 1 "$seconds"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
    fail "timeout waiting for ${what}"
}
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

step "install"
module="$(add-module "$image" 1 | python3 -c 'import ast,sys; print(ast.literal_eval(sys.stdin.read())["module_id"])')"
printf '%s\n' "$module" >/tmp/csc-module-id
echo "module: $module"
hub_host="crowdsec-hub.ns8.test"

step "configure as hub"
api-cli run "module/$module/configure-module" --data "{\"role\":\"hub\",\"hub_host\":\"$hub_host\",\"lets_encrypt\":false,\"ban_duration\":\"30m\",\"allowlist\":[\"192.0.2.0/24\"],\"samba_audit\":true}"
for unit in "$module.service" "$module-bouncer.service" "$module-refresh.timer"; do
    systemctl is-active --quiet "$unit" || fail "$unit is not active"
done
runagent -m "$module" podman exec "$module" cscli lapi status
runagent -m "$module" podman exec "$module" cscli bouncers list -o json | contains firewall || fail "local bouncer not registered"
wait_for 60 "nftables table" nft list table ip crowdsec-companion
state=/var/lib/nethserver/$module/state
grep -q 'CONTAINER_NAME=traefik' "$state/crowdsec_config/acquis.yaml" || fail "Traefik journal source not discovered"
cat "$state/discovery.json"
status_json="$(api-cli run "module/$module/get-companion-status")"
echo "$status_json"
[[ "$(echo "$status_json" | json 'd["lapi"]')" == ok ]] || fail "get-status reports no LAPI"
# Validation rejects a role change.
if api-cli run "module/$module/configure-module" --data '{"role":"member","token":"csc1.x"}' >/tmp/csc-val.txt 2>&1; then
    fail "role change was accepted"
fi
grep -q role_is_fixed /tmp/csc-val.txt || { cat /tmp/csc-val.txt; fail "unexpected validation result"; }

step "attacker namespace 198.51.100.2 -> node 198.51.100.1"
ip netns add csc-attacker
ip link add csc-test type veth peer name csc-client
ip link set csc-client netns csc-attacker
ip addr add 198.51.100.1/30 dev csc-test
ip link set csc-test up
ip -n csc-attacker addr add 198.51.100.2/30 dev csc-client
ip -n csc-attacker link set csc-client up
ip -n csc-attacker link set lo up
firewall-cmd --zone=public --add-interface=csc-test
attacker() { ip netns exec csc-attacker "$@"; }
login() {
    attacker curl -sk -o /dev/null -w '%{http_code}' --max-time 5 -H 'Content-Type: application/json' \
        -d '{"username":"admin","password":"wrong-password"}' https://198.51.100.1/cluster-admin/api/login
}
code="$(login)" || true
[[ "$code" == 401 ]] || fail "expected 401 from the NS8 admin login, got '$code'"

step "the agent reads the host journal"
# Same journalctl the agent runs, inside the CrowdSec container.
seen="$(podman exec "$module" journalctl -q --no-pager -o cat -n 3 CONTAINER_NAME=traefik "_UID=$(id -u traefik1)" 2>&1 || true)"
echo "$seen"
grep -q 'cluster-admin' <<<"$seen" || fail "journalctl inside the CrowdSec container cannot read the Traefik journal"
podman logs "$module" 2>&1 | grep -E "journalctl|Starting processing data" | head -5

step "failed NS8 admin logins until banned"
decisions() { runagent -m "$module" podman exec "$module" cscli decisions list -o raw; }
banned() { decisions | contains '198.51.100.2,ns8/ns8-admin-bf'; }
# Like the upstream CrowdSec module tests: retry, since lines written while
# the agent (re)starts are never read (journalctl -n 0).
for try in 1 2 3 4; do
    for _ in 1 2 3 4 5; do login >/dev/null || true; done
    for _ in $(seq 1 20); do banned && break 2; sleep 1; done
    echo "no ban after attempt $try"
done
banned || fail "198.51.100.2 was not banned"
decisions
wait_for 40 "nftables ban" sh -c "nft list table ip crowdsec-companion | grep -q 198.51.100.2"
code="$(login)" || true
[[ "$code" == 000 ]] || fail "banned address still reaches Traefik (HTTP $code)"
echo "198.51.100.2 is dropped"

step "member token works through the public route"
token_json="$(api-cli run "module/$module/add-member" --data '{"name":"ci-member"}')"
token="$(echo "$token_json" | json 'd["token"]')"
creds="$(python3 - "$token" <<'PY'
import base64, json, sys
t = sys.argv[1][5:]
d = json.loads(base64.urlsafe_b64decode(t + "=" * (-len(t) % 4)))
print(d["machine"], d["password"], d["bouncer_key"], d["url"])
PY
)"
read -r machine password bouncer_key url <<<"$creds"
[[ "$url" == "https://$hub_host/" ]] || fail "unexpected hub URL $url"
resolve=(--resolve "$hub_host:443:127.0.0.1")
login_code="$(curl -sk "${resolve[@]}" -o /tmp/csc-login.json -w '%{http_code}' -H 'Content-Type: application/json' \
    -d "{\"machine_id\":\"$machine\",\"password\":\"$password\"}" "https://$hub_host/v1/watchers/login")"
[[ "$login_code" == 200 ]] || { cat /tmp/csc-login.json; fail "member machine login returned $login_code"; }
curl -sk "${resolve[@]}" -H "X-Api-Key: $bouncer_key" "https://$hub_host/v1/decisions/stream?startup=true" | contains 198.51.100.2 \
    || fail "member bouncer key cannot read the ban list"
bad="$(curl -sk "${resolve[@]}" -o /dev/null -w '%{http_code}' -H 'X-Api-Key: wrong' "https://$hub_host/v1/decisions/stream?startup=true")"
[[ "$bad" == 403 || "$bad" == 401 ]] || fail "wrong bouncer key returned $bad"
api-cli run "module/$module/list-members" | contains ci-member || fail "member not listed"
api-cli run "module/$module/remove-member" --data '{"name":"ci-member"}'
gone="$(curl -sk "${resolve[@]}" -o /dev/null -w '%{http_code}' -H "X-Api-Key: $bouncer_key" "https://$hub_host/v1/decisions/stream?startup=true")"
[[ "$gone" == 403 || "$gone" == 401 ]] || fail "removed member bouncer still has access ($gone)"

step "unban restores access"
api-cli run "module/$module/list-decisions" | contains 198.51.100.2 || fail "list-decisions misses the ban"
api-cli run "module/$module/unban" --data '{"addresses":["198.51.100.2"]}'
wait_for 40 "nftables unban" sh -c "! nft list table ip crowdsec-companion | grep -q 198.51.100.2"
code="$(login)" || true
[[ "$code" == 401 ]] || fail "unbanned address cannot reach the login again (HTTP $code)"

step "allowlisted addresses are never banned"
ip -n csc-attacker addr add 192.0.2.9/32 dev csc-client
ip route add 192.0.2.9/32 dev csc-test
for _ in 1 2 3 4 5 6; do
    attacker curl -sk -o /dev/null --interface 192.0.2.9 --max-time 5 -H 'Content-Type: application/json' \
        -d '{"username":"admin","password":"x"}' https://198.51.100.1/cluster-admin/api/login || true
done
sleep 20
if decisions | contains 192.0.2.9; then fail "allowlisted address was banned"; fi

step "restart keeps working without changes"
systemctl restart "$module.service"
wait_for 120 "LAPI after restart" runagent -m "$module" podman exec "$module" cscli lapi status
runagent -m "$module" systemctl start "$module-refresh.service" 2>/dev/null || systemctl start "$module-refresh.service"
echo "smoke test passed"
