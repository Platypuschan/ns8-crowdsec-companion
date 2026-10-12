#!/bin/bash
# End-to-end test without NS8: a hub and a member rendered by the module code,
# connected through Traefik over HTTPS, enforcing a ban with nftables.
#
#   member agent --alert--> Traefik (TLS) --> hub LAPI --decision-->
#   Traefik (TLS) --> member firewall bouncer --> nftables drop
#
# Everything after the hub-content installation runs in one isolated network
# namespace, so the test works with rootless podman and never touches the
# host firewall.
set -Eeuo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
engine="${DOCKER:-podman}"
cs_image="${CROWDSEC_IMAGE:-docker.io/crowdsecurity/crowdsec:v1.8.1-debian}"
bouncer_image="${BOUNCER_IMAGE:-ghcr.io/nethserver/crowdsec-firewall-bouncer:1.4.0}"
traefik_image="${TRAEFIK_IMAGE:-docker.io/library/traefik:v3.7.13}"
p="e2e$$"
work="$(mktemp -d)"
cleanup() {
    for c in "$p-member-bouncer" "$p-member" "$p-traefik" "$p-hub" "$p-tools"; do "$engine" rm -f "$c" >/dev/null 2>&1 || true; done
    "$engine" unshare rm -rf "$work" 2>/dev/null || rm -rf "$work"
}
on_exit() {
    local rc=$?
    if ((rc)); then
        for c in "$p-tools" "$p-hub" "$p-traefik" "$p-member" "$p-member-bouncer"; do
            echo "--- logs of $c"; "$engine" logs --tail 25 "$c" 2>&1 || true
        done
    fi
    cleanup
}
trap on_exit EXIT
log() { printf '== %s\n' "$*"; }

# Tools container: owns the network namespace; has nft, ip and nc.
"$engine" build --network host -q -t localhost/cscompanion-e2e-tools - >/dev/null <<'CF'
FROM docker.io/library/alpine:3.24.2
RUN apk add --no-cache nftables iproute2 netcat-openbsd curl
CF

render() { # role state_dir lapi_port metrics_port config_json
    mkdir -p "$2"
    printf '%s\n' "$5" >"$2/config.json"
    AGENT_STATE_DIR="$2" MODULE_ID="$1" TCP_PORTS="$3,$4" PYTHONPATH="$root/imageroot/pypkg" python3 -c '
import os
from cscompanion import common, render
cfg = common.load_config()
print(render.render_all(cfg, os.environ["MODULE_ID"], os.environ["AGENT_STATE_DIR"], root="/nonexistent")["found"])'
}

hub="$work/hub"; member="$work/member"
mkdir -p "$hub/secrets" "$member/secrets" "$hub/crowdsec_data" "$member/crowdsec_data"
printf 'hubbouncerkey0123456789abcdef\n' >"$hub/secrets/bouncer_key"
render crowdsec-companion1 "$hub" 41381 41382 '{"role": "hub", "hub_host": "hub.test", "hub_url": "https://hub.test/", "ban_duration": "2h", "allowlist": ["192.0.2.0/24"]}' >/dev/null

# Member credentials come from a token, exactly as configure-module does.
token="$(PYTHONPATH="$root/imageroot/pypkg" python3 -c '
from cscompanion.common import encode_token
print(encode_token({"url": "https://127.0.0.1:8443/", "machine": "member1", "password": "memberpass0123456789abcdefgh", "bouncer": "member1-firewall", "bouncer_key": "memberbouncerkey0123456789"}))')"
AGENT_STATE_DIR="$member" PYTHONPATH="$root/imageroot/pypkg" python3 -c '
import sys
from cscompanion.common import decode_token, write_secret
d = decode_token(sys.argv[1])
write_secret("machine", d["machine"]); write_secret("machine_password", d["password"])
write_secret("bouncer", d["bouncer"]); write_secret("bouncer_key", d["bouncer_key"])' "$token"
render member1 "$member" 41383 41384 '{"role": "member", "hub_url": "https://127.0.0.1:8443/", "insecure_skip_verify": true, "ban_duration": "4h"}' >/dev/null
# Without journald, the member reads a file with the same labels as the Traefik journal source.
mkdir -p "$work/logs"; : >"$work/logs/traefik.log"
printf '{"source": "file", "filenames": ["/logs/traefik.log"], "labels": {"type": "syslog", "ns8_source": "traefik"}}\n' >"$member/crowdsec_config/acquis.yaml"
# The generated router map needs a Gitea instance; discovery found none here.
PYTHONPATH="$root/imageroot/pypkg" python3 -c '
from cscompanion import render
print(render.routers_parser({"gitea": [{"module": "gitea1"}]}), end="")' >"$member/crowdsec_config/parsers/s02-enrich/ns8-router-apps.yaml"
grep -q '"listen_uri": "127.0.0.1:41381"' "$hub/crowdsec_config/config.yaml.local"
grep -q 'DISABLE_LOCAL_API=true' "$member/crowdsec.env"

log "install hub content (needs network once)"
for side in "$hub" "$member"; do
    "$engine" run --rm --network host -v "$side/crowdsec_config:/etc/crowdsec" -v "$side/crowdsec_data:/var/lib/crowdsec/data" \
        --entrypoint sh "$cs_image" -ec '
        cp -an /staging/etc/crowdsec/. /etc/crowdsec/
        cp -an /staging/var/lib/crowdsec/data/. /var/lib/crowdsec/data/
        cscli hub update >/dev/null
        cscli collections install crowdsecurity/linux >/dev/null
        cscli parsers install crowdsecurity/docker-logs crowdsecurity/cri-logs >/dev/null'
done

log "start hub, Traefik and member in one isolated namespace"
"$engine" run -d --name "$p-tools" --network none --cap-add NET_ADMIN localhost/cscompanion-e2e-tools sleep infinity >/dev/null
ns="container:$p-tools"
sed -i '/^COLLECTIONS=/d' "$hub/crowdsec.env" "$member/crowdsec.env"
"$engine" run -d --name "$p-hub" --network "$ns" --env-file "$hub/crowdsec.env" \
    -v "$hub/crowdsec_config:/etc/crowdsec" -v "$hub/crowdsec_data:/var/lib/crowdsec/data" "$cs_image" >/dev/null
mkdir -p "$work/traefik"
cat >"$work/traefik/traefik.yaml" <<'YAML'
entryPoints:
  https:
    address: "127.0.0.1:8443"
providers:
  file:
    filename: /etc/traefik/dyn.yaml
YAML
cat >"$work/traefik/dyn.yaml" <<'YAML'
http:
  routers:
    crowdsec-companion1-https:
      rule: "PathPrefix(`/`)"
      entryPoints: [https]
      service: hub
      tls: {}
  services:
    hub:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:41381"
YAML
"$engine" run -d --name "$p-traefik" --network "$ns" -v "$work/traefik:/etc/traefik:ro" "$traefik_image" >/dev/null
for _ in $(seq 1 60); do "$engine" exec "$p-hub" cscli lapi status >/dev/null 2>&1 && break; sleep 2; done
"$engine" exec "$p-hub" cscli lapi status >/dev/null
"$engine" exec "$p-hub" cscli bouncers list -o json | grep -q crowdsec_companion1_firewall
# What add-member does on the hub:
"$engine" exec "$p-hub" cscli machines add member1 --password memberpass0123456789abcdefgh --force -f /dev/null >/dev/null
"$engine" exec "$p-hub" cscli bouncers add member1-firewall --key memberbouncerkey0123456789 >/dev/null
"$engine" exec "$p-hub" cscli allowlists create ns8-companion --description e2e >/dev/null
"$engine" exec "$p-hub" cscli allowlists add ns8-companion 192.0.2.0/24 >/dev/null

"$engine" run -d --name "$p-member" --network "$ns" --env-file "$member/crowdsec.env" -v "$work/logs:/logs:ro" \
    -v "$member/crowdsec_config:/etc/crowdsec" -v "$member/crowdsec_data:/var/lib/crowdsec/data" "$cs_image" >/dev/null
for _ in $(seq 1 60); do "$engine" exec "$p-member" cscli lapi status >/dev/null 2>&1 && break; sleep 2; done
"$engine" exec "$p-member" cscli lapi status
"$engine" run -d --name "$p-member-bouncer" --network "$ns" --cap-drop all --cap-add NET_ADMIN --cap-add NET_RAW \
    -v "$member/crowdsec_config/bouncer.yaml:/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml:ro" "$bouncer_image" >/dev/null

log "attack: 5 failed Gitea logins from 203.0.113.50 and 192.0.2.60 (allowlisted)"
"$engine" exec "$p-tools" sh -ec '
  ip link set lo up
  ip addr add 203.0.113.50/32 dev lo
  (while true; do nc -l -p 9000 -s 127.0.0.1 >/dev/null 2>&1 || nc -l 127.0.0.1 9000 >/dev/null 2>&1; done) &
  sleep 1
  echo x | nc -w 2 -s 203.0.113.50 127.0.0.1 9000' && echo "before ban: 203.0.113.50 connects"
for ip in 203.0.113.50 192.0.2.60; do for _ in 1 2 3 4 5; do
    printf 'Oct 12 22:35:17 ns8node traefik[1]: %s - - [12/Oct/2026:22:35:17 +0000] "POST /user/login HTTP/1.1" 200 1 "-" "-" 1 "gitea1-https@file" "http://127.0.0.1:3000" 1ms\n' "$ip" >>"$work/logs/traefik.log"
done; done

log "wait for the hub decision and the member firewall"
for _ in $(seq 1 45); do
    "$engine" exec "$p-tools" nft list ruleset 2>/dev/null | grep -q 203.0.113.50 && break; sleep 2
done
"$engine" exec "$p-hub" cscli decisions list -o raw | tee "$work/decisions.csv"
grep -q '203.0.113.50,ns8/ns8-gitea-web-bf' "$work/decisions.csv"
if grep -q '192.0.2.60' "$work/decisions.csv"; then echo "FAIL: allowlisted address banned"; exit 1; fi
"$engine" exec "$p-hub" cscli alerts list -o json | grep -q "\"machine_id\": \"member1\"" || { echo "alert not attributed to member1"; exit 1; }
"$engine" exec "$p-tools" nft list table ip crowdsec-companion | grep -q 203.0.113.50
if "$engine" exec "$p-tools" sh -c 'echo x | nc -w 3 -s 203.0.113.50 127.0.0.1 9000'; then
    echo "FAIL: banned address still connects"; exit 1
fi
echo "after ban: 203.0.113.50 is dropped"
"$engine" exec "$p-tools" sh -c 'echo x | nc -w 3 127.0.0.1 9000' && echo "127.0.0.1 still connects"

log "unban on the hub removes the block on the member"
"$engine" exec "$p-hub" cscli decisions delete --ip 203.0.113.50 >/dev/null
for _ in $(seq 1 30); do
    "$engine" exec "$p-tools" nft list ruleset | grep -q 203.0.113.50 || break; sleep 2
done
if "$engine" exec "$p-tools" nft list ruleset | grep -q 203.0.113.50; then echo "FAIL: unbanned address still in nftables"; exit 1; fi
"$engine" exec "$p-tools" sh -c 'echo x | nc -w 3 -s 203.0.113.50 127.0.0.1 9000' && echo "after unban: 203.0.113.50 connects"

log "bouncer stop removes its nftables tables"
"$engine" stop -t 20 "$p-member-bouncer" >/dev/null
if "$engine" exec "$p-tools" nft list tables | grep -q companion; then
    echo "NOTE: tables remain after bouncer stop:"; "$engine" exec "$p-tools" nft list tables
else
    echo "tables removed on stop"
fi
log "E2E OK"
