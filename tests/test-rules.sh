#!/bin/bash
# Replay log fixtures through the module's CrowdSec rules in the pinned
# CrowdSec image and compare the resulting decisions with expected.json.
# Needs podman (or docker via DOCKER=docker) and Python 3.
set -Eeuo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
engine="${DOCKER:-podman}"
image="${CROWDSEC_IMAGE:-docker.io/crowdsecurity/crowdsec:v1.8.1-debian}"
name="cscompanion-rules-$$"
work="$(mktemp -d)"
cleanup() { "$engine" rm -f "$name" >/dev/null 2>&1 || true; "$engine" volume rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
PYTHONPATH="$root/imageroot/pypkg" python3 -c '
from cscompanion import render
print(render.routers_parser({"gitea": [{"module": "gitea1"}], "organizr": [{"module": "organizr1"}]}), end="")' >"$work/ns8-router-apps.yaml"
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
metrics="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
printf '{"api": {"server": {"listen_uri": "127.0.0.1:%s"}}, "prometheus": {"listen_addr": "127.0.0.1", "listen_port": %s}}\n' "$port" "$metrics" >"$work/config.yaml.local"
printf 'url: http://127.0.0.1:%s/\n' "$port" >"$work/local_api_credentials.yaml.local"
"$engine" create --name "$name" --network host -v "$name:/var/lib/crowdsec/data" \
    -e DISABLE_ONLINE_API=true -e CUSTOM_HOSTNAME=test -e NO_HUB_UPGRADE=true \
    -e COLLECTIONS=crowdsecurity/linux "$image" >/dev/null
"$engine" cp "$root/imageroot/crowdsec/." "$name:/staging/etc/crowdsec/"
"$engine" cp "$work/ns8-router-apps.yaml" "$name:/staging/etc/crowdsec/parsers/s02-enrich/ns8-router-apps.yaml" 2>/dev/null || {
    mkdir -p "$work/s02" && cp "$work/ns8-router-apps.yaml" "$work/s02/" && "$engine" cp "$work/s02" "$name:/staging/etc/crowdsec/parsers/s02-enrich"; }
"$engine" cp "$work/config.yaml.local" "$name:/staging/etc/crowdsec/config.yaml.local"
"$engine" cp "$work/local_api_credentials.yaml.local" "$name:/staging/etc/crowdsec/local_api_credentials.yaml.local"
"$engine" cp "$root/tests/fixtures" "$name:/tmp/fixtures"
"$engine" start "$name" >/dev/null
for _ in $(seq 1 60); do
    "$engine" exec "$name" cscli lapi status >/dev/null 2>&1 && break
    sleep 2
done
"$engine" exec "$name" cscli lapi status >/dev/null || { "$engine" logs "$name" | tail -20; exit 1; }
"$engine" exec "$name" sh -ec '
  crowdsec -c /etc/crowdsec/config.yaml -dsn file:///tmp/fixtures/traefik.log -type syslog -label ns8_source:traefik -no-api
  crowdsec -c /etc/crowdsec/config.yaml -dsn file:///tmp/fixtures/samba.log -type syslog -label ns8_source:samba -no-api
' >"$work/replay.log" 2>&1 || { cat "$work/replay.log"; exit 1; }
grep -E "performed|level=(error|fatal)" "$work/replay.log" || true
"$engine" exec "$name" cscli alerts list -o json >"$work/alerts.json"
python3 - "$work/alerts.json" "$root/tests/fixtures/expected.json" <<'PY'
import json, sys
alerts = json.load(open(sys.argv[1])) or []
want = json.load(open(sys.argv[2]))
got = {}
for alert in alerts:
    for d in alert.get("decisions") or []:
        got.setdefault(d["value"], set()).add(d["scenario"])
errors = []
for ip, scenario in want["banned"].items():
    if scenario not in got.get(ip, set()):
        errors.append("missing ban %s by %s (got %s)" % (ip, scenario, sorted(got.get(ip, []))))
for ip in want["not_banned"]:
    if ip in got:
        errors.append("unexpected ban %s by %s" % (ip, sorted(got[ip])))
extra = set(got) - set(want["banned"]) - set(want["not_banned"])
errors += ["unexpected ban %s" % ip for ip in sorted(extra)]
print("\n".join(errors) if errors else "rules OK: %d bans as expected" % len(want["banned"]))
sys.exit(1 if errors else 0)
PY
