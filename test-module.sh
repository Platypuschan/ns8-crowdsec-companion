#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Run the NS8 tests against a leader node over SSH. The CI calls this from
# NethServer/ns8-github-actions test-on-qemu.yml through test-module-install.sh.
set -Eeuo pipefail
LEADER_NODE="${1:?missing leader node address}"
IMAGE_URL="${2:?missing module image URL}"
SCENARIO="${3:?missing test scenario}"
SSH_KEYFILE="${SSH_KEYFILE:-${HOME}/.ssh/id_ecdsa}"
[[ "${SCENARIO}" == install ]] || { echo "Unsupported scenario ${SCENARIO}" >&2; exit 64; }
[[ -r "${SSH_KEYFILE}" ]] || { echo "SSH key is not readable: ${SSH_KEYFILE}" >&2; exit 66; }
ssh_node() {
    ssh -i "${SSH_KEYFILE}" -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -o ConnectTimeout=10 -o ServerAliveInterval=30 \
        "root@${LEADER_NODE}" "$@"
}
mkdir -p tests/outputs
for name in ns8-smoke.sh ns8-remove.sh; do
    ssh_node "cat > /tmp/${name}" <"tests/${name}"
done
status=0
ssh_node bash /tmp/ns8-smoke.sh "${IMAGE_URL}" || status=$?
# Keep diagnostics for the workflow artifacts, also after a failure.
# shellcheck disable=SC2016 # expanded on the node
ssh_node 'module=$(cat /tmp/csc-module-id 2>/dev/null); [[ -n "$module" ]] || exit 0
  echo "--- crowdsec startup and sources"; podman logs "$module" 2>&1 | grep -vE "module=lapi|Adding (leaky|trigger|conditional) bucket" | head -150
  echo "--- crowdsec warnings"; podman logs "$module" 2>&1 | grep -E "level=(warning|error|fatal)" | tail -40
  echo "--- units"; journalctl --no-pager -n 150 -u "$module.service" -u "$module-bouncer.service" -u "$module-refresh.service"
  echo "--- journal read inside the container"; podman exec "$module" journalctl -q --no-pager -n 3 CONTAINER_NAME=traefik
  echo "--- acquisition"; cat "/var/lib/nethserver/$module/state/crowdsec_config/acquis.yaml"
  echo "--- discovery"; cat "/var/lib/nethserver/$module/state/discovery.json"
  echo "--- traefik journal fields"; journalctl --no-pager -o json -n 3 CONTAINER_NAME=traefik | head -c 3000' \
    >tests/outputs/companion-diagnostics.txt 2>&1 || true
[[ "${status}" -eq 0 ]] || exit "${status}"
ssh_node bash /tmp/ns8-remove.sh
