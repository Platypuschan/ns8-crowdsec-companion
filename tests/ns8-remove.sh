#!/bin/bash
# Runs only inside the disposable CI VM: removal cleans up host state.
set -Eeuo pipefail
module="$(cat /tmp/csc-module-id)"
remove-module --no-preserve "$module"
for unit in "$module.service" "$module-bouncer.service" "$module-refresh.timer"; do
    [[ ! -e "/etc/systemd/system/$unit" ]] || { echo "FAIL: $unit remains"; exit 1; }
done
for _ in $(seq 1 30); do nft list table ip crowdsec-companion >/dev/null 2>&1 || break; sleep 1; done
if nft list table ip crowdsec-companion >/dev/null 2>&1; then echo "FAIL: nftables table remains"; exit 1; fi
if podman ps -a --format '{{.Names}}' | grep -q "^$module"; then echo "FAIL: containers remain"; exit 1; fi
echo "removal clean"
