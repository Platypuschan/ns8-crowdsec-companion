#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build the NS8 module image. The engine images are upstream CrowdSec and the
# firewall bouncer image published by NethServer for its own CrowdSec module.
set -Eeuo pipefail
repobase="${REPOBASE:-ghcr.io/platypuschan}"
repobase="${repobase,,}"
module="${repobase}/crowdsec-companion"
crowdsec_image="docker.io/crowdsecurity/crowdsec:v1.8.1-debian"
bouncer_image="ghcr.io/nethserver/crowdsec-firewall-bouncer:1.4.0"
builder=""
cleanup() { if [[ -n "${builder}" ]]; then buildah rm "${builder}" >/dev/null; fi; }
trap cleanup EXIT
if [[ ! -d ui/dist ]]; then
    (cd ui && env -u YARN_NO_PROXY corepack yarn install --immutable && env -u YARN_NO_PROXY corepack yarn build)
fi
find imageroot -name __pycache__ -type d -prune -exec rm -rf {} +
builder="$(buildah from scratch)"
buildah add "${builder}" imageroot /imageroot
buildah add "${builder}" ui/dist /ui
buildah config --entrypoint=/ \
    --label="org.opencontainers.image.source=https://github.com/Platypuschan/ns8-crowdsec-companion" \
    --label="org.opencontainers.image.title=NS8 CrowdSec Companion" \
    --label="org.opencontainers.image.licenses=GPL-3.0-or-later" \
    --label="org.nethserver.authorizations=traefik@node:routeadm" \
    --label="org.nethserver.tcp-ports-demand=2" \
    --label="org.nethserver.rootfull=1" \
    --label="org.nethserver.max-per-node=1" \
    --label="org.nethserver.min-core=3.2.2" \
    --label="org.nethserver.images=${crowdsec_image} ${bouncer_image}" "${builder}"
buildah commit "${builder}" "${module}"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf 'module=%s\n' "${module}" >>"${GITHUB_OUTPUT}"
fi
printf 'Built %s\n' "${module}"
