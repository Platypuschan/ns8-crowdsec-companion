# CrowdSec Companion for NethServer 8

Shares CrowdSec bans between your NethServer 8 hosts and other servers through
**one private hub**. A failed-login attack detected on any member is banned on
every member within seconds. Nothing is sent to the CrowdSec cloud: the Central
API, the community blocklist and console enrollment are always disabled.

```
 NS8 host A (hub)                    NS8 host B (member)          Linux server C
 ┌───────────────────────┐           ┌─────────────────────┐      ┌──────────────────┐
 │ CrowdSec agent        │  alerts   │ CrowdSec agent      │      │ CrowdSec agent   │
 │ CrowdSec LAPI (bans) ◄├──HTTPS────┤                     ├──────┤                  │
 │ firewall bouncer      │ ban list  │ firewall bouncer    │      │ firewall bouncer │
 └───────────────────────┘           └─────────────────────┘      └──────────────────┘
```

- **Hub**: runs the CrowdSec Local API (LAPI) with the shared ban database on
  loopback. NS8 Traefik publishes it as `https://<hub host>/`. The hub also
  detects and enforces on its own host.
- **Member**: runs a CrowdSec agent without its own LAPI and a firewall bouncer.
  Both authenticate to the hub with per-member credentials from a token.
- **Bans** block all traffic from the address (nftables `input` and `forward`
  hooks, own tables `crowdsec-companion` / `crowdsec6-companion`). The duration
  is set on the hub (default 4 hours).

The module does not modify the official NethServer CrowdSec module and can run
next to it; both read the journal and use separate nftables tables.

## What is detected, and how

| Source | Signal | Ban after |
| --- | --- | --- |
| SSH | hub collection `crowdsecurity/sshd` (journal of `sshd.service`/`ssh.service`) | CrowdSec defaults |
| NS8 cluster-admin | Traefik access log: `POST /cluster-admin/api/login` → 401 on router `cluster-admin-https@file` | 5 failures (~10 min window) |
| Gitea web | Traefik access log: `POST /user/login` → 200 (a successful login returns 303) | 5 failures |
| Gitea git / API | Traefik access log: bursts of 401 on `/api/…` or `*.git` | > 30 in a burst |
| Organizr | Traefik access log: `POST /api/v2/login` → 401 | 5 failures |
| Samba (AD/SMB/LDAP) | Samba JSON authentication audit, failed statuses with a remote IP | 5 failures |

### Why the Traefik access log and not the application logs

Application logs often contain values chosen by the client. Gitea, for
example, logs the user name of a failed login verbatim, **including newlines**:

```
… Failed authentication attempt for x from 192.0.2.77:1: user does not exist [uid: 0, name: x from 203.0.113.10:0 …
```

A parser reading that line bans `192.0.2.77`, an address the attacker chose,
and a newline in the user name produces a complete fake log line. With shared
bans this would let anyone lock an administrator out of every host. (Verified
with Gitea 28.0.0; the CrowdSec Hub parser `LePresidente/gitea-logs` is
affected.)

NS8's Traefik writes its access log itself and drops request headers from it,
so method, path, status, router and backend cannot be forged by a client. The
companion therefore recognises HTTP applications by their Traefik router
(`<module>-https@file`) and counts failed logins by path and status. Samba is
read as structured JSON, so client-chosen account names stay inside their JSON
strings. Each journal source is bound to the owning module's container name
**and** Unix UID, so another module cannot write records for it.

A "trigger" inside every module that pushes failed logins was also considered
and rejected: none of these applications has a failed-login hook, so each
module would have to parse its own logs again.

### Samba auditing

Samba's NS8 default disables authentication auditing. With **Detect failed
Samba logins** enabled, the companion raises `auth_json_audit` to 2 in the
running Samba process with `smbcontrol`, without restarting Samba or changing
its saved configuration. Removing the companion restores the previous level.

## Install

The module is rootful (it manages host nftables tables) and allows one instance
per node. Development builds are published as
`ghcr.io/platypuschan/crowdsec-companion:sha-<commit>` and, after all tests on
`main`, as `:dev`. It is not in the module catalog yet.

```bash
add-module ghcr.io/platypuschan/crowdsec-companion:dev 1
```

### Hub

1. Point a DNS name, for example `crowdsec.example.org`, to the hub node.
2. **Settings → Role: Hub**: enter the host name, keep *Let's Encrypt* enabled
   and save.
3. **Members → Add a member** for each other host. Copy the token; it is shown
   only once.

### NS8 member

Install the module on the other node, choose **Role: Member**, paste the token
and save. **Status** shows the hub connection; **Members** on the hub shows the
member's last heartbeat and ban-list update.

### Servers without NS8

Install CrowdSec and `crowdsec-firewall-bouncer` from the CrowdSec packages.
After *Add a member*, the Members page shows the values for:

- `/etc/crowdsec/local_api_credentials.yaml`: `url`, `login`, `password`
- the bouncer configuration: `api_url`, `api_key`

Disable the local LAPI on that server (`api.server.enable: false`) and the
Central API (remove `online_client`), then restart both services.

## Allowlist and unban

The allowlist is kept on the hub (CrowdSec centralized allowlist
`ns8-companion`) and applies to detections from every member. Private networks
are never banned (`crowdsecurity/whitelists`). **Bans** on the hub lists all
active bans with the detecting member; unbanning removes the address from every
member's firewall at its next update (10 seconds).

## Security notes

- Member credentials can create alerts and therefore bans. Remove a member on
  the hub when its host is compromised or retired.
- Traefik logs the `X-Forwarded-For` header as the client address when it is
  present. Without trusted frontend proxies (the NS8 default) Traefik drops
  that header from clients, so the logged address is the real peer. With a
  frontend proxy configured in NS8 (*HTTP routes → Frontend proxies*), the
  address the proxy sends is used; a forwarded chain (`a, b`) is ignored, so a
  proxy is never banned by mistake. The host firewall cannot block clients
  behind a proxy; enforce bans at the proxy as well.
- The hub API is reachable through Traefik over HTTPS only; the LAPI listener
  and the metrics endpoint are bound to `127.0.0.1`.
- If the hub is down, members keep the bans they already have; new bans resume
  when the hub is reachable again.
- CrowdSec's container entrypoint runs `cscli … install` at every start. The
  companion pins `cscli.hub_branch`, so restarts work while the CrowdSec hub is
  unreachable.

## Relation to Fail2ban Reworked

[ns8-fail2ban-reworked](https://github.com/Platypuschan/ns8-fail2ban-reworked)
also shares bans between NS8 hosts (coordinator, permanent bans, ntfy
notifications). Use one of them per host; running both doubles detection and
lets two modules manage Samba's audit level.

## Development and tests

```bash
PYTHONPATH=imageroot/pypkg python3 -m unittest discover -s tests -p 'test_*.py'
bash tests/test-rules.sh   # replays tests/fixtures through the rules in the pinned CrowdSec image
bash tests/test-e2e.sh     # hub + member + Traefik TLS + nftables in an isolated network namespace
(cd ui && corepack yarn install --immutable && corepack yarn build)
./build-images.sh
```

CI (`.github/workflows/validate.yml`) runs these and then installs the module on
fresh single-node NS8 VMs (Rocky Linux 9, Debian 13) with
[`test-on-qemu.yml`](https://github.com/NethServer/ns8-github-actions). The VM
test sends real failed NS8 admin logins from a separate network namespace,
expects the ban and the dropped connection, checks a member token against the
public HTTPS route, unbans, checks the allowlist and removes the module.

Every change to `imageroot/`, `ui/` or `build-images.sh` needs a higher
`CATALOG_VERSION`.

GPL-3.0-or-later. The UI scaffold retains the upstream Nethesis copyright notices.
