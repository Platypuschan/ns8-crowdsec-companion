"""NS8 action entry points: python3 -m cscompanion.actions <action>."""
import ipaddress
import json
import os
import secrets
import sys

from . import lifecycle, render
from .common import (DURATION, HOST, MEMBER, ROLES, decode_token, encode_token, hub_url, load_config,
                     normalize_allowlist, read_secret, save_config, secret, state_dir, write_secret)


def fail(field, message):
    """Report a validation error the way NS8 shows it next to a form field."""
    import agent
    agent.set_status("validation-failed")
    json.dump([{"field": field, "parameter": field, "value": "", "error": message}], sys.stdout)
    sys.exit(2)


def read_input():
    data = sys.stdin.read().strip()
    return json.loads(data) if data else {}


def create_module(_request):
    lifecycle.prepare_dirs()
    save_config(load_config())


def configure_module(request):
    cfg = load_config()
    role = request.get("role", cfg["role"])
    if role not in ROLES:
        fail("role", "invalid_role")
    if cfg["role"] and role != cfg["role"]:
        # A hub's database holds every member's credentials; switching would
        # silently disconnect them. A new instance must be installed instead.
        fail("role", "role_is_fixed")
    cfg["role"] = role
    duration = str(request.get("ban_duration", cfg["ban_duration"])).strip()
    if not DURATION.match(duration):
        fail("ban_duration", "invalid_duration")
    cfg["ban_duration"] = duration
    try:
        cfg["allowlist"] = normalize_allowlist(request.get("allowlist", cfg["allowlist"]))
    except ValueError:
        fail("allowlist", "invalid_address")
    cfg["samba_audit"] = bool(request.get("samba_audit", cfg["samba_audit"]))
    token = ""
    if role == "hub":
        host = str(request.get("hub_host", cfg["hub_host"])).strip().lower()
        if not HOST.match(host):
            fail("hub_host", "invalid_host")
        cfg["hub_host"] = host
        cfg["lets_encrypt"] = bool(request.get("lets_encrypt", cfg["lets_encrypt"]))
        cfg["hub_url"] = hub_url(cfg)
        secret("bouncer_key", 32)
    else:
        token = str(request.get("token", "")).strip()
        if token:
            try:
                data = decode_token(token)
            except (ValueError, KeyError, TypeError):
                fail("token", "invalid_token")
            cfg["hub_url"] = data["url"]
            write_secret("machine", data["machine"])
            write_secret("machine_password", data["password"])
            write_secret("bouncer", data["bouncer"])
            write_secret("bouncer_key", data["bouncer_key"])
        elif not read_secret("machine_password"):
            fail("token", "token_required")
        cfg["insecure_skip_verify"] = bool(request.get("insecure_skip_verify", cfg["insecure_skip_verify"]))
    save_config(cfg)
    lifecycle.apply(cfg, restart=bool(token))
    if role == "hub":
        lifecycle.route(cfg)


def get_configuration(_request):
    cfg = load_config()
    out = {k: cfg[k] for k in ("role", "hub_host", "lets_encrypt", "hub_url", "ban_duration",
                               "allowlist", "samba_audit", "insecure_skip_verify")}
    out["member_name"] = read_secret("machine") if cfg["role"] == "member" else ""
    json.dump(out, sys.stdout)


def require_hub():
    if load_config()["role"] != "hub":
        fail("role", "hub_only")


def add_member(request):
    require_hub()
    name = str(request.get("name", "")).strip().lower()
    if not MEMBER.match(name) or name == os.environ["MODULE_ID"]:
        fail("name", "invalid_member_name")
    machines = {m.get("machineId") for m in lifecycle.cscli_json("machines", "list")}
    if name in machines:
        fail("name", "member_exists")
    password = secrets.token_urlsafe(36)
    key = secrets.token_urlsafe(32)
    bouncer = name + "-firewall"
    lifecycle.cscli("bouncers", "delete", bouncer, check=False)
    lifecycle.cscli("machines", "add", name, "--password", password, "--force", "-f", "/dev/null")
    lifecycle.cscli("bouncers", "add", bouncer, "--key", key)
    token = encode_token({"url": load_config()["hub_url"], "machine": name, "password": password,
                          "bouncer": bouncer, "bouncer_key": key})
    json.dump({"name": name, "token": token, "hub_url": load_config()["hub_url"]}, sys.stdout)


def list_members(_request):
    require_hub()
    module = os.environ["MODULE_ID"]
    bouncers = {b.get("name"): b for b in lifecycle.cscli_json("bouncers", "list")}
    members = []
    for m in lifecycle.cscli_json("machines", "list"):
        name = m.get("machineId", "")
        b = bouncers.get(name + "-firewall", {})
        members.append({
            "name": name,
            "local": name == module,
            "ip_address": m.get("ipAddress", ""),
            "version": m.get("version", ""),
            "last_heartbeat": m.get("last_heartbeat", ""),
            "last_push": m.get("last_push", ""),
            "bouncer_last_pull": b.get("last_pull", ""),
            "bouncer_ip_address": b.get("ip_address", ""),
        })
    json.dump({"members": members}, sys.stdout)


def remove_member(request):
    require_hub()
    name = str(request.get("name", "")).strip().lower()
    if not MEMBER.match(name) or name == os.environ["MODULE_ID"]:
        fail("name", "invalid_member_name")
    lifecycle.cscli("machines", "delete", name, check=False)
    lifecycle.cscli("bouncers", "delete", name + "-firewall", check=False)


def list_decisions(_request):
    require_hub()
    decisions = []
    for alert in lifecycle.cscli_json("decisions", "list", "--limit", "0"):
        for d in alert.get("decisions") or []:
            decisions.append({
                "id": d.get("id"),
                "ip": d.get("value", ""),
                "scope": d.get("scope", ""),
                "scenario": d.get("scenario", ""),
                "origin": d.get("origin", ""),
                "until": d.get("until", ""),
                "duration": d.get("duration", ""),
                "machine": alert.get("machine_id", ""),
                "country": (alert.get("source") or {}).get("cn", ""),
            })
    json.dump({"decisions": decisions}, sys.stdout)


def unban(request):
    require_hub()
    addresses = request.get("addresses") or []
    for value in addresses:
        try:
            ipaddress.ip_address(str(value))
        except ValueError:
            fail("addresses", "invalid_address")
    for value in addresses:
        lifecycle.cscli("decisions", "delete", "--ip", str(value))


def get_status(_request):
    cfg = load_config()
    status = {"role": cfg["role"], "hub_url": cfg["hub_url"], "services": {}, "lapi": "", "sources": {}}
    if not cfg["role"]:
        json.dump(status, sys.stdout)
        return
    status["services"] = lifecycle.services_state()
    result = lifecycle.cscli("lapi", "status", check=False, timeout=30)
    status["lapi"] = "ok" if result.returncode == 0 else (result.stderr or result.stdout).strip()[-300:]
    try:
        found = json.loads((state_dir() / "discovery.json").read_text())
    except (FileNotFoundError, ValueError):
        found = {}
    status["sources"] = {kind: [i["module"] for i in items] for kind, items in found.items()}
    if cfg["role"] == "hub" and status["lapi"] == "ok":
        alerts = lifecycle.cscli_json("decisions", "list", "--limit", "0")
        status["active_bans"] = sum(len(a.get("decisions") or []) for a in alerts)
        status["members"] = len(lifecycle.cscli_json("machines", "list"))
    json.dump(status, sys.stdout)


def destroy_module(_request):
    cfg = load_config()
    lifecycle.restore_samba_audit()
    if cfg["role"] == "hub":
        try:
            lifecycle.route(cfg, delete=True)
        except Exception as error:  # the module is being removed anyway
            print("Route removal failed: %s" % error, file=sys.stderr)
    lifecycle.remove_units()


def update_module(_request):
    cfg = load_config()
    if cfg["role"]:
        lifecycle.apply(cfg, restart=True)


def restore_module(request):
    lifecycle.prepare_dirs()
    lifecycle.restore_database()
    cfg = load_config()
    if cfg["role"]:
        lifecycle.apply(cfg, restart=True)
        if cfg["role"] == "hub":
            lifecycle.route(cfg)


def module_dump_state(_request):
    lifecycle.dump_database()


ACTIONS = {
    "create-module": create_module,
    "configure-module": configure_module,
    "get-configuration": get_configuration,
    "add-member": add_member,
    "list-members": list_members,
    "remove-member": remove_member,
    "list-decisions": list_decisions,
    "unban": unban,
    "get-companion-status": get_status,
    "destroy-module": destroy_module,
    "update-module": update_module,
    "restore-module": restore_module,
    "module-dump-state": module_dump_state,
}


def main():
    action = sys.argv[1]
    request = read_input() if action not in ("update-module", "module-dump-state") else {}
    ACTIONS[action](request)


if __name__ == "__main__":
    main()
