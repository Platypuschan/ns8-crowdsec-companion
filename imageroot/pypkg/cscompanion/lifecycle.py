"""Host services of the rootful module: CrowdSec, firewall bouncer, refresh timer."""
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import subprocess
import time

from . import discovery, render
from .common import atomic_write, load_config, state_dir

UNIT_DIR = Path("/etc/systemd/system")


def module_id():
    return os.environ["MODULE_ID"]


def run(args, check=True, timeout=120, **kwargs):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=timeout, **kwargs)


def systemctl(*args, check=True):
    return run(["systemctl", *args], check=check)


def cscli(*args, check=True, timeout=60):
    result = run(["podman", "exec", module_id(), "cscli", *args], check=False, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError("cscli %s failed: %s" % (args[0] if args else "", (result.stderr or result.stdout).strip()[-400:]))
    return result


def cscli_json(*args):
    out = cscli(*args, "-o", "json").stdout.strip()
    return json.loads(out) if out and out != "null" else []


def image(name):
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(name + " is missing from the NS8 module environment")
    return value


def units():
    module = module_id()
    state = state_dir()
    journal = "".join(" --volume=%s:%s:ro" % (d, d) for d in discovery.journal_dirs())
    crowdsec = (
        "/usr/bin/podman run --rm --replace --name=%s --network=host --security-opt=label=disable"
        " --env-file=%s/crowdsec.env --volume=%s/crowdsec_config:/etc/crowdsec"
        " --volume=%s/crowdsec_data:/var/lib/crowdsec/data%s --volume=/etc/machine-id:/etc/machine-id:ro"
        " --log-driver=journald %s"
    ) % (module, state, state, state, journal, image("CROWDSEC_IMAGE"))
    bouncer = (
        "/usr/bin/podman run --rm --replace --name=%s-bouncer --network=host --security-opt=label=disable"
        " --cap-drop=all --cap-add=NET_ADMIN --cap-add=NET_RAW"
        " --volume=%s/crowdsec_config/bouncer.yaml:/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml:ro"
        " --log-driver=journald %s"
    ) % (module, state, image("CROWDSEC_FIREWALL_BOUNCER_IMAGE"))
    refresh = "/usr/local/bin/runagent -m %s python3 -m cscompanion.refresh" % module
    # The journald log driver records the container output; systemd would log
    # the same lines a second time from the attached podman process.
    common = ("StartLimitIntervalSec=0\n\n[Service]\nRestart=always\nRestartSec=10\nTimeoutStopSec=40\n"
              "StandardOutput=null\n")
    return {
        module + ".service": (
            "[Unit]\nDescription=CrowdSec companion engine (%s)\nAfter=network-online.target\nWants=network-online.target\n%s"
            "ExecStart=%s\nExecStop=/usr/bin/podman stop --ignore -t 20 %s\n\n[Install]\nWantedBy=multi-user.target\n"
        ) % (module, common, crowdsec, module),
        module + "-bouncer.service": (
            "[Unit]\nDescription=CrowdSec companion firewall bouncer (%s)\nAfter=network-online.target %s.service\n"
            "Wants=network-online.target\n%s"
            "ExecStart=%s\nExecStop=/usr/bin/podman stop --ignore -t 20 %s-bouncer\n\n[Install]\nWantedBy=multi-user.target\n"
        ) % (module, module, common, bouncer, module),
        module + "-refresh.service": (
            "[Unit]\nDescription=CrowdSec companion source discovery (%s)\n\n[Service]\nType=oneshot\nExecStart=%s\n"
        ) % (module, refresh),
        module + "-refresh.timer": (
            "[Unit]\nDescription=CrowdSec companion source discovery (%s)\n\n[Timer]\nOnBootSec=2min\n"
            "OnUnitActiveSec=2min\nAccuracySec=15s\n\n[Install]\nWantedBy=timers.target\n"
        ) % module,
    }


def install_units():
    changed = False
    for name, text in units().items():
        path = UNIT_DIR / name
        try:
            same = path.read_text() == text
        except FileNotFoundError:
            same = False
        if not same:
            atomic_write(path, text, 0o644)
            changed = True
    if changed:
        systemctl("daemon-reload")
    return changed


def remove_units():
    module = module_id()
    for name in (module + "-refresh.timer", module + "-refresh.service", module + "-bouncer.service", module + ".service"):
        systemctl("disable", "--now", name, check=False)
        (UNIT_DIR / name).unlink(missing_ok=True)
    systemctl("daemon-reload", check=False)


def prepare_dirs():
    state = state_dir()
    for path in (state / "crowdsec_config", state / "crowdsec_data", state / "backup"):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)


def wait_lapi(timeout=180):
    """Wait until cscli can talk to the LAPI (local on a hub, remote on a member)."""
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        result = cscli("lapi", "status", check=False, timeout=30)
        if result.returncode == 0:
            return
        last = (result.stderr or result.stdout).strip()[-300:]
        time.sleep(3)
    raise RuntimeError("CrowdSec API is not reachable: " + last)


def wait_agent(timeout=240):
    """Wait until the agent reads its log sources.

    The journal sources start at the end of the journal ("journalctl -n 0"),
    so lines written before this point are never read.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = run(["podman", "logs", module_id()], check=False, timeout=60)
        if "Starting processing data" in result.stdout + result.stderr:
            return True
        time.sleep(3)
    raise RuntimeError("CrowdSec did not start reading its log sources")


def apply(cfg, restart=False):
    """Render configuration and bring the services to the configured state."""
    module = module_id()
    prepare_dirs()
    result = render.render_all(cfg, module, state_dir())
    install_units()
    systemctl("enable", module + ".service")
    if restart or result["restart"] or systemctl("is-active", "--quiet", module + ".service", check=False).returncode:
        systemctl("restart", module + ".service")
    elif result["reload"]:
        run(["podman", "kill", "--signal", "HUP", module], check=False)
    wait_lapi()
    wait_agent()
    if cfg["role"] == "hub":
        sync_allowlist(cfg)
    systemctl("enable", module + "-bouncer.service")
    if restart or result["restart"] or result["bouncer"] or systemctl("is-active", "--quiet", module + "-bouncer.service", check=False).returncode:
        systemctl("restart", module + "-bouncer.service")
    systemctl("enable", "--now", module + "-refresh.timer")
    apply_samba_audit(cfg, result["found"])
    return result


ALLOWLIST = "ns8-companion"


def sync_allowlist(cfg):
    """Make the hub's centralized allowlist equal to the configured entries."""
    lists = cscli_json("allowlists", "list")
    if not any(item.get("name") == ALLOWLIST for item in lists or []):
        cscli("allowlists", "create", ALLOWLIST, "--description", "Managed by the NS8 CrowdSec companion")
    current = cscli_json("allowlists", "inspect", ALLOWLIST)
    present = {i.get("value") for i in (current.get("items") or [])} if isinstance(current, dict) else set()
    wanted = set(cfg["allowlist"])
    if present - wanted:
        cscli("allowlists", "remove", ALLOWLIST, *sorted(present - wanted))
    if wanted - present:
        cscli("allowlists", "add", ALLOWLIST, *sorted(wanted - present))


def route(cfg, delete=False):
    import agent
    import agent.tasks
    traefik = agent.resolve_agent_id("traefik@node")
    if not traefik:
        raise RuntimeError("The NS8 Traefik module of this node was not found")
    data = {"instance": module_id()}
    if not delete:
        data.update(url="http://127.0.0.1:%d" % render.ports()[0], host=cfg["hub_host"],
                    http2https=True, lets_encrypt=bool(cfg["lets_encrypt"]))
    result = agent.tasks.run(agent_id=traefik, action="delete-route" if delete else "set-route", data=data)
    if result["exit_code"] and not delete:
        raise RuntimeError("Traefik route configuration failed")


# --- Samba authentication audit -------------------------------------------

SAMBA_DEFAULT = "1 auth_audit:0 auth_json_audit:0"


def samba_level(old):
    level = re.search(r"(?:^|\s)auth_json_audit:(\d+)(?:\s|$)", old)
    if level and int(level[1]) >= 2:
        return old
    return (re.sub(r"(?:^|\s)auth_json_audit:\S+", "", old).strip() + " auth_json_audit:2").strip()


def apply_samba_audit(cfg, found):
    """Raise Samba's JSON auth audit level in the running process only.

    The saved Samba environment is never changed, so removing this module or
    restarting Samba without it returns to Samba's own setting.
    """
    marker = state_dir() / "samba-levels.json"
    try:
        levels = json.loads(marker.read_text())
    except (FileNotFoundError, ValueError):
        levels = {}
    if not cfg.get("samba_audit"):
        restore_samba_audit()
        return
    for item in found.get("samba", []):
        module = item["module"]
        env = discovery.read_env(Path("/var/lib/nethserver") / module / "state" / "environment")
        old = env.get("SAMBA_LOGLEVEL", SAMBA_DEFAULT)
        new = samba_level(old)
        if new == old:
            continue
        levels.setdefault(module, old)
        atomic_write(marker, json.dumps(levels) + "\n")
        run(["runagent", "-m", module, "podman", "exec", "samba-dc", "smbcontrol", "all", "debug", new], check=False)


def restore_samba_audit():
    marker = state_dir() / "samba-levels.json"
    try:
        levels = json.loads(marker.read_text())
    except (FileNotFoundError, ValueError):
        return
    for module, level in levels.items():
        run(["runagent", "-m", module, "podman", "exec", "samba-dc", "smbcontrol", "all", "debug", level], check=False)
    marker.unlink(missing_ok=True)


# --- Backup ----------------------------------------------------------------

def dump_database():
    """Consistent online copy of the CrowdSec database for NS8 backups."""
    source = state_dir() / "crowdsec_data" / "crowdsec.db"
    target = state_dir() / "backup" / "crowdsec.db"
    if not source.exists():
        return False
    tmp = target.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    src = sqlite3.connect("file:%s?mode=ro" % source, uri=True, timeout=30)
    dst = sqlite3.connect(tmp)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    os.chmod(tmp, 0o600)
    os.replace(tmp, target)
    return True


def restore_database():
    backup = state_dir() / "backup" / "crowdsec.db"
    if not backup.exists():
        return False
    data = state_dir() / "crowdsec_data"
    data.mkdir(mode=0o700, parents=True, exist_ok=True)
    for suffix in ("", "-wal", "-shm"):
        (data / ("crowdsec.db" + suffix)).unlink(missing_ok=True)
    (data / "crowdsec.db").write_bytes(backup.read_bytes())
    os.chmod(data / "crowdsec.db", 0o600)
    return True


def services_state():
    module = module_id()
    names = (module + ".service", module + "-bouncer.service", module + "-refresh.timer")
    return {n: systemctl("is-active", n, check=False).stdout.strip() or "unknown" for n in names}


def shell_quote(args):
    return " ".join(shlex.quote(a) for a in args)
