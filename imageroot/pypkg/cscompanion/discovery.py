"""Find the NS8 modules on this host whose authentication failures we detect.

HTTP applications are recognised in the Traefik access log by their router
name (``<module>-http(s)@file``). Traefik writes that log itself, without
request headers, so a client cannot inject forged records into it. Application
logs are used only for protocols that bypass Traefik (SSH, Samba).
"""
import os
from pathlib import Path
import pwd
import re

MODULE_ID = re.compile(r"^[a-z][a-z0-9-]*[0-9]+$")


def read_env(path):
    env = {}
    try:
        lines = Path(path).read_text().splitlines()
    except (FileNotFoundError, PermissionError):
        return env
    for line in lines:
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip().strip('"')
    return env


def kind_of(env):
    keys = set(env)
    image = env.get("IMAGE_URL", "").lower().rsplit("/", 1)[-1].split(":", 1)[0].split("@", 1)[0]
    if "TRAEFIK_IMAGE" in keys or image == "traefik":
        return "traefik"
    if "SAMBA_DC_IMAGE" in keys or image.startswith("samba"):
        return "samba"
    if "GITEA_IMAGE" in keys or image.startswith("gitea"):
        return "gitea"
    if keys & {"ORGANIZR_IMAGE", "ORGANIZR_RUNTIME_IMAGE"} or image.startswith("organizr"):
        return "organizr"
    return None


def uid_of(module):
    try:
        return pwd.getpwnam(module).pw_uid
    except KeyError:
        return None


def discover(root="/"):
    """Return {kind: [{module, uid, rootfull}]} for the supported modules."""
    root = Path(root)
    found = {}
    candidates = [(p, False) for p in root.glob("home/*/.config/state/environment")]
    candidates += [(p, True) for p in root.glob("var/lib/nethserver/*/state/environment")]
    for path, rootfull in sorted(candidates):
        env = read_env(path)
        module = env.get("MODULE_ID") or (path.parts[-3] if rootfull else path.parts[-4])
        if not MODULE_ID.match(module):
            continue
        kind = kind_of(env)
        if not kind:
            continue
        uid = 0 if rootfull else uid_of(module)
        if uid is None:
            continue
        found.setdefault(kind, []).append({"module": module, "uid": uid, "rootfull": rootfull})
    return found


def ssh_units(root="/"):
    root = Path(root)
    units = [u for u in ("sshd.service", "ssh.service")
             if (root / "usr/lib/systemd/system" / u).exists() or (root / "lib/systemd/system" / u).exists()]
    return units or ["sshd.service", "ssh.service"]


def journal_dirs(root="/"):
    root = Path(root)
    return [d for d in ("/var/log/journal", "/run/log/journal") if (root / d.lstrip("/")).is_dir()]


def node_id():
    return os.environ.get("NODE_ID", "")
