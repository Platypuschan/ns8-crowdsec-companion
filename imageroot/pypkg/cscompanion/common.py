"""Settings, secrets and small helpers shared by actions and services."""
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import tempfile

ROLES = ("hub", "member")
DEFAULTS = {
    "role": "",
    "hub_host": "",
    "lets_encrypt": True,
    "hub_url": "",
    "ban_duration": "4h",
    "allowlist": [],
    "samba_audit": True,
    "insecure_skip_verify": False,
}
DURATION = re.compile(r"^[1-9][0-9]{0,4}(m|h)$")
HOST = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
MEMBER = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")


def state_dir():
    # NS8 runs actions with the module state directory as working directory.
    return Path(os.environ.get("AGENT_STATE_DIR", os.getcwd()))


def secrets_dir():
    path = state_dir() / "secrets"
    path.mkdir(mode=0o700, exist_ok=True)
    return path


def atomic_write(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix="." + path.name + ".")
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def changed_write(path, text, mode=0o600):
    """Write only when the content differs; report whether it changed."""
    path = Path(path)
    try:
        if path.read_text() == text:
            return False
    except FileNotFoundError:
        pass
    atomic_write(path, text, mode)
    return True


def load_config():
    try:
        stored = json.loads((state_dir() / "config.json").read_text())
    except FileNotFoundError:
        stored = {}
    return {**DEFAULTS, **{k: v for k, v in stored.items() if k in DEFAULTS}}


def save_config(cfg):
    atomic_write(state_dir() / "config.json", json.dumps(cfg, indent=2, sort_keys=True) + "\n")


def secret(name, length=32):
    """Return a persistent random secret, creating it on first use."""
    path = secrets_dir() / name
    try:
        value = path.read_text().strip()
        if value:
            return value
    except FileNotFoundError:
        pass
    value = secrets.token_urlsafe(length)
    atomic_write(path, value + "\n")
    return value


def read_secret(name):
    try:
        return (secrets_dir() / name).read_text().strip()
    except FileNotFoundError:
        return ""


def write_secret(name, value):
    atomic_write(secrets_dir() / name, value + "\n")


def normalize_allowlist(entries):
    """Validate IPs/CIDRs; return canonical strings or raise ValueError."""
    result = []
    for raw in entries:
        value = str(raw).strip()
        if not value:
            continue
        network = ipaddress.ip_network(value, strict=False)
        text = str(network.network_address) if network.num_addresses == 1 else str(network)
        if text not in result:
            result.append(text)
    return result


def hub_url(cfg):
    if cfg["role"] == "hub":
        return "https://" + cfg["hub_host"] + "/"
    return cfg["hub_url"]


def encode_token(data):
    raw = json.dumps({"v": 1, **data}, separators=(",", ":")).encode()
    return "csc1." + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_token(token):
    token = str(token).strip()
    if not token.startswith("csc1."):
        raise ValueError("Unknown token format")
    body = token[5:]
    data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    for key in ("url", "machine", "password", "bouncer", "bouncer_key"):
        if not isinstance(data.get(key), str) or not data[key]:
            raise ValueError("Token field missing: " + key)
    if not data["url"].startswith("https://"):
        raise ValueError("The hub URL must use HTTPS")
    return data
