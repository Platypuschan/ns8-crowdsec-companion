"""Render CrowdSec, bouncer and container configuration from settings.

YAML files are written as JSON documents, which every YAML parser accepts,
so no template engine or YAML library is needed.
"""
import json
import os
from pathlib import Path
import shutil

from . import discovery
from .common import changed_write, read_secret

COLLECTIONS = "crowdsecurity/linux"
STATIC_RULES = Path(__file__).resolve().parents[2] / "crowdsec"
# Router names Traefik derives from a module ID: <module>-http / <module>-https.
ROUTER_SUFFIXES = ("-https@file", "-http@file")


def ports():
    values = os.environ.get("TCP_PORTS", os.environ.get("TCP_PORT", "")).split(",")
    if len(values) < 2 or not all(v.strip().isdigit() for v in values[:2]):
        raise RuntimeError("NS8 did not allocate the two TCP ports this module needs")
    return int(values[0]), int(values[1])


def yaml_doc(data):
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def config_local(cfg):
    lapi, metrics = ports()
    data = {
        "prometheus": {"enabled": True, "level": "full", "listen_addr": "127.0.0.1", "listen_port": metrics},
        "db_config": {"use_wal": True, "flush": {"max_items": 20000, "max_age": "30d"}},
        # A fixed hub branch avoids cscli's online version lookup. The image's
        # entrypoint runs "cscli parsers install" at every start; without this
        # the container cannot start while version.crowdsec.net is unreachable.
        "cscli": {"hub_branch": "master"},
    }
    if cfg["role"] == "hub":
        # Traefik is the only client that reaches this loopback listener from
        # outside and replaces any X-Forwarded-For sent by the remote client.
        data["api"] = {"server": {"listen_uri": "127.0.0.1:%d" % lapi, "use_forwarded_for_headers": True}}
    return yaml_doc(data)


def acquisition(found, root="/"):
    docs = [{
        "source": "journalctl",
        "journalctl_filter": ["_SYSTEMD_UNIT=" + u for u in discovery.ssh_units(root)],
        "labels": {"type": "syslog", "ns8_source": "sshd"},
    }]
    for item in found.get("traefik", []):
        docs.append({
            "source": "journalctl",
            # Different fields are ANDed by journalctl: only this module's container.
            "journalctl_filter": ["CONTAINER_NAME=traefik", "_UID=%d" % item["uid"]],
            "labels": {"type": "syslog", "ns8_source": "traefik", "ns8_module": item["module"]},
        })
    for item in found.get("samba", []):
        docs.append({
            "source": "journalctl",
            "journalctl_filter": ["CONTAINER_NAME=samba-dc", "_UID=%d" % item["uid"]],
            "labels": {"type": "syslog", "ns8_source": "samba", "ns8_module": item["module"]},
        })
    return "---\n".join(yaml_doc(d) for d in docs)


def routers_parser(found):
    """Generated s02 parser: map Traefik router names to application kinds."""
    expr = "''"
    for kind in ("organizr", "gitea"):
        names = sorted(item["module"] + s for item in found.get(kind, []) for s in ROUTER_SUFFIXES)
        if names:
            expr = "evt.Meta.ns8_router in %s ? '%s' : (%s)" % (json.dumps(names), kind, expr)
    return yaml_doc({
        "name": "ns8/router-apps",
        "description": "Map NS8 Traefik routers to application kinds (generated)",
        "filter": "evt.Meta.log_type == 'ns8_traefik_access'",
        "onsuccess": "next_stage",
        "statics": [{"meta": "ns8_app", "expression": expr}],
    })


def profiles(cfg):
    return yaml_doc({
        "name": "ns8_ip_ban",
        "filters": ["Alert.Remediation == true && Alert.GetScope() == 'Ip'"],
        "decisions": [{"type": "ban", "duration": cfg["ban_duration"]}],
        "on_success": "break",
    })


def bouncer(cfg, module):
    url = "http://127.0.0.1:%d/" % ports()[0] if cfg["role"] == "hub" else cfg["hub_url"]
    return yaml_doc({
        "mode": "nftables",
        "update_frequency": "10s",
        "log_mode": "stdout",
        "log_level": "info",
        "api_url": url,
        "api_key": read_secret("bouncer_key"),
        "insecure_skip_verify": bool(cfg.get("insecure_skip_verify")),
        "disable_ipv6": False,
        "deny_action": "DROP",
        "deny_log": False,
        "supported_decisions_types": ["ban"],
        "nftables": {
            "ipv4": {"enabled": True, "set-only": False, "table": "crowdsec-companion",
                     "chain": "crowdsec-companion-chain", "priority": -10},
            "ipv6": {"enabled": True, "set-only": False, "table": "crowdsec6-companion",
                     "chain": "crowdsec6-companion-chain", "priority": -10},
        },
        "nftables_hooks": ["input", "forward"],
    })


def crowdsec_env(cfg, module):
    env = {
        "DISABLE_ONLINE_API": "true",
        "COLLECTIONS": COLLECTIONS,
        "CUSTOM_HOSTNAME": module,
        "METRICS_PORT": str(ports()[1]),
        "NO_HUB_UPGRADE": "true",
    }
    if cfg["role"] == "hub":
        env["BOUNCER_KEY_" + module.replace("-", "_") + "_firewall"] = read_secret("bouncer_key")
    else:
        env.update({
            "DISABLE_LOCAL_API": "true",
            "LOCAL_API_URL": cfg["hub_url"],
            "AGENT_USERNAME": read_secret("machine"),
            "AGENT_PASSWORD": read_secret("machine_password"),
        })
        if cfg.get("insecure_skip_verify"):
            env["INSECURE_SKIP_VERIFY"] = "true"
    return "".join("%s=%s\n" % kv for kv in sorted(env.items()))


def render_all(cfg, module, state, root="/"):
    """Write every generated file; return True if CrowdSec must reload."""
    state = Path(state)
    conf = state / "crowdsec_config"
    found = discovery.discover(root)
    reload = False
    reload |= changed_write(conf / "acquis.yaml", acquisition(found, root), 0o644)
    reload |= changed_write(conf / "parsers/s02-enrich/ns8-router-apps.yaml", routers_parser(found), 0o644)
    for path in sorted(STATIC_RULES.rglob("*.yaml")):
        target = conf / path.relative_to(STATIC_RULES)
        reload |= changed_write(target, path.read_text(), 0o644)
    restart = changed_write(conf / "config.yaml.local", config_local(cfg), 0o644)
    restart |= changed_write(conf / "profiles.yaml", profiles(cfg), 0o644)
    restart |= changed_write(state / "crowdsec.env", crowdsec_env(cfg, module))
    bouncer_changed = changed_write(conf / "bouncer.yaml", bouncer(cfg, module))
    changed_write(state / "discovery.json", json.dumps(found, indent=2, sort_keys=True) + "\n", 0o644)
    return {"reload": reload, "restart": restart, "bouncer": bouncer_changed, "found": found}


def remove_tree(path):
    shutil.rmtree(path, ignore_errors=True)
