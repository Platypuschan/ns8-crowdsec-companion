"""Periodic job: rediscover log sources and keep Samba auditing applied."""
import sys

from . import lifecycle, render
from .common import load_config, state_dir


def main():
    cfg = load_config()
    if not cfg["role"]:
        return
    module = lifecycle.module_id()
    result = render.render_all(cfg, module, state_dir())
    if result["restart"]:
        lifecycle.systemctl("restart", module + ".service")
    elif result["reload"]:
        # SIGHUP reloads acquisition, parsers and scenarios without dropping the LAPI.
        lifecycle.run(["podman", "kill", "--signal", "HUP", module], check=False)
    if result["bouncer"]:
        lifecycle.systemctl("restart", module + "-bouncer.service")
    lifecycle.apply_samba_audit(cfg, result["found"])
    if result["reload"] or result["restart"]:
        print("Log sources changed: %s" % {k: [i["module"] for i in v] for k, v in result["found"].items()}, file=sys.stderr)


if __name__ == "__main__":
    main()
