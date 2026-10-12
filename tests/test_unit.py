"""Unit tests for the module's Python package (no NS8, no containers)."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cscompanion import common, discovery, lifecycle, render


class TokenTests(unittest.TestCase):
    def test_round_trip(self):
        data = {"url": "https://hub.example.org/", "machine": "m1", "password": "p", "bouncer": "m1-firewall", "bouncer_key": "k"}
        self.assertEqual(common.decode_token(common.encode_token(data))["machine"], "m1")

    def test_rejects_plain_http_and_missing_fields(self):
        bad = common.encode_token({"url": "http://hub/", "machine": "m", "password": "p", "bouncer": "b", "bouncer_key": "k"})
        with self.assertRaises(ValueError):
            common.decode_token(bad)
        with self.assertRaises(ValueError):
            common.decode_token(common.encode_token({"url": "https://hub/"}))
        with self.assertRaises(ValueError):
            common.decode_token("not-a-token")


class AllowlistTests(unittest.TestCase):
    def test_normalizes_and_deduplicates(self):
        self.assertEqual(common.normalize_allowlist(["192.0.2.7/32", " 192.0.2.7 ", "198.51.100.9/24", "", "2001:db8::/48"]),
                         ["192.0.2.7", "198.51.100.0/24", "2001:db8::/48"])

    def test_rejects_garbage(self):
        with self.assertRaises(ValueError):
            common.normalize_allowlist(["example.org"])


class DiscoveryTests(unittest.TestCase):
    def tree(self, root):
        def env(path, text):
            p = Path(root, path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        env("home/traefik1/.config/state/environment", "MODULE_ID=traefik1\nTRAEFIK_IMAGE=docker.io/traefik:v3.7.13\n")
        env("home/gitea2/.config/state/environment", "MODULE_ID=gitea2\nIMAGE_URL=ghcr.io/platypuschan/gitea-reworked:0.4.2\n")
        env("home/organizr1/.config/state/environment", "MODULE_ID=organizr1\nORGANIZR_RUNTIME_IMAGE=ghcr.io/platypuschan/organizr-runtime:x\n")
        env("home/ntfy1/.config/state/environment", "MODULE_ID=ntfy1\nNTFY_IMAGE=x\n")
        env("home/../evil/.config/state/environment", "MODULE_ID=../x1\nGITEA_IMAGE=x\n")
        env("var/lib/nethserver/samba1/state/environment", "MODULE_ID=samba1\nSAMBA_DC_IMAGE=ghcr.io/nethserver/samba-dc:3\n")
        env("var/lib/nethserver/crowdsec-companion1/state/environment", "MODULE_ID=crowdsec-companion1\n")

    def test_kinds_and_owners(self):
        with tempfile.TemporaryDirectory() as root:
            self.tree(root)
            uids = {"traefik1": 1001, "gitea2": 1002, "organizr1": 1003}
            with mock.patch.object(discovery, "uid_of", side_effect=lambda m: uids.get(m)):
                found = discovery.discover(root)
        self.assertEqual(found["traefik"], [{"module": "traefik1", "uid": 1001, "rootfull": False}])
        self.assertEqual([i["module"] for i in found["gitea"]], ["gitea2"])
        self.assertEqual([i["module"] for i in found["organizr"]], ["organizr1"])
        self.assertEqual(found["samba"], [{"module": "samba1", "uid": 0, "rootfull": True}])
        self.assertNotIn("ntfy", found)

    def test_module_without_user_is_skipped(self):
        with tempfile.TemporaryDirectory() as root:
            self.tree(root)
            with mock.patch.object(discovery, "uid_of", return_value=None):
                found = discovery.discover(root)
        self.assertNotIn("gitea", found)
        self.assertIn("samba", found)


class RenderTests(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"TCP_PORTS": "20001,20002", "MODULE_ID": "crowdsec-companion1"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_hub_config_binds_loopback_and_pins_hub_branch(self):
        cfg = {**common.DEFAULTS, "role": "hub", "hub_host": "hub.example.org"}
        data = json.loads(render.config_local(cfg))
        self.assertEqual(data["api"]["server"]["listen_uri"], "127.0.0.1:20001")
        self.assertTrue(data["api"]["server"]["use_forwarded_for_headers"])
        self.assertEqual(data["prometheus"]["listen_addr"], "127.0.0.1")
        self.assertEqual(data["cscli"]["hub_branch"], "master")

    def test_member_config_has_no_listener(self):
        cfg = {**common.DEFAULTS, "role": "member", "hub_url": "https://hub.example.org/"}
        self.assertNotIn("api", json.loads(render.config_local(cfg)))

    def test_acquisition_binds_sources_to_owner_uid(self):
        found = {"traefik": [{"module": "traefik1", "uid": 1001}], "samba": [{"module": "samba1", "uid": 0}]}
        docs = [json.loads(d) for d in render.acquisition(found, "/nonexistent").split("---\n")]
        traefik = [d for d in docs if d["labels"]["ns8_source"] == "traefik"][0]
        self.assertEqual(traefik["journalctl_filter"], ["CONTAINER_NAME=traefik", "_UID=1001"])
        samba = [d for d in docs if d["labels"]["ns8_source"] == "samba"][0]
        self.assertEqual(samba["journalctl_filter"], ["CONTAINER_NAME=samba-dc", "_UID=0"])
        self.assertTrue(all(d["labels"]["type"] == "syslog" for d in docs))

    def test_router_map(self):
        text = render.routers_parser({"gitea": [{"module": "gitea2"}], "organizr": [{"module": "organizr1"}]})
        expr = json.loads(text)["statics"][0]["expression"]
        self.assertIn('"gitea2-https@file"', expr)
        self.assertIn('"organizr1-http@file"', expr)
        self.assertEqual(json.loads(render.routers_parser({}))["statics"][0]["expression"], "''")

    def test_member_env_and_bouncer(self):
        with tempfile.TemporaryDirectory() as state:
            with mock.patch.dict(os.environ, {"AGENT_STATE_DIR": state}):
                common.write_secret("machine", "member1")
                common.write_secret("machine_password", "secret-pass")
                common.write_secret("bouncer_key", "bkey")
                cfg = {**common.DEFAULTS, "role": "member", "hub_url": "https://hub.example.org/"}
                env = render.crowdsec_env(cfg, "crowdsec-companion1")
                bouncer = json.loads(render.bouncer(cfg, "crowdsec-companion1"))
        self.assertIn("DISABLE_LOCAL_API=true\n", env)
        self.assertIn("LOCAL_API_URL=https://hub.example.org/\n", env)
        self.assertIn("AGENT_PASSWORD=secret-pass\n", env)
        self.assertEqual(bouncer["api_url"], "https://hub.example.org/")
        self.assertEqual(bouncer["api_key"], "bkey")
        self.assertEqual(bouncer["nftables"]["ipv4"]["table"], "crowdsec-companion")
        self.assertFalse(bouncer["insecure_skip_verify"])

    def test_hub_registers_local_bouncer(self):
        with tempfile.TemporaryDirectory() as state:
            with mock.patch.dict(os.environ, {"AGENT_STATE_DIR": state}):
                key = common.secret("bouncer_key")
                env = render.crowdsec_env({**common.DEFAULTS, "role": "hub"}, "crowdsec-companion1")
                bouncer = json.loads(render.bouncer({**common.DEFAULTS, "role": "hub"}, "crowdsec-companion1"))
        self.assertIn("BOUNCER_KEY_crowdsec_companion1_firewall=%s\n" % key, env)
        self.assertNotIn("DISABLE_LOCAL_API", env)
        self.assertEqual(bouncer["api_url"], "http://127.0.0.1:20001/")

    def test_missing_ports_fail_clearly(self):
        with mock.patch.dict(os.environ, {"TCP_PORTS": "20001"}):
            with self.assertRaises(RuntimeError):
                render.ports()

    def test_render_all_reports_changes_once(self):
        with tempfile.TemporaryDirectory() as state, tempfile.TemporaryDirectory() as root:
            with mock.patch.dict(os.environ, {"AGENT_STATE_DIR": state}):
                common.secret("bouncer_key")
                cfg = {**common.DEFAULTS, "role": "hub", "hub_host": "hub.example.org"}
                first = render.render_all(cfg, "crowdsec-companion1", state, root)
                second = render.render_all(cfg, "crowdsec-companion1", state, root)
            self.assertTrue(first["reload"] and first["restart"])
            self.assertFalse(second["reload"] or second["restart"] or second["bouncer"])
            self.assertTrue(Path(state, "crowdsec_config/scenarios/ns8-gitea-web-bf.yaml").exists())
            self.assertEqual(oct(Path(state, "crowdsec.env").stat().st_mode & 0o777), "0o600")


class SambaLevelTests(unittest.TestCase):
    def test_raises_only_json_audit(self):
        self.assertEqual(lifecycle.samba_level("1 auth_audit:0 auth_json_audit:0"), "1 auth_audit:0 auth_json_audit:2")
        self.assertEqual(lifecycle.samba_level("3 auth_json_audit:5"), "3 auth_json_audit:5")
        self.assertEqual(lifecycle.samba_level("1"), "1 auth_json_audit:2")


if __name__ == "__main__":
    unittest.main()
