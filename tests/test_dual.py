"""Small checks for the dual-protocol contract and safe install decisions."""
import base64
import contextlib
import io
import json
from pathlib import Path
import types
import unittest
from unittest.mock import MagicMock, patch

from argosbx import manager, model, network


PRIVATE = "UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc"
PUBLIC = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"


class DualTests(unittest.TestCase):
    def setUp(self):
        self.node = model.new_node("node.example.com", PRIVATE, PUBLIC)

    def test_subscription_contains_both_real_nodes(self):
        node = self.node
        server = model.server_config(node)
        self.assertEqual([(x["type"], x["listen_port"]) for x in server["inbounds"]],
                         [("vless", 443), ("hysteria2", 443)])
        self.assertEqual(server["inbounds"][0]["users"][0]["flow"], "xtls-rprx-vision")
        self.assertEqual(model.subscription(node), f'https://node.example.com:8443/s/{node["token"]}')
        exports = model.exports(node)
        links = base64.b64decode(exports["shadowrocket.txt"]).decode().splitlines()
        self.assertEqual([link.split(":", 1)[0] for link in links], ["vless", "hysteria2"])
        self.assertIn(node["uuid"], links[0])
        self.assertIn(node["password"], links[1])
        self.assertEqual([link.rsplit("#", 1)[1] for link in links], ["VLESS", "Hysteria2"])
        self.assertEqual([x["type"] for x in json.loads(exports["singbox.json"])["outbounds"]],
                         ["vless", "hysteria2"])
        self.assertIn("packet-encoding: xudp", exports["clash.yaml"])
        self.assertIn('proxies: ["VLESS", "Hysteria2"]', exports["clash.yaml"])
        self.assertNotIn("url-test", exports["clash.yaml"])
        client = json.loads(exports["singbox.json"])
        self.assertEqual([item["tag"] for item in client["outbounds"]], ["VLESS", "Hysteria2"])
        self.assertEqual(client["route"]["final"], "VLESS")
        self.assertEqual(model.exports({**node, "name": "我的 HY2"}), exports)
        self.assertNotIn(node["token"], "".join(exports.values()))

    def test_reinstall_uses_existing_node_without_repair(self):
        current = MagicMock()
        current.is_symlink.return_value = True
        with patch.object(manager, "CURRENT", current), patch.object(manager, "current", return_value=current), \
             patch.object(manager, "read_json", return_value=self.node), \
             patch.object(manager, "probe"), \
             patch.object(manager, "apt_policy"), patch.object(manager, "set_units"), \
             patch.object(manager, "enable_units"), patch.object(manager, "current_exports", return_value=True), \
             patch.object(manager, "preflight", side_effect=AssertionError("reinstall changed system")), \
             patch.object(manager, "subscription", return_value="existing"):
            self.assertEqual(manager.install(types.SimpleNamespace(obfs=None)), "existing")

    def test_qr_encoder_receives_exact_subscription_url(self):
        output = io.StringIO()
        with patch.object(manager, "current", return_value=MagicMock()), \
             patch.object(manager, "read_json", return_value=self.node), \
             patch.object(manager, "run", return_value=types.SimpleNamespace(stdout="QR")) as command, \
             contextlib.redirect_stdout(output):
            manager.subscription()
        url = model.subscription(self.node)
        self.assertIn(url, output.getvalue())
        self.assertEqual(command.call_args.kwargs["input"], url)

    def test_bbr_requires_kernel_support(self):
        def fake_run(args, **kwargs):
            if args[:2] == ["sysctl", "-n"]:
                return types.SimpleNamespace(stdout="cubic reno\n")
            return types.SimpleNamespace(stdout="", returncode=1)
        config = MagicMock()
        config.is_symlink.return_value = False
        config.exists.return_value = False
        with patch.object(network, "SYSCTL", config):
            with self.assertRaisesRegex(ValueError, "不支持 BBR"):
                network.enable(MagicMock(), fake_run, lambda *_: None, lambda *_: None)

    def test_bbr_fq_restore_only_owned_changes(self):
        state = {"congestion": "cubic", "kind": "fq_codel"}
        saved = {}
        queue = {"root": True, "kind": "fq_codel", "handle": "0:", "options": {}}
        def fake_run(args, **kwargs):
            if args[:2] == ["sysctl", "-n"]:
                output = "cubic bbr" if args[2].endswith("available_congestion_control") else state["congestion"]
            elif args[:2] == ["sysctl", "-w"]:
                state["congestion"] = args[2].split("=", 1)[1]
                output = ""
            elif args[:2] == ["ip", "-j"]:
                output = json.dumps([{"dev": "eth0"}] if "-4" in args else [])
            elif args[:3] == ["tc", "-j", "qdisc"]:
                output = json.dumps([{**queue, "kind": state["kind"]}])
            elif args[:3] == ["tc", "qdisc", "replace"]:
                state["kind"] = args[-1]
                output = ""
            else:
                raise AssertionError(args)
            return types.SimpleNamespace(stdout=output, returncode=0)
        config = MagicMock()
        config.is_symlink.return_value = False
        config.exists.return_value = False
        root = Path.cwd() / ".network-test-unused"
        def save(path, value):
            saved[path.name] = value
        with patch.object(network, "SYSCTL", config), patch.object(network, "load", lambda p, default: saved.get(p.name, default)):
            result = network.enable(root, fake_run, save, lambda *_: None)
            self.assertEqual((result["congestion"], result["fq"]), ("bbr", True))
            network.undo(root, fake_run)
        self.assertEqual((state["congestion"], state["kind"]), ("cubic", "fq_codel"))

    def test_failed_fq_restore_keeps_journal(self):
        before = {"root": True, "kind": "fq_codel", "options": {}}
        saved = {"qdisc.json": [{"device": "eth0", "before": before}],
                 "sysctl.json": {"before": "cubic", "after": "bbr"}}
        def fake_run(args, **kwargs):
            self.assertEqual(args[:3], ["tc", "-j", "qdisc"])
            return types.SimpleNamespace(stdout="[]")
        with patch.object(network, "load", lambda p, default: saved.get(p.name, default)):
            with self.assertRaisesRegex(ValueError, "保留恢复记录"):
                network.undo(Path.cwd() / ".network-test-unused", fake_run,
                             pending=False)
        self.assertEqual(len(saved["qdisc.json"]), 1)


if __name__ == "__main__":
    unittest.main()
