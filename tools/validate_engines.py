"""Validate generated files with real official engines (Linux or Windows)."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import re

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from argosbx import manager, model


def validate(sb, caddy, openssl="openssl", mihomo=None, lego=None):
    with tempfile.TemporaryDirectory(prefix="ahy2-check-") as temp:
        root = Path(temp)
        (root / "tls").mkdir()
        result = subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                                "-keyout", str(root / "tls/key.pem"), "-out", str(root / "tls/fullchain.pem"),
                                "-days", "1", "-subj", "/CN=node.example.com",
                                "-addext", "subjectAltName=DNS:node.example.com"], capture_output=True)
        result.check_returncode()
        keys = subprocess.run([sb, "generate", "reality-keypair"], check=True, capture_output=True, text=True).stdout
        node = model.new_node("node.example.com", re.search(r"PrivateKey:\s*(\S+)", keys)[1],
                              re.search(r"PublicKey:\s*(\S+)", keys)[1])
        (root / "server.json").write_text(json.dumps(model.server_config(node, root.as_posix())), encoding="utf-8")
        (root / "client.json").write_text(json.dumps(model.client_config(node)), encoding="utf-8")
        for label, ua in [("default", []), ("recorded-ua", [{"pattern": "Mihomo/test*", "format": "clash"},
                                                           {"pattern": "Shadowrocket/test*", "format": "shadowrocket"}])]:
            config = root / f"{label}.Caddyfile"
            config.write_text(model.caddy_config(node, root.as_posix(), ua), encoding="utf-8")
            subprocess.run([caddy, "validate", "--config", str(config), "--adapter", "caddyfile"], check=True)
            adapted = subprocess.run([caddy, "adapt", "--config", str(config), "--adapter", "caddyfile"],
                                     check=True, capture_output=True, text=True)
            data = json.loads(adapted.stdout)
            for server in data["apps"]["http"]["servers"].values():
                assert server["protocols"] == ["h1", "h2"]
            assert data["admin"]["disabled"] is True
        for name in ("server", "client"):
            subprocess.run([sb, "check", "-c", str(root / f"{name}.json")], check=True)
        if mihomo:
            (root / "clash.yaml").write_text(model.clash_config(node), encoding="utf-8")
            subprocess.run([mihomo, "-t", "-d", str(root / "mihomo"), "-f", str(root / "clash.yaml")], check=True)
            print("Official Mihomo YAML validation: PASS")
        if lego:
            helptext = subprocess.run([lego, "run", "--help"], check=True, capture_output=True, text=True).stdout
            assert "--renew-days" in helptext and "lifetime" in helptext
            command = manager.certificate_command(node, lego, root / "acme", "", "http")
            for option in (arg for arg in command[3:] if isinstance(arg, str) and arg.startswith("--")):
                assert option in helptext, option
            print("Official lego invocation/renewal options: PASS")
        print("Official sing-box dual-inbound/client and Caddy configs: PASS")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sing-box", required=True)
    parser.add_argument("--caddy", required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--mihomo")
    parser.add_argument("--lego")
    args = parser.parse_args()
    validate(str(Path(args.sing_box).resolve()), str(Path(args.caddy).resolve()), args.openssl,
             str(Path(args.mihomo).resolve()) if args.mihomo else None,
             str(Path(args.lego).resolve()) if args.lego else None)
