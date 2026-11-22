import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch

import bootstrap
from argosbx import maintenance, manager, model, network, system
from test_dual import PRIVATE, PUBLIC


def result(stdout="", code=0):
    return types.SimpleNamespace(stdout=stdout, returncode=code)


def save(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


class MaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.node = model.new_node("node.example.com", PRIVATE, PUBLIC)
        self.stage = self.root / "stage"
        self.stage.mkdir()
        self.stack.enter_context(patch.multiple(manager, DATA=self.root, ETC=self.root, STATE=self.root / "state.json",
                                              JOURNAL=self.root / "tx.json", save=save))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.stack.enter_context(contextlib.redirect_stderr(io.StringIO()))

    def test_new_install_obfs_and_pending_credentials(self):
        args = types.SimpleNamespace(obfs="salamander", domain=self.node["domain"], email="", server_ip=None,
                                     firewall_external=False, arch="amd64")
        def record_generation(stage, node, *_):
            self.assertIn("obfs_password", node)
            self.assertEqual(model.server_config(node)["inbounds"][1]["obfs"]["type"], "salamander")
            self.assertIn("&obfs=salamander", model.uri(node))
        for name in ("preflight", "apt_policy", "dns_preflight", "reality_target_check", "identities", "ingress",
                     "tune", "firewall", "set_units", "activate", "enable_units", "subscription"):
            self.stack.enter_context(patch.object(manager, name))
        self.stack.enter_context(patch.object(manager, "CURRENT", self.root / "missing"))
        self.stack.enter_context(patch.object(manager, "generation", return_value=self.stage))
        self.stack.enter_context(patch.object(manager, "reality_keypair", return_value=(PRIVATE, PUBLIC)))
        self.stack.enter_context(patch.object(manager.releases, "install_binary"))
        self.stack.enter_context(patch.object(manager, "write_generation", side_effect=record_generation))
        issue = self.stack.enter_context(patch.object(manager, "obtain_certificate", side_effect=manager.Error("HTTP-01 failed")))
        with self.assertRaises(manager.Error):
            manager.install(args)
        pending = manager.read_json(self.root / "pending.json")["node"]
        issue.side_effect = None
        issue.return_value = (self.root / "fullchain", self.root / "key")
        manager.install(args)
        self.assertEqual(issue.call_args.args[0], pending)
        self.assertFalse((self.root / "pending.json").exists())

    def test_existing_upgrade_regenerates_exports_without_rotating(self):
        save(self.stage / "node.json", {**self.node, "name": "我的 HY2"})
        changed = self.root / "candidate"
        with patch.object(manager, "CURRENT", self.stage), patch.object(Path, "is_symlink", return_value=True), \
                patch.object(manager, "current", return_value=self.stage), patch.object(manager, "probe"), \
                patch.object(manager, "pending_caddy_update", return_value=None), \
                patch.object(manager, "apt_policy"), patch.object(manager, "set_units", return_value=set()), \
                patch.object(manager, "enable_units"), \
                patch.object(manager, "copy_generation", return_value=changed), patch.object(manager, "write_generation") as write, \
                patch.object(manager, "activate") as activate, patch.object(manager, "subscription"):
            manager.install(types.SimpleNamespace(obfs=None))
        deployed = write.call_args.args[1]
        self.assertEqual(deployed, {**self.node, "name": "我的 HY2"})
        self.assertEqual(model.subscription(deployed), model.subscription(self.node))
        activate.assert_called_once()

    def test_invalid_install_options_are_rejected_before_platform_access(self):
        with patch.object(manager, "root_platform") as platform:
            for option in ("--name=custom", "--challenge=dns", "--token-file=secret"):
                with self.subTest(option=option), self.assertRaises(SystemExit) as error:
                    manager.main(["install", option])
                self.assertEqual(error.exception.code, 2)
        platform.assert_not_called()

    def test_recovery_confirms_same_fault_and_keeps_backoff_and_budget(self):
        issues = {"web": "crashed"}
        with patch.object(manager, "current", return_value=self.stage), \
                patch.object(manager, "local_health_issues", side_effect=lambda _: issues.copy()), \
                patch.object(manager, "validate_recovery"), patch.object(manager, "cleanup_generations"), \
                patch.object(manager, "run", return_value=result()), patch.object(manager, "protocol_health", return_value={}), \
                patch.object(manager, "recover_runtime", side_effect=manager.Error("verification failed")) as recover:
            def tick(timestamp, failing=True):
                with patch.object(manager.time, "time", return_value=timestamp):
                    if failing:
                        with self.assertRaises(manager.Error):
                            manager.health(True)
                    else:
                        manager.health(True)
            tick(100000)
            recover.assert_not_called()
            tick(100060)
            self.assertEqual(recover.call_args.args[1], "web")
            self.assertEqual(manager.read_json(self.root / "health.json")["recovery"], "failed")
            tick(100120)
            self.assertEqual(recover.call_count, 1)
            tick(100180)
            tick(100420)
            self.assertEqual(recover.call_count, 2)
            save(self.root / "recovery-budget.json", {"attempts": [100180] * 8})
            tick(100480)
            self.assertEqual(recover.call_count, 2)
            recover.side_effect = None
            tick(186580, failing=False)
            self.assertEqual(recover.call_count, 3)
            self.assertEqual(manager.read_json(self.root / "health.json")["recovery"], "recovered")
            self.assertFalse(manager.read_json(self.root / "self-heal.json")["faults"])

    def test_fault_scope_and_start_limit(self):
        for fault, service, checks in (("proxy", manager.SERVICES[0], "check_proxy_listeners"),
                                       ("web", manager.SERVICES[1], "check_web_listener")):
            with self.subTest(fault=fault), patch.object(manager, "run", return_value=result("failed\n")) as run, \
                    patch.object(manager, checks), patch.object(manager, "probe_web"):
                manager.recover_runtime(self.stage, fault)
                writes = [call.args[0] for call in run.call_args_list if call.args[0][1] != "show"]
                self.assertEqual(writes, [["systemctl", "reset-failed", service], ["systemctl", "restart", service]])
        with patch.object(manager, "lock", return_value=contextlib.nullcontext()), patch.object(manager, "firewall") as rebuild, \
                patch.object(manager, "verify_firewall") as verify, patch.object(manager, "run") as run:
            manager.recover_runtime(self.stage, "firewall")
        rebuild.assert_called_once()
        verify.assert_called_once()
        run.assert_not_called()

    def test_external_probe_failure_is_not_local_failure(self):
        def probe(_stage, **kwargs):
            if kwargs["protocol"] == "hy2":
                raise manager.Error("network unavailable")
        with patch.object(manager, "local_public_ip", return_value=None), patch.object(manager, "proxy_probe", side_effect=probe), \
                patch.object(manager, "current", return_value=self.stage), patch.object(manager, "local_health_issues", return_value={}), \
                patch.object(manager, "cleanup_generations"), patch.object(manager, "run", return_value=result()), \
                patch.object(manager, "recover_runtime") as recover:
            manager.health(True)
        status = manager.read_json(self.root / "health.json")
        self.assertEqual(status["local"], "LOCAL_OK")
        self.assertEqual(status["protocols"]["vless"]["data"], "DATA_OK")
        self.assertEqual(status["protocols"]["hy2"]["data"], "EXTERNAL_UNKNOWN")
        recover.assert_not_called()

    def test_renew_has_no_network_when_not_due_and_preserves_old_cert_on_failure(self):
        save(self.stage / "node.json", self.node)
        save(manager.STATE, {})
        (self.stage / "tls").mkdir()
        cert = self.stage / "tls/fullchain.pem"
        cert.write_bytes(b"deployed")
        with patch.object(manager, "current", return_value=self.stage), patch.object(manager, "certificate_check") as check, \
                patch.object(manager, "obtain_certificate", side_effect=manager.Error("bad certificate")) as issue, \
                patch.object(manager, "run", return_value=result(code=1)), patch.object(manager, "activate") as activate:
            with patch.object(manager.time, "time", return_value=100000):
                manager.renew(True)
                issue.assert_not_called()
                check.side_effect = manager.Error("expired")
            with patch.object(manager.time, "time", return_value=186400):
                with self.assertRaises(manager.Error):
                    manager.renew(True)
                manager.renew(True)
            self.assertEqual(issue.call_count, 1)
            self.assertEqual(manager.read_json(self.root / "renewal.json")["next_at"], 190000)
            self.assertEqual(cert.read_bytes(), b"deployed")
            activate.assert_not_called()
            issue.side_effect = None
            issue.return_value = (self.root / "candidate-cert", self.root / "candidate-key")
            for path in issue.return_value:
                path.write_bytes(b"candidate")
            with patch.object(manager.time, "time", return_value=190000), \
                    patch.object(manager, "copy_generation", return_value=self.stage), patch.object(manager, "write_generation") as write:
                manager.renew(True)
            self.assertEqual(write.call_args.args[1], self.node)
            activate.assert_called_once()
            self.assertEqual(manager.read_json(self.root / "renewal.json")["status"], "renewed")

    def test_valid_certificate_from_interrupted_deploy_needs_no_new_acme_request(self):
        certs = self.root / "acme/certificates"
        certs.mkdir(parents=True)
        cert = certs / (self.node["domain"] + ".crt")
        key = cert.with_suffix(".key")
        cert.touch()
        key.touch()
        with patch.object(manager, "certificate_check") as verify, patch.object(manager, "http_challenge") as challenge:
            self.assertEqual(manager.obtain_certificate(self.node, self.root / "lego", ""), (cert, key))
        verify.assert_called_once_with(cert, key, self.node["domain"], minimum=manager.RENEW_WINDOW)
        challenge.assert_not_called()

    def test_apt_policy_conflict_and_uninstall_does_not_remove_admin_config(self):
        policy = self.root / "99zz-aaa"
        admin = self.root / "20auto-upgrades"
        admin.write_text('APT::Periodic::Unattended-Upgrade "1";')
        expected = "".join(f'{key} "0";\n' for key in manager.APT_KEYS)
        def atomic(path, content, _mode):
            path.write_text(content)
        with patch.object(manager, "APT_POLICY", policy), patch.object(manager, "atomic", side_effect=atomic), \
                patch.object(manager, "run", return_value=result(expected)) as run:
            manager.apt_policy()
            self.assertTrue(policy.is_file())
            run.return_value = result(expected.replace('"0"', '"1"', 1))
            with self.assertRaisesRegex(manager.Error, "更高优先级"):
                manager.verify_apt_policy()
            manager.apt_policy(remove=True)
            self.assertFalse(policy.exists())
            self.assertIn('"1"', admin.read_text())
            policy.write_text("admin")
            manager.apt_policy(remove=True)
            self.assertEqual(policy.read_text(), "admin")

    @unittest.skipUnless(shutil.which("apt-config"), "requires apt-config")
    def test_apt_policy_priority_with_real_apt_config(self):
        parts = self.root / "apt.conf.d"
        parts.mkdir()
        main_config = self.root / "apt.conf"
        entry_config = self.root / "load.conf"
        entry_config.write_text(f'Dir::Etc::Parts "{parts}";\nDir::Etc::Main "{main_config}";\n')
        admin = parts / "20auto-upgrades"
        admin.write_text('APT::Periodic::Unattended-Upgrade "1";')
        policy = parts / manager.APT_POLICY.name
        def run(args, **_kwargs):
            return subprocess.run(args, capture_output=True, text=True, check=True,
                                  env={**os.environ, "APT_CONFIG": str(entry_config)})
        with patch.object(manager, "APT_POLICY", policy), patch.object(manager, "run", side_effect=run):
            manager.apt_policy()
            main_config.write_text('APT::Periodic::Unattended-Upgrade "1";')
            with self.assertRaisesRegex(manager.Error, "Unattended-Upgrade"):
                manager.verify_apt_policy()
            manager.apt_policy(remove=True)
        self.assertEqual(admin.read_text(), 'APT::Periodic::Unattended-Upgrade "1";')
        self.assertFalse(policy.exists())

    @unittest.skipUnless(shutil.which("openssl"), "requires OpenSSL")
    def test_certificate_validation_chain_san_key_and_validity(self):
        from tools.runtime_smoke import make_cert
        local_ca = make_cert(self.stage, "openssl")
        cert, key = self.stage / "tls/fullchain.pem", self.stage / "tls/key.pem"
        wrong_key = self.root / "wrong.key"
        subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-out", wrong_key], capture_output=True, check=True)
        production_run = manager.run
        def isolated_ca(args, **kwargs):
            args = list(args)
            if "-CAfile" in args:
                args[args.index("-CAfile") + 1] = local_ca
            return production_run(args, **kwargs)
        with patch.object(manager, "run", side_effect=isolated_ca):
            manager.certificate_check(cert, key, self.node["domain"])
            with self.assertRaisesRegex(manager.Error, "私钥不匹配"):
                manager.certificate_check(cert, wrong_key, self.node["domain"])
            with self.assertRaises(manager.Error):
                manager.certificate_check(cert, key, "wrong.example.org")
            with self.assertRaises(manager.Error):
                manager.certificate_check(cert, key, self.node["domain"], minimum=3 * 86400)
        with self.assertRaises(manager.Error):
            manager.certificate_check(cert, key, self.node["domain"])

    def test_rotation_changes_only_requested_credentials(self):
        self.node.update(obfs="salamander", obfs_password="A" * 43)
        for kind, expected in (("token", {"token"}), ("password", {"password", "obfs_password"}),
                               ("both", {"token", "password", "obfs_password", "uuid", "short_id",
                                         "reality_private", "reality_public"})):
            save(self.stage / "node.json", self.node)
            with self.subTest(kind=kind), patch.object(manager, "current", return_value=self.stage), \
                    patch.object(manager, "copy_generation", return_value=self.stage), patch.object(manager, "activate"), \
                    patch.object(manager, "subscription"), patch.object(manager, "write_generation") as write, \
                    patch.object(manager, "reality_keypair", return_value=(PUBLIC, PRIVATE)):
                manager.rotate(kind)
                node = write.call_args.args[1]
                self.assertEqual({key for key in node if node[key] != self.node[key]}, expected)
                model.validate_node(node)

    def test_rollback_cannot_reinstate_revoked_credentials(self):
        previous = self.root / "generations/previous"
        previous.mkdir(parents=True)
        save(manager.STATE, {"previous": str(previous)})
        save(previous / "node.json", self.node)
        save(self.stage / "node.json", {**self.node, "password": "B" * 43})
        with patch.object(manager, "current", return_value=self.stage), patch.object(manager, "activate") as activate:
            with self.assertRaisesRegex(manager.Error, "已撤销"):
                manager.rollback()
        activate.assert_not_called()

    def test_status_never_recovers_pending_generation(self):
        (self.root / ".argosbx-owned").touch()
        save(manager.JOURNAL, {"old": None})
        with patch.object(manager, "root_platform", return_value="amd64"), \
                patch.object(manager.os, "umask"), patch.object(manager, "lock", return_value=contextlib.nullcontext()), \
                patch.object(manager, "ensure_public_page"), patch.object(manager, "recover") as recover, \
                patch.object(manager, "status") as status:
            self.assertEqual(manager.main(["status"]), 0)
        recover.assert_not_called()
        status.assert_called_once()

    def test_restart_scope_and_generation_recovery(self):
        candidate = self.root / "candidate"
        for folder in (self.stage, candidate):
            for name in ("server.json", "bin/sing-box", "Caddyfile", "bin/caddy", "tls/key.pem", "tls/fullchain.pem"):
                path = folder / name
                path.parent.mkdir(exist_ok=True, parents=True)
                path.write_text(name)
        self.assertEqual(manager.changed_services(self.stage, candidate), [])
        (candidate / "Caddyfile").write_text("new web")
        self.assertEqual(manager.changed_services(self.stage, candidate), [manager.SERVICES[1]])
        (candidate / "Caddyfile").write_text("Caddyfile")
        (candidate / "server.json").write_text("new proxy")
        self.assertEqual(manager.changed_services(self.stage, candidate), [manager.SERVICES[0]])
        (candidate / "tls/key.pem").write_text("new TLS")
        self.assertEqual(manager.changed_services(self.stage, candidate), manager.SERVICES)
        old = self.root / "generations/old"
        old.mkdir(parents=True)
        save(manager.JOURNAL, {"old": str(old), "old_state": {"current": str(old)}, "services": [manager.SERVICES[1]]})
        with patch.object(manager, "linked") as link, patch.object(manager, "run") as run, \
                patch.object(manager, "wait_for_probe", side_effect=manager.Error("not ready")) as probe, \
                patch.object(manager, "remove_journal", side_effect=manager.JOURNAL.unlink):
            with self.assertRaises(manager.Error):
                manager.recover()
            self.assertTrue(manager.JOURNAL.exists())
            probe.side_effect = None
            manager.recover()
        self.assertFalse(manager.JOURNAL.exists())
        self.assertEqual(link.call_args.args[1], old)
        self.assertEqual(run.call_args.args[0], ["systemctl", "restart", manager.SERVICES[1]])

    def test_udp_ownership_denial_and_reboot(self):
        read_key, write_key = network.UDP_KEYS
        config = self.root / "sysctl.conf"
        config.write_text(network.MARKER + network.KEY + " = bbr\n")
        save(self.root / "sysctl.json", {"before": "cubic", "after": "bbr"})
        values = {read_key: 200000, write_key: 8000000, network.KEY: "bbr"}
        denied = {read_key}
        writes = []
        def run(args, **_kwargs):
            if args[1] == "-n":
                return result(str(values[args[2]]))
            key, value = args[2].split("=", 1)
            writes.append(key)
            if key in denied:
                return result(code=1)
            values[key] = int(value) if value.isdecimal() else value
            return result()
        def atomic(path, content, _mode):
            path.write_text(content)
        with patch.object(network, "SYSCTL", config):
            self.assertEqual(network.enable_udp(self.root, run, save, atomic)[read_key], 200000)
            self.assertNotIn(read_key, config.read_text())
            denied.clear()
            self.assertEqual(network.enable_udp(self.root, run, save, atomic)[read_key], network.UDP_MIN)
            writes.clear()
            values[read_key] = int(config.read_text().split(read_key + " = ", 1)[1].splitlines()[0])
            network.enable_udp(self.root, run, save, atomic)
            self.assertFalse(writes)
            values[write_key] = 300000
            network.enable_udp(self.root, run, save, atomic)
            values[write_key] = 9000000
            network.enable_udp(self.root, run, save, atomic)
            self.assertNotIn(write_key, config.read_text())
            network.undo(self.root, run)
        self.assertEqual(values, {read_key: 200000, write_key: 9000000, network.KEY: "cubic"})

    def test_tcp_tuning_preserves_defaults_and_restores_owned_values(self):
        config = self.root / "sysctl.conf"
        config.write_text(network.MARKER)
        before = {network.TCP_WMEM: "4096 16384 4194304", network.TCP_MTU: "0", network.TCP_FASTOPEN: "1"}
        values = dict(before)

        def sysctl(args, **_):
            if args[1] == "-n":
                return result(values[args[2]].replace(" ", "\t"))
            key, value = args[2].split("=", 1)
            values[key] = value
            return result()

        def atomic(path, content, mode):
            path.write_text(content)

        with patch.object(network, "SYSCTL", config):
            tuned = network.enable_tcp(self.root, sysctl, save, atomic)
            self.assertEqual(tuned, {network.TCP_WMEM: "4096 16384 16777216",
                                     network.TCP_MTU: 1, network.TCP_FASTOPEN: 3})
            self.assertIn("tcp_wmem = 4096 16384 16777216", config.read_text())
            journal = self.root / "tcp-sysctl.json"
            network.restore_sysctls(journal, network.TCP_KEYS, network.tcp_value, sysctl)
            self.assertEqual(values, before)
            journal.unlink()
            values[network.TCP_WMEM] = "4096 32768 33554432"
            values[network.TCP_MTU] = "2"
            values[network.TCP_FASTOPEN] = "7"
            network.enable_tcp(self.root, sysctl, save, atomic)
            self.assertFalse(journal.exists())
            self.assertEqual(values[network.TCP_WMEM], "4096 32768 33554432")
            self.assertEqual(values[network.TCP_MTU], "2")
            self.assertEqual(values[network.TCP_FASTOPEN], "7")

    def test_app_rollback_normalizes_tcp_sysctl_vector(self):
        layout = types.SimpleNamespace(etc=self.root)
        key = network.TCP_WMEM
        before, after = "4096 16384 4194304", "4096 16384 16777216"
        save(self.root / "tcp-sysctl.json", {key: {"before": before, "after": after}})
        current = after

        def command(args, *_):
            nonlocal current
            if args[:2] == ["sysctl", "-w"]:
                current = args[2].split("=", 1)[1]
            return result((current.replace(" ", "\t") + "\n").encode())

        with patch.object(bootstrap, "command", side_effect=command):
            bootstrap.restore_new_sysctls(layout, {"files": {}}, "tcp-sysctl.json", network.TCP_KEYS)
        self.assertEqual(current, before)

    def test_units_keep_limits_and_independent_health_trigger(self):
        units = system.units()
        for name in manager.SERVICES:
            self.assertIn("RestartSec=5s", units[name])
            self.assertIn("StartLimitBurst=8", units[name])
            self.assertIn("NoNewPrivileges=true", units[name])
        self.assertIn("OnCalendar=*-*-* *:*:00", units["argosbx-health.timer"])
        self.assertNotIn("Requires=", units["argosbx-health.service"])

    def test_bootstrap_and_runtime_use_same_recovery_budget(self):
        layout = bootstrap.Layout(self.root)
        layout.data.mkdir(parents=True)
        tx = {"units": {unit: {"active": True} for unit in manager.SERVICES}}
        with patch.object(bootstrap, "save", side_effect=save), patch.object(bootstrap.time, "time", return_value=100000):
            layout.journal.parent.mkdir(parents=True)
            self.assertFalse(bootstrap.reserve_health_recovery(layout, tx))
            self.assertTrue(bootstrap.reserve_health_recovery(layout, tx))
            self.assertFalse(bootstrap.reserve_health_recovery(layout, tx))
        self.assertEqual(manager.read_json(layout.data / "recovery-budget.json")["attempts"], [100000] * 3)

    def test_cache_cleanup_only_removes_expired_owned_files(self):
        stale = self.root / ("a" * 64 + ".tar.gz")
        stale.write_text("stale")
        retained = self.root / "acme-account.json"
        retained.write_text("retained")
        alias = self.root / ("b" * 64 + ".tar.gz")
        os.link(retained, alias)
        self.assertEqual(maintenance.cleanup_cache(self.root, stale.stat().st_mtime + 9 * 86400, keep=0), 1)
        self.assertFalse(stale.exists())
        self.assertTrue(alias.exists())
        self.assertTrue(retained.exists())
