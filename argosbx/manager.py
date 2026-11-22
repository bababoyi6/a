"""Debian 13 node lifecycle. Run only through the root-owned launcher."""
import argparse
import contextlib
import datetime as dt
import filecmp
import getpass
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import uuid

from . import maintenance, model, network, releases, system

ETC = Path("/etc/argosbx-hy2")
DATA = Path("/var/lib/argosbx-hy2")
CURRENT = ETC / "current"
STATE = DATA / "state.json"
JOURNAL = DATA / "transaction.json"
SERVICES = ["argosbx-hy2.service", "argosbx-web.service"]
APP = Path(__file__).resolve().parent.parent
RESOLVER_POLICY = Path("/etc/systemd/resolved.conf.d/argosbx-hy2.conf")
UNIT_DIR = Path("/etc/systemd/system")
APT_POLICY = Path("/etc/apt/apt.conf.d/99zz-argosbx-hy2-auto-upgrades")
APT_MARKER = "// Managed by ArgoSBX-HY2\n"
APT_KEYS = ("APT::Periodic::Unattended-Upgrade", "APT::Periodic::Update-Package-Lists",
            "APT::Periodic::Download-Upgradeable-Packages")
RENEW_WINDOW = 30 * 86400


class Error(RuntimeError):
    pass


class Busy(Error):
    pass


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def read_json(path, default=None):
    return json.loads(Path(path).read_text()) if Path(path).exists() else default


def sync_directory(path):
    fd = os.open(path, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def remove_journal():
    JOURNAL.unlink()
    sync_directory(JOURNAL.parent)


def atomic(path, content, mode=0o600, group=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".new-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        if group:
            import grp
            os.fchown(fd, 0, grp.getgrnam(group).gr_gid)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def save(path, data):
    atomic(path, json.dumps(data, ensure_ascii=False, indent=2) + "\n")


def run(args, *, check=True, timeout=120, input=None, env=None):
    result = subprocess.run([str(x) for x in args], input=input, capture_output=True,
                            text=True, timeout=timeout, env=env)
    if check and result.returncode:
        # Tools may echo API credentials or complete generated configurations.
        # Preserve the executable and exit status, never arbitrary tool output.
        raise Error(f"{Path(str(args[0])).name} 执行失败（退出码 {result.returncode}）")
    return result


def event(stage, **values):
    save(DATA / "last-operation.json", {"time": now(), "stage": stage, **values})


def ensure_public_page():
    public = DATA / "public"
    page = public / "index.html"
    if public.is_symlink() or page.is_symlink():
        raise Error("公开网站路径不能是符号链接")
    if not page.exists():
        atomic(page, model.PUBLIC_PAGE, 0o644)


def root_platform():
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise Error("请在 Debian 13 上使用 root 或 sudo 执行")
    info = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            info[key] = value.strip('"')
    if info.get("ID") != "debian" or info.get("VERSION_ID") != "13":
        raise Error("当前仅支持 Debian 13（trixie）")
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if not arch:
        raise Error("仅支持 amd64 / arm64")
    if not Path("/run/systemd/system").exists():
        raise Error("需要以 systemd 启动的完整 VPS 系统")
    return arch


@contextlib.contextmanager
def lock(name="argosbx-hy2"):
    import fcntl
    fd = os.open(f"/run/lock/{name}.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, "r+") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_mode & 0o022 or info.st_nlink != 1):
            raise Error("管理锁不属于当前用户或类型/权限异常，停止修改")
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Busy("另一项安装/维护任务正在运行，稍后重试") from None
        yield


def linked(path, target):
    temp = Path(str(path) + ".next")
    temp.unlink(missing_ok=True)
    temp.symlink_to(target)
    os.replace(temp, path)
    sync_directory(path.parent)


def current():
    if not CURRENT.is_symlink():
        raise Error("尚未完成安装，请运行 argosbx install")
    path = CURRENT.resolve()
    if path.parent != (DATA / "generations").resolve() or not (path / "node.json").exists():
        raise Error("当前版本路径异常，停止修改")
    return path


def recover(restart=True, reset_failed=False):
    tx = read_json(JOURNAL)
    if not tx:
        return
    if not restart and maintenance.owner_alive(tx):
        return  # systemd prerequisites of the live activation must not undo it.
    old = tx["old"]
    if old:
        oldpath = Path(old)
        if oldpath.parent != DATA / "generations" or oldpath.resolve() != oldpath or not oldpath.is_dir():
            raise Error("事务备份路径异常，需人工恢复")
        linked(CURRENT, oldpath)
    else:
        CURRENT.unlink(missing_ok=True)
        sync_directory(CURRENT.parent)
    save(STATE, tx["old_state"])
    if restart:
        targets = tx.get("services", SERVICES)
        if targets:
            if old and reset_failed:
                reset_failed_services(targets)
            run(["systemctl", "restart" if old else "stop", *targets])
        if old:
            wait_for_probe(Path(old))
        # Keep the recovery record if systemctl/readiness fails, including across
        # reboot. A later invocation retries the same idempotent restoration.
        remove_journal()
        event("recovered", message="已恢复中断事务之前的版本")


def preflight():
    if shutil.disk_usage(DATA).free < 1024 ** 3:
        raise Error("至少需要 1 GiB 空闲空间（含下载、候选版本和回滚空间）")
    synced = run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"]).stdout.strip()
    if synced != "yes":
        raise Error("系统时间尚未同步；请先检查 timedatectl 的 NTP 状态")
    if not CURRENT.is_symlink():
        for kind, port in ((socket.SOCK_STREAM, 443), (socket.SOCK_DGRAM, 443),
                           (socket.SOCK_STREAM, 8443), (socket.SOCK_STREAM, 80)):
            with socket.socket(socket.AF_INET, kind) as sock:
                try:
                    sock.bind(("0.0.0.0", port))
                except OSError:
                    raise Error(f"TCP/UDP {port} 已被占用，未停止现有服务") from None
        # Include v6-only listeners that might collide with later configuration.
        listeners = run(["ss", "-H", "-lntup"]).stdout
        listeners = "\n".join(line for line in listeners.splitlines() if re.search(r":(?:443|8443|80)\s", line))
        if listeners:
            raise Error("发现已有 443 监听，请使用独立 VPS 或先自行处理冲突")


def identities():
    import grp
    import pwd
    registry = Path("/opt/argosbx-hy2/identities.json")
    owned = read_json(registry, {})
    try:
        grp.getgrnam("argosbx-tls")
        if not owned.get("tls"):
            raise Error("发现未知 argosbx-tls 组，拒绝复用")
    except KeyError:
        run(["groupadd", "--system", "argosbx-tls"])
        owned["tls"] = grp.getgrnam("argosbx-tls").gr_gid
        save(registry, owned)
    for name in ("argosbx-hy2", "argosbx-web"):
        try:
            user = pwd.getpwnam(name)
            if (owned.get(name) != user.pw_uid or
                    user.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin") or user.pw_uid == 0):
                raise Error(f"系统已有不符合要求的 {name} 用户")
        except KeyError:
            run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
                 "--shell", "/usr/sbin/nologin", name])
            owned[name] = pwd.getpwnam(name).pw_uid
            save(registry, owned)
        run(["usermod", "-a", "-G", "argosbx-tls", name])


def verify_server_address(address, server_ip=None):
    if not ipaddress.IPv4Address(address).is_global:
        raise Error("A 记录必须是公网 IPv4")
    interfaces = json.loads(run(["ip", "-j", "-4", "address", "show"]).stdout)
    local_ips = {a["local"] for interface in interfaces for a in interface.get("addr_info", [])}
    if server_ip:
        if not ipaddress.IPv4Address(server_ip).is_global:
            raise Error("--server-ip 必须是公网 IPv4")
        local_ips.add(server_ip)
    if str(address) not in local_ips:
        raise Error("域名未指向本机 IPv4；NAT VPS 可显式指定 --server-ip")


def dns_preflight(node, token=None, server_ip=None):
    domain = node["domain"]
    if token is None:
        answers = run(["dig", "+short", "@1.1.1.1", domain, "A"]).stdout.split()
        v6 = run(["dig", "+short", "@1.1.1.1", domain, "AAAA"]).stdout.strip()
        if len(answers) != 1 or v6:
            raise Error("HTTP 验证需要唯一的公网 A 记录，首版暂不接受 AAAA / CNAME")
        try:
            address = ipaddress.IPv4Address(answers[0])
        except ValueError:
            raise Error("域名必须使用直接 A 记录，不接受 CNAME") from None
        verify_server_address(address, server_ip)
        print(f"公共 DNS 检查通过：{domain} → {address}")
        return str(address)
    # Check the exact dedicated record through Cloudflare, without changing A/AAAA.
    import urllib.parse
    import urllib.request
    def cf(endpoint):
        req = urllib.request.Request("https://api.cloudflare.com/client/v4/" + endpoint,
                                     headers={"Authorization": "Bearer " + token,
                                              "User-Agent": "ArgoSBX-HY2"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.load(resp)
        except Exception:
            raise Error("Cloudflare 查询失败，请检查 Token 权限及网络") from None
        if not data.get("success"):
            raise Error("Cloudflare Token 未获得所需 Zone / DNS 权限")
        return data["result"]
    zones = []
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        zones = cf("zones?name=" + ".".join(parts[i:]))
        if zones:
            break
    if len(zones) != 1:
        raise Error("无法唯一确定该域名的 Cloudflare Zone")
    records = cf(f'zones/{zones[0]["id"]}/dns_records?name={domain}')
    a = [r for r in records if r["type"] == "A"]
    if len(a) != 1 or any(r.get("proxied") for r in records):
        raise Error("请先为专用子域名建立一个 DNS only（灰云）A 记录")
    if any(r["type"] in ("AAAA", "CNAME") for r in records):
        raise Error("第一版为 IPv4 模式；专用记录暂不能含 AAAA / CNAME")
    ip = a[0]["content"]
    if not ipaddress.ip_address(ip).is_global:
        raise Error("A 记录必须指向 VPS 的公网 IPv4")
    answers = set(run(["dig", "+short", "@1.1.1.1", domain, "A"]).stdout.split())
    v6 = run(["dig", "+short", "@1.1.1.1", domain, "AAAA"]).stdout.strip()
    if answers != {ip} or v6:
        raise Error("公共 DNS 尚未与 Cloudflare 记录一致，等待传播后重试")
    verify_server_address(ip, server_ip)
    # VPS may sit behind NAT; do not guess its public IP through an unrelated service.
    print(f"DNS 检查通过：{domain} → {ip}；稍后将验证此公网地址的 HTTPS")


def reality_target_check():
    try:
        context = ssl.create_default_context()
        with socket.create_connection(("addons.mozilla.org", 443), timeout=8) as raw:
            with context.wrap_socket(raw, server_hostname="addons.mozilla.org") as secure:
                if secure.version() != "TLSv1.3":
                    raise Error("REALITY 默认目标未提供 TLS 1.3")
    except (OSError, ssl.SSLError) as exc:
        raise Error("无法连通 REALITY 默认目标 addons.mozilla.org:443；请检查 VPS 出站网络") from exc


def certificate_check(cert, key, domain, minimum=86400):
    cert, key = Path(cert), Path(key)
    text = cert.read_text()
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
    if len(blocks) < 2:
        raise Error("证书缺少完整的中间证书链")
    with tempfile.TemporaryDirectory(prefix="tls-check-", dir=DATA) as tmp:
        leaf, chain = Path(tmp) / "leaf.pem", Path(tmp) / "chain.pem"
        leaf.write_text(blocks[0] + "\n")
        chain.write_text("\n".join(blocks[1:]) + "\n")
        run(["openssl", "verify", "-purpose", "sslserver", "-verify_hostname", domain,
             "-CAfile", "/etc/ssl/certs/ca-certificates.crt", "-untrusted", chain, leaf])
        run(["openssl", "x509", "-in", leaf, "-checkend", str(minimum), "-noout"])
        san = run(["openssl", "x509", "-in", leaf, "-noout", "-ext", "subjectAltName"]).stdout
        if f"DNS:{domain}" not in [v.strip() for v in san.replace("\n", ",").split(",")]:
            raise Error("证书 SAN 未包含精确域名")
        certpub = run(["openssl", "x509", "-in", leaf, "-pubkey", "-noout"]).stdout
        keypub = run(["openssl", "pkey", "-in", key, "-pubout"]).stdout
        if certpub != keypub:
            raise Error("证书与私钥不匹配")
    return text


def certificate_command(node, lego, acme, email, challenge):
    if challenge != "http":
        raise Error("仅支持 HTTP-01 证书验证")
    # lego 5 unifies issuance and lifetime/ARI-based renewal under `run`.
    command = [lego, "--log.level", "error", "run", "--path", acme,
               "--server", "https://acme-v02.api.letsencrypt.org/directory",
               "--account-id", "argosbx-hy2", "--domains", node["domain"], "--accept-tos",
               "--key-type", "EC256", "--cert.name", node["domain"], "--no-random-sleep",
               "--renew-days", "30", "--http", "--http.address", "0.0.0.0:80"]
    if email:
        command += ["--email", email]
    return command


def remove_ufw_comment(comment):
    if not shutil.which("ufw"):
        return
    text = run(["ufw", "status", "numbered"], check=False, env={**os.environ, "LC_ALL": "C"}).stdout
    indices = []
    for line in text.splitlines():
        match = re.match(r"\[\s*(\d+)\].*# " + re.escape(comment) + r"\s*$", line)
        if match:
            indices.append(int(match[1]))
    for index in sorted(indices, reverse=True):
        run(["ufw", "--force", "delete", str(index)])


def cleanup_http_challenge():
    state = read_json(ETC / "firewall.json", {})
    if state.get("http_challenge"):
        remove_ufw_comment("argosbx-hy2-acme-http")
        state.pop("http_challenge", None)
        save(ETC / "firewall.json", state)


@contextlib.contextmanager
def http_challenge(external=False):
    if run(["ss", "-H", "-lnt", "sport = :80"]).stdout.strip():
        raise Error("HTTP-01 需要空闲 TCP 80；未停止已有网站")
    try:
        with socket.socket() as sock:
            sock.bind(("0.0.0.0", 80))
        if not external and shutil.which("ufw"):
            status = run(["ufw", "status"], env={**os.environ, "LC_ALL": "C"}).stdout
            if "Status: active" in status and not re.search(r"80(?:/tcp)?\s+ALLOW", status):
                owned = read_json(ETC / "firewall.json", {"ufw": []})
                owned["http_challenge"] = True
                save(ETC / "firewall.json", owned)
                run(["ufw", "allow", "80/tcp", "comment", "argosbx-hy2-acme-http"])
        yield
    finally:
        cleanup_http_challenge()


def obtain_certificate(node, lego, email, challenge="http", external=False):
    acme = DATA / "acme"
    acme.mkdir(mode=0o700, exist_ok=True)
    env = {key: value for key, value in os.environ.items() if not key.startswith("LEGO_")}
    command = certificate_command(node, lego, acme, email, challenge)
    cert = acme / "certificates" / (node["domain"] + ".crt")
    key = cert.with_suffix(".key")
    if cert.is_file() and key.is_file():
        try:
            certificate_check(cert, key, node["domain"], minimum=RENEW_WINDOW)
        except (Error, OSError):
            pass
        else:
            return cert, key
    event("certificate-request")
    with http_challenge(external):
        run(command, env=env, timeout=1200)
    certificate_check(cert, key, node["domain"])
    return cert, key


def generation():
    parent = DATA / "generations"
    parent.mkdir(mode=0o711, exist_ok=True)
    parent.chmod(0o711)
    path = DATA / "generations" / (dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + secrets.token_hex(4))
    path.mkdir(parents=True, mode=0o711)
    path.chmod(0o711)
    (path / "bin").mkdir(mode=0o755)
    (path / "bin").chmod(0o755)
    return path


def copy_generation(old):
    stage = generation()
    # Preserve explicit restricted modes and ownership; never copy symlinks.
    for src in old.rglob("*"):
        if src.is_symlink():
            raise Error("版本目录包含意外符号链接")
        dest = stage / src.relative_to(old)
        if src.is_dir():
            dest.mkdir(exist_ok=True)
        else:
            shutil.copy2(src, dest)
        stat = src.stat()
        os.chown(dest, stat.st_uid, stat.st_gid)
        dest.chmod(stat.st_mode & 0o777)
    return stage


def write_generation(stage, node, cert, key, ua=None):
    save(stage / "node.json", node)
    for directory, group in [("tls", "argosbx-tls"), ("exports", "argosbx-web")]:
        (stage / directory).mkdir(exist_ok=True)
        shutil.chown(stage / directory, group=group)
        (stage / directory).chmod(0o750)
    atomic(stage / "tls/fullchain.pem", Path(cert).read_text(), 0o640, "argosbx-tls")
    atomic(stage / "tls/key.pem", Path(key).read_text(), 0o640, "argosbx-tls")
    atomic(stage / "server.json", json.dumps(model.server_config(node), indent=2), 0o640, "argosbx-hy2")
    atomic(stage / "Caddyfile", model.caddy_config(node, ua_rules=ua), 0o640, "argosbx-web")
    for name, content in model.exports(node).items():
        atomic(stage / "exports" / name, content, 0o640, "argosbx-web")
    save(stage / "ua.json", ua or [])


def validate_generation(stage, minimum_cert=86400):
    paths = list(stage.rglob('*'))
    if any(path.is_symlink() for path in paths):
        raise Error("候选版本存在符号链接，停止切换")
    node = model.validate_node(read_json(stage / "node.json"))
    certificate_check(stage / "tls/fullchain.pem", stage / "tls/key.pem", node["domain"], minimum_cert)
    sb = stage / "bin/sing-box"
    versions = read_json(stage / "versions.json")
    version = versions["sing-box"]
    actual = run([sb, "version"]).stdout
    if not re.search(r"sing-box version " + re.escape(version.lstrip("v")) + r"(?:\s|$)", actual):
        raise Error("内核实际版本与下载记录不一致")
    for binary, arguments, prefix in [("caddy", ["version"], "v"), ("lego", ["--version"], "")]:
        output = run([stage / "bin" / binary, *arguments]).stdout
        expected = prefix + versions[binary].lstrip("v")
        if not re.search(r"(?<![\d.])" + re.escape(expected) + r"(?:\s|$)", output):
            raise Error(f"{binary} 实际版本与固定清单不一致")
    # Validate the files that will actually run, including copied update configs.
    # Only substitute current's file paths so checks read staged certificates.
    staged_server = read_json(stage / "server.json")
    if [item.get("type") for item in staged_server.get("inbounds", [])] != ["vless", "hysteria2"]:
        raise Error("必须同时配置 VLESS 和 Hysteria2 入站")
    tls = staged_server["inbounds"][1]["tls"]
    for field, filename in [("certificate_path", "fullchain.pem"), ("key_path", "key.pem")]:
        if tls.get(field) != f"{model.ROOT}/tls/{filename}":
            raise Error("服务端证书路径不属于本项目当前部署")
        tls[field] = str(stage / "tls" / filename)
    staged_caddy = (stage / "Caddyfile").read_text().replace(model.ROOT, str(stage))
    checks = [(stage / ".check-server.json", json.dumps(staged_server),
               [sb, "check", "-c"]),
              (stage / ".check-Caddyfile", staged_caddy,
               [stage / "bin/caddy", "validate", "--adapter", "caddyfile", "--config"])]
    for path, content, command in checks:
        atomic(path, content)
        try:
            run([*command, path])
        finally:
            path.unlink(missing_ok=True)
    run([sb, "check", "-c", stage / "exports/singbox.json"])
    # copy2/chmod and executable renames are not durable merely because the
    # config files were atomic. Persist the complete candidate before switching.
    for path in paths:
        if path.is_file():
            with path.open('rb') as stream:
                os.fsync(stream.fileno())
    for path in sorted((p for p in paths if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        sync_directory(path)
    sync_directory(stage)
    sync_directory(stage.parent)


def set_units():
    changed = set()
    for name, content in system.units().items():
        path = UNIT_DIR / name
        if path.is_symlink() or (path.exists() and not path.read_text().startswith("# Managed by ArgoSBX-HY2\n")):
            raise Error(f"发现未知同名服务 {name}，拒绝覆盖")
        if not path.exists() or path.read_text() != content:
            atomic(path, content, 0o644)
            changed.add(name)
    if changed:
        run(["systemctl", "daemon-reload"])
    return changed


def enable_units(changed):
    timers = ("argosbx-renew.timer", "argosbx-health.timer")
    run(["systemctl", "enable", "argosbx-network.service", "argosbx-firewall.service", *SERVICES, *timers])
    for timer in timers:
        if timer in changed:
            run(["systemctl", "restart", timer])
        elif run(["systemctl", "is-active", "--quiet", timer], check=False).returncode:
            run(["systemctl", "start", timer])


def resolver_privacy(remove=False):
    path = RESOLVER_POLICY
    marker = "# Managed by ArgoSBX-HY2\n"
    if path.is_symlink() or (path.exists() and not path.read_text().startswith(marker)):
        if remove:
            return
        raise Error("发现未知同名解析器配置，拒绝覆盖")
    active = run(["systemctl", "is-active", "--quiet", "systemd-resolved.service"], check=False).returncode == 0
    if remove:
        changed = path.exists()
        path.unlink(missing_ok=True)
    elif active:
        content = marker + "[Resolve]\nLLMNR=no\nMulticastDNS=no\n"
        if path.parent.is_symlink():
            raise Error("解析器配置目录是符号链接，停止修改")
        created = not path.parent.exists()
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        permissions_changed = created
        if path.parent.stat().st_mode & 0o055 != 0o055:
            if any(p.name != path.name for p in path.parent.iterdir()):
                raise Error("既有解析器目录权限受限，未覆盖其他配置")
            path.parent.chmod(0o755)
            permissions_changed = True
        changed = permissions_changed or not path.exists() or path.read_text() != content
        if changed:
            atomic(path, content, 0o644)
    else:
        changed = False
    if active and changed:
        run(["systemctl", "restart", "systemd-resolved.service"])


def guard_rules(uid, resolvers):
    lines = ["table inet argosbx_hy2 {", "chain output {", "type filter hook output priority 0; policy accept;"]
    # Reply packets for incoming HY2 connections may legitimately target loopback
    # during self-test. New outbound proxy flows still pass the destination guard.
    lines.append(f"meta skuid {uid} ct direction reply accept")
    # The system resolver may legitimately reside on loopback/private infrastructure.
    for address in resolvers:
        ip = ipaddress.ip_address(address)
        family = "ip" if ip.version == 4 else "ip6"
        lines.append(f"meta skuid {uid} {family} daddr {ip} meta l4proto {{ tcp, udp }} th dport 53 accept")
    v4 = ", ".join(x for x in model.BLOCKED if ":" not in x)
    v6 = ", ".join(x for x in model.BLOCKED if ":" in x)
    lines += [f"meta skuid {uid} ip daddr {{ {v4} }} reject",
              f"meta skuid {uid} ip6 daddr {{ {v6} }} reject", "}", "}"]
    return "\n".join(lines) + "\n"


def firewall():
    import pwd
    uid = pwd.getpwnam("argosbx-hy2").pw_uid
    existing = run(["nft", "list", "table", "inet", "argosbx_hy2"], check=False).returncode == 0
    owned = ETC / "firewall.json"
    state = read_json(owned, {"ufw": []})
    if existing and not state.get("guard_owned"):
        raise Error("发现同名未知防火墙表，拒绝覆盖")
    resolvers = []
    for line in Path("/etc/resolv.conf").read_text().splitlines():
        if line.startswith("nameserver "):
            address = line.split()[1]
            try:
                ipaddress.ip_address(address)
                resolvers.append(address)
            except ValueError:
                pass
    rules = guard_rules(uid, resolvers)
    script = ("delete table inet argosbx_hy2\n" if existing else "") + rules
    # A single nft transaction: there is no empty-table window.
    run(["nft", "-c", "-f", "-"], input=script)
    state["guard_owned"] = True
    save(owned, state)
    run(["nft", "-f", "-"], input=script)
    payload = json.loads(run(["nft", "-j", "list", "table", "inet", "argosbx_hy2"]).stdout)
    state["guard_digest"] = maintenance.firewall_digest(payload)
    save(owned, state)


def verify_firewall():
    state = read_json(ETC / "firewall.json", {})
    result = run(["nft", "-j", "list", "table", "inet", "argosbx_hy2"], check=False)
    if result.returncode or not state.get("guard_owned") or not state.get("guard_digest"):
        raise Error("私网防护规则缺失或尚未登记完整性，请运行 argosbx repair")
    if maintenance.firewall_digest(json.loads(result.stdout)) != state["guard_digest"]:
        raise Error("私网防护规则不完整，请运行 argosbx repair")


def ingress(external=False):
    owned = read_json(ETC / "firewall.json", {"ufw": []})
    active = shutil.which("ufw") and "Status: active" in run(["ufw", "status"], env={**os.environ, "LC_ALL": "C"}).stdout
    if active and not external:
        status = run(["ufw", "status", "numbered"], env={**os.environ, "LC_ALL": "C"}).stdout
        # Do not adopt an existing equivalent rule. Only remove our exact comments later.
        for proto, port in (("tcp", 443), ("udp", 443), ("tcp", 8443)):
            comment = f"argosbx-hy2-{port}-{proto}"
            if comment not in status and not re.search(rf"(?<!\d){port}/{proto}\s+ALLOW", status):
                # Record intent first so a power loss cannot orphan an owned rule.
                if comment not in owned["ufw"]:
                    owned["ufw"].append(comment)
                save(ETC / "firewall.json", owned)
                run(["ufw", "allow", f"{port}/{proto}", "comment", comment])
    elif not external:
        ruleset = json.loads(run(["nft", "-j", "list", "ruleset"]).stdout)
        for item in ruleset.get("nftables", []):
            chain = item.get("chain", {})
            if chain.get("hook") == "input" and chain.get("table") != "argosbx_hy2":
                raise Error("检测到已有自定义入站防火墙；自行放行 TCP/UDP 443、TCP 8443/80 后加 --firewall-external 重试")
    save(ETC / "firewall.json", owned)


def rollback_ingress():
    owned = read_json(ETC / "firewall.json", {"ufw": []})
    if shutil.which("ufw"):
        # Delete by numbered exact comment and descending index, avoiding shared rules.
        text = run(["ufw", "status", "numbered"], check=False, env={**os.environ, "LC_ALL": "C"}).stdout
        indices = []
        for line in text.splitlines():
            match = re.match(r"\[\s*(\d+)\].*# (argosbx-hy2-(?:443|8443)-(?:tcp|udp))\s*$", line)
            if match and match[2] in owned["ufw"]:
                indices.append(int(match[1]))
        for index in sorted(indices, reverse=True):
            run(["ufw", "--force", "delete", str(index)])
    owned["ufw"] = []
    save(ETC / "firewall.json", owned)


def https_request(node, path, *, local=True, headers=None):
    import http.client
    connection = http.client.HTTPSConnection(node["domain"], 8443, timeout=15,
                                              context=ssl.create_default_context())
    if local:
        # Preserve domain-based SNI and certificate verification while connecting locally.
        connection._create_connection = lambda address, timeout, source_address=None: socket.create_connection(("127.0.0.1", 8443), timeout)
    try:
        connection.request("GET", path, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict((k.lower(), v) for k, v in response.getheaders()), response.read(2 * 1024 * 1024)
    finally:
        connection.close()


def probe_web(stage, public=False):
    node = read_json(stage / "node.json")
    run(["systemctl", "is-active", "--quiet", "argosbx-web.service"])
    path = "/s/" + node["token"]
    status, headers, body = https_request(node, path + "?format=clash", local=not public)
    if status != 200 or body != (stage / "exports/clash.yaml").read_bytes():
        raise Error("HTTPS 订阅内容自检失败")
    if "no-store" not in headers.get("cache-control", "") or "alt-svc" in headers:
        raise Error("订阅缓存策略或 HTTP/3 禁用检查失败")
    if public:
        return
    for fmt, filename in [("shadowrocket", "shadowrocket.txt"), ("singbox", "singbox.json")]:
        status, _, body = https_request(node, path + "?format=" + fmt)
        if status != 200 or body != (stage / "exports" / filename).read_bytes():
            raise Error("客户端导出自检失败")
    for ua, filename in [("clash-verge/v2.4.0", "clash.yaml"),
                         ("Shadowrocket/2.2.71", "shadowrocket.txt")]:
        status, headers, body = https_request(node, path, headers={"User-Agent": ua})
        if status != 200 or body != (stage / "exports" / filename).read_bytes():
            raise Error("单链接客户端自动适配检查失败")
        if "no-store" not in headers.get("cache-control", "") or "user-agent" not in headers.get("vary", "").lower():
            raise Error("单链接客户端缓存隔离检查失败")
    status, _, body = https_request(node, path)
    if status != 200 or b"Clash Verge Rev" not in body:
        raise Error("未知客户端格式页检查失败")
    status, _, _ = https_request(node, "/s/invalid-token?format=clash")
    if status != 404:
        raise Error("错误订阅 Token 未被拒绝")


def probe_listener(service, user, binary, kind, port):
    run(["systemctl", "is-active", "--quiet", service], timeout=5)
    main_pid = run(["systemctl", "show", "-p", "MainPID", "--value", service], timeout=5).stdout.strip()
    uid = __import__("pwd").getpwnam(user).pw_uid
    listeners = run(["ss", "-H", f"-ln{kind}pe", f"sport = :{port}"], timeout=5).stdout.splitlines()
    pid_pattern = r'\("' + re.escape(binary) + r'",pid=' + re.escape(main_pid) + r',fd='
    if (not main_pid.isdecimal() or int(main_pid) == 0 or not listeners or
            not all(re.search(pid_pattern, line) and re.search(rf"\buid:{uid}\b", line) for line in listeners)):
        raise Error(f"{service} 未以预期进程和权限监听 {port}/{kind}")


def probe_hy2():
    probe_listener(SERVICES[0], "argosbx-hy2", "sing-box", "u", 443)


def probe_vless():
    probe_listener(SERVICES[0], "argosbx-hy2", "sing-box", "t", 443)


def probe(stage, public=False):
    probe_web(stage, public)
    probe_hy2()
    probe_vless()
    verify_firewall()


def proxy_probe(stage, target_ip=None, protocol="hy2", check_private=True):
    """Exercise both real client handshakes and data forwarding."""
    node = read_json(stage / "node.json")
    config = model.client_config(node)
    if protocol == "hy2":
        config["outbounds"] = [config["outbounds"][1]]
        config["route"]["final"] = model.HYSTERIA2
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    config["inbounds"][0]["listen_port"] = port
    config["outbounds"][0]["server"] = "127.0.0.1"
    with tempfile.TemporaryDirectory(prefix="proxy-check-", dir=DATA) as temp:
        path = Path(temp) / "client.json"
        atomic(path, json.dumps(config))
        with subprocess.Popen([str(stage / "bin/sing-box"), "run", "-c", str(path)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as client:
            try:
                for _ in range(30):
                    if client.poll() is not None:
                        raise Error("本地代理测试客户端启动失败")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.1)
                proxy = f"socks5h://127.0.0.1:{port}"
                # A public address assigned to this VPS gives a complete local
                # HY2/TLS/data test without depending on an external website.
                targets = ([f'https://{node["domain"]}:8443/'] if target_ip else
                           ["https://example.com/", "https://www.cloudflare.com/cdn-cgi/trace"])
                connect = ["--connect-to", f'{node["domain"]}:8443:{target_ip}:8443'] if target_ip else []
                for target in targets:
                    response = run(["curl", "--fail", "--silent", "--show-error", "--max-time", "12",
                                    "--proxy", proxy, "--noproxy", "", *connect, "--output", "/dev/null", target],
                                   check=False, timeout=15)
                    if response.returncode == 0:
                        break
                else:
                    raise Error(protocol + " 实际 HTTPS 转发失败；检查节点、DNS 与外网连通性")
                private_targets = ("http://127.0.0.1:443/", "http://169.254.169.254/", "http://10.0.0.1/")
                for url in private_targets if check_private else ():
                    result = run(["curl", "--silent", "--max-time", "3", "--proxy", proxy,
                                  "--noproxy", "", "--output", "/dev/null", url], check=False, timeout=5)
                    # Clients may optimistically acknowledge SOCKS before the
                    # remote denial; curl then reports empty/reset data (52/56).
                    # A timeout is not evidence of an enforced destination guard.
                    if result.returncode not in (52, 56, 97):
                        raise Error("代理私网目标拒绝检查失败")
            finally:
                client.terminate()
                try:
                    client.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    client.kill()
                    client.wait()


def wait_for_probe(stage, attempts=10):
    failure = None
    for _ in range(attempts):
        try:
            probe(stage)
            return
        except (Error, OSError) as exc:
            failure = exc
            time.sleep(1)
    raise failure or Error("服务就绪检查失败")


def changed_services(old, stage, force=()):
    if old is None:
        return SERVICES.copy()
    shared = ("tls/fullchain.pem", "tls/key.pem")
    files = (("bin/sing-box", "server.json"), ("bin/caddy", "Caddyfile"))
    return [service for service, own in zip(SERVICES, files) if service in force or
            any(not (old / name).is_file() or not filecmp.cmp(old / name, stage / name, shallow=False)
                for name in (*own, *shared))]


def reset_failed_services(targets):
    for target in targets:
        state = run(["systemctl", "show", "-p", "ActiveState", "--value", target], timeout=5).stdout.strip()
        if state == "failed":
            run(["systemctl", "reset-failed", target])


def activate(stage, state, public=False, force=()):
    old = str(current()) if CURRENT.is_symlink() else None
    validate_generation(stage)
    targets = changed_services(Path(old) if old else None, stage, force)
    oldstate = read_json(STATE, {})
    save(JOURNAL, {"old": old, "new": str(stage), "old_state": oldstate, "time": now(),
                   "owner": maintenance.process_identity(), "services": targets})
    event("switching")
    linked(CURRENT, stage)
    try:
        if targets:
            reset_failed_services(targets)
            run(["systemctl", "restart", *targets])
        wait_for_probe(stage)
        # On a routed VPS this tests the entire local HY2 path without external
        # sites/DNS. NAT-only hosts retain the explicit external fallback probe.
        if SERVICES[0] in targets:
            target_ip = local_public_ip()
            for protocol in ("vless", "hy2"):
                proxy_probe(stage, target_ip=target_ip, protocol=protocol)
        if public:
            try:
                probe(stage, public=True)
            except Exception:
                print("提示：本地检查通过，公网 HTTPS 自测未通过；请从外部检查 DNS、安全组与 NAT 回环。", file=sys.stderr)
        state.update({"current": str(stage), "previous": old, "updated_at": now()})
        save(STATE, state)
        remove_journal()
        event("ready", message="本地检查通过；公网 UDP 与客户端导入仍需外部验证")
    except BaseException:
        recover()
        raise
    try:
        cleanup_generations()
    except OSError:
        # Retention housekeeping must never undo an already committed transaction.
        pass


def cleanup_generations():
    state = read_json(STATE, {})
    keep = {state.get("current"), state.get("previous")}
    app_tx = read_json(Path("/opt/argosbx-hy2/app-transaction.json"), {})
    if app_tx.get("old_deployment"):
        keep.add(app_tx["old_deployment"])
    generations = DATA / "generations"
    candidates = sorted((p for p in generations.iterdir() if p.is_dir() and not p.is_symlink()),
                        key=lambda p: p.name, reverse=True)
    keep.update(str(p) for p in candidates[:3])
    for path in candidates:
        if str(path) not in keep and re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{8}", path.name):
            shutil.rmtree(path)


def tune():
    result = network.enable(ETC, run, save, atomic)
    print("网络状态：" + json.dumps(result, ensure_ascii=False))
    if not result["udp_buffers_ok"]:
        print("UDP 缓冲区目标未完全生效；保留宿主机限制或管理员设置。", file=sys.stderr)
    return result


def undo_tune():
    network.undo(ETC, run)


def verify_apt_policy():
    env = {key: value for key, value in os.environ.items() if key != "APT_CONFIG"}
    config = run(["apt-config", "dump"], timeout=10, env=env).stdout
    values = dict(re.findall(r'^([\w:-]+)\s+"([^"\n]*)";$', config.lower(), re.M))
    conflicts = [key for key in APT_KEYS if values.get(key.lower()) != "0"]
    if conflicts:
        raise Error("APT 自动更新禁用未生效，检查更高优先级设置：" + ", ".join(conflicts))


def apt_policy(remove=False):
    record = ETC / "apt-policy.json"
    content = APT_MARKER + "".join(f'{key} "0";\n' for key in APT_KEYS)
    owned = read_json(record, {}).get("file") == str(APT_POLICY)
    if APT_POLICY.is_symlink() or (APT_POLICY.exists() and
            (not APT_POLICY.is_file() or APT_POLICY.read_text() != content or not owned)):
        if remove:
            print("APT 策略文件已由其他管理员管理，予以保留。", file=sys.stderr)
            return
        raise Error("AAA 的 APT 策略文件已被修改或不属于本项目，未覆盖")
    if remove:
        if owned:
            APT_POLICY.unlink(missing_ok=True)
            record.unlink(missing_ok=True)
        return
    if not APT_POLICY.exists():
        save(record, {"file": str(APT_POLICY)})
        atomic(APT_POLICY, content, 0o644)
    verify_apt_policy()


def reality_keypair(binary):
    keys = run([binary, "generate", "reality-keypair"]).stdout
    private = re.search(r"PrivateKey:\s*(\S+)", keys)
    public = re.search(r"PublicKey:\s*(\S+)", keys)
    if not private or not public:
        raise Error("无法生成 REALITY 密钥对")
    return private[1], public[1]


def pending_caddy_update(deployment):
    installed = read_json(deployment / "versions.json")["caddy"]
    lockdata = read_json(APP / "dependencies.lock.json")
    releases.validate_lock(lockdata)
    dependency = lockdata["dependencies"]["caddy"]
    if releases.version_tuple(installed) < releases.version_tuple(dependency["version"]):
        return dependency
    return None


def stage_caddy_update(stage, dependency):
    if dependency is None:
        return
    spec = dependency["assets"][root_platform()]
    releases.install_binary(spec, "caddy", stage / "bin/caddy", DATA / "cache")
    versions = read_json(stage / "versions.json")
    versions["caddy"] = dependency["version"]
    save(stage / "versions.json", versions)


def install(args):
    if CURRENT.is_symlink():
        old = current()
        node = read_json(old / "node.json")
        if node.get("schema") != 2:
            raise Error("发现旧版节点；不自动迁移或覆盖")
        if args.obfs is not None and args.obfs != node.get("obfs", "none"):
            raise Error("已安装；请用 argosbx obfs 显式切换混淆模式")
        caddy_update = pending_caddy_update(old)
        apt_policy()
        changed = set_units()
        force = set(SERVICES).intersection(changed)
        if os.environ.get("ARGOSBX_APP_DEPLOY"):
            tune()
        try:
            probe(old)
        except (Error, OSError):
            print("现有节点异常，尝试修复本项目服务。")
            repair(force=force)
        else:
            if caddy_update or force or not current_exports(old, node):
                stage = copy_generation(old)
                stage_caddy_update(stage, caddy_update)
                write_generation(stage, node, old / "tls/fullchain.pem", old / "tls/key.pem", read_json(old / "ua.json", []))
                activate(stage, read_json(STATE), force=force)
        enable_units(changed)
        print("检测到已安装，保留现有服务和凭据。")
        return subscription() if not os.environ.get("ARGOSBX_APP_DEPLOY") else None
    preflight()
    pending = read_json(DATA / "pending.json")
    if pending and ("domain" not in pending or (pending.get("node") and pending["node"].get("schema") != 2)):
        raise Error("发现旧版未完成安装；请人工检查项目备份后再部署新版本")
    domain = pending["domain"] if pending else model.domain_name(args.domain or input("请输入已解析到本机的域名：").strip())
    email = args.email or ""
    if email and (not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or email.startswith("-")):
        raise Error("无效邮箱")
    node = pending.get("node") if pending else None
    if node and args.obfs is not None and args.obfs != node.get("obfs", "none"):
        raise Error("未完成安装已记录混淆模式，请使用相同安装参数重试")
    if not pending:
        save(DATA / "pending.json", {"domain": domain})
    apt_policy()
    dns_preflight({"domain": domain}, server_ip=args.server_ip)
    reality_target_check()
    identities()
    ingress(args.firewall_external)
    stage = generation()
    lockdata = read_json(APP / "dependencies.lock.json")
    releases.validate_lock(lockdata)
    versions = {}
    event("downloading")
    for binary in ("sing-box", "caddy", "lego"):
        dep = lockdata["dependencies"][binary]
        spec = dep["assets"][args.arch]
        releases.install_binary(spec, binary, stage / "bin" / binary, DATA / "cache")
        versions[binary] = spec.get("version", dep["version"])
    save(stage / "versions.json", versions)
    if node is None:
        node = model.new_node(domain, *reality_keypair(stage / "bin/sing-box"))
        if args.obfs == "salamander":
            node.update(obfs="salamander", obfs_password=secrets.token_urlsafe(32))
        save(DATA / "pending.json", {"domain": domain, "node": node})
    cert, key = obtain_certificate(node, stage / "bin/lego", email, "http", args.firewall_external)
    write_generation(stage, node, cert, key)
    tune()
    firewall()
    changed = set_units()
    state = {"email": email, "challenge": "http", "firewall_external": args.firewall_external, "schema": 2}
    activate(stage, state, public=True)
    enable_units(changed)
    (DATA / "pending.json").unlink(missing_ok=True)
    if not os.environ.get("ARGOSBX_APP_DEPLOY"):
        subscription()


def subscription():
    if JOURNAL.exists():
        raise Error("部署事务尚未恢复，暂不输出可能已失效的订阅")
    node = read_json(current() / "node.json")
    url = model.subscription(node)
    print("私人订阅（Clash Verge Rev / Shadowrocket 使用同一个链接，请勿分享）：\n" + url)
    print(run(["qrencode", "-t", "ANSIUTF8"], input=url).stdout)


def status():
    state = read_json(STATE, {})
    print("最近操作：" + json.dumps(read_json(DATA / "last-operation.json", {}), ensure_ascii=False))
    if JOURNAL.exists():
        print("有未完成的部署事务；状态查询不会重启服务。")
    if not CURRENT.is_symlink():
        print("尚未完成安装；可重复执行安装命令继续。")
        return
    stage = current()
    print("版本：" + json.dumps(read_json(stage / "versions.json"), ensure_ascii=False))
    for service in SERVICES:
        data = run(["systemctl", "show", service, "-p", "ActiveState", "-p", "NRestarts", "-p", "Result"], check=False).stdout.strip()
        print(service + ": " + data.replace("\n", "; "))
    print("证书：" + run(["openssl", "x509", "-in", stage / "tls/fullchain.pem", "-noout", "-enddate"], check=False).stdout.strip())
    print(f"可用空间：{shutil.disk_usage(DATA).free // 1024**2} MiB")
    print("更新检查：" + json.dumps(read_json(DATA / "update.json", {}), ensure_ascii=False))
    print("健康检查：" + json.dumps(read_json(DATA / "health.json", {}), ensure_ascii=False))
    print("证书续期：" + json.dumps(read_json(DATA / "renewal.json", {}), ensure_ascii=False))
    try:
        verify_apt_policy()
        print("APT 周期性更新：三项均已禁用")
    except Error as exc:
        print(str(exc))
    try:
        print("系统网络：" + json.dumps(network.check(run), ensure_ascii=False))
        print("UDP 缓冲区：" + json.dumps({key: network.buffer_value(run, key) for key in network.UDP_KEYS}))
        print("TCP 设置：" + json.dumps({key: network.tcp_value(run, key) for key in network.TCP_KEYS}))
    except ValueError as exc:
        print("系统网络：" + str(exc))
    if state.get("blocked_version"):
        print("已暂停重复升级的版本：" + state["blocked_version"])


def check_update():
    lockdata = read_json(APP / "dependencies.lock.json")
    releases.validate_lock(lockdata)
    spec = releases.latest_sing_box(root_platform(), lockdata)
    state = read_json(STATE, {})
    installed = read_json(current() / "versions.json")["sing-box"]
    if releases.version_tuple(spec["version"]) < releases.version_tuple(installed):
        raise Error("官方 latest 版本低于已安装版本，拒绝自动降级")
    save(DATA / "update.json", {"checked_at": now(), "installed": installed,
                               "available": spec["version"], "blocked": state.get("blocked_version")})
    print(f'已安装 {installed}；官方稳定版 {spec["version"]}。使用 argosbx update 在维护时段切换。')
    return spec


def update(args):
    spec = check_update()
    old = current()
    versions = read_json(old / "versions.json")
    if versions["sing-box"] == spec["version"]:
        print("已是最新稳定版。")
        return
    state = read_json(STATE)
    if state.get("blocked_version") == spec["version"] and not args.retry:
        raise Error("此版本曾失败并已暂停；检查原因后使用 update --retry")
    preflight()
    stage = copy_generation(old)
    releases.install_binary(spec, "sing-box", stage / "bin/sing-box", DATA / "cache")
    versions["sing-box"] = spec["version"]
    save(stage / "versions.json", versions)
    try:
        activate(stage, state)
    except Exception:
        state = read_json(STATE)
        state["blocked_version"] = spec["version"]
        save(STATE, state)
        raise
    state = read_json(STATE)
    state.pop("blocked_version", None)
    save(STATE, state)
    print("内核更新与本地订阅检查通过。请在客户端运行外部 UDP 验证。")


def rollback():
    state = read_json(STATE, {})
    previous = state.get("previous")
    if not previous:
        raise Error("没有可回滚版本")
    stage = Path(previous)
    if stage.parent != DATA / "generations" or not stage.is_dir():
        raise Error("回滚目录异常")
    # Never restore revoked credentials through an ordinary binary rollback.
    oldnode = read_json(current() / "node.json")
    newnode = read_json(stage / "node.json")
    non_credentials = {"name", "endpoint_ip"}
    if ({key: value for key, value in oldnode.items() if key not in non_credentials} !=
            {key: value for key, value in newnode.items() if key not in non_credentials}):
        raise Error("上一版本含旧凭据；为避免恢复已撤销密码，不能普通回滚，请使用 repair 或再次 rotate")
    if pending_caddy_update(stage):
        raise Error("上一版本的 Caddy 低于当前安全版本，拒绝回滚")
    if not current_exports(stage, newnode):
        original = stage
        stage = copy_generation(original)
        write_generation(stage, newnode, original / "tls/fullchain.pem", original / "tls/key.pem",
                         read_json(original / "ua.json", []))
    activate(stage, state)
    print("已回滚，并通过本地检查。")


def current_exports(stage, node):
    files = {f"exports/{name}": content for name, content in model.exports(node).items()}
    files["Caddyfile"] = model.caddy_config(node, ua_rules=read_json(stage / "ua.json", []))
    return all((stage / name).is_file() and (stage / name).read_text(encoding="utf-8") == content
               for name, content in files.items())


def renew(scheduled=False):
    if JOURNAL.exists():
        if scheduled:
            return
        raise Error("部署事务尚未恢复，暂缓证书续期")
    old = current()
    node = read_json(old / "node.json")
    state = read_json(STATE)
    schedule_path = DATA / "renewal.json"
    schedule = read_json(schedule_path, {})
    timestamp = time.time()
    if scheduled and timestamp < schedule.get("next_at", 0):
        return
    deployed_cert = old / "tls/fullchain.pem"
    deployed_key = old / "tls/key.pem"
    urgent = True
    try:
        certificate_check(deployed_cert, deployed_key, node["domain"], minimum=RENEW_WINDOW)
    except (Error, OSError):
        urgent = bool(run(["openssl", "x509", "-in", deployed_cert, "-checkend", str(14 * 86400),
                           "-noout"], check=False, timeout=10).returncode)
    else:
        save(schedule_path, {"next_at": timestamp + 86400, "status": "not_due"})
        return
    delay = maintenance.defer(schedule, timestamp, (3600, 7200, 14400, 28800, 57600, 86400))
    schedule.update(status="attempting", urgent=urgent)
    save(schedule_path, schedule)
    try:
        cert, key = obtain_certificate(node, old / "bin/lego", state.get("email", ""),
                                       state.get("challenge", "http"), state.get("firewall_external", False))
        if deployed_cert.is_file() and deployed_key.is_file() and filecmp.cmp(cert, deployed_cert, shallow=False) and filecmp.cmp(key, deployed_key, shallow=False):
            schedule.update(status="unchanged", next_at=time.time() + delay)
            save(schedule_path, schedule)
            return
        stage = copy_generation(old)
        write_generation(stage, node, cert, key, read_json(old / "ua.json", []))
        activate(stage, state)
    except Exception:
        schedule.update(status="failed", next_at=time.time() + delay)
        save(schedule_path, schedule)
        raise Error("证书续期未完成；保留旧部署并按退避重试。请检查 TCP 80、安全组、DNS 与证书状态") from None
    save(schedule_path, {"next_at": time.time() + 86400, "status": "renewed"})
    print("证书已校验并部署，服务完成短暂重启。")


def repair(force=()):
    preflight()
    old = current()
    state = read_json(STATE)
    stage = copy_generation(old)
    stage_caddy_update(stage, pending_caddy_update(old))
    write_generation(stage, read_json(old / "node.json"), old / "tls/fullchain.pem", old / "tls/key.pem", read_json(old / "ua.json", []))
    try:
        verify_firewall()
    except Error:
        firewall()
    tune()
    ingress(state.get("firewall_external", False))
    changed = set_units()
    force = set(SERVICES).intersection(changed).union(force)
    for service, check in zip(SERVICES, (check_proxy_listeners, lambda: probe_web(old))):
        try:
            check()
        except (Error, OSError):
            force.add(service)
    activate(stage, state, force=force)
    enable_units(changed)
    print("已重新生成配置并修复服务，凭据保持不变。")


def rotate(kind):
    old = current()
    node = read_json(old / "node.json")
    if kind in ("token", "both"):
        node["token"] = secrets.token_urlsafe(32)
    if kind in ("password", "both"):
        node["password"] = secrets.token_urlsafe(32)
        if node.get("obfs") == "salamander":
            node["obfs_password"] = secrets.token_urlsafe(32)
    if kind == "both":
        private, public = reality_keypair(old / "bin/sing-box")
        node.update(reality_private=private, reality_public=public,
                    uuid=str(uuid.uuid4()), short_id=secrets.token_hex(8))
    stage = copy_generation(old)
    write_generation(stage, node, old / "tls/fullchain.pem", old / "tls/key.pem", read_json(old / "ua.json", []))
    activate(stage, read_json(STATE))
    print({"token": "仅订阅 Token 已轮换；已导入的节点凭据不受影响。",
           "password": "Hysteria2 密码及已启用的混淆密码已轮换；VLESS 和订阅地址不变。",
           "both": "已轮换两个协议的认证信息与订阅 Token，请重新导入新链接。"}[kind])
    subscription()


def set_obfuscation(mode):
    old = current()
    node = read_json(old / "node.json")
    if node.get("obfs", "none") == mode:
        print("当前已是所选模式。")
        return subscription()
    if mode == "salamander":
        node.update(obfs="salamander", obfs_password=secrets.token_urlsafe(32))
    elif mode == "none":
        node.pop("obfs", None)
        node.pop("obfs_password", None)
    else:
        raise Error("未知传输模式")
    model.validate_node(node)
    stage = copy_generation(old)
    write_generation(stage, node, old / "tls/fullchain.pem", old / "tls/key.pem", read_json(old / "ua.json", []))
    activate(stage, read_json(STATE))
    print("模式已切换；请在两个客户端刷新原订阅。此模式不保证绕过所有识别或封锁。")
    subscription()


def set_endpoint(value):
    old = current()
    node = read_json(old / "node.json")
    address = None if value == "domain" else model.endpoint_ipv4(value)
    if node.get("endpoint_ip") == address:
        print("客户端节点地址：" + (address or node["domain"]))
        return
    if address:
        if dns_preflight(node, server_ip=address) != address:
            raise Error("固定 IPv4 必须与当前域名的公网 A 记录一致")
        node["endpoint_ip"] = address
    else:
        node.pop("endpoint_ip")
    stage = copy_generation(old)
    write_generation(stage, node, old / "tls/fullchain.pem", old / "tls/key.pem", read_json(old / "ua.json", []))
    activate(stage, read_json(STATE))
    print("客户端节点地址已更新，请刷新原订阅。")


def add_ua(args):
    old = current()
    rules = read_json(old / "ua.json", [])
    rules.append({"pattern": args.pattern, "format": args.format, "verified_client": args.client_version})
    node = read_json(old / "node.json")
    model.caddy_config(node, ua_rules=rules)  # validate before creating the candidate
    stage = copy_generation(old)
    write_generation(stage, node, old / "tls/fullchain.pem", old / "tls/key.pem", rules)
    activate(stage, read_json(STATE))
    print("已登记实测 UA；显式 format 参数始终优先。")


def local_public_ip():
    interfaces = json.loads(run(["ip", "-j", "-4", "address", "show"]).stdout)
    for interface in interfaces:
        for address in interface.get("addr_info", []):
            ip = ipaddress.IPv4Address(address["local"])
            if ip.is_global:
                return str(ip)
    return None


def check_proxy_listeners():
    probe_vless()
    probe_hy2()


def check_web_listener():
    probe_listener(SERVICES[1], "argosbx-web", "caddy", "t", 8443)


def check_runtime_certificate(stage):
    node = model.validate_node(read_json(stage / "node.json"))
    certificate_check(stage / "tls/fullchain.pem", stage / "tls/key.pem", node["domain"], minimum=0)


def local_health_issues(stage):
    if JOURNAL.exists():
        issues = {"transaction": "发现未完成的部署事务"}
        try:
            if read_json(JOURNAL)["old"]:
                verify_firewall()
        except Error as exc:
            issues["firewall"] = safe_error(exc)
        return issues
    issues = {}
    for name, check in (("certificate", lambda: check_runtime_certificate(stage)),
                        ("firewall", verify_firewall), ("proxy", check_proxy_listeners),
                        ("web", check_web_listener)):
        try:
            check()
        except Exception as exc:
            issues[name] = safe_error(exc)
    return issues


def validate_recovery(stage, fault):
    if fault == "transaction" or (fault == "firewall" and stage is None):
        old = read_json(JOURNAL)["old"]
        if old:
            path = Path(old)
            if path.parent != DATA / "generations" or path.resolve() != path or not path.is_dir():
                raise Error("待恢复的部署路径无效")
            validate_generation(path, minimum_cert=0)
            if fault == "transaction":
                verify_firewall()
        return
    validate_generation(stage, minimum_cert=0)
    if fault != "firewall":
        verify_firewall()


def recover_runtime(stage, fault):
    if fault == "transaction":
        recover(reset_failed=True)
        return
    if fault == "firewall":
        with lock("argosbx-firewall"):
            firewall()
            verify_firewall()
        return
    target = SERVICES[0 if fault == "proxy" else 1]
    reset_failed_services([target])
    run(["systemctl", "restart", target])
    for attempt in range(10):
        try:
            if fault == "proxy":
                check_proxy_listeners()
            else:
                check_web_listener()
                probe_web(stage)
            return
        except (Error, OSError):
            if attempt == 9:
                raise
            time.sleep(1)


def protocol_health(stage):
    try:
        target_ip = local_public_ip()
    except Exception:
        target_ip = None
    results = {}
    for protocol in ("vless", "hy2"):
        try:
            proxy_probe(stage, target_ip=target_ip, protocol=protocol, check_private=False)
            results[protocol] = {"transport": "TRANSPORT_OK", "data": "DATA_OK"}
        except Exception as exc:
            results[protocol] = {"transport": "EXTERNAL_UNKNOWN", "data": "EXTERNAL_UNKNOWN",
                                 "detail": safe_error(exc)}
    return results


def health(heal=False):
    stage, timestamp = (None if JOURNAL.exists() else current()), time.time()
    history_path = DATA / "self-heal.json"
    history = read_json(history_path, {})
    budget_path = DATA / "recovery-budget.json"
    budget = read_json(budget_path, {"attempts": history.get("attempts", [])})
    issues, warnings = local_health_issues(stage), []
    recovery = "not_needed"
    action = None
    if heal:
        faults = history.get("faults", {})
        history["faults"] = {name: faults.get(name, {}) for name in issues}
        attempts = budget["attempts"] = maintenance.recent_attempts(budget, timestamp)
        for fault in history["faults"].values():
            fault["seen"] = min(2, fault.get("seen", 0) + 1)
        for name in ("firewall", "transaction", "proxy", "web"):
            if name not in issues:
                continue
            recovery = "waiting_or_rate_limited"
            fault = history["faults"][name]
            cost = max(1, len(read_json(JOURNAL).get("services", SERVICES))) if name == "transaction" else 1
            if maintenance.recovery_allowed(fault, attempts, timestamp, cost):
                delay = maintenance.defer(fault, timestamp, (120, 300, 600, 1200, 1800))
                save(history_path, history)
                try:
                    validate_recovery(stage, name)
                    attempts.extend([time.time()] * cost)
                    save(budget_path, budget)
                    action = name
                    recover_runtime(stage, name)
                    if name == "transaction" and CURRENT.is_symlink():
                        stage = current()
                        issues.update(local_health_issues(stage))
                    history["faults"].pop(name)
                    issues.pop(name)
                    recovery = "recovered"
                    event("self-healed", fault=name)
                except Exception as exc:
                    fault["next_at"] = time.time() + delay
                    issues["recovery"] = safe_error(exc)
                    recovery = "failed"
                break
            if name in ("transaction", "firewall"):
                break
        if stage is not None and not issues and timestamp - history.get("last_data_check", 0) >= 300:
            history.update(last_data_check=timestamp, protocols=protocol_health(stage))
        save(history_path, history)
    diagnostics = {}
    if timestamp - history.get("last_apt_check", 0) >= 3600 or not heal:
        try:
            verify_apt_policy()
            history.pop("apt_warning", None)
        except (Error, OSError, subprocess.TimeoutExpired) as exc:
            history["apt_warning"] = safe_error(exc)
        if heal:
            history["last_apt_check"] = timestamp
            save(history_path, history)
    if history.get("apt_warning"):
        warnings.append(history["apt_warning"])
    if stage is not None:
        try:
            run(["openssl", "x509", "-in", stage / "tls/fullchain.pem", "-checkend", str(14 * 86400), "-noout"])
        except Exception:
            warnings.append("证书有效期不足 14 天，请检查自动续期结果")
    try:
        if shutil.disk_usage(DATA).free < 512 * 1024**2:
            warnings.append("空闲磁盘低于 512 MiB")
        for service in SERVICES:
            output = run(["systemctl", "show", service, "-p", "NRestarts", "-p", "Result", "-p", "ActiveState",
                          "-p", "ExecMainStatus", "-p", "MemoryCurrent", "-p", "MemoryMax"]).stdout
            props = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
            diagnostics[service] = props
            if int(props.get("NRestarts", "0")) >= 5:
                warnings.append(service + " 重启次数较多")
        if heal and not issues and stage is not None and timestamp - history.get("last_cleanup", 0) >= 86400:
            maintenance.cleanup_cache(DATA / "cache", timestamp)
            cleanup_generations()
            history["last_cleanup"] = timestamp
            save(history_path, history)
    except Exception as exc:
        warnings.append(safe_error(exc))
    problems = list(issues.values()) + warnings
    save(DATA / "health.json", {"time": now(), "ok": not issues, "problems": problems,
                               "recovery": recovery, "auto_recovery": heal,
                               "recovery_action": action, "services": diagnostics,
                               "local": "FAILED" if issues else "LOCAL_OK",
                               "last_data_check": history.get("last_data_check"),
                               "protocols": history.get("protocols", {}),
                               "external_udp": "未自动验证"})
    for warning in warnings:
        print(warning, file=sys.stderr)
    if issues:
        raise Error("健康检查未通过：" + "; ".join(problems))
    print("本地健康检查通过；外部 UDP 和客户端状态需单独验证。")


def uninstall(purge):
    # Only exact project-owned files/services; no shared package uninstallation.
    unit_names = []
    for name in system.units():
        path = UNIT_DIR / name
        if path.is_symlink() or (path.exists() and not path.read_text().startswith("# Managed by ArgoSBX-HY2\n")):
            raise Error(f"同名服务 {name} 已不属于本项目，停止卸载以保留它")
        if path.exists():
            unit_names.append(name)
    for name in unit_names:
        run(["systemctl", "disable", "--now", name], check=False)
    rollback_ingress()
    cleanup_http_challenge()
    undo_tune()
    resolver_privacy(remove=True)
    apt_policy(remove=True)
    if read_json(ETC / "firewall.json", {}).get("guard_owned"):
        run(["nft", "delete", "table", "inet", "argosbx_hy2"], check=False)
    for name in unit_names:
        (UNIT_DIR / name).unlink(missing_ok=True)
    alias = Path("/usr/local/bin/aaa")
    if alias.is_file() and not alias.is_symlink() and alias.read_text().startswith("#!/bin/sh\n# Managed by ArgoSBX-HY2\n"):
        alias.unlink()
    run(["systemctl", "daemon-reload"])
    CURRENT.unlink(missing_ok=True)
    sync_directory(CURRENT.parent)
    if purge:
        for path in (ETC, DATA):
            if path.is_symlink():
                raise Error("敏感目录为符号链接，拒绝递归删除")
            shutil.rmtree(path)
        print("本项目配置、Cloudflare 凭据及敏感历史版本已清除。")
    else:
        print("服务与规则已移除；敏感备份仍在 /var/lib/argosbx-hy2，API Token 仍在 /etc/argosbx-hy2。")
        print("重新安装会从备份恢复原凭据。彻底清除请运行 argosbx uninstall --purge。")
    print("管理程序保留以便恢复/清除；未移除系统软件包、用户或任何其他站点。")


def rollback_new_install():
    """Undo only resources created by an incomplete fresh deployment."""
    for name in system.units():
        path = UNIT_DIR / name
        if path.is_file() and not path.is_symlink() and path.read_text().startswith("# Managed by ArgoSBX-HY2\n"):
            run(["systemctl", "disable", "--now", name], check=False)
            path.unlink()
    run(["systemctl", "daemon-reload"], check=False)
    CURRENT.unlink(missing_ok=True)
    save(STATE, {})
    rollback_ingress()
    cleanup_http_challenge()
    apt_policy(remove=True)
    undo_tune()
    if read_json(ETC / "firewall.json", {}).get("guard_owned"):
        run(["nft", "delete", "table", "inet", "argosbx_hy2"], check=False)
        save(ETC / "firewall.json", {"ufw": []})


def menu():
    choices = {"1": subscription, "2": status, "3": repair, "4": lambda: update(argparse.Namespace(retry=False)),
               "5": rollback, "6": renew, "7": lambda: rotate("both"), "8": health,
               "9": lambda: uninstall(False)}
    print("\nArgoSBX-HY2\n1 订阅链接\n2 状态\n3 修复/重启\n4 更新内核\n5 回滚\n6 续期证书\n7 轮换全部凭据\n8 健康检查\n9 卸载（保留备份）\n0 退出")
    choice = input("选择：").strip()
    if choice in choices:
        if choice in ("3", "4", "5", "7", "9"):
            recover()
            cleanup_http_challenge()
        choices[choice]()


def safe_error(exc):
    if isinstance(exc, (Error, releases.ReleaseError, ValueError)):
        # Our errors are fixed text, but sanitize any accidental secrets defensively.
        message = str(exc)
    else:
        message = type(exc).__name__ + "；请检查网络、磁盘和系统服务后重试"
    return re.sub(r"[A-Za-z0-9_-]{20,}", "[REDACTED]", message)[:500]


def main(argv=None):
    parser = argparse.ArgumentParser(description="ArgoSBX-HY2 管理命令")
    sub = parser.add_subparsers(dest="command")
    ins = sub.add_parser("install")
    ins.add_argument("--domain")
    ins.add_argument("--email", default="", help="可选联系邮箱；默认不设置，也不询问")
    ins.add_argument("--name", help=argparse.SUPPRESS)
    ins.add_argument("--obfs", choices=["none", "salamander"],
                     help="默认标准 HTTP/3；确认网络限制 QUIC 时可用 Salamander，非通用抗识别保证")
    ins.add_argument("--token-file", help=argparse.SUPPRESS)
    ins.add_argument("--challenge", choices=["http"], default="http")
    ins.add_argument("--server-ip", help="NAT VPS 的显式公网 IPv4；默认与本机接口地址比对")
    ins.add_argument("--firewall-external", action="store_true")
    upd = sub.add_parser("update")
    upd.add_argument("--retry", action="store_true")
    for name in ("subscription", "status", "repair", "rollback", "check-update", "firewall", "network", "recover"):
        sub.add_parser(name)
    sub.add_parser("renew").add_argument("--scheduled", action="store_true", help=argparse.SUPPRESS)
    health_parser = sub.add_parser("health")
    health_parser.add_argument("--heal", action="store_true", help="连续失败后限次恢复本项目服务、规则与网络参数")
    diag = sub.add_parser("netdiag", help="只读采样 VPS 网卡、CPU、TCP 和 UDP 计数")
    diag.add_argument("--seconds", type=int, default=10, help="采样秒数，1–120")
    endpoint = sub.add_parser("endpoint", help="固定客户端连接 IPv4，或恢复通过域名连接")
    endpoint.add_argument("address", metavar="IPv4|domain")
    rot = sub.add_parser("rotate")
    rot.add_argument("kind", choices=["token", "password", "both"], default="both", nargs="?")
    transport = sub.add_parser("obfs", help="切换传输模式，保留订阅地址；客户端需要刷新")
    transport.add_argument("mode", choices=["none", "salamander"])
    ua = sub.add_parser("add-ua")
    ua.add_argument("--pattern", required=True)
    ua.add_argument("--format", choices=["clash", "shadowrocket", "singbox"], required=True)
    ua.add_argument("--client-version", required=True, help="实际验证的客户端版本与平台")
    un = sub.add_parser("uninstall")
    un.add_argument("--purge", action="store_true")
    args = parser.parse_args(argv)
    if args.command == "install" and (args.name is not None or args.token_file is not None):
        ins.error("不支持 --name 或 --token-file；节点名固定，证书仅使用 HTTP-01")
    if args.command == "netdiag" and not 1 <= args.seconds <= 120:
        diag.error("--seconds 必须在 1–120 之间")
    had_current = CURRENT.is_symlink()
    try:
        args.arch = root_platform()
        if args.command == "netdiag":
            print(json.dumps(network.diagnostics(run, args.seconds), ensure_ascii=False, indent=2))
            return 0
        os.umask(0o077)
        # systemd starts the guard while activation holds the lifecycle lock.
        # Its own lock serializes nft changes without deadlocking activation.
        with lock("argosbx-" + args.command if args.command in ("firewall", "network") else "argosbx-hy2"):
            for path in (ETC, DATA):
                if path.is_symlink():
                    raise Error("本项目目录为符号链接，停止修改")
                if path.exists() and not (path / ".argosbx-owned").exists():
                    raise Error("发现未知同名目录，拒绝覆盖；请使用发布包安装器")
                path.mkdir(mode=0o755 if path == ETC else 0o711, exist_ok=True)
                path.chmod(0o755 if path == ETC else 0o711)
                (path / ".argosbx-owned").touch(mode=0o600, exist_ok=True)
            for path in (DATA / "generations", DATA / "public"):
                if path.is_symlink():
                    raise Error("本项目数据子目录不能是符号链接")
            (DATA / "generations").mkdir(mode=0o711, exist_ok=True)
            (DATA / "generations").chmod(0o711)
            (DATA / "public").mkdir(mode=0o755, exist_ok=True)
            (DATA / "public").chmod(0o755)
            ensure_public_page()
            if args.command == "recover":
                recover(restart=False)
                return 0
            if args.command in ("firewall", "network"):
                recover(restart=False)
            elif args.command == "renew":
                if not JOURNAL.exists():
                    cleanup_http_challenge()
            elif args.command not in (None, "health", "subscription", "status", "check-update"):
                recover()
                cleanup_http_challenge()
            command = args.command
            if command == "install":
                # Restore preserved installation after an uninstall, keeping credentials.
                state = read_json(STATE, {})
                if not CURRENT.is_symlink() and state.get("current") and Path(state["current"]).is_dir():
                    linked(CURRENT, state["current"])
                install(args)
            elif command == "update":
                update(args)
            elif command == "rotate":
                rotate(args.kind)
            elif command == "obfs":
                set_obfuscation(args.mode)
            elif command == "endpoint":
                set_endpoint(args.address)
            elif command == "add-ua":
                add_ua(args)
            elif command == "uninstall":
                uninstall(args.purge)
            elif command == "health":
                health(args.heal)
            elif command == "renew":
                renew(args.scheduled)
            elif command:
                {"subscription": subscription, "status": status, "repair": repair, "rollback": rollback,
                 "check-update": check_update, "firewall": firewall, "network": tune}[command]()
            else:
                menu()
        return 0
    except Busy as exc:
        if (args.command == "health" and args.heal) or (args.command == "renew" and args.scheduled):
            return 0
        print(str(exc), file=sys.stderr)
        return 1
    except (Exception, KeyboardInterrupt) as exc:
        message = safe_error(exc)
        print("未完成：" + message, file=sys.stderr)
        if DATA.exists():
            try:
                event("failed", error=message)
                pending = read_json(DATA / "pending.json", {})
                if args.command == "install" and not had_current and pending.get("domain"):
                    rollback_new_install()
            except Exception:
                pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
