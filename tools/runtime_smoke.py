"""Ephemeral real-engine HTTPS/HY2 tests. Uses a LOCAL TEST CA, never production TLS."""
import argparse
import contextlib
import copy
import http.client
import hashlib
import json
from pathlib import Path
import socket
import secrets
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import re

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from argosbx import model


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(type=kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def openssl_run(openssl, *args):
    subprocess.run([openssl, *map(str, args)], check=True, capture_output=True)


def make_cert(root, openssl):
    tls = root / "tls"
    tls.mkdir()
    ca, cakey = tls / "ca.pem", tls / "ca.key"
    openssl_run(openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", cakey,
                "-out", ca, "-days", "2", "-subj", "/CN=ArgoSBX ephemeral TEST CA",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl_run(openssl, "req", "-newkey", "rsa:2048", "-nodes", "-keyout", tls / "key.pem",
                "-out", tls / "leaf.csr", "-subj", "/CN=node.example.com")
    (tls / "extensions.txt").write_text("subjectAltName=DNS:node.example.com,DNS:addons.mozilla.org\n"
                                       "basicConstraints=critical,CA:FALSE\n"
                                       "keyUsage=critical,digitalSignature,keyEncipherment\n"
                                       "subjectKeyIdentifier=hash\n"
                                       "authorityKeyIdentifier=keyid,issuer\n"
                                       "extendedKeyUsage=serverAuth\n")
    openssl_run(openssl, "x509", "-req", "-in", tls / "leaf.csr", "-CA", ca, "-CAkey", cakey,
                "-CAcreateserial", "-out", tls / "leaf.pem", "-days", "2", "-extfile", tls / "extensions.txt")
    (tls / "fullchain.pem").write_bytes((tls / "leaf.pem").read_bytes() + ca.read_bytes())
    return ca


def receive(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise OSError("Connection closed during SOCKS reply")
        data += chunk
    return data


@contextlib.contextmanager
def socks(port, host, target_port):
    with socket.create_connection(("127.0.0.1", port), timeout=15) as sock:
        sock.settimeout(20)
        sock.sendall(b"\x05\x01\x00")
        assert receive(sock, 2) == b"\x05\x00"
        encoded = host.encode("ascii")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded + struct.pack("!H", target_port))
        header = receive(sock, 4)
        if header[1] != 0:
            raise ConnectionRefusedError("SOCKS target explicitly rejected")
        size = {1: 4, 4: 16}.get(header[3])
        if header[3] == 3:
            size = receive(sock, 1)[0]
        receive(sock, size + 2)
        yield sock


def smoke(sb, caddy, openssl, external=False, obfs='none',mihomo=None):
    processes = []
    with tempfile.TemporaryDirectory(prefix="ahy2-runtime-") as tmp:
        root = Path(tmp)
        ca = make_cert(root, openssl)
        context = ssl.create_default_context(cafile=str(ca))
        pair = subprocess.run([sb, "generate", "reality-keypair"], check=True, capture_output=True, text=True).stdout
        node = model.new_node("node.example.com", re.search(r"PrivateKey:\s*(\S+)", pair)[1],
                              re.search(r"PublicKey:\s*(\S+)", pair)[1])
        if obfs == "salamander":
            node.update(obfs=obfs, obfs_password=secrets.token_urlsafe(32))
        tcp_port, udp_port, local_port, vless_port = free_port(), free_port(socket.SOCK_DGRAM), free_port(), free_port()
        echo = socket.socket(type=socket.SOCK_DGRAM)
        echo.bind(('127.0.0.1', 0))
        echo.settimeout(5)
        echo_port = echo.getsockname()[1]
        (root / "exports").mkdir()
        (root / "public").mkdir()
        (root / "public/index.html").write_text(model.PUBLIC_PAGE)
        for name, content in model.exports(node).items():
            (root / "exports" / name).write_text(content, encoding="utf-8")
        web = model.caddy_config(node, root.as_posix(), [{"pattern": "Verified-Mihomo/test*", "format": "clash"}])
        web = web.replace("https://node.example.com:8443 {", f"https://node.example.com:{tcp_port} {{\n  bind 127.0.0.1")
        web = web.replace("/var/lib/argosbx-hy2/public", (root / "public").as_posix())
        (root / "Caddyfile").write_text(web, encoding="utf-8")
        server = model.server_config(node, root.as_posix())
        server["inbounds"][0]["listen_port"] = free_port()
        server["inbounds"][1]["listen_port"] = udp_port
        for inbound in server["inbounds"]:
            inbound["listen"] = "127.0.0.1"
        server["inbounds"][0]["tls"]["reality"]["handshake"].update(server="127.0.0.1", server_port=tcp_port)
        server["inbounds"][1]["masquerade"]["directory"] = (root / "public").as_posix()
        # TEST FIXTURE ONLY: permit the local Caddy port to prove data transfer
        # without depending on an external network. Production has no such rule.
        server["route"]["rules"].insert(1, {"ip_cidr": ["127.0.0.1/32"], "port": tcp_port,
                                           "action": "route", "outbound": "direct"})
        server['route']['rules'].insert(1, {'ip_cidr': ['127.0.0.1/32'], 'port': echo_port,
                                           'action': 'route', 'outbound': 'direct'})
        vless_client = model.client_config(node)
        vless_client["inbounds"][0]["listen_port"] = vless_port
        vless_client["outbounds"] = [vless_client["outbounds"][0]]
        vless_client["outbounds"][0].update(server="127.0.0.1", server_port=server["inbounds"][0]["listen_port"])
        client = model.client_config(node)
        client["outbounds"] = [client["outbounds"][1]]
        client["route"]["final"] = model.HYSTERIA2
        client["inbounds"][0]["listen_port"] = local_port
        outbound = client["outbounds"][0]
        outbound.update(server="127.0.0.1", server_port=udp_port)
        outbound["tls"]["certificate_path"] = ca.as_posix()
        for name, content in [("server", server), ("client", client), ("vless-client", vless_client)]:
            (root / f"{name}.json").write_text(json.dumps(content), encoding="utf-8")
        try:
            for command in [[caddy, "run", "--config", str(root / "Caddyfile"), "--adapter", "caddyfile"],
                            [sb, "run", "-c", str(root / "server.json")],
                            [sb, "run", "-c", str(root / "client.json")],
                            [sb, "run", "-c", str(root / "vless-client.json")]]:
                processes.append(subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            def request(path, ua="Unknown/test", ctx=context):
                conn = http.client.HTTPSConnection("node.example.com", tcp_port, context=ctx, timeout=5)
                conn._create_connection = lambda address, timeout, source_address=None: socket.create_connection(("127.0.0.1", tcp_port), timeout)
                try:
                    conn.request("GET", path, headers={"User-Agent": ua})
                    res = conn.getresponse()
                    return res.status, dict((k.lower(), v) for k, v in res.getheaders()), res.read()
                finally:
                    conn.close()
            for _ in range(50):
                if any(p.poll() is not None for p in processes):
                    raise RuntimeError("A smoke-test engine exited unexpectedly")
                try:
                    request("/")
                    break
                except OSError:
                    time.sleep(0.1)
            path = "/s/" + node["token"]
            for fmt, filename in [("clash", "clash.yaml"), ("shadowrocket", "shadowrocket.txt"), ("singbox", "singbox.json")]:
                status, headers, body = request(path + "?format=" + fmt)
                assert status == 200 and body == (root / "exports" / filename).read_bytes(), fmt
                assert "no-store" in headers["cache-control"] and "alt-svc" not in headers
            assert request(path)[2] == (root / "exports/index.html").read_bytes()
            for ua in ("clash-verge/v2.4.0", "Clash-Verge/v3.0.0", "Clash.Meta/1.19.32", "mihomo/1.19.32"):
                status, headers, body = request(path, ua)
                assert status == 200 and body == (root / "exports/clash.yaml").read_bytes(), ua
                assert "user-agent" in headers["vary"].lower() and "no-store" in headers["cache-control"]
            for ua in ("Shadowrocket/2.2.71", "shadowrocket/2.2.71 CFNetwork/1 Darwin/1", "Shadowrocket"):
                assert request(path, ua)[2] == (root / "exports/shadowrocket.txt").read_bytes(), ua
            for ua in ("Mozilla/5.0 Shadowrocket/2.2.71", "clash-verge-unknown/1", "ShadowrocketFake/1"):
                assert request(path, ua)[2] == (root / "exports/index.html").read_bytes(), ua
            assert request(path + "?format=clash", "Shadowrocket/2.2.71")[2] == (root / "exports/clash.yaml").read_bytes()
            assert request(path, "Verified-Mihomo/test1")[2] == (root / "exports/clash.yaml").read_bytes()
            assert request(path + "?format=shadowrocket", "Verified-Mihomo/test1")[2] == (root / "exports/shadowrocket.txt").read_bytes()
            assert request(path + "?format=unknown", "Verified-Mihomo/test1")[2] == (root / "exports/index.html").read_bytes()
            for illegal in ("/s/bad", "/clash.yaml", "/exports/clash.yaml", "/tls/key.pem", "/node.json"):
                assert request(illegal)[0] == 404, illegal
            try:
                request("/", ctx=ssl.create_default_context())
                raise AssertionError("Untrusted test CA was accepted")
            except ssl.SSLCertVerificationError:
                pass
            with socks(local_port, "127.0.0.1", tcp_port) as raw:
                with context.wrap_socket(raw, server_hostname="node.example.com") as secure:
                    secure.sendall(b"GET / HTTP/1.1\r\nHost: node.example.com\r\nConnection: close\r\n\r\n")
                    response = b""
                    while True:
                        chunk = secure.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    assert b"200 OK" in response and b"This site is online" in response
            with socks(vless_port, "127.0.0.1", tcp_port) as raw:
                with context.wrap_socket(raw, server_hostname="node.example.com") as secure:
                    secure.sendall(b"GET / HTTP/1.1\r\nHost: node.example.com\r\nConnection: close\r\n\r\n")
                    assert b"200 OK" in secure.recv(4096)
            print("Real VLESS REALITY Vision local data relay: PASS")
            # Exercise real HY2 UDP relay via SOCKS5 UDP ASSOCIATE, not just TCP
            # over the QUIC transport. The echo exception exists only here.
            with socket.create_connection(('127.0.0.1', local_port), timeout=5) as control:
                control.settimeout(5)
                control.sendall(b'\x05\x01\x00')
                assert receive(control, 2) == b'\x05\x00'
                control.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
                header = receive(control, 4)
                assert header[1] == 0 and header[3] == 1
                endpoint = receive(control, 6)
                relay_port = struct.unpack('!H', endpoint[4:])[0]
                payload = b'argosbx-udp-test-' + bytes(range(32))
                packet = b'\x00\x00\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', echo_port) + payload
                with socket.socket(type=socket.SOCK_DGRAM) as datagram:
                    datagram.settimeout(5)
                    datagram.sendto(packet, ('127.0.0.1', relay_port))
                    data, sender = echo.recvfrom(4096)
                    assert data == payload
                    echo.sendto(data, sender)
                    returned, _ = datagram.recvfrom(4096)
                    assert returned[10:] == payload
            print('Real HY2 UDP relay: PASS')
            for fault in ('password', 'sni', 'ca', 'uuid', 'short_id'):
                bad = copy.deepcopy(vless_client if fault in ('uuid', 'short_id') else client)
                bad_port = free_port()
                bad['inbounds'][0]['listen_port'] = bad_port
                if fault == 'password': bad['outbounds'][0]['password'] = 'invalid-password'
                if fault == 'sni': bad['outbounds'][0]['tls']['server_name'] = 'wrong.example.com'
                if fault == 'ca': bad['outbounds'][0]['tls'].pop('certificate_path')
                if fault == 'uuid': bad['outbounds'][0]['uuid'] = '00000000-0000-4000-8000-000000000000'
                if fault == 'short_id': bad['outbounds'][0]['tls']['reality']['short_id'] = '0000000000000000'
                bad_path = root / ('negative-' + fault + '.json')
                bad_path.write_text(json.dumps(bad), encoding='utf-8')
                bad_proc = subprocess.Popen([sb, 'run', '-c', str(bad_path)],
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                processes.append(bad_proc)
                for _ in range(50):
                    assert bad_proc.poll() is None
                    try:
                        with socket.create_connection(('127.0.0.1', bad_port), timeout=.1): break
                    except OSError: time.sleep(.1)
                else:
                    raise RuntimeError('Invalid-credential test client never started: ' + fault)
                try:
                    with socks(bad_port, '127.0.0.1', tcp_port) as raw:
                        raw.settimeout(2)
                        raw.sendall(b'GET / HTTP/1.0\r\n\r\n')
                        assert not raw.recv(4096), 'Invalid credentials/TLS forwarded data: ' + fault
                except (OSError, EOFError):
                    pass
                bad_proc.terminate()
                bad_proc.wait(timeout=5)
            print('Real HY2 wrong password, wrong SNI and untrusted CA rejection: PASS')
            print('Real VLESS wrong UUID and REALITY short_id rejection: PASS')
            if mihomo:
                mhport=free_port()
                # Test-only CA pin verifies chain/name without changing system trust.
                pin=hashlib.sha256(ssl.PEM_cert_to_DER_cert(ca.read_text())).hexdigest()
                yaml=model.clash_config(node).replace('mixed-port: 7890',f'mixed-port: {mhport}')
                yaml=yaml.replace('server: "node.example.com"','server: "127.0.0.1"').replace('    port: 443',f'    port: {udp_port}')
                yaml=yaml.replace('proxies: ["VLESS", "Hysteria2"]','proxies: ["Hysteria2", "VLESS"]')
                yaml=yaml.replace('    skip-cert-verify: false',f'    skip-cert-verify: false\n    fingerprint: "{pin}"')
                path=root/'mihomo.yaml'
                path.write_text(yaml,encoding='utf-8')
                mh=subprocess.Popen([mihomo,'-d',str(root/'mihomo'),'-f',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                processes.append(mh)
                for _ in range(50):
                    if mh.poll() is not None: raise RuntimeError('Mihomo runtime fixture exited')
                    try:
                        with socket.create_connection(('127.0.0.1',mhport),timeout=.1): break
                    except OSError: time.sleep(.1)
                with socks(mhport,'127.0.0.1',tcp_port) as raw:
                    with context.wrap_socket(raw,server_hostname='node.example.com') as secure:
                        secure.sendall(b'GET / HTTP/1.1\r\nHost: node.example.com\r\nConnection: close\r\n\r\n')
                        res=http.client.HTTPResponse(secure);res.begin()
                        assert res.status==200 and b'This site is online' in res.read()
                print('Real Mihomo HY2 auth/TLS/data mode '+obfs+': PASS')
            # A reachable local sentinel distinguishes rejection from a closed port.
            with socket.socket() as sentinel:
                sentinel.bind(("127.0.0.1", 0))
                sentinel.listen()
                sentinel.settimeout(0.2)
                sentinel_port = sentinel.getsockname()[1]
                stopped = threading.Event()
                private_hits = []
                def answer():
                    while not stopped.is_set():
                        try:
                            conn, _ = sentinel.accept()
                            private_hits.append(True)
                            with conn:
                                conn.sendall(b"PRIVATE-SENTINEL")
                        except TimeoutError:
                            continue
                        except OSError:
                            break
                worker = threading.Thread(target=answer, daemon=True)
                worker.start()
                try:
                    with socket.create_connection(("127.0.0.1", sentinel_port)) as direct:
                        assert direct.recv(100) == b"PRIVATE-SENTINEL"
                    assert len(private_hits) == 1
                    for proxy_port in (local_port, vless_port):
                        for host, target in [("127.0.0.1", sentinel_port), ("localhost", sentinel_port),
                                         ("10.0.0.1", 80), ("169.254.169.254", 80)]:
                            try:
                                with socks(proxy_port, host, target) as raw:
                                    raw.settimeout(3)
                                    raw.sendall(b"GET / HTTP/1.0\r\n\r\n")
                                    assert not raw.recv(4096), "Private data forwarded: " + host
                            except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, TimeoutError):
                                pass
                            assert len(private_hits) == 1, "Private sentinel was reached: " + host
                finally:
                    stopped.set()
                    worker.join(timeout=1)
            if external:
                with socks(local_port, "example.com", 443) as raw:
                    with ssl.create_default_context().wrap_socket(raw, server_hostname="example.com") as secure:
                        secure.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
                        assert b"200" in secure.recv(4096).split(b"\r\n", 1)[0]
            print("HTTPS formats/token/UA/cache/TLS and both protocols' private-destination rejection: PASS")
            print("Real HY2 auth/TLS/data with isolated local fixture: PASS")
            if external:
                print("Real HY2 authentication + public HTTPS request: PASS")
        finally:
            echo.close()
            for proc in reversed(processes):
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sing-box", required=True)
    parser.add_argument("--caddy", required=True)
    parser.add_argument("--openssl", default="openssl")
    parser.add_argument("--external", action="store_true", help="Also request example.com through HY2")
    parser.add_argument("--obfs", choices=['none','salamander'], default='none')
    parser.add_argument('--mihomo')
    args = parser.parse_args()
    smoke(str(Path(args.sing_box).resolve()), str(Path(args.caddy).resolve()), args.openssl, args.external,args.obfs,
          str(Path(args.mihomo).resolve()) if args.mihomo else None)
