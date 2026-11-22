"""Pure configuration generation. No network, process or filesystem mutations."""
import base64
import ipaddress
import json
import re
import secrets
import uuid
from urllib.parse import quote

ROOT = "/etc/argosbx-hy2/current"
VLESS = "VLESS"
VLESS_FAST_OPEN = "VLESS Fast Open"
VLESS_UDP = "VLESS over UDP"
VLESS_HIGH_LOSS = "VLESS High Loss"
HY2_RATE = "Hysteria2 Rate"
HYSTERIA2 = "Hysteria2"
AUTO = "AUTO"
# Explicitly includes multicast, CGNAT, documentation, mapped IPv4 and metadata.
BLOCKED = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "::ffff:0:0/96",
    "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32",
    "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "ff00::/8",
]


def domain_name(value):
    value = value.strip().rstrip(".").lower()
    if len(value) > 253 or "." not in value:
        raise ValueError("请填写专用的完整子域名")
    if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x)
               for x in value.split(".")):
        raise ValueError("域名须为 ASCII/Punycode，不允许通配符、URL 或特殊字符")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("第一版使用域名证书，请勿填写 IP")


def endpoint_ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        raise ValueError("节点地址必须是公网 IPv4，或用 domain 恢复域名") from None
    if not address.is_global or address.is_multicast:
        raise ValueError("节点地址必须是公网单播 IPv4")
    return str(address)


def validate_node(node):
    if domain_name(node["domain"]) != node["domain"]:
        raise ValueError("元数据域名必须使用规范形式")
    if "endpoint_ip" in node and endpoint_ipv4(node["endpoint_ip"]) != node["endpoint_ip"]:
        raise ValueError("节点 IPv4 必须使用规范形式")
    if "vless_udp_rate" in node:
        rate = node["vless_udp_rate"]
        if "endpoint_ip" not in node:
            raise ValueError("高丢包线路需要固定 VPS 公网 IPv4")
        if (not isinstance(rate, dict) or set(rate) != {"up_mbps", "down_mbps"} or
                any(type(value) is not int or not 1 <= value <= 1000 for value in rate.values())):
            raise ValueError("高丢包线路的上传和下载目标速率须为 1–1000 Mbps 的整数")
    for key in ("password", "token"):
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", node[key]):
            raise ValueError(f"无效的 {key}（要求 32 字节随机值）")
    if node["password"] == node["token"]:
        raise ValueError("节点密码不得与订阅 Token 复用")
    if node.get("schema") != 2:
        raise ValueError("仅支持双协议新安装；旧版节点不会自动迁移")
    uuid.UUID(node["uuid"])
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", node.get("reality_private", "")) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", node.get("reality_public", "")):
        raise ValueError("REALITY 密钥无效")
    if not re.fullmatch(r"[0-9a-f]{16}", node.get("short_id", "")):
        raise ValueError("REALITY short_id 无效")
    mode = node.get("obfs", "none")
    if mode not in ("none", "salamander"):
        raise ValueError("仅支持标准 HTTP/3 或 Salamander 模式")
    if mode == "salamander":
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", node.get("obfs_password", "")):
            raise ValueError("混淆密码必须是独立的 32 字节随机值")
        if node["obfs_password"] in (node["password"], node["token"]):
            raise ValueError("混淆密码不得复用节点密码或订阅 Token")
    elif "obfs_password" in node:
        raise ValueError("标准模式不能保留混淆密码")
    name = node["name"]
    if not isinstance(name, str) or not name or len(name) > 80 or any(ord(c) < 32 for c in name):
        raise ValueError("节点名应为 1–80 个无控制字符的字符")
    if name.upper() in {"PROXY", "DIRECT", "REJECT", "GLOBAL", "PASS", "REJECT-DROP", "COMPATIBLE"}:
        raise ValueError("节点名称与客户端保留策略名冲突，请换一个名称")
    return node


def new_node(domain, private_key, public_key):
    return validate_node({"schema": 2, "domain": domain_name(domain), "name": HYSTERIA2,
                          "uuid": str(uuid.uuid4()), "reality_private": private_key,
                          "reality_public": public_key, "short_id": secrets.token_hex(8),
                          "password": secrets.token_urlsafe(32), "token": secrets.token_urlsafe(32)})


def obfuscation(node):
    validate_node(node)
    return ({"obfs": {"type": "salamander", "password": node["obfs_password"]}}
            if node.get("obfs") == "salamander" else {})


def subscription(node):
    return f'https://{node["domain"]}:8443/s/{node["token"]}'


def vless_uri(node):
    validate_node(node)
    return (f'vless://{node["uuid"]}@{node.get("endpoint_ip", node["domain"])}:443?encryption=none&security=reality'
            f'&sni=addons.mozilla.org&fp=chrome&pbk={node["reality_public"]}'
            f'&sid={node["short_id"]}&flow=xtls-rprx-vision&type=tcp&packetEncoding=xudp'
            f'#{VLESS}')


def uri(node):
    validate_node(node)
    obfs = ("&obfs=salamander&obfs-password=" + quote(node["obfs_password"], safe="")
            if node.get("obfs") == "salamander" else "")
    return (f'hysteria2://{quote(node["password"], safe="")}@{node.get("endpoint_ip", node["domain"])}:443/'
            f'?sni={node["domain"]}&insecure=0{obfs}#{HYSTERIA2}')


def server_config(node, root=ROOT):
    validate_node(node)
    rate = node.get("vless_udp_rate")
    bandwidth = ({"up_mbps": rate["down_mbps"], "down_mbps": rate["up_mbps"]} if rate
                 else {"ignore_client_bandwidth": True})
    return {
        "log": {"level": "error", "timestamp": True},
        "dns": {"servers": [{"type": "local", "tag": "local"}]},
        "inbounds": [{"type": "vless", "tag": "vless-in", "listen": "0.0.0.0", "listen_port": 443,
                      "tcp_fast_open": True,
                      "users": [{"name": "personal", "uuid": node["uuid"], "flow": "xtls-rprx-vision"}],
                      "tls": {"enabled": True, "server_name": "addons.mozilla.org",
                              "reality": {"enabled": True,
                                          "handshake": {"server": "addons.mozilla.org", "server_port": 443},
                                          "private_key": node["reality_private"],
                                          "short_id": [node["short_id"]]}}},
                     {"type": "hysteria2", "tag": "hy2-in", "listen": "0.0.0.0",
                      "listen_port": 443, "users": [{"name": "personal", "password": node["password"]}],
                      **bandwidth, **obfuscation(node),
                      "tls": {"enabled": True, "server_name": node["domain"],
                              "certificate_path": f"{root}/tls/fullchain.pem",
                              "key_path": f"{root}/tls/key.pem"},
                      "masquerade": {"type": "file", "directory": "/var/lib/argosbx-hy2/public"}}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"default_domain_resolver": {"server": "local", "strategy": "ipv4_only"},
                  "rules": [{"action": "resolve", "strategy": "ipv4_only"},
                            {"ip_is_private": True, "action": "reject"},
                            {"ip_cidr": BLOCKED, "action": "reject"}], "final": "direct"},
    }


def vless_outbound(node, endpoint, tag):
    return {"type": "vless", "tag": tag, "server": endpoint, "server_port": 443,
            "uuid": node["uuid"], "flow": "xtls-rprx-vision", "packet_encoding": "xudp",
            "tls": {"enabled": True, "server_name": "addons.mozilla.org",
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {"enabled": True, "public_key": node["reality_public"], "short_id": node["short_id"]}}}


def client_config(node):
    validate_node(node)
    endpoint = node.get("endpoint_ip", node["domain"])
    hy2 = {"type": "hysteria2", "tag": HYSTERIA2, "server": endpoint, "server_port": 443,
           "password": node["password"], **obfuscation(node),
           "tls": {"enabled": True, "server_name": node["domain"], "insecure": False}}
    outbounds = [vless_outbound(node, endpoint, VLESS), hy2,
                 {**vless_outbound(node, endpoint, VLESS_FAST_OPEN), "tcp_fast_open": True}]
    if rate := node.get("vless_udp_rate"):
        outbounds.extend([{**hy2, **rate, "tag": HY2_RATE},
                          {**vless_outbound(node, endpoint, VLESS_UDP), "detour": HY2_RATE}])
    return {
        "log": {"level": "warn"},
        "dns": {"servers": [{"type": "local", "tag": "local"}]},
        "inbounds": [{"type": "mixed", "tag": "local-in", "listen": "127.0.0.1", "listen_port": 7890}],
        "outbounds": outbounds,
        "route": {"default_domain_resolver": "local", "final": VLESS},
    }


def clash_config(node):
    validate_node(node)
    # JSON quoted strings are valid YAML scalars; never interpolate raw user text.
    q = lambda value: json.dumps(value, ensure_ascii=False)
    endpoint = q(node.get("endpoint_ip", node["domain"]))
    obfs = ('    obfs: salamander\n    obfs-password: ' + q(node["obfs_password"]) + '\n'
            if node.get("obfs") == "salamander" else '')

    def vless_proxy(name, options=""):
        return f'''  - name: "{name}"
    type: vless
    server: {endpoint}
    port: 443
    uuid: {q(node["uuid"])}
    network: tcp
{options}    udp: true
    packet-encoding: xudp
    tls: true
    servername: addons.mozilla.org
    client-fingerprint: chrome
    reality-opts:
      public-key: {q(node["reality_public"])}
      short-id: {q(node["short_id"])}
    flow: xtls-rprx-vision
'''

    def hy2_proxy(name, options=""):
        return f'''  - name: "{name}"
    type: hysteria2
    server: {endpoint}
    port: 443
    password: {q(node["password"])}
{options}{obfs}    sni: {q(node["domain"])}
    skip-cert-verify: false
'''

    def fallback(name, primary, secondary):
        return f'''  - name: {q(name)}
    type: fallback
    proxies: [{q(primary)}, {q(secondary)}]
    url: https://www.gstatic.com/generate_204
    expected-status: 204
    interval: 120
    timeout: 5000
    max-failed-times: 2
    lazy: true
'''

    proxies = vless_proxy(VLESS) + hy2_proxy(HYSTERIA2) + vless_proxy(VLESS_FAST_OPEN, "    tfo: true\n")
    choices = [AUTO, VLESS, VLESS_FAST_OPEN, HYSTERIA2]
    groups = fallback(AUTO, VLESS, HYSTERIA2)
    if rate := node.get("vless_udp_rate"):
        proxies += hy2_proxy(HY2_RATE, f'    up: {rate["up_mbps"]}\n    down: {rate["down_mbps"]}\n')
        proxies += vless_proxy(VLESS_UDP, f"    dialer-proxy: {q(HY2_RATE)}\n")
        choices.insert(1, VLESS_HIGH_LOSS)
        groups += fallback(VLESS_HIGH_LOSS, VLESS_UDP, VLESS)
    return f'''# ArgoSBX-HY2 — Mihomo; local mixed proxy at 127.0.0.1:7890
mixed-port: 7890
allow-lan: false
bind-address: 127.0.0.1
mode: rule
log-level: warning
ipv6: false
dns:
  enable: true
  listen: 127.0.0.1:1053
  ipv6: false
  enhanced-mode: redir-host
  respect-rules: true
  default-nameserver: [223.5.5.5, 119.29.29.29]
  proxy-server-nameserver: [https://dns.alidns.com/dns-query, https://doh.pub/dns-query]
  nameserver: [https://1.1.1.1/dns-query, https://8.8.8.8/dns-query]
proxies:
{proxies}proxy-groups:
  - name: PROXY
    type: select
    proxies: {q(choices)}
{groups}rules:
  - MATCH,PROXY
'''


def format_page(node):
    # No extra subscription URLs: the same address serves both supported apps.
    return '''<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>私人订阅</title>
<body><h1>私人订阅</h1><p>请将当前地址直接粘贴到 Clash Verge Rev 或 Shadowrocket 的订阅导入框。</p>
<p>两个客户端使用同一个地址，服务器自动返回对应格式。请保留客户端默认 User-Agent。</p>
<p>这是私人订阅，请勿分享地址。</p></body></html>'''


def exports(node):
    validate_node(node)
    return {"clash.yaml": clash_config(node),
            "shadowrocket.txt": base64.b64encode((vless_uri(node) + "\n" + uri(node) + "\n").encode()).decode() + "\n",
            "singbox.json": json.dumps(client_config(node), ensure_ascii=False, indent=2) + "\n",
            "index.html": format_page(node)}


def caddy_config(node, root=ROOT, ua_rules=None):
    """One URL, explicit format overrides, custom UA overrides, built-in app UAs."""
    validate_node(node)
    path = f'/s/{node["token"]}'
    routes = []
    # Explicit unknown format must never fall back to an inferred client format.
    for fmt, filename, mime in [
        ("clash", "clash.yaml", "text/yaml; charset=utf-8"),
        ("shadowrocket", "shadowrocket.txt", "text/plain; charset=utf-8"),
        ("singbox", "singbox.json", "application/json; charset=utf-8"),
    ]:
        routes.append(f'''            @fmt_{fmt} query format={fmt}
            handle @fmt_{fmt} {{
                header Content-Type "{mime}"
                rewrite * /{filename}
                file_server
            }}''')
    for i, rule in enumerate(ua_rules or []):
        if rule["format"] not in ("clash", "shadowrocket", "singbox"):
            raise ValueError("未知 UA 格式")
        pattern = rule["pattern"]
        if not re.fullmatch(r"[A-Za-z0-9 ._/*()+-]{1,160}", pattern):
            raise ValueError("UA 模式包含不允许的字符")
        filename, mime = {"clash": ("clash.yaml", "text/yaml"),
                          "shadowrocket": ("shadowrocket.txt", "text/plain"),
                          "singbox": ("singbox.json", "application/json")}[rule["format"]]
        routes.append(f'''            @ua_{i} {{
                not query format=*
                header User-Agent "{pattern}"
            }}
            handle @ua_{i} {{
                header Content-Type "{mime}; charset=utf-8"
                rewrite * /{filename}
                file_server
            }}''')
    # Clash Verge Rev defaults to clash-verge/vVERSION (upstream network.rs).
    # Shadowrocket uses its product prefix; match case-insensitively and anchor
    # the product boundary so browser strings containing the name cannot match.
    for name, pattern, filename, mime in [
        ("clash", r"(?i)^(clash-verge|clash[.]meta|clash|mihomo)([/ ]|$)", "clash.yaml", "text/yaml"),
        ("shadowrocket", r"(?i)^shadowrocket([/ ]|$)", "shadowrocket.txt", "text/plain"),
    ]:
        routes.append(f'''            @app_{name} {{
                not query format=*
                header_regexp User-Agent "{pattern}"
            }}
            handle @app_{name} {{
                header Content-Type "{mime}; charset=utf-8"
                rewrite * /{filename}
                file_server
            }}''')
    return f'''{{
    admin off
    persist_config off
    auto_https off
    servers {{
        protocols h1 h2
        max_header_size 32KB
        timeouts {{
            read_header 10s
            read_body 15s
            write 30s
            idle 2m
        }}
    }}
}}
https://{node["domain"]}:8443 {{
    bind 0.0.0.0
    tls {root}/tls/fullchain.pem {root}/tls/key.pem
    header {{
        -Server
        -Alt-Svc
        X-Content-Type-Options nosniff
        Referrer-Policy no-referrer
    }}
    @subscription {{
        method GET HEAD
        path_regexp ^{path}$
    }}
    route {{
        handle @subscription {{
            header {{
                Cache-Control "private, no-store"
                >Vary "User-Agent, Accept-Encoding"
                X-Robots-Tag "noindex, nofollow"
                Content-Disposition "attachment; filename=ArgoSBX-HY2"
                Profile-Update-Interval "24"
            }}
            root * {root}/exports
{chr(10).join(routes)}
            handle {{
                header Content-Type "text/html; charset=utf-8"
                rewrite * /index.html
                file_server
            }}
        }}
        handle /s/* {{
            respond 404
        }}
        handle {{
            root * /var/lib/argosbx-hy2/public
            file_server
        }}
    }}
}}
'''


PUBLIC_PAGE = '''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome</title><body><h1>Welcome</h1><p>This site is online.</p></body></html>'''
