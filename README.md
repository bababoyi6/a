# AAA 个人代理节点

在 Debian 13 VPS 上一次安装 VLESS REALITY Vision 与 Hysteria2，自动管理证书，并生成私人 HTTPS 订阅。

## 准备

- VPS：Debian 13，amd64 或 arm64，完整 systemd，公网 IPv4。
- 将自己的子域名（如 `node.example.com`）设置一条指向 VPS 公网 IPv4 的 A 记录。Cloudflare 用户请使用 **DNS Only（灰云）**。
- 确保 TCP 80、TCP 443、UDP 443、TCP 8443 未被其他服务占用，并在云厂商安全组中放行。TCP 80 用于首次签发和日后续期。
- 终端需已有 `curl` 和系统 CA 证书。

## 安装

先查看 [v0.3.0 发布说明](https://github.com/bababoyi6/a/releases/tag/v0.3.0) 的支持范围和验证状态。在符合要求的 VPS 上，下载固定版本的安装器再运行：

```bash
curl -fsSLo quick.sh https://github.com/bababoyi6/a/releases/download/v0.3.0/quick.sh && bash quick.sh
```

安装器会校验发行包的 SHA-256 和包内清单。也可以把审查过的完整源码传到 VPS，在源码目录执行：

```bash
sudo bash install.sh
```

只需输入一次域名，脚本自动生成 UUID、REALITY 密钥、HY2 密码和订阅 Token。安装成功后显示：

```text
私人订阅（Clash Verge Rev / Shadowrocket 使用同一个链接，请勿分享）：
https://node.example.com:8443/s/<随机Token>
<终端二维码>
```

将同一个链接粘贴到 Clash Verge Rev 或 Shadowrocket 的订阅导入框。v0.3.0 统一显示为 `VLESS`（TCP 443，主用）和 `Hysteria2`（UDP 443，备用）；Clash 保留手动 `PROXY`，没有自动换线。sing-box 可加 `?format=singbox`，默认出口为 VLESS。在 SSH 终端输入 `aaa` 可重新显示链接及二维码。

## 日常维护

```bash
sudo argosbx status          # 查看服务、证书、APT、BBR/FQ 和 UDP 缓冲实际值
sudo argosbx health          # 本机健康检查
sudo argosbx renew           # 手动触发证书检查
sudo argosbx repair          # 必要时修复本项目服务
sudo argosbx uninstall       # 卸载服务并恢复项目管理的网络改动
```

v0.3.0 的维护策略：

- systemd 对进程失败按 5 秒延迟重试，保留 300 秒内最多 8 次启动的限制。健康任务每分钟查进程、监听、证书和自有防火墙；每约 5 分钟分别探测两种协议。`EXTERNAL_UNKNOWN` 表示不能确认转发，不会仅为外网故障重启服务。
- 同一故障连查两次后才自愈；失败按 2、5、10、20、30 分钟退避，滚动 24 小时内最多 8 次健康任务发起的重启或规则重建。额度耗尽仍继续检查，不重启 VPS。
- 证书正常时每日检查；到期前 30 天进入续期窗口，失败约 1 小时后开始退避，最多每天重试一次；余期不足 14 天告警。只有通过 CA 链、SAN、私钥匹配和有效期校验的证书才会部署。TCP 80 被安全组封锁时需到云控制台放行。
- 保留 BBR/FQ；在宿主机允许时将低于 7,500,000 字节的 UDP 读写缓冲上限提高至该值，首次值更高时不降低。卸载仅回滚 AAA 改动且仍未被覆盖的值。
- 禁用 Debian APT 的三项周期任务，不自动升级 Debian、sing-box、Caddy、lego 或内核。其他供应商的运维工具不受 AAA 控制；APT 策略被覆盖时会报告，不覆盖管理员文件。
- `install --obfs salamander` 仅用于显式启用，默认不启用；已安装后通过 `argosbx obfs` 切换。只支持 `--challenge http`，拒绝 `--name`、`--token-file`。
- `argosbx rotate token` 只换订阅 URL；`rotate password` 只换 Hysteria2 密码及已启用的混淆密码；`rotate both` 同时撤销两协议旧凭据并更换 Token。普通版本回滚不能恢复已撤销凭据。

## v0.3.0 升级与发布

已安装 v0.2.0 双协议节点的用户，可在校验 v0.3.0 包外 SHA-256 与包内 `MANIFEST.sha256` 后，从解包目录运行 `sudo bash install.sh`。无需传域名、重装服务或重新导入订阅；原 URL、Token、UUID、REALITY 密钥及 HY2 凭据不变。旧的单协议 HY2 安装不自动迁移。

维护者可运行 `python3 tools/make_release.py --repo OWNER/REPO` 生成发布包、SHA-256 和 `dist/quick.sh`，将 `OWNER/REPO` 换成当前仓库全名。正式上传并重新下载哈希校验后，才用生成的脚本启用公开安装入口。

Debian 13 CI 检查配置、订阅及隔离的真实协议行为，不代表生产 VPS 已通过验收。公网 UDP、真实证书签发、实际客户端、跨境吞吐和长期运行需单独验证。
