"""Build a deterministic, source-inclusive release and a hash-pinned install command."""
import argparse
import gzip
import hashlib
import io
from pathlib import Path
import re
import tarfile

ROOT = Path(__file__).resolve().parent.parent


def sources():
    selected = [ROOT / name for name in ("install.sh", "entry.py", "bootstrap.py", "VERSION", "dependencies.lock.json",
                                         "LICENSE", "NOTICE.md")]
    selected += sorted((ROOT / "argosbx").glob("*.py"))
    return sorted(set(selected), key=lambda p: p.relative_to(ROOT).as_posix())


def build(output, repo=None):
    version = (ROOT / "VERSION").read_text().strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("VERSION must be a stable semantic version")
    if repo and not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("Use owner/repository")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    filename = f"argosbx-hy2-v{version}.tar.gz"
    buffer = io.BytesIO()
    manifest = []
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in sources():
            relative = path.relative_to(ROOT).as_posix()
            content = path.read_bytes().replace(b"\r\n", b"\n")
            manifest.append(f"{hashlib.sha256(content).hexdigest()}  {relative}\n")
            item = tarfile.TarInfo("argosbx-hy2/" + relative)
            item.size = len(content)
            item.mode = 0o755 if path.suffix == ".sh" else 0o644
            tar.addfile(item, io.BytesIO(content))
        content = "".join(manifest).encode()
        item = tarfile.TarInfo("argosbx-hy2/MANIFEST.sha256")
        item.size = len(content)
        item.mode = 0o644
        tar.addfile(item, io.BytesIO(content))
    archive = output / filename
    # Stored DEFLATE avoids zlib/zlib-ng compressor differences across build
    # hosts. The small source bundle remains gzip-compatible and byte-reproducible.
    with archive.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=0) as out:
        out.write(buffer.getvalue())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / "SHA256SUMS").write_text(f"{digest}  {filename}\n", encoding="utf-8")
    if repo:
        url = f"https://github.com/{repo}/releases/download/v{version}/{filename}"
        quick = (ROOT / "quick.sh").read_text(encoding="utf-8")
        for name, value in (("archive_url", url), ("archive_sha256", digest)):
            quick, replaced = re.subn(rf"^{name}='[^'\n]+'$", f"{name}='{value}'", quick, flags=re.M)
            if replaced != 1:
                raise ValueError(f"quick.sh must contain one {name} pin")
        (output / "quick.sh").write_bytes(quick.encode("utf-8"))
        # Download the whole fixed archive, authenticate it before extracting/executing.
        # All variables are internal constants or validated repo/version, never secrets.
        command = ("bash -c 'set -euo pipefail; "
                   'as_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }; '
                   'if ! command -v curl >/dev/null || [ ! -s /etc/ssl/certs/ca-certificates.crt ]; then '
                   'as_root apt-get update -qq; '
                   'as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl; fi; '
                   't=$(mktemp -d); '
                   'cleanup() { rm -rf -- "$t"; }; trap cleanup EXIT; '
                   f'curl --proto =https --proto-redir =https --tlsv1.2 -fL --retry 3 '
                   f'--connect-timeout 15 --max-time 300 --retry-max-time 900 "{url}" -o "$t/release.tar.gz"; '
                   f'echo "{digest}  $t/release.tar.gz" | sha256sum -c -; '
                   'tar -xzf "$t/release.tar.gz" -C "$t"; '
                   '(cd "$t/argosbx-hy2" && sha256sum -c MANIFEST.sha256); '
                   'as_root bash "$t/argosbx-hy2/install.sh" "$@"' + "' --")
        (output / "INSTALL.md").write_text(
            f"# AAA v{version}\n\nDebian 13，amd64 / arm64。先设置专用灰云 A 记录并放行 TCP 80/443/8443、UDP 443。\n\n"
            f"```bash\n{command}\n```\n\n"
            "此命令中的 SHA-256 必须来自你信任的发布页面。不要把同时下载的未认证校验文件当作独立信任来源。\n"
            "命令自动补齐 curl 和系统 CA。首次安装只询问域名；也可在命令末尾追加 `--domain 你的域名` 无人值守安装。默认 HTTP-01 无需 API Token。自动启用 BBR，并仅在安全时设置 FQ。成功后输出双协议订阅及本地二维码。\n"
            "此文档为构建产物；仅在该版本附件已发布且 SHA-256 与此处一致后使用远程命令。未发布时请从已审查源码执行 sudo bash install.sh。\n",
            encoding="utf-8")
    return archive, digest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", help="GitHub owner/repository; generates exact INSTALL.md")
    parser.add_argument("--output", default=str(ROOT / "dist"))
    args = parser.parse_args()
    path, digest = build(args.output, args.repo)
    print(f"Built: {path}\nSHA256: {digest}")
    if args.repo:
        print(f"Candidate install entry: {Path(args.output).resolve() / 'quick.sh'}")
        print(f"Install command: {Path(args.output).resolve() / 'INSTALL.md'}")
