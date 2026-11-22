#!/usr/bin/env bash
# Fetch a fixed AAA release over HTTPS and authenticate it before execution.
set -Eeuo pipefail
umask 077
archive_url='https://github.com/bababoyi6/a/releases/download/v0.3.3/argosbx-hy2-v0.3.3.tar.gz'
archive_sha256='ad7d1b0f882d26b904ed0f3c4971b2ff6b117007dc9484fc8f8f11d43e755f86'
if [[ ! "$archive_url" =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/download/ ]] ||
   [[ ! "$archive_sha256" =~ ^[0-9a-f]{64}$ ]]; then
  printf '%s\n' '远程安装入口尚未发布。请从已审查的源码目录运行 sudo bash install.sh。' >&2
  exit 1
fi
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
curl --proto =https --proto-redir =https --tlsv1.2 -fL --retry 3 \
  --connect-timeout 15 --max-time 300 "$archive_url" -o "$tmp/release.tar.gz"
printf '%s  %s\n' "$archive_sha256" "$tmp/release.tar.gz" | sha256sum -c -
tar -xzf "$tmp/release.tar.gz" -C "$tmp"
(cd "$tmp/argosbx-hy2" && sha256sum -c MANIFEST.sha256)
if [[ -t 2 ]]; then
  exec 3</dev/tty
else
  exec 3</dev/null
fi
if [[ $EUID -eq 0 ]]; then
  bash "$tmp/argosbx-hy2/install.sh" "$@" <&3
else
  sudo bash "$tmp/argosbx-hy2/install.sh" "$@" <&3
fi
