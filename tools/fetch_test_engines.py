"""Download locked official Linux validation tools; never run remote installers."""
import argparse
import gzip
import json
from pathlib import Path
import platform
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from argosbx import releases


def fetch(output, arch):
    root = Path(__file__).resolve().parent.parent
    lock = json.loads((root / "dependencies.lock.json").read_text())
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    cache = output / "cache"
    for name in ("sing-box", "caddy", "lego"):
        releases.install_binary(lock["dependencies"][name]["assets"][arch], name, output / name, cache)
        print("Verified:", name, lock["dependencies"][name]["version"])
    spec = lock["validation"]["mihomo"]["assets"][arch]
    asset = cache / (spec["sha256"] + ".gz")
    if not asset.exists() or releases.sha256(asset) != spec["sha256"]:
        releases.fetch(spec["url"], asset)
    if releases.sha256(asset) != spec["sha256"]:
        raise releases.ReleaseError("Mihomo checksum mismatch")
    with gzip.open(asset, "rb") as src, (output / "mihomo").open("wb") as dst:
        shutil.copyfileobj(src, dst)
    (output / "mihomo").chmod(0o755)
    print("Verified: mihomo", lock["validation"]["mihomo"]["version"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=".research/bin")
    parser.add_argument("--arch", choices=["amd64", "arm64"],
                        default={"x86_64": "amd64", "AMD64": "amd64", "aarch64": "arm64"}.get(platform.machine()))
    args = parser.parse_args()
    if not args.arch:
        parser.error("Specify --arch amd64 or arm64")
    fetch(args.output, args.arch)
