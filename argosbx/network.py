"""Conservative BBR and fq management for Debian 13 default egress devices."""
import json
from pathlib import Path
import re

MARKER = "# Managed by ArgoSBX-HY2\n"
SYSCTL = Path("/etc/sysctl.d/90-argosbx-hy2.conf")
KEY = "net.ipv4.tcp_congestion_control"
UDP_KEYS = ("net.core.rmem_max", "net.core.wmem_max")
UDP_MIN = 7_500_000


def load(path, default):
    return json.loads(path.read_text()) if path.exists() else default


def interfaces(run):
    devices = set()
    for family in ("-4", "-6"):
        for route in json.loads(run(["ip", "-j", family, "route", "show", "default"]).stdout):
            for item in [route, *route.get("nexthops", [])]:
                if item.get("dev"):
                    devices.add(item["dev"])
    if not devices or any(not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", d) or d == "lo" for d in devices):
        raise ValueError("无法确定默认出口网卡；FQ 未配置")
    return sorted(devices)


def queues(run, device):
    data = json.loads(run(["tc", "-j", "qdisc", "show", "dev", device]).stdout)
    roots = [q for q in data if q.get("root")]
    if len(roots) != 1:
        raise ValueError("出口网卡队列层级不明确，未修改")
    root = roots[0]
    if root["kind"] == "mq":
        major = root.get("handle", "").split(":")[0]
        leaves = [q for q in data if q.get("parent", "").split(":")[0] == major]
        if not leaves or len(data) != len(leaves) + 1:
            raise ValueError("多队列网卡含自定义层级，未修改")
        return leaves
    if len(data) != 1:
        raise ValueError("出口网卡含自定义层级，未修改")
    return roots


def position(queue):
    return ["root"] if queue.get("root") else ["parent", queue["parent"]]


def restore_options(queue):
    opts = queue.get("options", {})
    if queue["kind"] != "fq_codel" or set(opts) - {"limit", "flows", "quantum", "target", "interval", "memory_limit", "ecn", "drop_batch"}:
        raise ValueError("发现自定义队列参数，未覆盖")
    result = []
    for key, value in opts.items():
        if key == "ecn":
            result.append("ecn" if value else "noecn")
        else:
            value = str(value)
            if key in ("target", "interval") and value.isdigit():
                value += "us"
            result.extend([key, value])
    return result


def replace(run, device, queue, kind, options=()):
    run(["tc", "qdisc", "replace", "dev", device, *position(queue), kind, *options])


def check(run):
    congestion = run(["sysctl", "-n", KEY]).stdout.strip()
    devices = {}
    try:
        for device in interfaces(run):
            devices[device] = [q["kind"] for q in queues(run, device)]
    except ValueError as exc:
        return {"congestion": congestion, "qdisc": devices, "fq": False, "note": str(exc)}
    return {"congestion": congestion, "qdisc": devices,
            "fq": bool(devices) and all(all(k == "fq" for k in kinds) for kinds in devices.values())}


def buffer_value(run, key):
    result = run(["sysctl", "-n", key], check=False)
    value = result.stdout.strip()
    return int(value) if result.returncode == 0 and value.isdecimal() else None


def enable_udp(etc, run, save, atomic):
    journal = etc / "udp-sysctl.json"
    ownership = load(journal, {})
    values = {}
    for key in UDP_KEYS:
        value = buffer_value(run, key)
        record = ownership.get(key)
        if record and value is not None and value != record["after"] and not record.get("pending"):
            record["released"] = True
        if record and record.get("pending") and value == record["after"]:
            record.pop("pending")
        if value is not None and value < UDP_MIN and (not record or
                (record.get("pending") and value == record["before"])):
            ownership[key] = {"before": value, "after": UDP_MIN, "pending": True}
            save(journal, ownership)
            run(["sysctl", "-w", f"{key}={UDP_MIN}"], check=False)
            value = buffer_value(run, key)
            if value == UDP_MIN:
                ownership[key].pop("pending")
            elif value is not None:
                ownership.pop(key)
        elif record and record.get("pending") and value is not None:
            record.pop("pending")
            record["released"] = True
        values[key] = value
    if ownership or journal.exists():
        save(journal, ownership)
    existing = SYSCTL.read_text() if SYSCTL.exists() else MARKER
    lines = [line for line in existing.splitlines(keepends=True)
             if line.split("=", 1)[0].strip() not in UDP_KEYS]
    lines.extend(f'{key} = {record["after"]}\n' for key, record in ownership.items()
                 if not record.get("pending") and not record.get("released"))
    content = "".join(lines)
    if content != existing:
        atomic(SYSCTL, content, 0o644)
    return values


def enable(etc, run, save, atomic):
    owned, qstate = etc / "sysctl.json", etc / "qdisc.json"
    if SYSCTL.is_symlink() or (SYSCTL.exists() and not SYSCTL.read_text().startswith(MARKER)):
        raise ValueError("发现未知同名 sysctl 文件，拒绝覆盖")
    available = run(["sysctl", "-n", "net.ipv4.tcp_available_congestion_control"]).stdout.split()
    if "bbr" not in available:
        run(["modprobe", "tcp_bbr"], check=False)
        available = run(["sysctl", "-n", "net.ipv4.tcp_available_congestion_control"]).stdout.split()
    if "bbr" not in available:
        raise ValueError("内核不支持 BBR；无法达到完整性能目标")
    before = run(["sysctl", "-n", KEY]).stdout.strip()
    record = load(owned, {})
    if before != "bbr":
        if not record:
            record = {"before": before, "after": "bbr"}
            save(owned, record)
        existing = SYSCTL.read_text() if SYSCTL.exists() else MARKER
        lines = [line for line in existing.splitlines(keepends=True) if line.split("=", 1)[0].strip() != KEY]
        atomic(SYSCTL, "".join(lines) + KEY + " = bbr\n", 0o644)
        run(["sysctl", "-w", KEY + "=bbr"])
    if run(["sysctl", "-n", KEY]).stdout.strip() != "bbr":
        raise ValueError("BBR 未实际启用")
    udp = enable_udp(etc, run, save, atomic)
    records = load(qstate, [])
    known = {(r["device"], tuple(position(r["before"]))) for r in records}
    notes = []
    try:
        devices = interfaces(run)
    except ValueError as exc:
        result = check(run)
        result["note"] = str(exc)
        result["udp_buffers"] = udp
        result["udp_buffers_ok"] = all(value is not None and value >= UDP_MIN for value in udp.values())
        return result
    for device in devices:
        try:
            for queue in queues(run, device):
                if queue["kind"] == "fq":
                    continue
                if queue["kind"] != "fq_codel":
                    notes.append(device + ": 现有 " + queue["kind"] + "，未覆盖")
                    continue
                restore_options(queue)
                identity = (device, tuple(position(queue)))
                if identity not in known:
                    records.append({"device": device, "before": queue})
                    save(qstate, records)
                    known.add(identity)
                replace(run, device, queue, "fq")
        except (ValueError, RuntimeError) as exc:
            notes.append(device + ": " + str(exc))
    result = check(run)
    result["udp_buffers"] = udp
    result["udp_buffers_ok"] = all(value is not None and value >= UDP_MIN for value in udp.values())
    result["note"] = "; ".join(notes) if notes else result.get("note", "")
    return result


def undo(etc, run, pending=False):
    qstate, owned = etc / "qdisc.json", etc / "sysctl.json"
    records = load(qstate, [])
    remaining = []
    for record in reversed(records):
        try:
            current = next((q for q in queues(run, record["device"])
                            if position(q) == position(record["before"])), None)
            if current and current["kind"] == "fq":
                replace(run, record["device"], record["before"], "fq_codel", restore_options(record["before"]))
        except (ValueError, RuntimeError):
            remaining.append(record)
    if remaining:
        raise ValueError("部分 FQ 队列未能安全恢复；已保留恢复记录，请检查网卡状态后重试卸载")
    else:
        qstate.unlink(missing_ok=True)
    record = load(owned, {})
    if record and run(["sysctl", "-n", KEY], check=False).stdout.strip() == record["after"]:
        run(["sysctl", "-w", KEY + "=" + record["before"]])
    udp_journal = etc / "udp-sysctl.json"
    udp = load(udp_journal, {})
    for key in UDP_KEYS:
        record = udp.get(key)
        if not record or record.get("released"):
            continue
        value = buffer_value(run, key)
        if value == record["after"]:
            run(["sysctl", "-w", f'{key}={record["before"]}'])
            if buffer_value(run, key) != record["before"]:
                raise ValueError(f"{key} 未能安全恢复；已保留恢复记录")
        elif value is None and not record.get("pending"):
            raise ValueError(f"无法读取 {key}；已保留恢复记录")
    if SYSCTL.exists() and not SYSCTL.is_symlink() and SYSCTL.read_text().startswith(MARKER):
        SYSCTL.unlink()
    owned.unlink(missing_ok=True)
    udp_journal.unlink(missing_ok=True)
