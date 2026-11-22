"""Conservative BBR and fq management for Debian 13 default egress devices."""
import json
from pathlib import Path
import re
from statistics import median
import time

MARKER = "# Managed by ArgoSBX-HY2\n"
SYSCTL = Path("/etc/sysctl.d/90-argosbx-hy2.conf")
KEY = "net.ipv4.tcp_congestion_control"
UDP_KEYS = ("net.core.rmem_max", "net.core.wmem_max")
UDP_MIN = 7_500_000
TCP_WMEM = "net.ipv4.tcp_wmem"
TCP_MTU = "net.ipv4.tcp_mtu_probing"
TCP_FASTOPEN = "net.ipv4.tcp_fastopen"
TCP_KEYS = (TCP_WMEM, TCP_MTU, TCP_FASTOPEN)
TCP_WMEM_MIN = 16 * 1024**2
TRAFFIC_COUNTERS = ("TcpOutSegs", "TcpRetransSegs", "TcpExtTCPTimeouts",
                    "UdpInDatagrams", "UdpInErrors", "UdpRcvbufErrors", "UdpSndbufErrors")


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


def tcp_value(run, key):
    if key != TCP_WMEM:
        return buffer_value(run, key)
    result = run(["sysctl", "-n", key], check=False)
    values = result.stdout.split()
    if result.returncode != 0 or len(values) != 3 or not all(value.isdecimal() for value in values):
        return None
    return " ".join(values)


def tcp_send_target(value):
    minimum, default, ceiling = map(int, value.split())
    return f"{minimum} {default} {max(ceiling, TCP_WMEM_MIN)}"


def tcp_mtu_target(value):
    return max(value, 1)


def tcp_fastopen_target(value):
    # Enable the listener flag while retaining the client's and administrator's bits.
    return value | 2


def traffic_snapshot(run, devices):
    # -s keeps nstat from updating the system's history file.
    counters = {}
    for row in run(["nstat", "-asz", *TRAFFIC_COUNTERS], timeout=5).stdout.splitlines():
        fields = row.split()
        if len(fields) >= 2 and fields[0] in TRAFFIC_COUNTERS:
            counters[fields[0]] = int(fields[1])
    links = {}
    for device in devices:
        link, = json.loads(run(["ip", "-j", "-s", "link", "show", "dev", device], timeout=5).stdout)
        stats = link.get("stats64", link.get("stats", {}))
        queues = json.loads(run(["tc", "-j", "-s", "qdisc", "show", "dev", device], timeout=5).stdout)
        root = next((queue for queue in queues if queue.get("root")), {})
        links[device] = {"rx_bytes": stats.get("rx", {}).get("bytes"),
                         "tx_bytes": stats.get("tx", {}).get("bytes"),
                         "rx_dropped": stats.get("rx", {}).get("dropped"),
                         "tx_dropped": stats.get("tx", {}).get("dropped"),
                         "root_qdisc_dropped": root.get("drops")}
    with Path("/proc/stat").open() as stats:
        cpu = [int(value) for value in stats.readline().split()[1:9]]
    return counters, links, cpu


def counter_delta(before, after):
    if before is None or after is None or after < before:
        return None
    return after - before


def diagnostics(run, seconds):
    devices = interfaces(run)
    initial_time = time.monotonic()
    old_counters, old_links, old_cpu = traffic_snapshot(run, devices)
    time.sleep(seconds)
    counters, links, cpu = traffic_snapshot(run, devices)
    elapsed = time.monotonic() - initial_time
    cpu_ticks = [new - old for old, new in zip(old_cpu, cpu)]
    total = sum(cpu_ticks)
    valid_cpu = len(cpu_ticks) == 8 and total > 0 and min(cpu_ticks) >= 0
    tcp = run(["ss", "-Htin", "state", "established", "( sport = :443 )"], timeout=5).stdout
    rtt = [float(value) for value in re.findall(r"\brtt:([\d.]+)/", tcp)]
    return {
        "seconds": round(elapsed, 2),
        "host_busy_percent": round(100 * (total - sum(cpu_ticks[3:5]) - cpu_ticks[7]) / total, 2) if valid_cpu else None,
        "host_steal_percent": round(100 * cpu_ticks[7] / total, 2) if valid_cpu else None,
        "host_transport_deltas": {key: counter_delta(old_counters.get(key), counters.get(key))
                                  for key in TRAFFIC_COUNTERS},
        "interface_deltas": {device: {key: counter_delta(old_links[device][key], value)
                                      for key, value in stats.items()} for device, stats in links.items()},
        "tcp_443_rtt_samples": len(rtt),
        "tcp_443_rtt_median_ms": median(rtt) if rtt else None,
        "network": check(run),
        "udp_buffer_limits": {key: buffer_value(run, key) for key in UDP_KEYS},
        "tcp_settings": {key: tcp_value(run, key) for key in TCP_KEYS},
    }


def tune_sysctls(journal, targets, read, run, save, atomic):
    ownership = load(journal, {})
    values = {}
    for key, adjust in targets.items():
        value = read(run, key)
        target = adjust(value) if value is not None else None
        record = ownership.get(key)
        if record and value is not None and value != record["after"] and not record.get("pending"):
            record["released"] = True
        if record and record.get("pending") and value == record["after"]:
            record.pop("pending")
        if value is not None and value != target and (not record or
                (record.get("pending") and value == record["before"])):
            ownership[key] = {"before": value, "after": target, "pending": True}
            save(journal, ownership)
            run(["sysctl", "-w", f"{key}={target}"], check=False)
            value = read(run, key)
            if value == target:
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
    lines = existing.splitlines(keepends=True)
    managed = [line for line in lines if line.split("=", 1)[0].strip() in targets]
    desired = [f'{key} = {record["after"]}\n' for key, record in ownership.items()
               if key in targets and not record.get("pending") and not record.get("released")]
    if managed != desired:
        unmanaged = [line for line in lines if line.split("=", 1)[0].strip() not in targets]
        atomic(SYSCTL, "".join(unmanaged + desired), 0o644)
    return values


def enable_udp(etc, run, save, atomic):
    def udp_target(value):
        return max(value, UDP_MIN)

    return tune_sysctls(etc / "udp-sysctl.json", dict.fromkeys(UDP_KEYS, udp_target),
                        buffer_value, run, save, atomic)


def enable_tcp(etc, run, save, atomic):
    targets = {TCP_WMEM: tcp_send_target, TCP_MTU: tcp_mtu_target, TCP_FASTOPEN: tcp_fastopen_target}
    return tune_sysctls(etc / "tcp-sysctl.json", targets, tcp_value, run, save, atomic)


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
    tcp = enable_tcp(etc, run, save, atomic)
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
        result["tcp_settings"] = tcp
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
    result["tcp_settings"] = tcp
    result["note"] = "; ".join(notes) if notes else result.get("note", "")
    return result


def restore_sysctls(journal, keys, read, run):
    records = load(journal, {})
    for key in keys:
        record = records.get(key)
        if not record or record.get("released"):
            continue
        value = read(run, key)
        if value == record["after"]:
            run(["sysctl", "-w", f'{key}={record["before"]}'])
            if read(run, key) != record["before"]:
                raise ValueError(f"{key} 未能安全恢复；已保留恢复记录")
        elif value is None and not record.get("pending"):
            raise ValueError(f"无法读取 {key}；已保留恢复记录")


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
    tcp_journal = etc / "tcp-sysctl.json"
    restore_sysctls(udp_journal, UDP_KEYS, buffer_value, run)
    restore_sysctls(tcp_journal, TCP_KEYS, tcp_value, run)
    if SYSCTL.exists() and not SYSCTL.is_symlink() and SYSCTL.read_text().startswith(MARKER):
        SYSCTL.unlink()
    owned.unlink(missing_ok=True)
    udp_journal.unlink(missing_ok=True)
    tcp_journal.unlink(missing_ok=True)
