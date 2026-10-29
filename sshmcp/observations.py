"""Bounded parsers and explicit heuristic findings, never remote instructions."""

from copy import deepcopy
import math
import re

from .catalog import TITLES

LEVELS = {"critical": 0, "warning": 1, "info": 2}


def number(value):
    try:
        n = float(value)
        return n if math.isfinite(n) else None
    except (TypeError, ValueError):
        return None


def metric(
    summary,
    findings,
    key,
    value,
    unit="",
    threshold=None,
    above=True,
    hint="进一步核查业务与历史监控",
    critical=None,
):
    if value is None:
        return
    level = "info"
    if threshold is not None and (value >= threshold if above else value <= threshold):
        level = (
            "critical"
            if critical is not None
            and (value >= critical if above else value <= critical)
            else "warning"
        )
        findings.append(
            {
                "level": level,
                "metric": key,
                "value": value,
                "threshold": threshold,
                "hint": hint,
            }
        )
    summary["metrics"].append(
        {
            "metric": key,
            "value": round(value, 3),
            "unit": unit,
            "threshold": threshold,
            "level": level,
        }
    )


# Zabbix "Linux by Zabbix agent" default {$LOAD_AVG_PER_CPU.MAX.WARN}; keeping the
# same line means an active load alert is not reported back as "info".
LOAD_PER_CORE_WARN = 1.5
VMSTAT_FIELDS = {
    "r": "vmstat_runnable",
    "b": "vmstat_blocked",
    "us": "cpu_user_percent",
    "sy": "cpu_system_percent",
    "id": "cpu_idle_percent",
    "wa": "cpu_iowait_percent",
    "st": "cpu_steal_percent",
}


def vmstat_sample(text):
    """Last `vmstat 1 2` row (a 1 s sample, not since-boot averages) by column name."""
    lines = text.splitlines()
    for index in range(len(lines) - 1, -1, -1):
        names = lines[index].split()
        if names[:2] == ["r", "b"] and "id" in names:
            rows = [
                line.split()
                for line in lines[index + 1 :]
                if len(line.split()) == len(names)
                and all(number(v) is not None for v in line.split())
            ]
            return dict(zip(names, map(number, rows[-1]))) if rows else {}
    return {}


def cpu(text, summary, findings):
    m = re.search(r"(?m)^(\d+\.\d+)\s+(\d+\.\d+)\s+(\d+\.\d+)\s+\d+/\d+\s+\d+", text)
    cores = len(re.findall(r"(?m)^cpu\d+\s", text))
    n = re.search(r"(?m)^CPU_COUNT=(\d+)$", text)
    cores = int(n[1]) if n else cores
    per_core = None
    if m:
        metric(summary, findings, "load_1m", float(m[1]))
        metric(summary, findings, "load_5m", float(m[2]))
        metric(summary, findings, "load_15m", float(m[3]))
        if cores:
            per_core = float(m[1]) / cores
            metric(summary, findings, "cpu_cores", cores)
            metric(
                summary,
                findings,
                "load_per_core",
                per_core,
                threshold=LOAD_PER_CORE_WARN,
                critical=4,
                hint="负载包含等待 I/O 的任务；结合 PSI、vmstat 与进程排行核查",
            )
            metric(summary, findings, "load_per_core_5m", float(m[2]) / cores)
    for key in ("procs_running", "procs_blocked"):
        found = re.search(r"(?m)^" + key + r"\s+(\d+)$", text)
        if found:
            metric(
                summary,
                findings,
                key,
                int(found[1]),
                threshold=1 if key == "procs_blocked" else None,
                hint="存在不可中断等待（D 状态）任务；负载升高可能来自 I/O 或内核等待，结合 PSI 与进程状态核查",
            )
    sample = vmstat_sample(text)
    for column, key in VMSTAT_FIELDS.items():
        if column in sample:
            metric(
                summary, findings, key, sample[column], "%" if "percent" in key else ""
            )
    idle = sample.get("id")
    if per_core is not None and idle is not None and per_core >= LOAD_PER_CORE_WARN:
        if idle >= 50:
            findings.append(
                {
                    "level": "warning",
                    "metric": "load_cpu_divergence",
                    "value": {
                        "load_per_core": round(per_core, 3),
                        "cpu_idle_percent": idle,
                    },
                    "threshold": {
                        "load_per_core": LOAD_PER_CORE_WARN,
                        "cpu_idle_percent": 50,
                    },
                    "hint": "负载偏高但 CPU 空闲较多：负载可能来自 D 状态（不可中断等待）任务或宿主机 CPU 争抢，而非计算繁忙。"
                    "核查 procs_blocked、PSI 与 D 状态进程；VMware 等虚拟机通常不上报 steal，需在虚拟化平台查看 CPU Ready",
                }
            )


def memory(text, summary, findings):
    values = {
        k: int(v)
        for k, v in re.findall(
            r"(?m)^(MemTotal|MemAvailable|SwapTotal|SwapFree):\s+(\d+)\s+kB", text
        )
    }
    for k, v in values.items():
        metric(summary, findings, k + "_KiB", v, "KiB")
    if values.get("MemTotal") and "MemAvailable" in values:
        metric(
            summary,
            findings,
            "memory_available_percent",
            values["MemAvailable"] * 100 / values["MemTotal"],
            "%",
            10,
            False,
            "可用内存偏低，结合 RSS、PSI 与 OOM 日志确认；缓存占用不等同于内存不足",
            critical=5,
        )
    if values.get("SwapTotal") and "SwapFree" in values:
        used = max(0, values["SwapTotal"] - values["SwapFree"])
        metric(
            summary,
            findings,
            "swap_used_KiB",
            used,
            "KiB",
            1,
            hint="存在 Swap 占用不一定代表当前抖动，结合 vmstat si/so 与内存压力确认",
        )


def disk(text, summary, findings):
    inode = False
    rows = []
    for line in text.splitlines():
        if line.startswith("Filesystem"):
            inode = "IUse%" in line or "Inodes" in line
            continue
        fields = line.split()
        if (
            len(fields) >= 6
            and re.fullmatch(r"\d+%", fields[4])
            and fields[0].startswith(("/", "tmpfs", "overlay"))
        ):
            key = ("inode:" if inode else "disk:") + fields[5]
            metric(
                summary,
                findings,
                key,
                int(fields[4][:-1]),
                "%",
                90,
                hint="核查增长来源与保留策略，诊断服务不会自动清理文件",
                critical=98,
            )
            rows.append(
                {
                    "filesystem": fields[0],
                    "mount": fields[5],
                    "kind": "inode" if inode else "capacity",
                    "used_percent": int(fields[4][:-1]),
                }
            )
    summary["filesystems"] = rows[:100]


def pressure(text, summary, findings):
    resource = "unknown"
    for line in text.splitlines():
        m = re.match(r"\[(cpu|memory|io) PSI\]", line)
        if m:
            resource = m[1]
        m = re.match(r"(some|full) avg10=([\d.]+)", line)
        if m:
            metric(
                summary,
                findings,
                f"psi_{resource}_{m[1]}_avg10",
                number(m[2]),
                "%",
                20 if resource == "cpu" else 10,
                hint="PSI 为任务受资源阻塞的时间比例，阈值为经验规则，请结合业务基线",
                critical=50,
            )


def services(text, summary, findings):
    props = dict(re.findall(r"(?m)^(\w+)=(.*)$", text))
    summary["properties"] = {k: v[:160] for k, v in props.items()}
    state = props.get("ActiveState")
    if state and state not in {"active", "reloading", "activating"}:
        findings.append(
            {
                "level": "warning",
                "metric": "service_active_state",
                "value": state,
                "threshold": "active",
                "hint": "确认该服务是否按设计停用；结合 Result 与日志核查",
            }
        )
    failed = [
        l.split()[0].lstrip("●")
        for l in text.splitlines()
        if ".service" in l and ("failed" in l or summary["action"] == "failed_services")
    ]
    metric(
        summary,
        findings,
        "failed_service_count",
        len(failed),
        threshold=1,
        hint="检查失败服务的依赖、退出原因和日志；不自动重启",
    )
    summary["failed_services"] = failed[:60]


def time_sync(text, summary, findings):
    summary["properties"] = dict(
        re.findall(r"(?m)^(Timezone|LocalRTC|NTP|NTPSynchronized)=(.*)$", text)
    )
    if summary["properties"].get("NTPSynchronized") == "no":
        findings.append(
            {
                "level": "warning",
                "metric": "NTPSynchronized",
                "value": "no",
                "threshold": "yes",
                "hint": "核查 NTP 服务与时间源可达性，单次查询不能量化时钟偏差",
            }
        )


def logs(text, summary, findings):
    rows = [
        l
        for l in text.splitlines()
        if l.strip() and not l.startswith(("-- No entries", "AIOPS_GATEWAY"))
    ]
    errors = [
        l
        for l in rows
        if re.search(
            r"(?i)\boom[- ]kill|out of memory|killed process|memory cgroup out of memory",
            l,
        )
    ]
    metric(summary, findings, "observed_log_lines", len(rows))
    metric(
        summary,
        findings,
        "oom_matches",
        len(errors),
        threshold=1,
        critical=1,
        hint="本窗口内发现 OOM 线索；核查 cgroup 限额、内存增长与被终止的进程",
    )
    if summary["action"] in {"kernel", "log_errors"} and rows:
        findings.append(
            {
                "level": "warning",
                "metric": "warning_log_lines",
                "value": len(rows),
                "threshold": 1,
                "hint": "只统计有界窗口中的返回行数；详情中核查具体事件，不等同于故障次数",
            }
        )
    summary["coverage"] = "有界日志窗口；无匹配不能证明历史未发生故障"


def table_rows(text, summary, findings):
    rows = [
        line.split()[:16]
        for line in text.splitlines()
        if line.strip() and not line.startswith("AIOPS_GATEWAY")
    ]
    summary["rows"] = rows[:25]
    metric(summary, findings, "observed_rows", len(rows))
    summary["coverage"] = "当前有界快照；表格字段与可用性取决于目标工具版本"


def io(text, summary, findings):
    header = []
    samples = {}
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0].rstrip(":") == "Device":
            header = fields
        elif header and len(fields) == len(header):
            row = dict(zip(header, fields))
            util = number(row.get("%util"))
            if util is not None:
                samples[fields[0]] = util
    for device, util in samples.items():
        metric(
            summary,
            findings,
            "io_util:" + device,
            util,
            "%",
            90,
            hint="设备繁忙度并非通用饱和度指标；结合 await、PSI 和设备并行度确认",
        )
    if not samples:
        table_rows(text, summary, findings)
        summary["coverage"] = (
            "累计 diskstats 计数或未识别格式；缺少时间差，不能据此判断速率与延迟"
        )


def network(text, summary, findings):
    interfaces = []
    for line in text.splitlines():
        m = re.match(r"\s*([\w.@-]+):\s+(\d+(?:\s+\d+){15})\s*$", line)
        if not m:
            continue
        values = [int(x) for x in m[2].split()]
        interfaces.append(
            {
                "interface": m[1],
                "rx_bytes": values[0],
                "tx_bytes": values[8],
                "rx_errors": values[2],
                "tx_errors": values[10],
                "rx_dropped": values[3],
                "tx_dropped": values[11],
            }
        )
    summary["interfaces"] = interfaces[:50]
    summary["coverage"] = "接口累计计数；需要间隔采样才能判断当前速率与新增丢包"
    if not interfaces:
        table_rows(text, summary, findings)


def security(text, summary, findings):
    match = re.search(r"\[SELinux\]\n([^\n]+)", text)
    summary["selinux"] = match[1] if match else None
    summary["firewall_services"] = dict(
        re.findall(r"(?m)^(firewalld|nftables|ufw):\s*(\S+)", text)
    )
    summary["coverage"] = "服务状态仅表示组件运行情况；不是规则或合规审计"
    metric(
        summary,
        findings,
        "reported_firewall_services",
        len(summary["firewall_services"]),
    )


def tcp(text, summary, findings):
    counts = {
        k: int(v) for k, v in re.findall(r"(?m)^([A-Z][A-Z-]+)\s+(\d+)\s*$", text)
    }
    summary["states"] = counts
    for key, value in counts.items():
        metric(
            summary,
            findings,
            "tcp_" + key,
            value,
            threshold=100 if key == "CLOSE-WAIT" else None,
            hint="CLOSE-WAIT 积压可能是应用未关闭连接，请结合基线核查",
        )


def capabilities(text, summary, findings):
    states = dict(re.findall(r"(?m)^(\w+) (available|unavailable)$", text))
    summary["capabilities"] = states
    metric(
        summary,
        findings,
        "unavailable_commands",
        sum(v == "unavailable" for v in states.values()),
    )
    summary["coverage"] = "命令存在不等于账号有读取权限"


def connection(text, summary, findings):
    m = re.search(r"AIOPS_SSH_OK\n(\d+)\nLinux", text)
    summary["identity"] = {"uid": int(m[1]), "os": "Linux"} if m else None
    if not m:
        findings.append(
            {
                "level": "warning",
                "metric": "ssh_identity",
                "value": "unrecognized",
                "threshold": "AIOPS_SSH_OK + UID + Linux",
                "hint": "未获得预期连接身份信息，不应视为测试通过",
            }
        )


def health(text, summary, findings):
    for parser in (cpu, memory, disk):
        parser(text, summary, findings)


def processes(text, summary, findings):
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].isdigit() and fields[1].isdigit():
            rows.append(
                {
                    "pid": int(fields[0]),
                    "ppid": int(fields[1]),
                    "name": fields[2],
                    "cpu_percent": number(fields[3]),
                    "memory_percent": number(fields[4]),
                    "rss_KiB": number(fields[5]),
                    "elapsed": fields[6],
                    "state": fields[7],
                }
            )
    # Join optional, sanitized APP_IDENTITY records to the matching RSS snapshot.
    # No guessed application labels: comm=java alone does not identify a workload.
    labels = {}
    for match in re.finditer(
        r"(?m)^AIOPS_APP ([0-9]{1,10}) (jar|service) ([A-Za-z0-9_.@-]{1,160})$",
        text,
    ):
        labels[int(match[1])] = (match[3], match[2])
    for row in rows:
        if row["pid"] in labels:
            row["application"], row["identity_source"] = labels[row["pid"]]
    summary["processes"] = rows[:25]
    summary["coverage"] = (
        "进程排行快照；CPU 口径为进程生命周期平均值，多线程进程可超过 100%"
    )
    # Optional sections (A-mode `processes` since v0.5.0); absent on gateway hosts.
    states = {
        m[2]: int(m[1])
        for m in re.finditer(r"(?m)^\s*(\d+) ([A-Za-z])$", section(text, "STATES"))
    }
    if states:
        summary["state_counts"] = states
        metric(
            summary,
            findings,
            "processes_uninterruptible",
            states.get("D", 0),
            threshold=1,
            hint="存在 D 状态（不可中断等待）进程，会计入负载但不占 CPU；查看 wchan 判断在等待磁盘、网络存储还是内核锁",
        )
    blocked = [
        {"pid": int(m[1]), "wchan": m[2], "name": m[3]}
        for m in re.finditer(
            r"(?m)^\s*(\d+) D\S* (\S+) (\S.{0,63})$", section(text, "DSTATE")
        )
    ]
    if blocked:
        summary["uninterruptible"] = blocked[:10]
    interval = [
        {
            "pid": int(m[1]),
            "cpu_percent_1s": float(m[2]),
            "state": m[3],
            "name": m[4],
        }
        for m in re.finditer(
            r"(?m)^AIOPS_DELTA (\d+) (\d+(?:\.\d+)?) (\S+) (\S.{0,63})$", text
        )
    ]
    if states or interval:
        summary["cpu_interval"] = interval[:15]
        summary["coverage"] = (
            "进程排行快照；processes.cpu_percent 为进程生命周期平均值，"
            "cpu_interval 为最近 1 秒的采样增量（多线程可超过 100%），用于判断当前占用"
        )


def section(text, name):
    """Text of a `[AIOPS_<name>]` block up to the next block marker."""
    match = re.search(r"(?ms)^\[AIOPS_" + name + r"\]\n(.*?)(?=^\[AIOPS_|\Z)", text)
    return match[1] if match else ""


def resources(text, summary, findings):
    match = re.search(r"\[系统文件句柄\]\n(\d+)\s+(\d+)\s+(\d+)", text)
    if match and int(match[3]):
        metric(
            summary,
            findings,
            "file_handles_used_percent",
            max(0, int(match[1]) - int(match[2])) * 100 / int(match[3]),
            "%",
            90,
            hint="系统级句柄接近上限；具体进程限制仍需单独核查",
            critical=98,
        )
    summary["shell_limits"] = [l.split() for l in text.splitlines() if l.strip()][:25]
    summary["coverage"] = "系统限制和本次 SSH shell 的限制；不代表业务进程的 RLIMIT"


def mounts(text, summary, findings):
    sections = text.split("[只读文件系统]", 1)
    summary["mounts"] = [
        dict(zip(("target", "filesystem"), line.split()[:2]))
        for line in sections[0].splitlines()
        if len(line.split()) >= 2
    ][:80]
    readonly = (
        [
            dict(zip(("target", "filesystem"), line.split()[:2]))
            for line in sections[1].splitlines()
            if len(line.split()) >= 2
        ]
        if len(sections) == 2
        else []
    )
    summary["readonly_mounts"] = readonly[:80]
    for row in readonly:
        if row["filesystem"] not in {
            "squashfs",
            "iso9660",
            "proc",
            "sysfs",
            "cgroup",
            "cgroup2",
        }:
            findings.append(
                {
                    "level": "info",
                    "metric": "readonly_mount",
                    "value": row["target"],
                    "threshold": "按挂载设计确认",
                    "hint": "观察到只读挂载；可能是有意配置，结合内核错误和预期用途核查",
                }
            )


def devices(text, summary, findings):
    rows = []
    for line in text.splitlines():
        f = line.split()
        if len(f) >= 5 and f[2].isdigit() and f[3] in {"0", "1"}:
            rows.append(
                {
                    "name": f[0],
                    "type": f[1],
                    "size_bytes": int(f[2]),
                    "readonly": f[3] == "1",
                    "rotational": f[4] == "1",
                    "mountpoint": f[5] if len(f) > 5 else None,
                }
            )
    summary["devices"] = rows[:80]


def containers(text, summary, findings):
    rows = []
    for line in text.splitlines():
        f = line.split("\t")
        if len(f) < 4:
            continue
        if summary["action"] == "containers":
            rows.append({"id": f[0], "name": f[1], "image": f[2], "state": f[3]})
            if re.search(r"Exited \([1-9][0-9]*\)|Restarting|Dead", f[3]):
                findings.append(
                    {
                        "level": "warning",
                        "metric": "container_state",
                        "value": f[1] + ": " + f[3],
                        "threshold": "预期运行状态",
                        "hint": "核查容器退出原因和应用日志，停止状态也可能是计划操作",
                    }
                )
        elif len(f) >= 6:
            rows.append(
                {
                    "id": f[0],
                    "name": f[1],
                    "cpu_percent": number(f[2].rstrip("%")),
                    "memory": f[3],
                    "network_io": f[4],
                    "block_io": f[5],
                }
            )
    summary["containers"] = rows[:60]


def system(text, summary, findings):
    cpu(text, summary, findings)
    lines = text.removeprefix("AIOPS_GATEWAY_V1\n").splitlines()
    summary["kernel"] = lines[0] if lines else None
    uptime = re.search(r"(?m)^(\d+\.\d+) (\d+\.\d+)$", text)
    if uptime:
        metric(summary, findings, "uptime_seconds", float(uptime[1]), "s")


PARSERS = {
    "connection": connection,
    "cpu": cpu,
    "memory": memory,
    "disk": disk,
    "health": health,
    "pressure": pressure,
    "service": services,
    "failed_services": services,
    "service_inventory": services,
    "time_sync": time_sync,
    "logs": logs,
    "kernel": logs,
    "log_errors": logs,
    "oom": logs,
    "io": io,
    "network": network,
    "tcp_states": tcp,
    "capabilities": capabilities,
    "security_status": security,
    "system": system,
    "processes": processes,
    "memory_processes": processes,
    "resource_limits": resources,
    "mount_health": mounts,
    "block_devices": devices,
    "containers": containers,
    "container_stats": containers,
}
for _action in (
    "processes",
    "memory_processes",
    "sockets",
    "resource_limits",
    "mount_health",
    "block_devices",
    "timers",
    "containers",
    "container_stats",
    "directory",
    "peer_connections",
    "peer_traffic",
):
    PARSERS.setdefault(_action, table_rows)


def analyze(action, text, *, data=None, status="success", truncated=False):
    summary = {
        "action": action,
        "title": TITLES.get(action, action),
        "metrics": [],
        "coverage": "当前有界快照；规则仅提供排查线索",
    }
    findings = []
    PARSERS[action](text, summary, findings)
    if data is not None:
        summary.pop("rows", None)
        summary["analysis"] = data
    missing = sorted(set(re.findall(r"CAPABILITY_MISSING:([\w-]+)", text)))
    if missing or status != "success" or truncated:
        findings.append(
            {
                "level": "info",
                "metric": "collection_coverage",
                "value": missing or status,
                "threshold": "complete",
                "hint": "采集未完整完成，不能用缺失数据排除故障；查看退出码、截断标记及原始输出",
            }
        )
    summary["assessment"] = (
        "发现排查线索"
        if any(f["level"] != "info" for f in findings)
        else "已采集；未触发已实现规则不代表健康"
    )
    findings.sort(key=lambda f: LEVELS[f["level"]])
    return {"summary": summary, "findings": findings}


def present(value, detail="summary"):
    if detail not in {"summary", "full"}:
        raise ValueError("detail 必须为 summary 或 full")
    value = deepcopy(value)

    def visit(node):
        if isinstance(node, dict):
            if "output" in node:
                if "summary" not in node and node.get("action") in PARSERS:
                    node.update(
                        analyze(
                            node["action"],
                            node["output"],
                            data=node.get("data"),
                            status=node["status"],
                            truncated=node.get("truncated", False),
                        )
                    )
                if detail == "summary":
                    node.pop("output", None)
                    node.pop("stderr", None)
            for v in list(node.values()):
                visit(v)
        elif isinstance(node, list):
            for v in node:
                visit(v)

    visit(value)
    return value
