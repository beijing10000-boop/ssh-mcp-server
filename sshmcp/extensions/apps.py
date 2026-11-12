"""Java application inventory with the ports each one can be reached on (``java_apps``).

One SSH session answers "which Java applications run here and on which
address:port": the Java processes (name, jar, profiles, owner, unit or
container), the TCP sockets they listen on (``ss -ltnp``), the host ports
Docker publishes for their containers, and the host's own IPv4 addresses.
It is the light, batchable counterpart of ``java`` (which describes each JVM
in depth) and of ``service_map`` (which lists every listener): an inventory a
caller collects from many hosts to match traffic sent to ``address:port``
with the application behind it.

Like ``java`` it only reads /proc and never attaches to a JVM. Command lines
are read to name the application and are not returned.
"""

from __future__ import annotations

import re

from ..observations import metric, section
from . import ActionSpec, guard, register, timed
from .java import (
    _block,
    _clean,
    _int,
    _props,
    _value,
    application_of,
    main_name,
    main_of,
    redact_args,
)

MAX_APPS = 60  # keep in sync with `head -n 60` in APPS_BODY
# Process managers that start other people's programs: their unit does not
# name the application (a Java main class under supervisord is not
# "supervisord").
MANAGER_UNITS = re.compile(
    r"(?:supervisord?|docker|containerd|crio|kubelet|podman|sshd|crond?|atd"
    r"|pm2[\w.@-]*|session-[\w.-]*)\.(?:service|scope)"
)
MAX_PORTS = 16
MAX_ADDRESSES = 16

TMO = "".join(
    f"tmo{seconds}() {{ " + timed(seconds, '"$@"') + "; }\n" for seconds in (2, 3, 4, 6)
)
# The listening TCP sockets of the wanted PIDs as "L <pid> <address:port>",
# then how many sockets ss listed and how many of them named a process (a
# non-root account sees the owner of its own sockets only). Reads both the
# `ss -ltn` layout and the one with a leading Netid column, and both forms of
# the users:(( list: ("java",pid=12,fd=3) and the older ("java",12,3).
LISTEN_AWK = """BEGIN {
    n = split(want, w, " ")
    for (i = 1; i <= n; i++)
        ok[w[i]] = 1
}
$1 == "Netid" || $1 == "State" || $1 == "udp" {
    next
}
{
    total++
    at = $4
    if ($1 == "tcp")
        at = $5
    s = $0
    i = index(s, "users:((")
    if (i == 0)
        next
    users++
    s = substr(s, i + 8)
    while ((j = index(s, "\\",")) != 0) {
        s = substr(s, j + 2)
        t = s
        if (substr(t, 1, 4) == "pid=")
            t = substr(t, 5)
        sub(/[^0-9].*$/, "", t)
        if (t != "" && (t in ok) && !((t, at) in seen)) {
            seen[t, at] = 1
            if (shown++ < 400)
                print "L", t, substr(at, 1, 80)
        }
    }
}
END {
    print "LISTEN_TOTAL", total + 0
    print "LISTEN_USERS", users + 0
}"""

# /proc/PID/cgroup -> "UNIT <name>.service" and "CONTAINER <12 hex>" lines,
# as the java action reads them (kept out of `$( )`: a program in a variable).
CGROUP_AWK = """u == "" {
    s = $0
    while (match(s, /[A-Za-z0-9_.@-]+[.]service/)) {
        u = substr(s, RSTART, RLENGTH)
        s = substr(s, RSTART + RLENGTH)
    }
}
c == "" && /docker|kubepods|containerd|crio|libpod/ {
    s = $0
    while (match(s, /[0-9a-f]+/)) {
        if (RLENGTH == 64) {
            c = substr(s, RSTART, 12)
            break
        }
        s = substr(s, RSTART + RLENGTH)
    }
}
END {
    if (u != "")
        print "UNIT", u
    if (c != "")
        print "CONTAINER", c
}"""

# Host addresses first (bridges and virtual interfaces are not addresses a
# peer would use), then one `[AIOPS_APP_PID]` block per Java process: owner,
# unit or container, and the argv the name is read from (cut to a per-PID
# byte budget; -D properties that do not name the application go first).
# Docker is asked for its published ports only when a process runs in a
# container.
APPS_BODY = r"""printf '[AIOPS_APPS]\nSCAN_UID %s\n' "$(id -u)"
if command -v ip >/dev/null 2>&1; then
{ tmo2 ip -4 -o addr show scope global; } 2>/dev/null | awk '$2 !~ /^(docker|br-|veth|cni|flannel|cali|virbr|kube|tunl|podman)/ { split($4, a, "/"); if (a[1] ~ /^[0-9.]+$/ && n++ < 16) print "ADDR", a[1] }'
else
{ tmo2 hostname -I; } 2>/dev/null | tr ' ' '\n' | awk '/^[0-9]+[.][0-9.]+$/ && n++ < 16 { print "ADDR", $1 }'
fi
all=$( { tmo3 ps -e -o pid= -o comm= --sort=-rss; } 2>/dev/null | awk '$2 == "jsvc" || $2 ~ /^java/ { print $1 }')
if [ -z "$all" ]; then printf 'NO_JAVA\n'; exit 0; fi
total=$(printf '%s\n' "$all" | wc -l)
pids=$(printf '%s\n' "$all" | head -n 60)
count=$(printf '%s\n' "$pids" | wc -l)
lim=$((30000 / count))
if [ "$lim" -lt 500 ]; then lim=500; fi
if [ "$lim" -gt 4000 ]; then lim=4000; fi
printf 'JAVA_TOTAL %s\n' "$total"
read -r up0 rest < /proc/uptime; up0=${up0%%.*}; up0=${up0:-0}
hasct=0
for pid in $pids; do
case "$pid" in ''|*[!0-9]*) continue;; esac
read -r now rest < /proc/uptime; now=${now%%.*}; now=${now:-0}
if [ $((now - up0)) -ge 8 ]; then printf 'APPS_TIME_BUDGET %s\n' "$pid"; break; fi
if [ ! -d "/proc/$pid" ]; then continue; fi
printf '[AIOPS_APP_PID]\nPID %s\n' "$pid"
{ tmo2 ps -o user= -o etimes= -o rss= -p "$pid"; } 2>/dev/null | awk 'NF >= 3 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ { print "PS", $1, $2, $3; exit }'
printf 'USER %s\n' "$(stat -c %U "/proc/$pid" 2>/dev/null)"
cgl=$(awk "$cgawk" "/proc/$pid/cgroup" 2>/dev/null)
if [ -n "$cgl" ]; then printf '%s\n' "$cgl"; fi
case "$cgl" in *CONTAINER*) hasct=1;; esac
{ tmo2 tr '\000' '\n' < "/proc/$pid/cmdline"; } 2>/dev/null | awk -v lim="$lim" '{ n++ }
n > 200 || over { over = 1; next }
{ v = substr($0, 1, 296); l = length(v) + 5 }
used + l <= lim { used += l; print "ARG " v; next }
substr(v, 1, 2) == "-D" && v !~ /^-D(spring[.](application[.]name|profiles[.]active)|app[.=]|service[.]name|server[.]port)/ { skip++; next }
{ v = substr(v, 1, 160); hard += length(v) + 5; if (hard > lim) { over = 1; next }; print "ARG " v }
END { if (over) print "ARGS_TRUNCATED"; if (skip) print "ARGS_SKIPPED " skip; print "ARGS_END " (n + 0) }'
done
printf '[AIOPS_LISTEN]\n'
if command -v ss >/dev/null 2>&1; then
{ tmo6 ss -ltnp; } 2>/dev/null | awk -v want="$(printf '%s ' $pids)" "$lawk"
else
printf 'CAPABILITY_MISSING:ss\n'
fi
printf '[AIOPS_DOCKER]\n'
if [ "$hasct" = 1 ]; then
if command -v docker >/dev/null 2>&1; then
dk=$( { tmo4 docker ps --no-trunc --format '{{.ID}} {{.Ports}}'; } 2>/dev/null)
if [ $? -eq 0 ]; then printf '%s\n' "$dk" | head -n 200 | cut -c1-700 | sed 's/^/D /'; else printf 'DOCKER_UNAVAILABLE\n'; fi
else
printf 'DOCKER_ABSENT\n'
fi
fi
exit 0
"""


def apps_script(options: dict) -> str:
    return (
        guard("ps", "awk")
        + TMO
        + "lawk='"
        + LISTEN_AWK
        + "'\ncgawk='"
        + CGROUP_AWK
        + "'\n"
        + APPS_BODY
    )


COVERAGE = (
    "只读 /proc 的单次快照（按 RSS 取前 60 个 java/jsvc 进程），不附加 JVM、不返回启动命令；"
    "端口取自 ss -ltnp 的 TCP 监听与 docker ps 的发布端口；非 root 时看不到其他用户进程的端口归属，"
    "bridge 网络容器内的监听只能从 Docker 发布端口得知；没有端口不代表应用不对外服务"
)
ADDRESS = re.compile(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}")
# One published TCP mapping of `docker ps`: 0.0.0.0:8080->8080/tcp,
# :::8080->8080/tcp, 10.0.0.5:7000-7002->7000-7002/tcp. Exposed but
# unpublished ports ("9000/tcp") have no "->" and are left out.
PUBLISHED = re.compile(
    r"(?:^|[\s,])(\[[0-9a-fA-F:.]*\]|[0-9a-fA-F:.]*):"
    r"([0-9]{1,5})(?:-([0-9]{1,5}))?->[0-9]{1,5}(?:-[0-9]{1,5})?/tcp"
)


def _port(value):
    port = _int(value)
    return port if port is not None and 0 < port < 65536 else None


def _loopback(host):
    host = host.strip("[]").split("%", 1)[0]
    return host in ("::1", "localhost") or host.startswith(("127.", "::ffff:127."))


def listeners_of(body):
    """{pid: {port: reachable beyond loopback}} from the `L pid address:port` lines."""
    found = {}
    for match in re.finditer(r"(?m)^L ([0-9]{1,10}) (\S{1,80})$", body):
        host, _, raw = match[2].rpartition(":")
        port = _port(raw)
        if port is None:
            continue
        ports = found.setdefault(int(match[1]), {})
        ports[port] = ports.get(port, False) or not _loopback(host)
    return found


def published_of(body):
    """{container id (12): {host port: reachable beyond loopback}} from `docker ps`."""
    found = {}
    for match in re.finditer(r"(?m)^D ([0-9a-f]{12})[0-9a-f]*(?: (.*))?$", body):
        ports = found.setdefault(match[1], {})
        for host, first, last in PUBLISHED.findall(match[2] or ""):
            start, end = _port(first), _port(last) if last else _port(first)
            if start is None or end is None or not 0 <= end - start < MAX_PORTS:
                continue
            for port in range(start, end + 1):
                ports[port] = ports.get(port, False) or not _loopback(host)
    return found


def app_of(block, listeners, published):
    """One `[AIOPS_APP_PID]` block as an inventory row."""
    fields, lists = _block(block)
    pid = _int(fields.get("PID"))
    if pid is None:
        return None
    ps = (fields.get("PS") or "").split()
    user = fields.get("USER") or ""
    if user in ("", "UNKNOWN") and ps:
        user = ps[0]
    unit = (fields.get("UNIT") or "")[:80] or None
    container = fields.get("CONTAINER") or ""
    container = container if re.fullmatch(r"[0-9a-f]{12}", container) else None
    args = redact_args(lists["ARG"])
    main, index = main_of(args)
    options, app_args = args[1:index], args[index + 1 :]
    sysprops, appprops = _props(options, "-D"), _props(app_args, "--")
    profiles = _clean(
        sysprops.get("spring.profiles.active")
        or appprops.get("spring.profiles.active"),
        200,
    )
    declared = _port(
        _clean(appprops.get("server.port") or sysprops.get("server.port"), 8)
    )
    ports, source = dict(listeners.get(pid, {})), None
    if ports:
        source = "listen"
    elif container and published.get(container):
        ports, source = dict(published[container]), "docker"
    elif declared is not None and not container:
        # A port the process was told to use but ss did not show as its own
        # (another account's socket, seen without root); a container's own
        # port says nothing about the host port.
        ports, source = {declared: True}, "argument"
    return {
        "pid": pid,
        "application": application_of(
            sysprops,
            appprops,
            main,
            None if unit and MANAGER_UNITS.fullmatch(unit) else unit,
        ),
        "main": main_name(main),
        "jar_path": main["name"] if main["kind"] == "jar" else None,
        "profiles": [
            item.strip()[:40] for item in (profiles or "").split(",") if item.strip()
        ][:10],
        "user": user[:64] or None,
        "unit": unit,
        "container": container,
        "elapsed_seconds": _int(ps[1]) if len(ps) > 1 else None,
        "rss_KiB": _int(ps[2]) if len(ps) > 2 else None,
        "ports": sorted(ports)[:MAX_PORTS],
        # Bound to loopback only: reachable from this host (a local Nginx).
        "local_ports": sorted(port for port, wide in ports.items() if not wide)[
            :MAX_PORTS
        ],
        "ports_source": source,
        "declared_port": declared,
        "args_truncated": "ARGS_END" not in fields or "ARGS_TRUNCATED" in fields,
    }


def _finding(level, key, value, threshold, hint):
    return {
        "level": level,
        "metric": key,
        "value": value,
        "threshold": threshold,
        "hint": hint,
    }


def parse_apps(text: str, summary: dict, findings: list, options: dict) -> None:
    text = text if isinstance(text, str) else ""
    header = section(text, "APPS")
    summary["coverage"] = COVERAGE
    summary["addresses"] = list(
        dict.fromkeys(
            match[1]
            for match in re.finditer(r"(?m)^ADDR (\S{1,40})$", header)
            if ADDRESS.fullmatch(match[1])
        )
    )[:MAX_ADDRESSES]
    summary["scan_uid"] = _int(_value(header, "SCAN_UID"))
    if re.search(r"(?m)^NO_JAVA\s*$", text):
        summary["java_processes"] = 0
        summary["apps"] = []
        metric(summary, findings, "java_processes", 0)
        findings.append(
            _finding(
                "info",
                "java_not_found",
                0,
                "≥1 个 java/jsvc 进程",
                "未发现进程名为 java/jsvc 的进程；由启动器改名的 JVM 可能不在此列",
            )
        )
        return
    listen = section(text, "LISTEN")
    sockets, owned = (
        _int(_value(listen, "LISTEN_TOTAL")),
        _int(_value(listen, "LISTEN_USERS")),
    )
    listeners = listeners_of(listen)
    docker = section(text, "DOCKER")
    published = published_of(docker)
    apps = []
    for block in re.split(r"(?m)^\[AIOPS_APP_PID\]\n", text)[1 : MAX_APPS + 1]:
        row = app_of(
            re.split(r"(?m)^\[AIOPS_", block, maxsplit=1)[0], listeners, published
        )
        if row is not None:
            apps.append(row)
    total = _int(_value(header, "JAVA_TOTAL"))
    count = None
    if "[AIOPS_APPS]" in text or apps:
        count = max(total or 0, len(apps))
    summary["java_processes"] = count
    summary["apps"] = apps
    if count is not None and len(apps) < count:
        summary["apps_shown"] = len(apps)
    if "APPS_TIME_BUDGET" in text:
        summary["time_budget_reached"] = True
    # None: ss did not run or was cut off; False: it listed sockets without
    # naming a single process.
    summary["port_owner_visible"] = (
        None if sockets is None else bool(owned) or sockets == 0
    )
    if re.search(r"(?m)^DOCKER_UNAVAILABLE$", docker):
        summary["docker_ports"] = "unavailable"
    elif re.search(r"(?m)^DOCKER_ABSENT$", docker):
        summary["docker_ports"] = "absent"
    elif any(row["container"] for row in apps):
        summary["docker_ports"] = "ok" if re.search(r"(?m)^D ", docker) else "none"
    metric(summary, findings, "java_processes", count)
    unknown = [row["pid"] for row in apps if not row["ports"]]
    if unknown:
        reasons = []
        if summary["scan_uid"] not in (0, None):
            reasons.append("当前账号不是 root，看不到其他用户进程的端口归属")
        if any(row["container"] and not row["ports"] for row in apps):
            reasons.append(
                "容器内进程的端口要从 docker ps 的发布端口得知"
                + (
                    "，而本次读不到 Docker"
                    if summary.get("docker_ports") in ("unavailable", "absent")
                    else ""
                )
            )
        reasons.append("也可能确实不监听 TCP（定时任务、消息消费者）")
        findings.append(
            _finding(
                "info",
                "ports_unknown",
                {"count": len(unknown), "pids": unknown[:20]},
                "每个应用都有端口",
                "；".join(reasons),
            )
        )
    if count is not None and len(apps) < count:
        findings.append(
            _finding(
                "info",
                "apps_not_all_listed",
                {"listed": len(apps), "total": count},
                MAX_APPS,
                f"Java 进程多于本次列出的数量（上限 {MAX_APPS} 个，按 RSS 从大到小）或在时间预算内未读完",
            )
        )


register(
    ActionSpec(
        id="java_apps",
        tool="ssh_diagnose_java_apps",
        title="Java 应用清单",
        question="主机上运行着哪些 Java 应用？各自监听哪些端口，本机有哪些 IPv4 地址？",
        category="应用与中间件",
        params=(),
        script=apps_script,
        parse=parse_apps,
        sensitive=True,
        risk="low",
        timeout=20,
        output_limit=65536,
        estimated_seconds=4,
        notes=(
            "最多 60 个 Java 进程；读取启动命令只为识别应用名、JAR 与 profiles，不返回命令本身。",
            "端口取自 ss -ltnp 与 docker ps 的发布端口：非 root 账号看不到其他用户进程的端口归属。",
        ),
    )
)
