"""Java process inventory (``java``) and bounded JVM probes (``jvm``).

``java`` only reads /proc (ps, cmdline, cgroup, limits, fd links): it never
attaches to a JVM and never starts one. ``jvm`` runs ``jcmd GC.heap_info`` /
``VM.flags`` and ``jstat -gc`` as the JVM owner and tails the GC log. jcmd
attaches by sending SIGQUIT, which terminates a process that does not handle
it, so the script first checks that the PID is named java/jsvc and that it
catches SIGQUIT (``-Xrs`` JVMs and the jsvc controller process do not).

The only value interpolated into either script is the validated integer PID;
everything that may stall runs under ``timeout``. Command lines are redacted
twice, by the executor (``diagnostics.redact_output``) and here per argument,
and only a 400-character preview reaches the summary.
"""

from __future__ import annotations

import re

from ..observations import metric, number, section
from . import ActionSpec, Param, guard, register, timed

MAX_PIDS = 20  # keep in sync with `head -n 20` in JAVA_BODY
# cgroup v1 reports "no limit" as 2^63 rounded down to the page size.
UNLIMITED = 1 << 62
REDACTED = "[REDACTED]"
DIGITS = re.compile(r"[0-9]{1,19}")

# `timeout` wrappers shared by both scripts; a vanished PID is not an error,
# so callers discard stderr of the group ({ tmo2 ...; } 2>/dev/null).
TMO = (
    "tmo2() { " + timed(2, '"$@"') + "; }\n" + "tmo3() { " + timed(3, '"$@"') + "; }\n"
)

# Candidate PIDs by RSS, then one `[AIOPS_JAVA_PID]` block of "KEY value"
# lines per PID: structured lines first, argv last (ARG lines are the bulk).
# Every argv element is cut to 296 bytes; past a per-PID byte budget (16 KB
# shared by all PIDs, 0.8–12 KB each) unimportant -D properties are only
# counted, and positional arguments are kept so the main class stays known.
JAVA_BODY = r"""all=$( { tmo3 ps -eo pid=,comm= --sort=-rss; } 2>/dev/null | awk '$2 == "jsvc" || $2 ~ /^java/ { print $1 }')
if [ -z "$all" ]; then printf 'NO_JAVA\n'; exit 0; fi
total=$(printf '%s\n' "$all" | wc -l)
pids=$(printf '%s\n' "$all" | head -n 20)
count=$(printf '%s\n' "$pids" | wc -l)
lim=$((16000 / count))
if [ "$lim" -lt 800 ]; then lim=800; fi
if [ "$lim" -gt 12000 ]; then lim=12000; fi
printf '[AIOPS_JAVA]\nSCAN_UID %s\nJAVA_TOTAL %s\n' "$(id -u)" "$total"
printf 'JAVA_PIDS'; printf ' %s' $pids; printf '\n'
read -r up0 rest < /proc/uptime; up0=${up0%%.*}; up0=${up0:-0}
for pid in $pids; do
case "$pid" in ''|*[!0-9]*) continue;; esac
read -r now rest < /proc/uptime; now=${now%%.*}; now=${now:-0}
if [ $((now - up0)) -ge 10 ]; then printf 'JAVA_TIME_BUDGET %s\n' "$pid"; break; fi
if [ ! -d "/proc/$pid" ]; then continue; fi
printf '[AIOPS_JAVA_PID]\nPID %s\n' "$pid"
pl=$( { tmo2 ps -o user=,etimes=,rss=,pcpu=,pmem=,nlwp= -p "$pid"; } 2>/dev/null | awk 'NF >= 6 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ { print "PS", $1, $2, $3, $4, $5, $6; exit }')
if [ -z "$pl" ]; then pl=$( { tmo2 ps -o user=,etimes=,rss=,pcpu=,pmem= -p "$pid"; } 2>/dev/null | awk 'NF >= 5 && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ { print "PS", $1, $2, $3, $4, $5, "-"; exit }'); fi
if [ -n "$pl" ]; then printf '%s\n' "$pl"; fi
printf 'USER %s\n' "$(stat -c %U "/proc/$pid" 2>/dev/null)"
awk '/^Threads:/ { print "THREADS", $2; exit }' "/proc/$pid/status" 2>/dev/null
awk '/^Max open files/ { print "FDLIMIT", $4; exit }' "/proc/$pid/limits" 2>/dev/null
awk 'u == "" { s = $0; while (match(s, /[A-Za-z0-9_.@-]+[.]service/)) { u = substr(s, RSTART, RLENGTH); s = substr(s, RSTART + RLENGTH) } }
c == "" && /docker|kubepods|containerd|crio|libpod/ { s = $0; while (match(s, /[0-9a-f]+/)) { if (RLENGTH == 64) { c = substr(s, RSTART, 12); break }; s = substr(s, RSTART + RLENGTH) } }
END { if (u != "") print "UNIT", u; if (c != "") print "CONTAINER", c }' "/proc/$pid/cgroup" 2>/dev/null
cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null)
if [ -n "$cwd" ]; then printf 'CWD %.290s\n' "$cwd"; fi
exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
if [ -n "$exe" ]; then printf 'EXE %.290s\n' "$exe"; fi
jx=$exe
if [ -z "$jx" ]; then
a0=$( { tmo2 tr '\000' '\n' < "/proc/$pid/cmdline"; } 2>/dev/null | head -n 1)
case "$a0" in /*) jx=$(readlink -f "$a0" 2>/dev/null);; esac
fi
case "$jx" in
/*)
rt=''; if [ -n "$exe" ] && [ -d "/proc/$pid/root/" ]; then rt="/proc/$pid/root"; fi
jh=${jx%/*}; jh=${jh%/*}
for rf in "$rt$jh/release" "$rt${jh%/*}/release"; do
if [ -f "$rf" ] && [ -r "$rf" ]; then
grep -E '^(JAVA_VERSION|IMPLEMENTOR)=' "$rf" 2>/dev/null | head -n 2 | cut -c1-280 | sed 's/^/RELEASE /'
break
fi
done
;;
esac
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
cb=/sys/fs/cgroup; cf=memory.max
cg=$(awk 'substr($0, 1, 3) == "0::" { print substr($0, 4); exit }' "/proc/$pid/cgroup" 2>/dev/null)
else
cb=/sys/fs/cgroup/memory; cf=memory.limit_in_bytes
cg=$(awk -F: '{ n = split($2, c, ","); for (i = 1; i <= n; i++) if (c[i] == "memory") { print substr($0, length($1) + length($2) + 3); exit } }' "/proc/$pid/cgroup" 2>/dev/null)
fi
case "$cg" in /*) ;; *) cg='';; esac
case "$cg" in *..*) cg='';; esac
if [ -n "$cg" ]; then
if [ "$cg" = / ]; then cg=''; fi
k=0
while [ "$k" -lt 16 ]; do
if [ -r "$cb$cg/$cf" ]; then printf 'CGMEM %s\n' "$(head -n 1 "$cb$cg/$cf" 2>/dev/null)"; fi
if [ -z "$cg" ]; then break; fi
cn=${cg%/*}
if [ "$cn" = "$cg" ]; then break; fi
cg=$cn; k=$((k + 1))
done
fi
if [ -r "/proc/$pid/fd" ] && [ -x "/proc/$pid/fd" ]; then
{ tmo3 ls -l "/proc/$pid/fd"; } 2>/dev/null | awk '{ i = index($0, " -> "); if (i == 0) next; n++; t = substr($0, i + 4) }
t ~ /[.](log|out|txt)( [(]deleted[)])?$/ && !(t in seen) && k < 10 { seen[t] = 1; k++; print "LOGFD " substr(t, 1, 290) }
END { print "FDS " (n + 0) }'
fi
{ tmo2 tr '\000' '\n' < "/proc/$pid/cmdline"; } 2>/dev/null | awk -v lim="$lim" '{ n++ }
n > 200 || over { over = 1; next }
{ v = substr($0, 1, 296); l = length(v) + 5 }
used + l <= lim { used += l; print "ARG " v; next }
substr(v, 1, 2) == "-D" && v !~ /^-D(spring[.](application[.]name|profiles[.]active)|app[.=]|service[.]name|logging[.]|log[._]|LOG_|catalina[.]base)/ { skip++; next }
{ v = substr(v, 1, 160); hard += length(v) + 5; if (hard > lim) { over = 1; next }; print "ARG " v }
END { if (over) print "ARGS_TRUNCATED"; if (skip) print "ARGS_SKIPPED " skip; print "ARGS_END " (n + 0) }'
done
exit 0
"""


def java_script(options: dict) -> str:
    return guard("ps", "awk") + TMO + JAVA_BODY


JAVA_COVERAGE = (
    "只读 /proc 的单次快照（按 RSS 取前 20 个 java/jsvc 进程），不附加 JVM；"
    "堆与 GC 参数只来自启动命令，JAVA_TOOL_OPTIONS 与 @argfile 中的设置不可见，"
    "生效值用 ssh_diagnose_jvm 的 vm_flags 确认；非 root 时其他用户进程的 fd、cwd、exe 不可读；"
    "CPU 为进程生命周期平均值"
)
# Second-layer redaction: keys naming a secret ("key" deliberately broad).
SECRET_KEY = re.compile(r"(?i)password|passwd|pwd|secret|token|key|credential")
# java/jsvc options whose value is the next argv element.
VALUE_OPTIONS = frozenset(
    {
        "-cp",
        "-classpath",
        "--class-path",
        "-p",
        "--module-path",
        "--upgrade-module-path",
        "--add-modules",
        "--limit-modules",
        "--add-reads",
        "--add-exports",
        "--add-opens",
        "--patch-module",
        "--source",
        "--enable-native-access",
        "-jvm",
        "-user",
        "-home",
        "-java-home",
        "-wait",
        "-restarts",
        "-umask",
        "-outfile",
        "-errfile",
        "-pidfile",
        "-procname",
        "-cwd",
    }
)
COLLECTORS = {
    "UseG1GC": "G1",
    "UseParallelGC": "Parallel",
    "UseParallelOldGC": "Parallel",
    "UseConcMarkSweepGC": "CMS",
    "UseZGC": "ZGC",
    "UseShenandoahGC": "Shenandoah",
    "UseSerialGC": "Serial",
    "UseEpsilonGC": "Epsilon",
}
HEAP_OPTIONS = (
    ("-Xmx", "xmx"),
    ("-XX:MaxHeapSize=", "xmx"),
    ("-Xms", "xms"),
    ("-XX:InitialHeapSize=", "xms"),
    ("-Xss", "xss"),
    ("-XX:MaxMetaspaceSize=", "max_metaspace"),
    ("-XX:MaxDirectMemorySize=", "max_direct"),
)
APP_KEYS = ("spring.application.name", "app.name", "app", "service.name")
LOG_KEY = re.compile(
    r"(?i)logging\.(?:file|path|config)[\w.-]*|logs?[._-]?(?:path|dir|home|file)"
    r"|[\w.-]*\.logs?\.(?:dir|path|home|file)|catalina\.base"
    r"|log4j2?\.configuration(?:file)?|logback\.configurationfile"
    r"|java\.util\.logging\.config\.file"
)
SIZE_RE = re.compile(r"([0-9]{1,15})([kKmMgGtT]?)")
SIZE_FACTOR = {"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}
LIST_KEYS = ("ARG", "RELEASE", "CGMEM", "LOGFD")
SINGLE_KEYS = (
    "PID",
    "PS",
    "USER",
    "THREADS",
    "FDS",
    "FDLIMIT",
    "UNIT",
    "CONTAINER",
    "CWD",
    "EXE",
    "ARGS_TRUNCATED",
    "ARGS_SKIPPED",
    "ARGS_END",
)


def _int(value):
    value = str(value if value is not None else "").strip()
    return int(value) if DIGITS.fullmatch(value) else None


def _value(text, key):
    """Value of the first `KEY value` line, "" for a bare `KEY`, else None."""
    if not text:
        return None
    match = re.search(r"(?m)^" + re.escape(key) + r"(?: (.*))?$", text)
    return (match[1] or "").strip() if match else None


def size_bytes(text):
    """JVM size syntax (2g, 512m, 1024k, 1073741824) in bytes."""
    match = SIZE_RE.fullmatch((text or "").strip())
    return int(match[1]) * SIZE_FACTOR[match[2].lower()] if match else None


def redact_args(args):
    """Mask arguments whose key names a secret; -X/-XX: JVM options stay as is.

    Covers -Dkey=value, --key=value and KEY=value forms and the value that
    follows a bare ``--secret-option`` (-D options never take a separate
    value), then re-applies the executor's patterns (URL credentials, tokens
    inside values) so the parser stays safe on unredacted input too.
    """
    from ..diagnostics import redact_output  # diagnostics imports extensions

    result, hide_next = [], False
    for arg in args:
        if hide_next and not arg.startswith("-"):
            result.append(REDACTED)
            hide_next = False
            continue
        hide_next = False
        if arg.startswith("-X"):
            result.append(arg)
            continue
        key, sep, _ = arg.partition("=")
        if sep:
            if SECRET_KEY.search(key):
                arg = key + "=" + REDACTED
        elif (
            arg.startswith("-")
            and not arg.startswith("-D")
            and ":" not in arg
            and SECRET_KEY.search(arg)
        ):
            hide_next = True
        result.append(redact_output(arg))
    return result


def main_of(args):
    """(main {kind, name}, argv index of the main jar/class) for java and jsvc.

    As in the java launcher, ``-jar`` only selects jar mode: JVM options may
    still follow it (``java -jar -Xmx1g app.jar``) and the first non-option
    argument is the jar.
    """
    index, kind = 1, "class"
    while index < len(args):
        arg = args[index]
        if arg == "-jar":
            kind = "jar"
            index += 1
            continue
        if arg in ("-m", "--module"):
            if index + 1 >= len(args):
                break
            return {"kind": "class", "name": args[index + 1][:200]}, index + 1
        if arg.startswith("--module="):
            return {"kind": "class", "name": arg[9:][:200]}, index
        if arg in VALUE_OPTIONS:
            index += 2
            continue
        if not arg or arg == REDACTED or arg.startswith(("-", "@")):
            index += 1
            continue
        return {"kind": kind, "name": arg[:200]}, index
    return {"kind": "unknown", "name": None}, len(args)


def _props(args, prefix):
    found = {}
    for arg in args:
        if arg.startswith(prefix):
            key, _, value = arg[len(prefix) :].partition("=")
            if key:
                found[key] = value
    return found


def _clean(value, limit=80):
    value = (value or "").strip().strip("'\"").strip()
    return value[:limit] if value and value != REDACTED else None


def application_of(sysprops, appprops, main, unit):
    for key in APP_KEYS:
        for source in (sysprops, appprops):
            value = _clean(source.get(key))
            if value:
                return value
    if main["kind"] == "jar" and main["name"]:
        base = re.sub(r"(?i)\.[jw]ar$", "", main["name"].rsplit("/", 1)[-1])
        if base:
            return base[:80]
    if unit and not unit.startswith("user@"):
        return unit.removesuffix(".service")
    return "未识别"


def heap_of(options):
    heap = dict.fromkeys(
        ("xms", "xmx", "xss", "max_ram_percentage", "max_metaspace", "max_direct")
    )
    bounded = False  # MaxRAM / MaxRAMFraction also cap the default heap
    for arg in options:
        if arg.startswith("-XX:MaxRAMPercentage="):
            heap["max_ram_percentage"] = number(arg.split("=", 1)[1])
        elif arg.startswith(("-XX:MaxRAMFraction=", "-XX:MaxRAM=")):
            bounded = True
        elif arg.startswith("-XX:ThreadStackSize="):
            heap["xss"] = arg.split("=", 1)[1][:24] + "k"
        else:
            for prefix, key in HEAP_OPTIONS:
                if arg.startswith(prefix):
                    heap[key] = arg[len(prefix) :][:32]
                    break
    size = size_bytes(heap["xmx"])
    heap["xmx_MiB"] = round(size / 1048576, 1) if size else None
    return heap, bounded


def gc_log_path_of(options):
    verbose = False
    for arg in options:
        if arg.startswith("-Xloggc:"):
            return arg[8:].strip('"')[:240] or None
        if arg.startswith("-Xlog:"):
            parts = arg[6:].split(":")
            if "gc" not in parts[0]:
                continue
            output = parts[1].strip('"') if len(parts) > 1 else ""
            if output.startswith("file="):
                output = output[5:].strip('"')
            return (output or "stdout")[:240]
        if arg == "-verbose:gc" or arg.startswith("-XX:+PrintGC"):
            verbose = True
    return "stdout" if verbose else None


def _block(block):
    fields, lists = {}, {key: [] for key in LIST_KEYS}
    for line in block.splitlines():
        key, _, value = line.partition(" ")
        if key in lists:
            if len(lists[key]) < 240:
                lists[key].append(value)
        elif key in SINGLE_KEYS and key not in fields:
            fields[key] = value.strip()
    return fields, lists


def process_of(block):
    """One `[AIOPS_JAVA_PID]` block as a summary row plus finding inputs."""
    fields, lists = _block(block)
    pid = _int(fields.get("PID"))
    if pid is None:
        return None, {}
    ps = (fields.get("PS") or "").split()
    user = fields.get("USER") or ""
    if user in ("", "UNKNOWN") and ps:
        user = ps[0]
    release = {}
    for line in lists["RELEASE"]:
        key, _, value = line.partition("=")
        release[key.strip()] = value.strip().strip('"')[:80]
    limits = [
        value
        for value in (_int(item) for item in lists["CGMEM"])
        if value is not None and value < UNLIMITED
    ]
    unit = (fields.get("UNIT") or "")[:80] or None
    container = fields.get("CONTAINER") or ""
    args = redact_args(lists["ARG"])
    main, index = main_of(args)
    options, app_args = args[1:index], args[index + 1 :]
    sysprops, appprops = _props(options, "-D"), _props(app_args, "--")
    heap, bounded = heap_of(options)
    profiles = _clean(
        sysprops.get("spring.profiles.active")
        or appprops.get("spring.profiles.active"),
        200,
    )
    threads = _int(ps[5]) if len(ps) > 5 else None
    fds = _int(fields.get("FDS"))
    proc = {
        "pid": pid,
        "user": user[:64] or None,
        "elapsed_seconds": _int(ps[1]) if len(ps) > 1 else None,
        "rss_KiB": _int(ps[2]) if len(ps) > 2 else None,
        "cpu_percent": number(ps[3]) if len(ps) > 3 else None,
        "mem_percent": number(ps[4]) if len(ps) > 4 else None,
        "threads": threads if threads is not None else _int(fields.get("THREADS")),
        # A live JVM always holds descriptors; 0 means the list was unreadable.
        "fds": fds or None,
        "fd_limit": _int(fields.get("FDLIMIT")),
        "unit": unit,
        "container": container if re.fullmatch(r"[0-9a-f]{12}", container) else None,
        "cwd": fields.get("CWD") or None,
        "exe": fields.get("EXE") or None,
        "java_version": release.get("JAVA_VERSION") or None,
        "implementor": release.get("IMPLEMENTOR") or None,
        "main": main,
        "application": application_of(sysprops, appprops, main, unit),
        "profiles": [
            item.strip()[:40] for item in (profiles or "").split(",") if item.strip()
        ][:10],
        "heap": heap,
        "gc": {
            "collector": next(
                (
                    COLLECTORS[arg[5:]]
                    for arg in reversed(options)
                    if arg.startswith("-XX:+") and arg[5:] in COLLECTORS
                ),
                "default",
            ),
            "gc_log": gc_log_path_of(options),
            "xx_flags": [arg[:120] for arg in options if arg.startswith("-XX:")][:20],
        },
        "logs": {
            "configured": [
                (key + "=" + value)[:200]
                for source in (sysprops, appprops)
                for key, value in source.items()
                if value and LOG_KEY.fullmatch(key)
            ][:10],
            "open_files": [path[:290] for path in lists["LOGFD"]][:10],
        },
        "cgroup_memory_limit_bytes": min(limits) if limits else None,
        "system_properties_count": sum(arg.startswith("-D") for arg in options)
        + (_int(fields.get("ARGS_SKIPPED")) or 0),
        "command_preview": " ".join(args)[:400],
        "args_truncated": "ARGS_END" not in fields or "ARGS_TRUNCATED" in fields,
    }
    extra = {
        "args_complete": not proc["args_truncated"] and bool(args),
        "bounded": bounded,
        # Options from @argfiles or -XX:Flags= files are not visible here.
        "indirect": any(
            arg.startswith(("@", "-XX:Flags=", "-XX:VMOptionsFile=")) for arg in options
        ),
    }
    return proc, extra


def _finding(level, key, value, threshold, hint):
    return {
        "level": level,
        "metric": key,
        "value": value,
        "threshold": threshold,
        "hint": hint,
    }


def process_findings(proc, extra):
    label = {"pid": proc["pid"], "application": proc["application"]}
    heap = proc["heap"]
    xmx, limit = heap["xmx_MiB"], proc["cgroup_memory_limit_bytes"]
    found = []
    if (
        extra.get("args_complete")
        and not extra.get("indirect")
        and not extra.get("bounded")
        and heap["xmx"] is None
        and heap["max_ram_percentage"] is None
    ):
        found.append(
            _finding(
                "warning",
                "heap_max_unset",
                label,
                "-Xmx 或 -XX:MaxRAMPercentage",
                "启动命令未设置 -Xmx 或 -XX:MaxRAMPercentage：JVM 默认最大堆取物理内存或容器限制的 1/4，"
                "容器内或同机多实例时容易 OOM 或互相挤占；也可能通过 JAVA_TOOL_OPTIONS 设置，"
                "用 ssh_diagnose_jvm 的 vm_flags 确认实际 MaxHeapSize",
            )
        )
    if xmx and limit and xmx > limit / 1048576 * 0.9:
        found.append(
            _finding(
                "warning",
                "heap_exceeds_cgroup",
                {
                    **label,
                    "xmx_MiB": xmx,
                    "cgroup_limit_MiB": round(limit / 1048576, 1),
                },
                "-Xmx ≤ cgroup 内存限制的 90%",
                "-Xmx 超过 cgroup 内存限制的 90%（经验值）：元空间、线程栈、直接内存与 JIT 还需堆外空间，"
                "容易被 cgroup OOM Killer 终止；调低 -Xmx 或改用 -XX:MaxRAMPercentage",
            )
        )
    threads = proc["threads"]
    if threads is not None and threads >= 2000:
        found.append(
            _finding(
                "critical" if threads >= 5000 else "warning",
                "threads_high",
                {**label, "threads": threads},
                2000,
                "线程数 ≥2000（经验值，≥5000 视为严重）：常见于线程池无上限或线程泄漏；"
                "用线程转储按线程名分组核查，并对照 ulimit -u 与 pids cgroup 上限",
            )
        )
    fds, fd_limit = proc["fds"], proc["fd_limit"]
    if fds and fd_limit and fds >= fd_limit * 0.8:
        found.append(
            _finding(
                "warning",
                "fds_near_limit",
                {**label, "fds": fds, "fd_limit": fd_limit},
                int(fd_limit * 0.8),
                "打开的文件描述符达到软限制的 80%（经验值）：连接或文件句柄泄漏、或 LimitNOFILE 偏低，"
                "到达上限会报 Too many open files",
            )
        )
    rss = proc["rss_KiB"]
    if xmx and rss and rss > xmx * 1024 * 1.5:
        found.append(
            _finding(
                "info",
                "rss_far_above_heap",
                {**label, "rss_MiB": round(rss / 1024, 1), "xmx_MiB": xmx},
                "RSS ≤ 1.5 × Xmx",
                "RSS 超过 -Xmx 的 1.5 倍（经验值）：堆外占用较多（元空间、线程栈、直接内存/Netty、JNI、glibc arena），"
                "可在下次重启时加 -XX:NativeMemoryTracking=summary 定位",
            )
        )
    elapsed = proc["elapsed_seconds"]
    if elapsed is not None and elapsed < 600:
        found.append(
            _finding(
                "warning",
                "recent_start",
                {**label, "elapsed_seconds": elapsed},
                600,
                "进程运行不足 10 分钟：最近启动或重启过，结合 systemd 重启记录、OOM 日志与应用日志确认是否异常退出",
            )
        )
    return found


def parse_java(text: str, summary: dict, findings: list, options: dict) -> None:
    summary["coverage"] = JAVA_COVERAGE
    if re.search(r"(?m)^NO_JAVA\s*$", text):
        summary["java_processes"] = 0
        summary["processes"] = []
        metric(summary, findings, "java_processes", 0)
        findings.append(
            _finding(
                "info",
                "java_not_found",
                0,
                "≥1 个 java/jsvc 进程",
                "未发现进程名为 java/jsvc 的进程；容器内进程、由启动器改名的 JVM 可能不在此列",
            )
        )
        return
    header = section(text, "JAVA")
    total = _int(_value(header, "JAVA_TOTAL"))
    listed = re.findall(r"[0-9]{1,10}", _value(header, "JAVA_PIDS") or "")
    processes, extras = [], []
    for block in re.split(r"(?m)^\[AIOPS_JAVA_PID\]\n", text)[1 : MAX_PIDS + 1]:
        proc, extra = process_of(block)
        if proc is not None:
            processes.append(proc)
            extras.append(extra)
    count = None
    if "[AIOPS_JAVA]" in text or processes:
        count = total if total is not None else max(len(listed), len(processes))
    summary["java_processes"] = count
    summary["processes"] = processes
    if count is not None and len(processes) < count:
        summary["processes_shown"] = len(processes)
    if "JAVA_TIME_BUDGET" in text:
        summary["time_budget_reached"] = True
    metric(summary, findings, "java_processes", count)
    for proc, extra in zip(processes, extras):
        findings.extend(process_findings(proc, extra))
    if count is not None and count >= 5:
        findings.append(
            _finding(
                "info",
                "many_java_processes",
                count,
                5,
                "同一主机运行 ≥5 个 Java 进程（经验值）：核对各进程 -Xmx 之和与物理内存，以及 CPU 争用",
            )
        )


# ----------------------------------------------------------------- jvm -----

PROBES = ("heap_info", "vm_flags", "gc_stat", "gc_log")
DEFAULT_PROBES = ("heap_info", "vm_flags", "gc_stat")
ATTACH_PROBES = ("heap_info", "vm_flags", "gc_stat")

# Refuses anything but java/jsvc (jcmd would SIGQUIT an arbitrary process),
# then records owner, uptime, binary and the GC log path from the argv
# (-Xlog:gc...:file=PATH:... or -Xloggc:PATH, made absolute against the cwd).
JVM_HEAD = r"""printf '[AIOPS_PROC]\n'
comm=$(cat "/proc/$pid/comm" 2>/dev/null)
case "$comm" in
java|jsvc) ;;
*) printf 'COMM %.40s\nAIOPS_REFUSED:pid\n' "$comm"; exit 69;;
esac
owner=$(stat -c %U "/proc/$pid" 2>/dev/null)
ouid=$(stat -c %u "/proc/$pid" 2>/dev/null)
exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
cwd=$(readlink "/proc/$pid/cwd" 2>/dev/null)
printf 'PID %s\nCOMM %s\nUSER %s\n' "$pid" "$comm" "$owner"
printf 'ETIMES %s\n' "$( { tmo2 ps -o etimes= -p "$pid"; } 2>/dev/null | tr -d ' ')"
printf 'EXE %.290s\n' "$exe"
gclog=$( { tmo2 tr '\000' '\n' < "/proc/$pid/cmdline"; } 2>/dev/null | awk '/^-Xloggc:/ { p = substr($0, 9); gsub(/"/, "", p); if (p != "") { print p; exit } }
/^-Xlog:/ { n = split(substr($0, 7), f, ":"); if (n >= 2 && f[1] ~ /gc/ && f[2] != "" && f[2] != "stdout" && f[2] != "stderr") { p = f[2]; if (substr(p, 1, 5) == "file=") p = substr(p, 6); gsub(/"/, "", p); if (p != "") { print p; exit } } }')
case "$gclog" in /*|'') ;; *) if [ -n "$cwd" ]; then gclog="$cwd/$gclog"; fi;; esac
printf 'GCLOG %.290s\n' "$gclog"
rc=0
"""
# Attach as the JVM owner: root switches with runuser; any other account must
# be the owner itself. jcmd is skipped unless the JVM catches SIGQUIT (signal
# 3, i.e. 0x4 in the last hex digit of SigCgt) and allows attach. Tools come
# from the JVM's own JDK first; as root only root-owned binaries are run.
JVM_ATTACH = (
    r"""printf '[AIOPS_ATTACH]\n'
uid=$(id -u)
mode=direct; skip=''; jskip=''
if [ "$uid" = 0 ]; then
if [ -n "$owner" ] && [ "$owner" != root ] && [ "$owner" != UNKNOWN ]; then
if command -v runuser >/dev/null 2>&1; then mode=runuser; else printf 'CAPABILITY_MISSING:runuser\n'; skip=runuser; rc=69; fi
fi
elif [ "$uid" != "$ouid" ]; then
printf 'ATTACH_UNAVAILABLE\n'; skip=uid; rc=69
fi
sq=$(awk '/^SigCgt:/ { print substr($2, length($2), 1); exit }' "/proc/$pid/status" 2>/dev/null)
case "$sq" in [4567cdefCDEF]) ;; *) jskip=sigquit;; esac
if { tmo2 tr '\000' '\n' < "/proc/$pid/cmdline"; } 2>/dev/null | grep -qxF -- '-XX:+DisableAttachMechanism'; then jskip=disabled; fi
printf 'UID %s\nMODE %s\nJCMD %s\n' "$uid" "$mode" "${jskip:-ok}"
jb=''; case "$exe" in /*) jb=${exe%/*};; esac
ab=''; case "$jb" in */jre/bin) ab=${jb%/jre/bin}/bin;; esac
jtool() {
for c in "$jb/$1" "$ab/$1" "$(command -v "$1" 2>/dev/null)"; do
case "$c" in /*) ;; *) continue;; esac
if [ -f "$c" ] && [ -x "$c" ]; then
if [ "$mode" = direct ] && [ "$uid" = 0 ] && [ ! -O "$c" ]; then continue; fi
printf '%s' "$c"; return 0
fi
done
return 1
}
jrun() {
if [ "$mode" = runuser ]; then
"""
    + timed(8, 'runuser -u "$owner" -- "$@"')
    + "\nelse\n"
    + timed(8, '"$@"')
    + "\nfi\n}\n"
)
JCMD_GUARD = r"""if [ -n "$skip" ]; then printf 'SKIPPED %s\n' "$skip"
elif [ -n "$jskip" ]; then printf 'SKIPPED %s\n' "$jskip"
elif ! jc=$(jtool jcmd); then printf 'CAPABILITY_MISSING:jcmd\n'; rc=69
else
"""
# A JVM that let one jcmd time out is not asked again (keeps within 30 s).
PROBE_RC = r"""printf 'RC %s\n' "$r"; if [ "$r" != 0 ] && [ "$rc" = 0 ]; then rc=1; fi
if [ "$r" = 124 ] || [ "$r" = 137 ]; then jskip=timeout; fi
fi
"""
# The tools' own JVMs run with a small heap and without a perf-data file.
PROBE_SCRIPTS = {
    "heap_info": r"""printf '[AIOPS_HEAP_INFO]\n'
"""
    + JCMD_GUARD
    + r"""out=$(jrun "$jc" -J-XX:-UsePerfData -J-Xmx64m "$pid" GC.heap_info); r=$?
printf '%s\n' "$out" | awk 'NR <= 40 { print substr($0, 1, 300) }'
"""
    + PROBE_RC,
    "vm_flags": r"""printf '[AIOPS_VM_FLAGS]\n'
"""
    + JCMD_GUARD
    + r"""out=$(jrun "$jc" -J-XX:-UsePerfData -J-Xmx64m "$pid" VM.flags); r=$?
printf '%s\n' "$out" | awk '/^-XX:/ || / -XX:/ { for (i = 1; i <= NF; i++) if (k < 120) { k++; print substr($i, 1, 160) }; next }
NR <= 20 { print substr($0, 1, 300) }'
"""
    + PROBE_RC,
    "gc_stat": r"""printf '[AIOPS_GC_STAT]\n'
if [ -n "$skip" ]; then printf 'SKIPPED %s\n' "$skip"
elif ! js=$(jtool jstat); then printf 'CAPABILITY_MISSING:jstat\n'; rc=69
else
out=$(jrun "$js" -J-XX:-UsePerfData -J-Xmx64m -gc "$pid"); r=$?
printf '%s\n' "$out" | awk 'NR <= 6 { print substr($0, 1, 300) }'
"""
    + PROBE_RC,
    # The path comes from the target's own argv, so it is resolved in the
    # JVM's mount namespace (/proc/<pid>/root) and read only when the JVM's
    # uid owns the file: a fake "java" with -Xloggc:/etc/shadow gets nothing.
    # %p is the PID; other placeholders (%t, rotation suffixes) fall back to
    # the newest file with the same name prefix.
    "gc_log": r"""printf '[AIOPS_GC_LOG]\n'
gl=''; rt=''
if [ -d "/proc/$pid/root/" ]; then rt="/proc/$pid/root"; fi
case "$gclog" in
'') printf 'GC_LOG_NOT_CONFIGURED\n';;
/*)
gp=$(printf '%s\n' "$gclog" | awk -v p="$pid" '{ while ((i = index($0, "%p")) > 0) $0 = substr($0, 1, i - 1) p substr($0, i + 2); print }')
case "$gp" in *%*) ;; *) if [ -f "$rt$gp" ] && [ -r "$rt$gp" ]; then gl=$gp; fi;; esac
if [ -z "$gl" ]; then
gd=${gp%/*}; gb=${gp##*/}
pre=$(printf '%s\n' "$gb" | sed 's/%.*//')
if [ -n "$pre" ] && [ -d "$rt$gd" ] && [ -r "$rt$gd" ]; then
gn=$( { tmo2 ls -t "$rt$gd"; } 2>/dev/null | awk -v p="$pre" 'index($0, p) == 1 { print; exit }')
if [ -n "$gn" ] && [ -f "$rt$gd/$gn" ] && [ -r "$rt$gd/$gn" ]; then gl="$gd/$gn"; fi
fi
fi
if [ -z "$gl" ]; then printf 'GC_LOG_UNREADABLE\n'
elif [ "$(stat -c %u "$rt$gl" 2>/dev/null)" != "$ouid" ]; then printf 'GC_LOG_FOREIGN_OWNER\n'
else
printf 'FILE %.290s\n' "$gl"
{ tmo3 tail -n 40 "$rt$gl"; } 2>/dev/null | cut -c1-300
fi
;;
*) printf 'GC_LOG_UNREADABLE\n';;
esac
""",
}


def probes_of(options: dict) -> list[str]:
    chosen = options.get("probes")
    if not isinstance(chosen, list) or not chosen:
        chosen = DEFAULT_PROBES
    return [probe for probe in PROBES if probe in chosen]


def jvm_script(options: dict) -> str:
    probes = probes_of(options)
    parts = ["pid=" + str(int(options["pid"])) + "\n", TMO, JVM_HEAD]
    if any(probe in ATTACH_PROBES for probe in probes):
        parts.append(JVM_ATTACH)
    parts.extend(PROBE_SCRIPTS[probe] for probe in probes)
    parts.append('exit "$rc"\n')
    return "".join(parts)


JVM_COVERAGE = (
    "单个 JVM 的 jcmd/jstat 单次快照与 GC 日志尾部 40 行；GC 次数与耗时是进程启动以来的累计值，"
    "堆使用率包含尚未回收的年轻代对象，不能单独据此判断内存泄漏"
)
SIZE = r"([0-9]{1,15}(?:\.[0-9]{1,6})?)([BKMGT]?)"
UNIT_KIB = {
    "": 1 / 1024,
    "B": 1 / 1024,
    "K": 1,
    "M": 1 << 10,
    "G": 1 << 20,
    "T": 1 << 30,
}
G1_HEAP = re.compile(
    r"garbage-first heap\s+total\s+(?:reserved\s+)?"
    + SIZE
    + r"(?:,\s*committed\s+"
    + SIZE
    + r")?,\s*used\s+"
    + SIZE
)
G1_REGIONS = re.compile(
    r"region size "
    + SIZE
    + r", ([0-9]{1,9}) young \("
    + SIZE
    + r"\), ([0-9]{1,9}) survivors \("
    + SIZE
    + r"\)"
)
GENERATIONS = re.compile(
    r"(?m)^\s*(PSYoungGen|ParOldGen|PSOldGen|def new generation|tenured generation"
    r"|par new generation|concurrent mark-sweep generation)\s+total "
    + SIZE
    + r", used "
    + SIZE
)
YOUNG_GENERATIONS = ("PSYoungGen", "def new generation", "par new generation")
OLD_COLLECTORS = {
    "ParOldGen": "Parallel",
    "PSOldGen": "Parallel",
    "tenured generation": "Serial",
    "concurrent mark-sweep generation": "CMS",
}
ZGC_HEAP = re.compile(
    r"ZHeap\s+used "
    + SIZE
    + r", capacity "
    + SIZE
    + r"(?:, max capacity "
    + SIZE
    + r")?"
)
METASPACE = re.compile(
    r"Metaspace\s+used "
    + SIZE
    + r",(?: capacity "
    + SIZE
    + r",)? committed "
    + SIZE
    + r", reserved "
    + SIZE
)
FLAG = re.compile(r"(?m)^-XX:([+-]?)([A-Za-z][A-Za-z0-9_]{0,79})(?:=(\S{0,200}))?\s*$")
MAIN_FLAGS = ("MaxHeapSize", "InitialHeapSize", "MaxMetaspaceSize")
THREAD_FLAGS = ("ParallelGCThreads", "ConcGCThreads")
HEAP_EXPECTED = re.compile(
    r"garbage-first heap|PSYoungGen|ParOldGen|PSOldGen|def new generation"
    r"|tenured generation|par new generation|concurrent mark-sweep|ZHeap"
    r"|Shenandoah Heap|Metaspace\s+used"
)
EXPECTED = {
    "heap_info": HEAP_EXPECTED,
    "vm_flags": re.compile(r"(?m)^-XX:"),
    "gc_stat": re.compile(r"\bYGC\b"),
}
PAUSE_MS = re.compile(r"Pause\b.*?([0-9]{1,9}(?:\.[0-9]{1,6})?)ms\b")
PAUSE_SECS = re.compile(r"([0-9]{1,9}\.[0-9]{1,9}) secs\]")
ATTACH_REASONS = {
    "skipped:uid": "诊断账号既不是 root 也不是 JVM 属主，无法附加",
    "skipped:runuser": "目标机缺少 runuser，root 无法切换为 JVM 属主",
    "skipped:sigquit": "目标进程未捕获 SIGQUIT（以 -Xrs 启动，或是 jsvc 守护父进程而非 JVM），"
    "为免 SIGQUIT 终止进程已跳过 jcmd",
    "skipped:disabled": "启动参数含 -XX:+DisableAttachMechanism，JVM 禁止 attach",
    "missing_tool": "目标机缺少 jcmd/jstat（只装了 JRE），可安装同版本 JDK 工具或改用 gc_log 探针",
    "timeout": "jcmd/jstat 8 秒内无响应，JVM 可能卡在安全点或长时间 GC",
    "skipped:timeout": "前一个 jcmd 已超时，为免重复等待跳过了后续 jcmd",
    "failed": "附加失败：常见原因是 /tmp 下的 .java_pid 套接字或 hsperfdata 被定期清理、"
    "容器 PID/挂载命名空间隔离、JDK 版本不匹配或 -XX:-UsePerfData；错误详情见 stderr/warnings",
    "no_output": "没有取得该探针的输出（超时或输出被截断）",
}


def _kib(num, unit=""):
    value = number(num)
    return None if value is None else round(value * UNIT_KIB.get(unit, 1), 1)


def _section(text, name):
    """Body of `[AIOPS_<name>]`, or None when the marker is absent."""
    if "[AIOPS_" + name + "]" not in text:
        return None
    return section(text, name)


def _percent(part, whole):
    if part is None or not whole:
        return None
    return round(part * 100 / whole, 2)


def probe_state(probe, body):
    if body is None:
        return "no_output"
    skipped = re.search(r"(?m)^SKIPPED ([a-z_]{1,16})", body)
    if skipped:
        return "skipped:" + skipped[1]
    if "CAPABILITY_MISSING:" in body:
        return "missing_tool"
    if EXPECTED[probe].search(body):
        return "ok"
    if "Unknown diagnostic command" in body:
        return "unsupported"
    if _value(body, "RC") in ("124", "137"):
        return "timeout"
    return "failed"


def gc_log_state(body):
    if body is None:
        return "no_output"
    if "GC_LOG_NOT_CONFIGURED" in body:
        return "not_configured"
    if "GC_LOG_UNREADABLE" in body:
        return "unreadable"
    if "GC_LOG_FOREIGN_OWNER" in body:
        return "foreign_owner"
    return "ok" if _value(body, "FILE") else "failed"


def heap_info_of(body):
    """Heap layout from `jcmd GC.heap_info` for G1, Parallel, Serial, CMS, ZGC
    and Shenandoah; sizes in KiB."""
    heap = {}
    g1 = G1_HEAP.search(body)
    zgc = ZGC_HEAP.search(body)
    generations = GENERATIONS.findall(body)
    if g1:
        first, committed, used = (
            _kib(g1[1], g1[2]),
            _kib(g1[3], g1[4]) if g1[3] else None,
            _kib(g1[5], g1[6]),
        )
        heap.update(collector="G1", total_KiB=committed or first, used_KiB=used)
        if committed:
            heap["max_KiB"] = first
        regions = G1_REGIONS.search(body)
        if regions and used is not None:
            young = _kib(regions[4], regions[5])
            heap["young"] = {
                "used_KiB": young,
                "regions": int(regions[3]),
                "survivor_KiB": _kib(regions[7], regions[8]),
            }
            heap["old"] = {"used_KiB": round(max(0.0, used - (young or 0)), 1)}
    elif generations:
        young, old = {}, {}
        for name, total, total_unit, used, used_unit in generations:
            target = young if name in YOUNG_GENERATIONS else old
            target.update(
                name=name,
                total_KiB=_kib(total, total_unit),
                used_KiB=_kib(used, used_unit),
            )
            if target is old:
                heap["collector"] = OLD_COLLECTORS.get(name)
                if name == "tenured generation" and "par new" in body:
                    heap["collector"] = "ParNew"
        if young or old:
            heap["young"], heap["old"] = young, old
            if old.get("total_KiB"):
                old["used_percent"] = _percent(old.get("used_KiB"), old["total_KiB"])
            parts = [young, old]
            if all(p.get("total_KiB") is not None for p in parts):
                heap["total_KiB"] = round(sum(p["total_KiB"] for p in parts), 1)
            if all(p.get("used_KiB") is not None for p in parts):
                heap["used_KiB"] = round(sum(p["used_KiB"] for p in parts), 1)
    elif zgc:
        heap.update(
            collector="ZGC",
            used_KiB=_kib(zgc[1], zgc[2]),
            total_KiB=_kib(zgc[3], zgc[4]),
        )
        if zgc[5]:
            heap["max_KiB"] = _kib(zgc[5], zgc[6])
    elif "Shenandoah Heap" in body:
        segment = body.split("Shenandoah Heap", 1)[1][:600]
        found = {
            key: re.search(SIZE + pattern, segment)
            for key, pattern in (
                ("max_KiB", r" (?:max|total)\b"),
                ("total_KiB", r" committed"),
                ("used_KiB", r" used"),
            )
        }
        heap["collector"] = "Shenandoah"
        for key, match in found.items():
            if match:
                heap[key] = _kib(match[1], match[2])
    meta = METASPACE.search(body)
    if meta:
        heap["metaspace"] = {
            "used_KiB": _kib(meta[1], meta[2]),
            "committed_KiB": _kib(meta[5], meta[6]),
            "reserved_KiB": _kib(meta[7], meta[8]),
        }
    if heap:
        heap["source"] = "jcmd GC.heap_info"
    return heap


def _flag_value(text):
    if re.fullmatch(r"[0-9]{1,20}", text):
        return int(text)
    if re.fullmatch(r"-?[0-9]{1,15}(?:\.[0-9]{1,9})?", text):
        return number(text)
    return text[:80]


def flags_of(body):
    values = {}
    for sign, name, value in FLAG.findall(body):
        if len(values) >= 240:
            break
        values[name] = (sign == "+") if sign else _flag_value(value)
    flags = {key: values.get(key) for key in MAIN_FLAGS}
    flags["collector"] = next(
        (
            COLLECTORS[name]
            for name, on in values.items()
            if on is True and name in COLLECTORS
        ),
        None,
    )
    flags.update({key: values.get(key) for key in THREAD_FLAGS})
    flags.update([(k, v) for k, v in values.items() if k not in flags][:30])
    return flags


def jstat_of(body):
    """`jstat -gc` values by column name (columns differ between JDK 8 and 11+)."""
    rows = [line.split() for line in body.splitlines() if line.strip()]
    for index, names in enumerate(rows[:-1]):
        if "YGC" in names and len(rows[index + 1]) == len(names):
            return {
                name: number(value)
                for name, value in zip(names[:24], rows[index + 1][:24])
            }
    return {}


def gc_of(row, elapsed):
    gc = {}
    for key, column in (
        ("young_count", "YGC"),
        ("full_count", "FGC"),
        ("concurrent_count", "CGC"),
    ):
        if row.get(column) is not None:
            gc[key] = int(row[column])
    for key, column in (
        ("young_time_s", "YGCT"),
        ("full_time_s", "FGCT"),
        ("concurrent_time_s", "CGCT"),
        ("total_time_s", "GCT"),
    ):
        if row.get(column) is not None:
            gc[key] = round(row[column], 3)
    total = gc.get("total_time_s")
    if total is not None and elapsed:
        gc["gc_time_ratio"] = round(total / elapsed, 5)
        gc["gc_time_percent"] = round(total * 100 / elapsed, 3)
    gc["old_used_percent"] = _percent(row.get("OU"), row.get("OC"))
    gc["metaspace_used_percent"] = _percent(row.get("MU"), row.get("MC"))
    gc["columns"] = row
    return gc


def heap_from_jstat(row):
    """Heap totals from jstat capacities (JDK 8 has no GC.heap_info)."""

    def total(*columns):
        values = [row.get(column) for column in columns]
        return round(sum(values), 1) if all(v is not None for v in values) else None

    young = {
        "total_KiB": total("S0C", "S1C", "EC"),
        "used_KiB": total("S0U", "S1U", "EU"),
    }
    old = {
        "total_KiB": total("OC"),
        "used_KiB": total("OU"),
        "used_percent": _percent(row.get("OU"), row.get("OC")),
    }
    heap = {
        "total_KiB": total("S0C", "S1C", "EC", "OC"),
        "used_KiB": total("S0U", "S1U", "EU", "OU"),
        "young": young,
        "old": old,
        "source": "jstat -gc",
    }
    if row.get("MU") is not None:
        heap["metaspace"] = {"used_KiB": row["MU"], "committed_KiB": row.get("MC")}
    return heap if heap["used_KiB"] is not None else {}


def gc_log_summary(body):
    lines = [
        line[:300]
        for line in body.splitlines()
        if line.strip() and not line.startswith("FILE ")
    ][-40:]
    last = None
    for line in reversed(lines):
        match = PAUSE_MS.search(line)
        if match:
            last = number(match[1])
            break
        match = PAUSE_SECS.search(line)
        if match:
            seconds = number(match[1])
            last = None if seconds is None else round(seconds * 1000, 3)
            break
    return {
        "file": _value(body, "FILE") or None,
        "lines": lines,
        "full_pauses": sum("Pause Full" in line or "Full GC" in line for line in lines),
        "last_pause_ms": last,
    }


def attach_hint(failed):
    reasons = []
    for state in failed.values():
        reason = ATTACH_REASONS.get(state) or ATTACH_REASONS["failed"]
        if reason not in reasons:
            reasons.append(reason)
    return (
        "jcmd/jstat 需以 JVM 属主身份执行（同一用户，或 root 通过 runuser 切换）；"
        + "；".join(reasons)
    )


def parse_jvm(text: str, summary: dict, findings: list, options: dict) -> None:
    options = options if isinstance(options, dict) else {}
    probes = probes_of(options)
    summary["coverage"] = JVM_COVERAGE
    proc = _section(text, "PROC")
    pid = _int(_value(proc, "PID"))
    requested = options.get("pid")
    if pid is None and isinstance(requested, int) and not isinstance(requested, bool):
        pid = requested
    elapsed = _int(_value(proc, "ETIMES"))
    process = {
        "pid": pid,
        "user": _value(proc, "USER") or None,
        "elapsed_seconds": elapsed,
        "exe": _value(proc, "EXE") or None,
        "gc_log_path": _value(proc, "GCLOG") or None,
        "attach": "unknown",
    }
    summary["process"] = process
    if re.search(r"(?m)^AIOPS_REFUSED:pid\s*$", text):
        process["attach"] = "refused"
        process["comm"] = (_value(proc, "COMM") or "")[:40] or None
        findings.append(
            _finding(
                "warning",
                "pid_not_java",
                pid,
                "/proc/<pid>/comm 为 java 或 jsvc",
                "PID 不存在或不是 Java 进程，已拒绝附加（jcmd 的 SIGQUIT 会终止非 JVM 进程）；"
                "先用 ssh_diagnose_java 取得 Java 进程 PID",
            )
        )
        return
    # Each probe prints its own `[AIOPS_<PROBE>]` block (heap_info -> HEAP_INFO).
    bodies = {probe: _section(text, probe.upper()) for probe in probes}
    states = {
        probe: gc_log_state(body) if probe == "gc_log" else probe_state(probe, body)
        for probe, body in bodies.items()
    }
    summary["probes"] = states
    needed = [probe for probe in probes if probe in ATTACH_PROBES]
    if proc is None:
        attach = "unknown"
    elif not needed:
        attach = "not_requested"
    elif any(states[probe] in ("ok", "unsupported") for probe in needed):
        attach = "ok"
    elif "CAPABILITY_MISSING:runuser" in text or "missing_tool" in states.values():
        attach = "missing_tool"
    else:
        attach = "unavailable"
    process["attach"] = attach
    failed = {
        probe: states[probe]
        for probe in needed
        if states[probe] not in ("ok", "unsupported")
    }
    if proc is not None and failed:
        findings.append(
            _finding(
                "warning",
                "attach_failed",
                failed,
                "jcmd/jstat 可附加",
                attach_hint(failed),
            )
        )
    heap = heap_info_of(bodies["heap_info"]) if states.get("heap_info") == "ok" else {}
    flags = flags_of(bodies["vm_flags"]) if states.get("vm_flags") == "ok" else {}
    row = jstat_of(bodies["gc_stat"]) if states.get("gc_stat") == "ok" else {}
    if not heap.get("used_KiB") and row:
        metaspace = heap.get("metaspace")
        heap = heap_from_jstat(row) or heap
        if metaspace:
            heap["metaspace"] = metaspace
    max_heap = flags.get("MaxHeapSize")
    max_kib = (
        max_heap / 1024
        if isinstance(max_heap, int) and not isinstance(max_heap, bool) and max_heap
        else heap.get("max_KiB")
    )
    used = heap.get("used_KiB")
    if used is not None and (max_kib or heap.get("total_KiB")):
        heap["used_percent"] = _percent(used, max_kib or heap["total_KiB"])
        heap["used_percent_basis"] = "max_heap" if max_kib else "committed"
    if "heap_info" in probes or heap:
        summary["heap"] = heap
    if "vm_flags" in probes:
        summary["flags"] = flags
    gc = gc_of(row, elapsed) if row else {}
    if "gc_stat" in probes:
        summary["gc"] = gc
    gc_log = gc_log_summary(bodies["gc_log"]) if states.get("gc_log") == "ok" else {}
    if "gc_log" in probes:
        summary["gc_log"] = gc_log or {
            "file": None,
            "lines": [],
            "full_pauses": None,
            "last_pause_ms": None,
        }
    metric(
        summary,
        findings,
        "heap_used_percent",
        heap.get("used_percent"),
        "%",
        90,
        hint="堆使用率 ≥90%（经验值，≥95% 视为严重）；快照包含尚未回收的年轻代对象，"
        "需结合老年代占用、Full GC 次数与 GC 日志判断是否堆不足或泄漏"
        + (
            ""
            if heap.get("used_percent_basis") != "committed"
            else "；当前按已提交堆计算，未取得最大堆"
        ),
        critical=95,
    )
    old = gc.get("old_used_percent")
    if old is None:
        old = (heap.get("old") or {}).get("used_percent")
    metric(
        summary,
        findings,
        "old_gen_used_percent",
        old,
        "%",
        90,
        hint="老年代使用率 ≥90%（经验值）：接近 Full GC 或 OOM，结合 GC 日志看回收后是否仍居高不下",
    )
    metric(
        summary,
        findings,
        "gc_time_ratio",
        gc.get("gc_time_ratio"),
        threshold=0.02,
        hint="GC 累计耗时占进程运行时间 ≥2%（经验值，≥10% 视为严重）：吞吐受 GC 影响，"
        "检查堆大小、对象分配速率与 Full GC 原因",
        critical=0.1,
    )
    metric(
        summary,
        findings,
        "full_gc_count",
        gc.get("full_count"),
        threshold=10,
        hint="Full GC 次数是进程启动以来的累计值（≥10 次为经验阈值），需结合运行时长判断频率；"
        "JDK 8 的 CMS/G1 会把并发周期的初始标记与重新标记停顿也计入 FGC",
    )
    max_meta = flags.get("MaxMetaspaceSize")
    meta = heap.get("metaspace") or {}
    meta_used = meta.get("committed_KiB") or meta.get("used_KiB")
    if (
        isinstance(max_meta, int)
        and not isinstance(max_meta, bool)
        and 0 < max_meta < UNLIMITED
        and meta_used
    ):
        metric(
            summary,
            findings,
            "metaspace_limit_percent",
            meta_used * 1024 * 100 / max_meta,
            "%",
            90,
            hint="元空间已提交量达到 MaxMetaspaceSize 的 90%（经验值）：可能是类加载泄漏（动态代理、热部署、脚本引擎）"
            "或上限过低，超限会抛 OutOfMemoryError: Metaspace",
        )
    metric(
        summary,
        findings,
        "gc_log_full_pauses",
        gc_log.get("full_pauses"),
        threshold=3,
        hint="GC 日志最近 40 行出现 ≥3 次 Full GC（经验值）：查看触发原因"
        "（Allocation Failure、Metadata GC Threshold、System.gc() 等）",
    )


register(
    ActionSpec(
        id="java",
        tool="ssh_diagnose_java",
        title="Java 进程盘点",
        question="主机上有哪些 Java 进程？各自的应用、JDK、堆与 GC 参数、线程与句柄、日志位置是什么？",
        category="应用与中间件",
        params=(),
        script=java_script,
        parse=parse_java,
        sensitive=True,
        risk="low",
        timeout=20,
        output_limit=49152,
        estimated_seconds=5,
        notes=(
            "最多盘点 20 个 Java 进程；启动命令按密码、Token、密钥等键名二次脱敏，摘要只含 400 字符的 command_preview。",
        ),
    )
)
register(
    ActionSpec(
        id="jvm",
        tool="ssh_diagnose_jvm",
        title="JVM 堆与 GC 探针",
        question="指定 Java 进程的堆各代用量、生效 JVM 参数、GC 次数与累计耗时以及 GC 日志近况如何？",
        category="应用与中间件",
        params=(
            Param(
                "pid",
                "int",
                "Java 进程 PID（可先用 ssh_diagnose_java 获取）",
                required=True,
                minimum=1,
                maximum=4194304,
            ),
            Param(
                "probes",
                "list",
                "探针：heap_info、vm_flags、gc_stat、gc_log；缺省前三项",
                choices=PROBES,
                max_items=4,
            ),
        ),
        script=jvm_script,
        parse=parse_jvm,
        sensitive=True,
        risk="medium",
        timeout=30,
        output_limit=32768,
        estimated_seconds=12,
        notes=(
            "jcmd 会让 JVM 短暂进入安全点，生产高峰期谨慎使用；GC 计数是进程启动以来的累计值。",
        ),
    )
)
