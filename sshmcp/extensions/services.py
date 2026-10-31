"""systemd service deep dive (``service_detail``) and port/process/unit map (``service_map``).

service_detail reads one unit through ``systemctl show`` / ``systemctl cat``
(never start, stop, restart or reset-failed), lists the processes of its
cgroup and the sockets they listen on, the unit's journal in the window and
PID 1's lifecycle records for the unit over the last 24 hours. service_map
joins ``ss -ltnup`` listeners to processes, systemd units and containers.
Both are bounded snapshots; parsers keep "unknown" apart from "stopped".
"""

from __future__ import annotations

import re
import shlex

from . import (
    ActionSpec,
    Param,
    SERVICE_RE,
    guard,
    has_section,
    journal_permission_probe,
    quote,
    register,
    resolve_window,
    timed,
    unit_name,
)
from ..observations import LOG_PATTERNS, metric, section

SHOW_PROPERTIES = (
    "Id,Description,LoadState,UnitFileState,ActiveState,SubState,Result,MainPID,"
    "ExecMainPID,ExecMainStartTimestamp,ExecMainExitTimestamp,ExecMainCode,"
    "ExecMainStatus,NRestarts,Restart,RestartUSec,TimeoutStartUSec,TimeoutStopUSec,"
    "MemoryCurrent,MemoryMax,MemoryLimit,TasksCurrent,TasksMax,CPUUsageNSec,"
    "ActiveEnterTimestamp,InactiveEnterTimestamp,StateChangeTimestamp,ExecStart,"
    "ExecStartPre,User,Group,WorkingDirectory,FragmentPath,DropInPaths,LimitNOFILE,"
    "ControlGroup,StatusText,Type,KillMode"
)
# Monotonic twins (µs since boot) give epochs without parsing zone
# abbreviations: GNU date reads "CST" as US Central time, not China.
MONOTONIC_PROPERTIES = (
    "ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,"
    "ActiveEnterTimestampMonotonic,InactiveEnterTimestampMonotonic"
)
UNIT_KEYS = (
    r"^(\[|ExecStart|ExecStartPre|ExecStop|ExecReload|Restart|RestartSec|User|Group"
    r"|WorkingDirectory|Environment|EnvironmentFile|LimitNOFILE|LimitNPROC|MemoryMax"
    r"|MemoryLimit|TimeoutStartSec|TimeoutStopSec|Type|KillMode|After|Requires|Wants"
    r"|WantedBy|StartLimit|OOMScoreAdjust|Nice)"
)
UNSET = {"", "[not set]", "infinity", "18446744073709551615", "n/a"}
EXIT_CODES = {"1": "exited", "2": "killed", "3": "dumped"}
HISTORY_KINDS = {
    "started",
    "stopped",
    "failed",
    "exited",
    "restart_scheduled",
    "start_limit",
    "oom",
    "reload",
    "other",
}
SECRET_NAME = re.compile(r"(?i)password|passwd|secret|token|key|credential")
SECRET_ARG = re.compile(
    r"(?i)((?:^|\s)-{0,2}[\w.-]*(?:password|passwd|secret|token|key|credential)"
    r"[\w.-]*=)(\"[^\"]*\"|'[^']*'|\S+)"
)
STAMP = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?"
)

# Keep the first n lines within b bytes, each cut to w characters.
HEAD_AWK = """{
    x = substr($0, 1, w)
    used += length(x) + 1
    if (n < NR || b < used)
        exit
    print x
}"""
# Keep the newest n lines within b bytes, each cut to w characters.
TAIL_AWK = """{
    total++
    x = substr($0, 1, w)
    gsub(/CAPABILITY_MISSING/, "CAPABILITY-MISSING", x)
    buf[total % n] = x
}
END {
    s = total - n + 1
    if (s < 1)
        s = 1
    used = 0
    f = total + 1
    for (i = total; s <= i; i--) {
        if (b < used + length(buf[i % n]) + 1)
            break
        used += length(buf[i % n]) + 1
        f = i
    }
    for (i = f; i <= total; i++)
        print buf[i % n]
}"""
# Socket lines whose users:(( list names one of the unit's PIDs (pid=N, or the
# "name",N,fd form of old iproute2).
PORT_AWK = """BEGIN {
    n = split(pl, p, ",")
}
index($0, "users:((") {
    for (i = 1; i <= n; i++)
        if (index($0, "pid=" p[i] ",") || index($0, "\\"," p[i] ",")) {
            print
            next
        }
}"""
# PID 1 lifecycle records of the unit: kind per line, the newest 40 lines and
# counters over all of them (one canonical line per failure / restart).
HISTORY_AWK = """{
    k = ""
    if ($0 ~ /[Ss]tart request repeated too quickly|start-limit/)
        k = "start_limit"
    else if ($0 ~ /oom-kill|OOM killer|[Oo]ut of memory/)
        k = "oom"
    else if ($0 ~ /[Ss]cheduled restart|scheduling restart/)
        k = "restart_scheduled"
    else if ($0 ~ /Failed with result|entered failed state|Failed to start|failed[.]$|dumped core/)
        k = "failed"
    else if ($0 ~ /[Mm]ain process exited/)
        k = "exited"
    else if ($0 ~ /Started /)
        k = "started"
    else if ($0 ~ /Stopped |Deactivated|Killed |Killing /)
        k = "stopped"
    else if ($0 ~ /Reloaded |Reloading/)
        k = "reload"
    else if ($0 ~ /Starting |Stopping /)
        k = "other"
    if (k == "")
        next
    if ($0 ~ /Started /)
        sc++
    if ($0 ~ /Failed with result|entered failed state/)
        fc++
    if ($0 ~ /[Ss]cheduled restart|scheduling restart/)
        rc++
    if ($0 ~ /oom-kill|OOM killer/)
        oc++
    if ($0 ~ /[Ss]tart request repeated too quickly|start-limit-hit/)
        lc++
    total++
    buf[total % 40] = substr($0, 1, 200)
    kind[total % 40] = k
}
END {
    s = total - 39
    if (s < 1)
        s = 1
    for (i = s; i <= total; i++)
        print "H", kind[i % 40], buf[i % 40]
    print "HCOUNT starts", sc + 0
    print "HCOUNT failures", fc + 0
    print "HCOUNT restarts", rc + 0
    print "HCOUNT oom", oc + 0
    print "HCOUNT start_limit", lc + 0
}"""
# ss -ltnup without its header (no -H: iproute2 on EL7 lacks it).
LISTEN_AWK = """$1 == "Netid" || $1 == "State" {
    next
}
{
    c++
    x = substr($0, 1, w)
    used += length(x) + 1
    if (n < c || b < used)
        exit
    print x
}"""
# Unique PIDs named in users:(( lists, new (pid=N) and old ("name",N,fd) form.
PIDS_AWK = """{
    s = $0
    i = index(s, "users:((")
    if (i == 0)
        next
    s = substr(s, i + 8)
    while ((j = index(s, "\\",")) != 0) {
        s = substr(s, j + 2)
        t = s
        if (substr(t, 1, 4) == "pid=")
            t = substr(t, 5)
        sub(/[^0-9].*$/, "", t)
        if (t != "" && !(t in seen)) {
            seen[t] = 1
            print t
        }
    }
}"""
# /proc/PID/cgroup (v1 or v2) -> "<unit|-> <container|->": the deepest
# *.service component, or a 64-hex container id (docker-<id>.scope,
# libpod-<id>.scope, cri-containerd:<id>, /docker/<id>) shortened to 12.
CGROUP_AWK = """{
    path = $0
    sub(/^[^:]*:[^:]*:/, "", path)
    m = split(path, c, "/")
    for (i = 1; i <= m; i++) {
        if (c[i] ~ /[.]service$/)
            u = c[i]
        q = split(c[i], part, "[-:.]")
        for (j = 1; j <= q; j++)
            if (length(part[j]) == 64 && part[j] ~ /^[0-9a-f]+$/)
                ct = substr(part[j], 1, 12)
    }
}
END {
    if (ct != "" || u == "")
        u = "-"
    if (ct == "")
        ct = "-"
    print u, ct
}"""
# Joins "P pid user etimes rss" (ps) with "X pid comm unit container".
JOIN_AWK = """$1 == "P" && NF == 5 {
    us[$2] = $3
    et[$2] = $4
    rs[$2] = $5
    next
}
$1 == "X" && NF == 5 {
    m++
    order[m] = $2
    cm[$2] = $3
    un[$2] = $4
    ct[$2] = $5
}
END {
    for (i = 1; i <= m; i++) {
        p = order[i]
        u = "-"
        e = "-"
        r = "-"
        if (p in us) {
            u = us[p]
            e = et[p]
            r = rs[p]
        }
        print "PID", p, cm[p], u, e, r, un[p], ct[p]
    }
}"""

PS_COLUMNS = "pid=,ppid=,{user}=,etimes=,rss=,pcpu=,nlwp=,comm="


def _ps(columns: str) -> str:
    """ps for the PIDs in $pl; falls back from user:32 to the plain column."""
    wide = timed(3, "ps -o " + columns.format(user="user:32") + ' -p "$pl"')
    plain = timed(3, "ps -o " + columns.format(user="user") + ' -p "$pl"')
    return (
        "o=$("
        + wide
        + ' 2>/dev/null); if [ -z "$o" ]; then o=$('
        + plain
        + " 2>/dev/null); fi"
    )


def detail_script(options: dict) -> str:
    since, until = resolve_window({"minutes": int(options.get("minutes") or 30)})
    s, u, day = str(int(since)), str(int(until)), str(int(until) - 86400)
    unit = quote(options["service"])
    mangled = quote(unit_name(options["service"]))
    show = timed(
        4,
        "systemctl show --no-pager -p "
        + SHOW_PROPERTIES
        + ","
        + MONOTONIC_PROPERTIES
        + " -- "
        + unit,
    )
    parts = [
        guard("systemctl").rstrip(),
        "headawk='" + HEAD_AWK + "'",
        "tailawk='" + TAIL_AWK + "'",
        "portawk='" + PORT_AWK + "'",
        "hist='" + HISTORY_AWK + "'",
        "printf '[AIOPS_SHOW]\\n'",
        "show=$(" + show + " 2>/dev/null)",
        "printf '%s\\n' \"$show\" | cut -c1-300",
        # The canonical Id (aliases resolved) for journal matches; only the
        # unit-name alphabet passes, anything else falls back to the request.
        "id=$(printf '%s\\n' \"$show\" | sed -n 's/^Id=//p' | head -n 1)",
        "case \"$id\" in ''|*[!A-Za-z0-9_.@:-]*) id=" + mangled + ";; esac",
        "printf '[AIOPS_CLOCK]\\n'",
        "printf 'NOW %s\\n' \"$(date +%s)\"",
        "if [ -r /proc/uptime ]; then printf 'UPTIME %s\\n' \"$(cut -d' ' -f1 /proc/uptime)\"; fi",
        "printf 'WINDOW %s %s\\n' " + s + " " + u,
        "printf '[AIOPS_CAT]\\n'",
        timed(3, "systemctl cat -- " + unit)
        + " 2>/dev/null | grep -vE '^[[:space:]]*[#;]' | grep -E '"
        + UNIT_KEYS
        + '\' | awk -v n=60 -v b=6000 -v w=300 "$headawk"',
        "printf '[AIOPS_PROCS]\\n'",
        "cg=$(printf '%s\\n' \"$show\" | sed -n 's/^ControlGroup=//p' | head -n 1)",
        "mp=$(printf '%s\\n' \"$show\" | sed -n 's/^MainPID=//p' | head -n 1)",
        "pids=''; ok=0",
        'case "$cg" in /*) ok=1;; esac',
        'case "$cg" in *..*) ok=0;; esac',
        'if [ "$ok" = 1 ]; then for f in "/sys/fs/cgroup$cg/cgroup.procs" '
        '"/sys/fs/cgroup/unified$cg/cgroup.procs" "/sys/fs/cgroup/systemd$cg/cgroup.procs"; '
        "do if [ -r \"$f\" ]; then pids=$(head -n 30 \"$f\" 2>/dev/null | tr '\\n' ' '); "
        "printf 'PROCS_SOURCE %s\\n' \"$f\"; break; fi; done; fi",
        "if [ -z \"$(printf '%s' \"$pids\" | tr -dc '0-9')\" ]; then pids=''; "
        "case \"$mp\" in ''|0|*[!0-9]*) ;; *) pids=$mp; "
        "printf 'PROCS_SOURCE MainPID\\n';; esac; fi",
        "pl=$(printf '%s\\n' $pids | grep -E '^[0-9]+$' | head -n 30 | tr '\\n' ',' "
        "| sed 's/,*$//')",
        'if [ -n "$pl" ]; then',
        _ps(PS_COLUMNS),
        "printf '%s\\n' \"$o\" | head -n 30 | cut -c1-300",
        "else printf 'PROCS_NONE\\n'; fi",
        "printf '[AIOPS_PORTS]\\n'",
        "if [ -z \"$pl\" ]; then printf 'PORTS_UNAVAILABLE no-process\\n'",
        "elif ! command -v ss >/dev/null 2>&1; then printf 'PORTS_UNAVAILABLE ss-missing\\n'",
        "else",
        "lst=$(" + timed(4, "ss -ltnup") + " 2>/dev/null)",
        "case \"$lst\" in *'users:(('*) printf '%s\\n' \"$lst\" | "
        'awk -v pl="$pl" "$portawk" | head -n 40 | cut -c1-300;; '
        "*) printf 'PORTS_UNAVAILABLE no-process-info\\n';; esac",
        "fi",
        "printf '[AIOPS_JOURNAL]\\n'",
        "if command -v journalctl >/dev/null 2>&1; then",
        # Not JOURNAL_GUARD: the unit state is still useful without journal access.
        journal_permission_probe(),
        timed(
            5,
            'journalctl --no-pager -q -u "$id" --since @'
            + s
            + " --until @"
            + u
            + " -o short-iso",
        )
        + ' 2>/dev/null | awk -v n=80 -v b=8000 -v w=240 "$tailawk"',
        "printf '[AIOPS_HISTORY]\\n'",
        # PID 1's own records about the unit (and its core dumps): complete
        # for 24 h even when the service itself logs heavily.
        timed(
            4,
            "journalctl --no-pager -q -o short-iso --since @"
            + day
            + " --until @"
            + u
            + ' _PID=1 "UNIT=$id" + "COREDUMP_UNIT=$id"',
        )
        + ' 2>/dev/null | awk "$hist"',
        "else printf 'JOURNAL=missing\\n'; fi",
        "exit 0",
    ]
    return "\n".join(parts) + "\n"


def map_script(options: dict) -> str:
    parts = [
        guard("ss").rstrip(),
        "listen='" + LISTEN_AWK + "'",
        "pidawk='" + PIDS_AWK + "'",
        "cgawk='" + CGROUP_AWK + "'",
        "joinawk='" + JOIN_AWK + "'",
        "printf '[AIOPS_LISTEN]\\n'",
        "out=$("
        + timed(6, "ss -ltnup")
        + ' 2>/dev/null | awk -v n=120 -v b=20000 -v w=220 "$listen")',
        "printf '%s\\n' \"$out\"",
        "printf '[AIOPS_PIDS]\\n'",
        'pids=$(printf \'%s\\n\' "$out" | awk "$pidawk" | head -n 60)',
        "if [ -z \"$pids\" ]; then printf 'PROCESS_UNAVAILABLE\\n'; else",
        "pl=$(printf '%s\\n' \"$pids\" | tr '\\n' ',' | sed 's/,*$//')",
        _ps("pid=,{user}=,etimes=,rss="),
        "{ printf '%s\\n' \"$o\" | awk 'NF == 4 { print \"P\", $1, $2, $3, $4 }'",
        'for p in $pids; do c=-; read -r c 2>/dev/null < "/proc/$p/comm" || c=-; '
        "c=$(printf '%s' \"$c\" | tr -c 'A-Za-z0-9_.:@+-' '_' | cut -c1-32); "
        'g=$(awk "$cgawk" "/proc/$p/cgroup" 2>/dev/null); '
        'printf \'X %s %s %s\\n\' "$p" "${c:--}" "${g:-- -}"; done',
        '} | awk "$joinawk"',
        "fi",
        "exit 0",
    ]
    return "\n".join(parts) + "\n"


def _value(raw):
    if raw is None:
        return None
    value = raw.strip()
    return None if value in UNSET else value


def _number(raw):
    value = _value(raw)
    return (
        int(value) if value is not None and re.fullmatch(r"\d{1,20}", value) else None
    )


def _exit_code(raw):
    """ExecMainCode is a CLD_* number: 1 exited, 2 killed, 3 dumped; 0 none."""
    value = _value(raw)
    if value is None or value == "0":
        return None
    return EXIT_CODES.get(value, value[:16])


def _argv(raw):
    """argv[] of a systemctl show Exec* value, redacted and cut to 300."""
    value = _value(raw)
    if value is None:
        return None
    # argv may contain ";" (nginx -g "daemon on;"): stop only at the next
    # field (ignore_errors= on systemd 219, flags= later) or the closing brace;
    # a line cut at 300 characters keeps what it has.
    match = re.search(
        r"argv\[\]=(.*?)(?: ; (?:ignore_errors|flags|start_time)=|\s*\}?\s*$)", value
    )
    argv = (match[1] if match else value).strip()
    argv = SECRET_ARG.sub(lambda m: m[1] + "[REDACTED]", argv)
    return argv[:300] or None


def _redact_environment(value: str) -> str:
    """Environment= assignments whose name looks secret keep only the name."""
    try:
        tokens = shlex.split(value)
    except ValueError:
        return "[REDACTED]" if SECRET_NAME.search(value) else value
    out = []
    for token in tokens:
        name, sep, _ = token.partition("=")
        if sep and SECRET_NAME.search(name):
            token = name + "=[REDACTED]"
        out.append('"' + token + '"' if re.search(r"\s", token) else token)
    return " ".join(out)


def _unit_file(body: str) -> dict:
    lines, files = [], []
    for raw in body.splitlines():
        line = raw.rstrip()[:300]
        if not line.strip():
            continue
        key, sep, value = line.partition("=")
        key = key.strip()
        if sep and key == "Environment":
            line = "Environment=" + _redact_environment(value)
        elif sep and key == "EnvironmentFile":
            files.append(value.strip()[:200])
        lines.append(line[:300])
    return {"lines": lines[:60], "environment_files": files[:10]}


def _sockets(body: str) -> list[dict]:
    rows = []
    for raw in body.splitlines():
        fields = raw.split()
        if len(fields) < 6 or fields[0] not in ("tcp", "udp"):
            continue
        local = fields[4]
        host, _, port = local.rpartition(":")
        users = re.findall(
            r'\("((?:[^"\\]|\\.){0,64})",(?:pid=)?(\d{1,10}),(?:fd=)?\d{1,10}\)', raw
        )
        procs = sorted({(int(pid), name) for name, pid in users})
        rows.append(
            {
                "proto": fields[0],
                "address": host.strip("[]") or None,
                "port": int(port) if port.isdigit() else None,
                "pid": procs[0][0] if procs else None,
                "process": procs[0][1] if procs else None,
                "pids": [pid for pid, _ in procs][:8],
                "has_users": "users:((" in raw,
            }
        )
    return rows


def _journal_state(body: str, present: bool) -> str | None:
    if not present:
        return None
    if re.search(r"(?m)^JOURNAL=missing$", body):
        return "missing"
    if re.search(r"(?m)^CAPABILITY_MISSING:journal-permission$", body):
        return "limited"
    return "available"


def parse_detail(text: str, summary: dict, findings: list, options: dict) -> None:
    text = text if isinstance(text, str) else ""
    options = options if isinstance(options, dict) else {}
    props, execs = {}, {"ExecStart": [], "ExecStartPre": []}
    for raw in section(text, "SHOW").splitlines():
        match = re.match(r"^([A-Za-z]+)=(.*)$", raw)
        if not match:
            continue
        key, value = match[1], match[2]
        if key in execs:
            execs[key].append(value)
        props.setdefault(key, value)
    clock = section(text, "CLOCK")
    now = re.search(r"(?m)^NOW (\d{1,12})$", clock)
    uptime = re.search(r"(?m)^UPTIME (\d{1,10})(?:\.\d+)?$", clock)
    window = re.search(r"(?m)^WINDOW (\d{1,12}) (\d{1,12})$", clock)
    boot = int(now[1]) - int(uptime[1]) if now and uptime else None

    def epoch(name):
        mono = _number(props.get(name + "Monotonic"))
        return boot + mono // 1000000 if boot is not None and mono else None

    memory, memory_max = (
        _number(props.get("MemoryCurrent")),
        _number(props.get("MemoryMax")),
    )
    if memory_max is None:
        memory_max = _number(props.get("MemoryLimit"))
    cpu = _number(props.get("CPUUsageNSec"))
    drop_ins = (_value(props.get("DropInPaths")) or "").split()
    unit = {
        "id": _value(props.get("Id")),
        "description": (_value(props.get("Description")) or "")[:160] or None,
        "load": _value(props.get("LoadState")),
        "unit_file": _value(props.get("UnitFileState")),
        "active": _value(props.get("ActiveState")),
        "sub": _value(props.get("SubState")),
        "result": _value(props.get("Result")),
        "main_pid": _number(props.get("MainPID")) or None,
        "started_at": _value(props.get("ExecMainStartTimestamp")),
        "started_epoch": epoch("ExecMainStartTimestamp"),
        "exited_at": _value(props.get("ExecMainExitTimestamp")),
        "exit_code": _exit_code(props.get("ExecMainCode")),
        "exit_status": _number(props.get("ExecMainStatus")),
        "restarts": _number(props.get("NRestarts")),
        "restart_policy": _value(props.get("Restart")),
        "restart_delay": _value(props.get("RestartUSec")),
        "timeout_start": _value(props.get("TimeoutStartUSec")),
        "memory_bytes": memory,
        "memory_max": memory_max,
        "tasks": _number(props.get("TasksCurrent")),
        "tasks_max": _number(props.get("TasksMax")),
        "cpu_seconds": round(cpu / 1e9, 3) if cpu is not None else None,
        "active_since": _value(props.get("ActiveEnterTimestamp")),
        "inactive_since": _value(props.get("InactiveEnterTimestamp")),
        "state_changed": _value(props.get("StateChangeTimestamp")),
        "exec_start": _argv(execs["ExecStart"][0]) if execs["ExecStart"] else None,
        "exec_start_pre": [a for a in map(_argv, execs["ExecStartPre"][:5]) if a],
        "user": _value(props.get("User")),
        "group": _value(props.get("Group")),
        "cwd": _value(props.get("WorkingDirectory")),
        "fragment_path": _value(props.get("FragmentPath")),
        "drop_ins": drop_ins[:10],
        "limit_nofile": _number(props.get("LimitNOFILE")),
        "type": _value(props.get("Type")),
        "kill_mode": _value(props.get("KillMode")),
        "status_text": (_value(props.get("StatusText")) or "")[:200] or None,
    }

    processes = []
    for match in re.finditer(
        r"(?m)^\s*(\d{1,10})\s+(\d{1,10})\s+(\S{1,32})\s+(\d{1,12})\s+(\d{1,15})"
        r"\s+(\d{1,5}(?:\.\d+)?)\s+(\d{1,7})\s+(\S.{0,63})$",
        section(text, "PROCS"),
    ):
        processes.append(
            {
                "pid": int(match[1]),
                "ppid": int(match[2]),
                "user": match[3],
                "elapsed_seconds": int(match[4]),
                "rss_KiB": int(match[5]),
                "cpu_percent": float(match[6]),
                "threads": int(match[7]),
                "name": match[8].strip(),
            }
        )
    ports_text = section(text, "PORTS")
    listening = [
        {key: row[key] for key in ("proto", "address", "port", "pid")}
        for row in _sockets(ports_text)
    ][:40]
    ports_available = has_section(text, "PORTS") and not re.search(
        r"(?m)^PORTS_UNAVAILABLE", ports_text
    )

    journal_text = section(text, "JOURNAL")
    access = _journal_state(journal_text, has_section(text, "JOURNAL"))
    entries = [
        line[:240]
        for line in journal_text.splitlines()
        if line.strip()
        and not re.fullmatch(r"JOURNAL=missing|CAPABILITY_MISSING:[\w-]+", line.strip())
    ][-80:]
    matched = {}
    for line in entries:
        for kind, pattern in LOG_PATTERNS:
            if re.search(pattern, line) and len(matched.setdefault(kind, [])) < 20:
                matched[kind].append(line)

    history_text = section(text, "HISTORY")
    history = []
    for match in re.finditer(r"(?m)^H (\w+) (.+)$", history_text):
        stamp = STAMP.match(match[2])
        history.append(
            {
                "time": stamp[0] if stamp else None,
                "kind": match[1] if match[1] in HISTORY_KINDS else "other",
                "line": match[2][:240],
            }
        )
    hcounts = {
        m[1]: int(m[2])
        for m in re.finditer(
            r"(?m)^HCOUNT (starts|failures|restarts|oom|start_limit) (\d{1,9})$",
            history_text,
        )
    }
    counts = {
        "restarts_24h": hcounts.get("restarts"),
        "failures_24h": hcounts.get("failures"),
        "starts_24h": hcounts.get("starts"),
    }
    since = int(window[1]) if window else None

    summary.update(
        {
            "unit": unit,
            "unit_file": _unit_file(section(text, "CAT")),
            "processes": processes[:30],
            "listening": listening,
            "ports_available": ports_available,
            "journal": {
                "entries": entries,
                "matched": matched,
                "journal_access": access,
            },
            "history": history[-40:],
            "counts": counts,
            "coverage": _detail_coverage(text, access, options),
        }
    )
    _detail_findings(summary, findings, unit, counts, hcounts, matched, history, since)
    if access == "limited":
        findings.append(
            {
                "level": "warning",
                "metric": "journal_access",
                "value": "limited",
                "threshold": "root 或 systemd-journal/adm/wheel 组",
                "hint": "诊断账号不在 systemd-journal/adm/wheel 组：单元日志与重启记录可能为空或不完整，不能视为无异常",
            }
        )


def _detail_coverage(text, access, options) -> str:
    if "CAPABILITY_MISSING:systemctl" in text and not has_section(text, "SHOW"):
        return "目标没有 systemctl，无法读取 systemd 单元；不能据此判断服务状态"
    minutes = options.get("minutes") if isinstance(options.get("minutes"), int) else 30
    journal = {
        "available": f"最近 {minutes} 分钟单元日志（最多 80 行）与近 24 小时 PID 1 生命周期记录（最多 40 行）",
        "limited": "单元日志受账号权限限制，只含本账号可见部分",
        "missing": "主机没有 journalctl，无单元日志与重启记录",
    }.get(access, "单元日志未采集")
    return (
        "systemctl show/cat 当前状态与单元文件、cgroup 进程与监听端口快照；"
        + journal
        + "；只读，不启动、不重启、不 reset-failed"
    )


def _finding(findings, level, name, value, threshold, hint):
    findings.append(
        {
            "level": level,
            "metric": name,
            "value": value,
            "threshold": threshold,
            "hint": hint,
        }
    )


def _detail_findings(summary, findings, unit, counts, hcounts, matched, history, since):
    if unit["load"] == "not-found":
        _finding(
            findings,
            "warning",
            "unit_not_found",
            unit["id"] or "unknown",
            "loaded",
            "systemd 中没有这个单元：核对单元名（如 nginx 与 openresty、sshd 与 ssh），"
            "或改用进程、端口证据；不能据此判定服务已停止",
        )
        return
    if unit["load"] is None and unit["active"] is None:
        return
    result, active = unit["result"], unit["active"]
    if active == "failed" or result not in (None, "success"):
        _finding(
            findings,
            "critical",
            "service_failed",
            f"{active}/{result}",
            "active/success",
            "单元处于 failed 或上次运行以非 success 结束（exit-code / signal / timeout / oom-kill 等）；"
            "查看 exit_code、exit_status 与 journal、history 中的失败记录",
        )
    elif active == "inactive":
        _finding(
            findings,
            "warning",
            "service_inactive",
            f"{active}/{unit['sub']}",
            "active",
            "单元未运行且上次正常结束：确认是否按设计停用（unit_file 为 disabled/static）或被人工停止",
        )
    restarts = max(unit["restarts"] or 0, counts["restarts_24h"] or 0)
    if restarts >= 3:
        _finding(
            findings,
            "critical",
            "restart_loop",
            {"NRestarts": unit["restarts"], "restarts_24h": counts["restarts_24h"]},
            3,
            "服务反复被 systemd 自动重启（经验阈值 ≥3 次）；查看 history 中每次退出的原因与 exit_status，"
            "修复根因前不要单纯拉长 RestartSec",
        )
    started = unit["started_epoch"]
    if since is not None and started is not None and since <= started:
        _finding(
            findings,
            "warning",
            "recent_restart",
            unit["started_at"],
            "窗口开始前已运行",
            "主进程在本窗口内（重新）启动过：核对启动前后的日志、发布或人工操作记录",
        )
    if unit["exit_code"] == "exited" and unit["exit_status"] not in (None, 0):
        _finding(
            findings,
            "warning",
            "exit_nonzero",
            unit["exit_status"],
            0,
            "主进程上次以非零状态码退出；结合 journal 中退出前的错误行定位原因",
        )
    oom_lines = matched.get("oom") or [h for h in history if h["kind"] == "oom"]
    if result == "oom-kill" or hcounts.get("oom") or oom_lines:
        _finding(
            findings,
            "critical",
            "oom_killed",
            result if result == "oom-kill" else len(oom_lines) or hcounts.get("oom"),
            "无 OOM",
            "该服务的进程被 OOM killer 终止：核查 memory_max（MemoryMax）、应用内存增长与主机可用内存",
        )
    if result == "timeout":
        _finding(
            findings,
            "critical",
            "start_timeout",
            unit["timeout_start"],
            "在 TimeoutStartSec 内完成",
            "启动或停止超过 systemd 时限被终止：检查启动依赖（数据库、网络、挂载）与 TimeoutStartSec",
        )
    journal_hits = sum(
        "start request repeated too quickly" in line.lower()
        for lines in matched.values()
        for line in lines
    )
    if result in ("start-limit-hit", "start-limit"):
        limit_hit = result
    else:
        limit_hit = hcounts.get("start_limit") or journal_hits
    if limit_hit:
        _finding(
            findings,
            "critical",
            "start_limit_hit",
            limit_hit,
            "未触发 StartLimitBurst",
            "启动过于频繁触发了 StartLimitBurst/StartLimitIntervalSec，systemd 不再自动拉起；"
            "修复根因后需人工执行 systemctl reset-failed 再启动（本工具不会执行）",
        )
    for name, used, limit, label in (
        ("memory_near_max", unit["memory_bytes"], unit["memory_max"], "内存"),
        ("tasks_near_max", unit["tasks"], unit["tasks_max"], "任务数"),
    ):
        if used is None or not limit:
            continue
        percent = round(used * 100 / limit, 1)
        metric(
            summary, findings, name.replace("near_max", "percent_of_max"), percent, "%"
        )
        if percent >= 90:
            _finding(
                findings,
                "warning",
                name,
                percent,
                90,
                f"{label}已达 cgroup 上限的 {percent}%（经验阈值 90%）：接近上限会触发 OOM 或 fork 失败，"
                "核查增长趋势与上限设置",
            )


def parse_map(text: str, summary: dict, findings: list, options: dict) -> None:
    text = text if isinstance(text, str) else ""
    info = {}
    for match in re.finditer(
        r"(?m)^PID (\d{1,10}) (\S{1,64}) (\S{1,64}) (\S{1,20}) (\S{1,20}) (\S{1,160}) (\S{1,64})$",
        section(text, "PIDS"),
    ):
        info[int(match[1])] = {
            "process": None if match[2] == "-" else match[2],
            "user": None if match[3] == "-" else match[3],
            "elapsed_seconds": int(match[4]) if match[4].isdigit() else None,
            "rss_KiB": int(match[5]) if match[5].isdigit() else None,
            "unit": None if match[6] == "-" else match[6],
            "container": None if match[7] == "-" else match[7],
        }
    sockets = _sockets(section(text, "LISTEN"))
    listeners = []
    for row in sockets:
        extra = info.get(row["pid"], {})
        listeners.append(
            {
                "proto": row["proto"],
                "address": row["address"],
                "port": row["port"],
                "pid": row["pid"],
                "process": row["process"] or extra.get("process"),
                "user": extra.get("user"),
                "unit": extra.get("unit"),
                "container": extra.get("container"),
                "elapsed_seconds": extra.get("elapsed_seconds"),
                "rss_KiB": extra.get("rss_KiB"),
            }
        )
    listeners.sort(
        key=lambda r: (
            r["port"] is None,
            r["port"] or 0,
            r["proto"],
            r["address"] or "",
        )
    )
    by_unit = {}
    for row in listeners:
        owner = row["unit"] or (
            "container:" + row["container"] if row["container"] else None
        )
        if owner and row["port"] is not None:
            by_unit.setdefault(owner, set()).add(row["port"])
    available = any(row["has_users"] for row in sockets) and not re.search(
        r"(?m)^PROCESS_UNAVAILABLE$", text
    )
    without = sorted({r["port"] for r in listeners if r["pid"] is None and r["port"]})
    summary.update(
        {
            "listeners": listeners[:80],
            "by_unit": {k: sorted(v) for k, v in sorted(by_unit.items())},
            "ports_without_process": without[:80],
            "process_info_available": available,
            "coverage": (
                "ss -ltnup 当前监听快照（最多 120 行，返回 80 个）关联进程、systemd 单元与容器；"
                + (
                    "进程归属完整"
                    if available and not without
                    else "部分或全部端口没有进程归属（非 root 只能看到本账号的进程）"
                )
                + "；端口不在列表中只说明采集时未监听"
            ),
        }
    )
    metric(summary, findings, "listening_sockets", len(sockets))
    if sockets and not available:
        _finding(
            findings,
            "info",
            "process_info_unavailable",
            len(sockets),
            "端口带进程归属",
            "ss 没有返回进程信息：需要 root（或 CAP_NET_ADMIN/CAP_SYS_PTRACE）才能看到其他用户进程占用的端口",
        )
    owners = {}
    for row in listeners:
        if row["port"] is not None and row["process"]:
            owners.setdefault((row["proto"], row["port"]), set()).add(row["process"])
    shared = [
        f"{proto}/{port}: " + "/".join(sorted(names))
        for (proto, port), names in sorted(owners.items(), key=lambda kv: kv[0][1])
        if len(names) > 1
    ]
    if shared:
        _finding(
            findings,
            "info",
            "duplicate_port",
            shared[:10],
            "每个端口一个程序",
            "同一端口被不同程序监听（可能分别绑定 IPv4/IPv6 或不同地址，也可能是 SO_REUSEPORT）；确认是否符合预期",
        )
    if len(sockets) >= 60:
        _finding(
            findings,
            "info",
            "many_listeners",
            len(sockets),
            60,
            "监听套接字较多（经验阈值 60）：核对是否有未预期的服务或调试端口暴露",
        )


register(
    ActionSpec(
        id="service_detail",
        tool="ssh_diagnose_service_detail",
        title="服务深度诊断",
        question="指定 systemd 服务的状态、退出原因、重启记录、进程、端口与日志如何？",
        category="服务与日志",
        params=(
            Param(
                "service",
                "str",
                "systemd 单元名，如 nginx.service、app@1.service",
                required=True,
                pattern=SERVICE_RE,
                max_length=64,
            ),
            Param(
                "minutes",
                "int",
                "日志回溯窗口（分钟，1–1440）",
                default=30,
                minimum=1,
                maximum=1440,
            ),
        ),
        script=detail_script,
        parse=parse_detail,
        sensitive=True,
        risk="low",
        timeout=25,
        output_limit=49152,
        estimated_seconds=6,
        notes=(
            "只读：不启动、不重启、不 reset-failed；单元文件中的敏感环境变量值会被替换为 [REDACTED]。",
        ),
    )
)

register(
    ActionSpec(
        id="service_map",
        tool="ssh_diagnose_service_map",
        title="端口与服务映射",
        question="哪个进程、systemd 单元或容器在监听哪些端口？",
        category="网络",
        params=(),
        script=map_script,
        parse=parse_map,
        sensitive=False,
        risk="low",
        timeout=15,
        output_limit=32768,
        estimated_seconds=4,
        notes=("非 root 账号只能看到自己进程的端口归属。",),
    )
)
