"""System log diagnostics (``syslog``): journalctl with /var/log fallback.

journalctl is preferred: exact priorities, unit and PID matches and counts per
level. When journalctl is missing, the account cannot read the system journal,
or the journal does not reach back to the window start (volatile journald,
rotation), the rsyslog file (/var/log/messages or /var/log/syslog) is filtered
on the host by time, unit, PID and keyword instead; the priority is then only
approximated by keywords and the summary says so.

One POSIX awk pass per source keeps the newest lines within a byte budget,
counts every matching line, ranks the logging units and classifies OOM / I/O /
link / service / kernel / auth lines over the whole window, so only bounded
evidence leaves the host. Window bounds are absolute Unix seconds computed by
the server (``journalctl --since @N``, systemd >= 219); the file fallback
compares MMDDHHMMSS keys built by the host's ``date`` in its local time.
"""

from __future__ import annotations

import re

from . import (
    KEYWORD_RE,
    SERVICE_RE,
    WINDOW_PARAMS,
    ActionSpec,
    Param,
    quote,
    register,
    resolve_window,
    timed,
)
from ..observations import LOG_PATTERNS, metric, section

PRIORITIES = ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug")
# Level counts (journalctl -p FROM..TO); a range runs when the requested
# priority includes it, crit (emerg/alert/crit) always.
COUNT_RANGES = (("crit", "0..2", 2), ("err", "3..3", 3), ("warning", "4..4", 4))
SYSLOG_FILES = ("/var/log/messages", "/var/log/syslog")
AUTH_FILES = ("/var/log/secure", "/var/log/auth.log")
SOURCE_FILES = SYSLOG_FILES + AUTH_FILES + ("/var/log/kern.log",)
FILE_TAIL_BYTES = 20000000
AUTH_TAIL_BYTES = 5000000
LINE_CHARS = 240
# Bytes of log lines per source so the whole output stays near 24 KiB.
JOURNAL_BUDGET = 16000
SHARED_BUDGETS = (6000, 9000)  # journal, file: both sources are read
UNIT_SUFFIXES = (
    ".service",
    ".socket",
    ".target",
    ".timer",
    ".path",
    ".mount",
    ".automount",
    ".swap",
    ".slice",
    ".scope",
    ".device",
)
# POSIX ERE equivalents of observations.LOG_PATTERNS (matched against the
# lower-cased line on the host), so the classification spans the whole window.
AWK_PATTERNS = {
    "oom": "oom[- ]kill|out of memory|killed process",
    "io_error": "i/o error|blk_update_request|ext4-fs error|xfs_|buffer i/o"
    "|read-only file system|remounting|medium error",
    "network": "link is down|link down|nic link|carrier lost|no carrier",
    "service": "failed to start|failed with result|start request repeated too quickly"
    "|main process exited|entered failed state",
    "kernel": "segfault|soft lockup|hung_task|hung task|nmi watchdog"
    "|general protection|call trace|bug:",
    "auth": "failed password|authentication failure|invalid user|possible break-in",
}
KINDS = tuple(AWK_PATTERNS)
# Files carry no syslog priority: warning and stricter keep lines with these
# words (plus every classified pattern above) and the result says so.
PRIORITY_WORDS = "|".join(
    (
        "error|fail|crit|emerg|alert|warn|denied|refused|timeout|timed out|oom"
        "|panic|segfault|unreachable",
    )
    + tuple(AWK_PATTERNS.values())
)

# Shared by the file and auth programs: MMDDHHMMSS key of a classic rsyslog
# line ("Oct 29 14:03:21 host tag: msg") or an RFC 3339 one
# ("2026-10-29T14:03:21.123+08:00 host tag: msg"); "" when $0 has no stamp.
# Comparisons are written with < / <= only: the script never contains ">"
# except the /dev/null redirections.
TIME_AWK = r"""
function key(  m, d, t) {
    if ($1 ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)
        return substr($1, 6, 2) substr($1, 9, 2) substr($1, 12, 2) substr($1, 15, 2) substr($1, 18, 2)
    m = tolower($1)
    if (!(m in mon) || $2 !~ /^[0-9][0-9]?$/ || $3 !~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/)
        return ""
    d = $2
    if (length(d) == 1)
        d = "0" d
    t = $3
    gsub(/:/, "", t)
    return mon[m] d t
}
function inwin(k) {
    if (wrap)
        return sk <= k || k <= uk
    return sk <= k && k <= uk
}
function timesetup(  i) {
    split("jan feb mar apr may jun jul aug sep oct nov dec", mn, " ")
    for (i = 1; i <= 12; i++)
        mon[mn[i]] = sprintf("%02d", i)
    sk = sk ""
    uk = uk ""
    if (tf && (sk == "" || uk == "")) {
        tf = 0
        notime = 1
    }
    wrap = 0
    if (tf && uk < sk)
        wrap = 1
    cur = 1
    if (tf)
        cur = 0
}
"""

# One pass over one source (journal short-iso or a syslog file). -v: n lines
# kept, b byte budget, w line width, tf time filter (sk/uk keys, tz host
# offset), jr journal stream (AIOPS_RC marker), kw keyword (literal,
# case-insensitive), tag/unit/pid file filters, approx keyword priority.
AGG_AWK = (
    TIME_AWK
    + r"""
function stamp(  m) {
    if ($1 ~ /^[0-9][0-9][0-9][0-9]-/)
        return $1
    m = tolower($1)
    if (m in mon)
        return $1 " " $2 " " $3
    return ""
}
function cut(x) {
    x = substr(x, 1, w)
    gsub(/CAPABILITY_MISSING/, "CAPABILITY-MISSING", x)
    return x
}
function entry(x) {
    x = cut(x)
    if (x ~ /^[A-Z_]+[ =:]/ || x ~ /^\[/)
        x = " " x
    return x
}
BEGIN {
    timesetup()
    kw = tolower(kw)
    nk = split("@KINDS@", kn, " ")
@PATTERNS@
    pre = "@PRIORITY@"
}
jr && /^AIOPS_RC [0-9]+$/ {
    rc = $2
    next
}
NF == 0 {
    next
}
{
    if (tf) {
        k = key()
        if (k != "") {
            if (fk == "")
                fk = k
            cur = inwin(k)
            if (!tzc && $1 ~ /T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) {
                tzc = 1
                o = $1
                sub(/^[^T]*T[0-9:.]*/, "", o)
                gsub(/:/, "", o)
                if (o == "Z")
                    o = "+0000"
                if (tz != "" && o != "" && o != tz)
                    tzm = o
            }
        }
        if (!cur)
            next
    }
    if (tag != "" && !index($0, " " tag "[") && !index($0, " " tag ":") && !index($0, unit))
        next
    if (pid != "" && !index($0, "[" pid "]"))
        next
    low = tolower($0)
    if (kw != "" && !index(low, kw))
        next
    if (approx && low !~ pre)
        next
    total++
    buf[total % n] = $0
    if ($0 !~ /^[ \t]/) {
        s = stamp()
        if (s != "") {
            if (fa == "")
                fa = s
            la = s
        }
        u = $5
        if ($1 ~ /^[0-9][0-9][0-9][0-9]-/)
            u = $3
        sub(/\[.*$/, "", u)
        sub(/:$/, "", u)
        if (u != "")
            uc[u]++
    }
    for (i = 1; i <= nk; i++)
        if (low ~ kre[i]) {
            mc[i]++
            if (mc[i] <= 3)
                ml[i, mc[i]] = $0
        }
}
END {
    s = total - n + 1
    if (s < 1)
        s = 1
    used = 0
    f = total + 1
    for (i = total; s <= i; i--) {
        x = entry(buf[i % n])
        if (b < used + length(x) + 1)
            break
        used += length(x) + 1
        out[i] = x
        f = i
    }
    for (i = f; i <= total; i++)
        print out[i]
    print "LINES_TOTAL", total + 0
    if (s < f)
        print "ENTRIES_CLIPPED", total - f + 1
    for (i = 1; i <= nk; i++)
        if (mc[i]) {
            print "MATCH", kn[i], mc[i]
            for (j = 1; j <= mc[i] && j <= 3; j++)
                print "MATCHLINE", kn[i], substr(cut(ml[i, j]), 1, 200)
        }
    for (k = 1; k <= 15; k++) {
        bu = ""
        bc = 0
        for (u in uc)
            if (bc < uc[u]) {
                bu = u
                bc = uc[u]
            }
        if (bu == "")
            break
        print "UNIT", bu, bc
        delete uc[bu]
    }
    if (fa != "")
        print "FIRST_AT", fa
    if (la != "")
        print "LAST_AT", la
    if (rc != "" && rc != 0)
        print "EXIT", rc
    if (notime)
        print "NO_TIME_FILTER"
    if (wrap)
        print "YEAR_WRAP"
    if (tf && fk == "")
        print "NO_TIMESTAMPS"
    if (tf && fk != "" && !wrap && sk < fk)
        print "STARTS_AFTER_SINCE", fk
    if (tzm != "")
        print "TZ_MISMATCH", tzm
    if (approx)
        print "PRIORITY_APPROX=keyword"
}
"""
)
AGG_AWK = (
    AGG_AWK.replace("@KINDS@", " ".join(KINDS))
    .replace(
        "@PATTERNS@",
        "\n".join(
            "    kre[" + str(i) + '] = "' + AWK_PATTERNS[kind] + '"'
            for i, kind in enumerate(KINDS, 1)
        ),
    )
    .replace("@PRIORITY@", PRIORITY_WORDS)
)

# sshd login audit: -v tf (time filter for files; the journal is filtered by
# journalctl), sk/uk keys. Sources counted from failure lines only.
AUTH_AWK = (
    TIME_AWK
    + r"""
BEGIN {
    timesetup()
}
{
    if (tf) {
        k = key()
        if (k != "")
            cur = inwin(k)
        if (!cur)
            next
    }
    hit = 0
    if (index($0, "Failed password")) {
        failed++
        hit = 1
    }
    if (index($0, "Invalid user")) {
        invalid++
        hit = 1
    }
    if (index($0, "Accepted "))
        accepted++
    if (hit) {
        i = index($0, " from ")
        if (i) {
            ip = substr($0, i + 6)
            sub(/ .*$/, "", ip)
            if (ip ~ /^[0-9A-Fa-f:.]+$/)
                src[ip]++
        }
    }
}
END {
    print "FAILED", failed + 0
    print "INVALID", invalid + 0
    print "ACCEPTED", accepted + 0
    for (k = 1; k <= 5; k++) {
        bi = ""
        bc = 0
        for (ip in src)
            if (bc < src[ip]) {
                bi = ip
                bc = src[ip]
            }
        if (bi == "")
            break
        print "TOP_SOURCE", bc, bi
        delete src[bi]
    }
}
"""
)

# Entries of one journalctl -p range, plus its exit code (124 = timed out).
COUNT_AWK = (
    "/^AIOPS_RC [0-9]+$/ { rc = $2; next } /^[0-9]/ { n++ } END { print n + 0, rc + 0 }"
)

# Not JOURNAL_GUARD: a missing journalctl or a limited account falls back to
# the files instead of exiting.
PERMISSION_PROBE = (
    "if [ \"$(id -u)\" != 0 ] && ! id -nG 2>/dev/null | tr ' ' '\\n' | "
    "grep -qxE 'systemd-journal|adm|wheel|root'; then jlim=1; "
    "printf 'CAPABILITY_MISSING:journal-permission\\n'; fi"
)


def _mangle(unit: str) -> str:
    return unit if unit.endswith(UNIT_SUFFIXES) else unit + ".service"


def script(options: dict) -> str:
    since, until = resolve_window(options)
    s, u = str(int(since)), str(int(until))
    lines = str(int(options.get("lines") or 120))
    priority = options.get("priority") or "warning"
    level = PRIORITIES.index(priority)
    unit, keyword, pid = options.get("unit"), options.get("keyword"), options.get("pid")
    window = " --since @" + s + " --until @" + u
    matches = (" -u " + quote(unit) if unit else "") + (
        " _PID=" + str(int(pid)) if pid is not None else ""
    )
    keyword_var = " -v kw=" + (quote(keyword) if keyword else "''")
    # Literal, case-insensitive; the second pattern keeps the exit-code marker.
    keyword_grep = (
        " | grep -i -F -e " + quote(keyword) + " -e 'AIOPS_RC '" if keyword else ""
    )
    journal = "journalctl --no-pager -q -o short-iso" + window
    if unit:
        tag = unit[: -len(".service")] if unit.endswith(".service") else unit
        file_filters = " -v tag=" + quote(tag) + " -v unit=" + quote(_mangle(unit))
    else:
        file_filters = " -v tag='' -v unit=''"
    file_filters += " -v pid=" + (str(int(pid)) if pid is not None else "''")
    file_filters += " -v approx=" + (
        "1" if level <= PRIORITIES.index("warning") else "0"
    )
    counts = [
        "printf 'COUNT "
        + name
        + " %s\\n' \"$( { "
        + timed(2, journal + " -p " + span + matches)
        + '; printf \'\\nAIOPS_RC %s\\n\' "$?"; } 2>/dev/null | awk "$cnt")"'
        for name, span, top in COUNT_RANGES
        if top <= max(level, 2)
    ]
    parts = [
        "agg='" + AGG_AWK + "'",
        "authawk='" + AUTH_AWK + "'",
        "cnt='" + COUNT_AWK + "'",
        "printf '[AIOPS_SOURCE]\\n'",
        "printf 'WINDOW %s %s\\n' " + s + " " + u,
        "printf 'NOW %s\\n' \"$(date +%s)\"",
        "jc=0; jlim=0; cover=no",
        "if command -v journalctl >/dev/null 2>&1; then",
        "jc=1; printf 'JOURNAL=available\\n'",
        PERMISSION_PROBE,
        # Is there an entry before the window start? -r + --until seeks there
        # on systemd 219 too (short-unix and --until with plain -n do not).
        "c=$("
        + timed(3, "journalctl --no-pager -q -r -o short-iso --until @" + s + " -n 1")
        + " 2>/dev/null | grep -c '^[0-9]')",
        "case \"$c\" in ''|0) ;; *) cover=yes;; esac",
        "printf 'JOURNAL_COVERS_WINDOW=%s\\n' \"$cover\"",
        "else printf 'JOURNAL=missing\\n'; fi",
        "fl=''; fu=''",
        "for f in " + " ".join(SOURCE_FILES) + "; do "
        'if [ -r "$f" ]; then fl="$fl $f"; elif [ -e "$f" ]; then fu="$fu $f"; fi; done',
        "printf 'FILES%s\\n' \"$fl\"",
        'if [ -n "$fu" ]; then printf \'FILES_UNREADABLE%s\\n\' "$fu"; fi',
        "need=0",
        'if [ "$jc" = 0 ] || [ "$jlim" = 1 ] || [ "$cover" = no ]; then need=1; fi',
        "jb=" + str(JOURNAL_BUDGET) + "; fb=" + str(JOURNAL_BUDGET),
        'if [ "$need" = 1 ] && [ "$jc" = 1 ]; then jb='
        + str(SHARED_BUDGETS[0])
        + "; fb="
        + str(SHARED_BUDGETS[1])
        + "; fi",
        'sk=$(date -d "@' + s + "\" '+%m%d%H%M%S' 2>/dev/null)",
        'uk=$(date -d "@' + u + "\" '+%m%d%H%M%S' 2>/dev/null)",
        "tz=$(date '+%z' 2>/dev/null)",
        'if [ "$jc" = 1 ]; then',
        "printf '[AIOPS_JOURNAL]\\n'",
        "printf 'PRIORITY %s\\n' " + quote(priority),
        "{ "
        + timed(7, journal + " -p " + quote(priority) + matches)
        + "; printf '\\nAIOPS_RC %s\\n' \"$?\"; } 2>/dev/null"
        + keyword_grep
        + " | awk -v n="
        + lines
        + ' -v b="$jb" -v w='
        + str(LINE_CHARS)
        + ' -v tf=0 -v jr=1 "$agg"',
        *counts,
        "fi",
        'if [ "$need" = 1 ]; then',
        "printf '[AIOPS_FILES]\\n'",
        "lf=''",
        "for f in " + " ".join(SYSLOG_FILES) + "; do "
        'if [ -r "$f" ]; then lf=$f; break; fi; done',
        'if [ -n "$lf" ]; then',
        "printf 'FILE_SOURCE %s\\n' \"$lf\"",
        timed(5, "tail -c " + str(FILE_TAIL_BYTES) + ' -- "$lf"')
        + " 2>/dev/null | awk -v n="
        + lines
        + ' -v b="$fb" -v w='
        + str(LINE_CHARS)
        + ' -v tf=1 -v sk="$sk" -v uk="$uk" -v tz="$tz"'
        + keyword_var
        + file_filters
        + ' "$agg"',
        "else",
        "printf 'FILE_SOURCE none\\n'",
        'if [ "$jc" = 0 ] || [ "$jlim" = 1 ]; then '
        "printf 'CAPABILITY_MISSING:log-files\\n'; fi",
        "fi",
        "fi",
        "printf '[AIOPS_AUTH]\\n'",
        "af=''",
        "for f in " + " ".join(AUTH_FILES) + "; do "
        'if [ -r "$f" ]; then af=$f; break; fi; done',
        'if [ "$jc" = 1 ] && [ "$jlim" = 0 ] && '
        '{ [ "$cover" = yes ] || [ -z "$af" ]; }; then',
        "printf 'AUTH_SOURCE journal\\n'",
        "if [ \"$cover\" = no ]; then printf 'AUTH_PARTIAL\\n'; fi",
        timed(
            4,
            "journalctl --no-pager -q -o cat" + window + " -u sshd -u ssh",
        )
        + ' 2>/dev/null | awk -v tf=0 "$authawk"',
        'elif [ -n "$af" ]; then',
        "printf 'AUTH_SOURCE %s\\n' \"$af\"",
        timed(3, "tail -c " + str(AUTH_TAIL_BYTES) + ' -- "$af"')
        + ' 2>/dev/null | awk -v tf=1 -v sk="$sk" -v uk="$uk" "$authawk"',
        "else printf 'AUTH_UNAVAILABLE\\n'; fi",
        "printf '[AIOPS_BOOT]\\n'",
        "bt=''; b=$(uptime -s 2>/dev/null)",
        'if [ -n "$b" ]; then bt=$(date -d "$b" +%s 2>/dev/null); fi',
        'case "$bt" in \'\'|*[!0-9]*) bt=$(awk -v now="$(date +%s)" '
        "'{ if (0 < now) printf \"%d\\n\", now - int($1) }' /proc/uptime 2>/dev/null);; esac",
        "printf 'BOOT_AT %s\\n' \"$bt\"",
        "exit 0",
    ]
    return "\n".join(parts) + "\n"


def _has(text: str, name: str) -> bool:
    return re.search(r"(?m)^\[AIOPS_" + name + r"\]$", text) is not None


def _source(body: str) -> dict:
    info = {
        "since": None,
        "until": None,
        "now": None,
        "journal": None,
        "limited": False,
        "covers": None,
        "files": [],
        "unreadable": [],
    }
    for raw in body.splitlines():
        line = raw.strip()
        if m := re.fullmatch(r"WINDOW (\d{1,12}) (\d{1,12})", line):
            info["since"], info["until"] = int(m[1]), int(m[2])
        elif m := re.fullmatch(r"NOW (\d{1,12})", line):
            info["now"] = int(m[1])
        elif line in ("JOURNAL=available", "JOURNAL=missing"):
            info["journal"] = line.split("=", 1)[1]
        elif line == "CAPABILITY_MISSING:journal-permission":
            info["limited"] = True
        elif m := re.fullmatch(r"JOURNAL_COVERS_WINDOW=(yes|no)", line):
            info["covers"] = m[1] == "yes"
        elif line.startswith("FILES_UNREADABLE"):
            info["unreadable"] = [p for p in line.split()[1:] if p in SOURCE_FILES]
        elif line.startswith("FILES"):
            info["files"] = [p for p in line.split()[1:] if p in SOURCE_FILES]
    return info


def _block(body: str) -> dict:
    """Entries and the metadata lines one aggregation pass printed."""
    data = {
        "entries": [],
        "total": None,
        "clipped": None,
        "exit": None,
        "units": [],
        "match": {},
        "samples": {},
        "counts": {},
        "count_exit": {},
        "flags": set(),
        "first_at": None,
        "last_at": None,
        "file": None,
        "starts_after": None,
        "tz": None,
        "capabilities": set(),
    }
    numbers = {
        "LINES_TOTAL": "total",
        "ENTRIES_CLIPPED": "clipped",
        "EXIT": "exit",
    }
    for raw in body.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if m := re.fullmatch(r"(LINES_TOTAL|ENTRIES_CLIPPED|EXIT) (\d{1,12})", line):
            data[numbers[m[1]]] = int(m[2])
        elif m := re.fullmatch(r"UNIT (\S{1,96}) (\d{1,12})", line):
            data["units"].append({"unit": m[1], "lines": int(m[2])})
        elif m := re.fullmatch(r"MATCH (\w+) (\d{1,12})", line):
            if m[1] in KINDS:
                data["match"][m[1]] = int(m[2])
        elif m := re.fullmatch(r"MATCHLINE (\w+) (.*)", line):
            if m[1] in KINDS and m[2].strip():
                data["samples"].setdefault(m[1], []).append(m[2][:LINE_CHARS])
        elif m := re.fullmatch(
            r"COUNT (crit|err|warning) (\d{1,12})(?: (\d{1,5}))?", line
        ):
            data["counts"][m[1]] = int(m[2])
            data["count_exit"][m[1]] = int(m[3]) if m[3] else 0
        elif m := re.fullmatch(r"(FIRST_AT|LAST_AT) (\S.{0,63})", line):
            data["first_at" if m[1] == "FIRST_AT" else "last_at"] = m[2]
        elif m := re.fullmatch(r"FILE_SOURCE (\S{1,128})", line):
            data["file"] = m[1] if m[1] in SYSLOG_FILES else None
        elif m := re.fullmatch(r"STARTS_AFTER_SINCE (\d{10})", line):
            data["starts_after"] = m[1]
        elif m := re.fullmatch(r"TZ_MISMATCH ([+-]\d{4})", line):
            data["tz"] = m[1]
        elif line in (
            "YEAR_WRAP",
            "NO_TIME_FILTER",
            "NO_TIMESTAMPS",
            "PRIORITY_APPROX=keyword",
        ):
            data["flags"].add(line)
        elif re.fullmatch(r"PRIORITY \w+", line):
            continue
        elif m := re.fullmatch(r"CAPABILITY_MISSING:([\w-]+)", line):
            data["capabilities"].add(m[1])
        else:
            data["entries"].append(line[:LINE_CHARS])
    return data


def _auth(body: str, present: bool) -> dict:
    info = {
        "available": False,
        "source": None,
        "partial": False,
        "failed": None,
        "invalid_users": None,
        "accepted": None,
        "top_sources": [],
    }
    if not present:
        return info
    unavailable = False
    names = {"FAILED": "failed", "INVALID": "invalid_users", "ACCEPTED": "accepted"}
    for raw in body.splitlines():
        line = raw.strip()
        if line == "AUTH_UNAVAILABLE":
            unavailable = True
        elif line == "AUTH_PARTIAL":
            info["partial"] = True
        elif m := re.fullmatch(r"AUTH_SOURCE (journal|/var/log/[\w.-]{1,32})", line):
            info["source"] = m[1]
        elif m := re.fullmatch(r"(FAILED|INVALID|ACCEPTED) (\d{1,12})", line):
            info[names[m[1]]] = int(m[2])
        elif m := re.fullmatch(r"TOP_SOURCE (\d{1,12}) ([0-9A-Fa-f:.]{1,64})", line):
            if len(info["top_sources"]) < 5:
                info["top_sources"].append({"ip": m[2], "count": int(m[1])})
    info["available"] = not unavailable and info["failed"] is not None
    return info


def _int(value, default=None):
    return value if isinstance(value, int) and not isinstance(value, bool) else default


def _coverage(name, state, covers, file_path, priority, total, shown, auth) -> str:
    login = (
        "登录审计来自 " + (auth["source"] or "未知来源")
        if auth["available"]
        else "登录审计不可用"
    )
    if name is None:
        return (
            "没有可读取的日志来源（journal："
            + (state or "未知")
            + "，/var/log 文件不可读或不存在）；结果为空不代表无异常"
        )
    shown_text = (
        f"匹配 {total if total is not None else '未知'} 行，返回最新 {shown} 行"
    )
    if name == "journal":
        scope = (
            f"journalctl（-p {priority} 即该级别及更严重）"
            + ("，只含本账号可见的日志" if state == "limited" else "")
            + ("，journal 未覆盖窗口起点" if covers is False else "")
        )
    else:
        reason = {
            "missing": "主机没有 journalctl",
            "limited": "账号无权读取 journal",
        }.get(state, "journal 未覆盖窗口起点")
        scope = (
            f"{reason}，改读 {file_path} 尾部 20MB 在主机上按时间过滤"
            "（不含轮转文件，级别按关键字近似）"
        )
    return (
        f"{scope}；{shown_text}（受 lines 与字节上限约束），"
        f"分类计数与单元排行覆盖全部匹配行；{login}；无匹配不能证明未发生故障"
    )


def parse(text: str, summary: dict, findings: list, options: dict) -> None:
    summary.setdefault("metrics", [])
    text = text if isinstance(text, str) else ""
    options = options if isinstance(options, dict) else {}
    limit = min(max(_int(options.get("lines"), 120), 1), 300)
    priority = options.get("priority")
    priority = priority if priority in PRIORITIES else "warning"
    src = _source(section(text, "SOURCE"))
    journal = _block(section(text, "JOURNAL")) if _has(text, "JOURNAL") else None
    files = _block(section(text, "FILES")) if _has(text, "FILES") else None
    state = src["journal"]
    if state == "available" and src["limited"]:
        state = "limited"
    # A limited account probes only its own entries: coverage is unknown.
    covers = src["covers"] if state == "available" else None
    file_path = files["file"] if files else None
    if journal is not None and state == "available" and covers is not False:
        primary, name = journal, "journal"
    elif file_path:
        primary, name = files, "files"
    elif journal is not None:
        primary, name = journal, "journal"
    else:
        primary, name = None, None
    other = files if primary is journal else journal

    entries = primary["entries"][-limit:] if primary else []
    total = primary["total"] if primary else None
    approx = bool(name == "files" and "PRIORITY_APPROX=keyword" in primary["flags"])
    # Level counts need a readable system journal; a limited account only
    # sees its own entries, which would read as "no errors".
    levels = journal if journal is not None and state == "available" else None
    counts = {
        "total": total,
        **{
            level: (levels["counts"].get(level) if levels else None)
            for level in ("crit", "err", "warning")
        },
    }
    # Counts: the larger whole-window count of either source (journal and
    # file overlap, so never their sum), at least the hits among the entries.
    matched, match_counts, hits = {}, {}, {}
    for block in (primary, other):
        if block is None:
            continue
        for kind, lines in block["samples"].items():
            matched.setdefault(kind, []).extend(lines)
        for kind, n in block["match"].items():
            match_counts[kind] = max(match_counts.get(kind, 0), n)
    for line in entries:
        for kind, pattern in LOG_PATTERNS:
            if re.search(pattern, line):
                matched.setdefault(kind, []).append(line)
                hits[kind] = hits.get(kind, 0) + 1
    for kind in list(matched):
        matched[kind] = list(dict.fromkeys(matched[kind]))[:20]
    for kind, n in hits.items():
        match_counts[kind] = max(match_counts.get(kind, 0), n)
    if primary is not None:
        for kind in KINDS:
            match_counts.setdefault(kind, 0)

    auth = _auth(section(text, "AUTH"), _has(text, "AUTH"))
    since = src["since"] if src["since"] is not None else _int(options.get("since"))
    until = src["until"] if src["until"] is not None else _int(options.get("until"))
    boot = re.search(r"(?m)^BOOT_AT (\d{1,12})$", section(text, "BOOT"))
    booted = int(boot[1]) if boot else None
    rebooted = since <= booted <= until if None not in (booted, since, until) else None
    files_used = [file_path] if file_path and name == "files" else []
    if auth["source"] and auth["source"] != "journal":
        files_used.append(auth["source"])

    summary.update(
        {
            "source": {
                "journal": state,
                "journal_covers_window": covers,
                "files_used": files_used,
                "priority_approx": approx,
                "entries_from": name,
                "files_readable": src["files"],
                "files_unreadable": src["unreadable"],
            },
            "window": {"since": since, "until": until, "host_now": src["now"]},
            "counts": counts,
            "top_units": primary["units"][:15] if primary else [],
            "entries": entries,
            "matched": matched,
            "matched_counts": match_counts,
            "auth": auth,
            "boot": {"booted_at": booted, "rebooted_in_window": rebooted},
            "first_at": primary["first_at"] if primary else None,
            "last_at": primary["last_at"] if primary else None,
            "coverage": _coverage(
                name, state, covers, file_path, priority, total, len(entries), auth
            ),
        }
    )
    _findings(
        summary,
        findings,
        state=state,
        covers=covers,
        primary=primary,
        name=name,
        journal=journal,
        files=files,
        counts=counts,
        match_counts=match_counts if primary is not None else {},
        auth=auth,
        booted=booted,
        rebooted=rebooted,
    )


def _findings(summary, findings, *, state, covers, primary, name, journal, files, **f):
    counts, match_counts, auth = f["counts"], f["match_counts"], f["auth"]
    usable = primary is not None and not (
        name == "journal" and state == "limited" and not (files and files["file"])
    )
    if state == "limited":
        findings.append(
            {
                "level": "warning",
                "metric": "journal_access",
                "value": "limited",
                "threshold": "root 或 systemd-journal/adm/wheel 组",
                "hint": "诊断账号不在 systemd-journal/adm/wheel 组：journalctl 只能看到本账号的日志，"
                "已尝试回退到 /var/log 文件；空结果不能视为无异常，需为账号授予日志读取权限",
            }
        )
    if state is not None and not usable:
        findings.append(
            {
                "level": "warning",
                "metric": "log_source_unavailable",
                "value": f"journal={state}; files="
                + (files["file"] if files and files["file"] else "none"),
                "threshold": "journal 或 /var/log/messages、syslog 可读",
                "hint": "没有可读取的系统日志来源（journalctl 缺失或无权限，且 /var/log/messages、syslog 不可读）："
                "本次结果为空不代表系统无异常；请让诊断账号加入 systemd-journal/adm 组或改用有权限的账号",
            }
        )
    metric(
        summary,
        findings,
        "crit_entries",
        counts["crit"],
        threshold=1,
        critical=1,
        hint="窗口内存在 crit/alert/emerg 级别日志（经验阈值：≥1 即严重）；查看 entries 与 top_units 定位来源",
    )
    metric(
        summary,
        findings,
        "err_entries",
        counts["err"],
        threshold=10,
        critical=50,
        hint="err 级别日志偏多（经验阈值：≥10 警告、≥50 严重）；按 top_units 找出主要来源，再用 service_detail 深入",
    )
    for kind, level, hint in (
        (
            "oom",
            "critical",
            "窗口内出现 OOM / Killed process 线索（≥1 即严重）；核查被杀进程、cgroup 内存上限与内存增长",
        ),
        (
            "io_error",
            "critical",
            "内核报告磁盘/文件系统 I/O 错误或只读重挂载（≥1 即严重）；核查块设备、RAID/多路径与挂载状态",
        ),
        (
            "service",
            "warning",
            "有服务启动失败、异常退出或触发启动频率限制（≥1 即警告）；用 service_detail 查看退出原因与重启记录",
        ),
        (
            "kernel",
            "warning",
            "内核异常线索（segfault / soft lockup / hung task / call trace，≥1 即警告）；结合负载与 D 状态进程核查",
        ),
        (
            "network",
            "warning",
            "网卡链路断开或无载波（≥1 即警告）；核查网线/交换机端口、bond 状态与驱动日志",
        ),
    ):
        metric(
            summary,
            findings,
            "log_" + kind,
            match_counts.get(kind),
            threshold=1,
            critical=1 if level == "critical" else None,
            hint=hint,
        )
    if auth["available"]:
        metric(
            summary,
            findings,
            "auth_failures",
            (auth["failed"] or 0) + (auth["invalid_users"] or 0),
            threshold=20,
            critical=200,
            hint="SSH 登录失败行数（Failed password + Invalid user，同一次尝试可能各记一行；经验阈值 ≥20 警告、≥200 严重）；"
            "核查 auth.top_sources 是否为暴力破解来源并评估封禁或限速",
        )
    if f["rebooted"]:
        findings.append(
            {
                "level": "critical",
                "metric": "reboot_in_window",
                "value": f["booted"],
                "threshold": "窗口内无重启",
                "hint": "主机启动时间落在该时间窗口内（发生过重启）；易失 journal 会丢失重启前的日志，"
                "结合 /var/log 文件、监控与 last -x 核查重启原因",
            }
        )
    count_exits = [n for n in (journal or {}).get("count_exit", {}).values() if n]
    used = name == "journal" or state == "available"
    if (
        journal is not None
        and used
        and (journal["exit"] not in (None, 0) or count_exits)
    ):
        findings.append(
            {
                "level": "info",
                "metric": "journal_query_incomplete",
                "value": journal["exit"] or count_exits[0],
                "threshold": 0,
                "hint": "journalctl 以非零状态退出（124 表示超过时限被终止）：返回的行与计数只是部分结果",
            }
        )
    total = counts["total"]
    if state is not None and not total and not summary["entries"]:
        failed_query = bool(journal and journal["exit"] not in (None, 0))
        restricted = not usable or state == "limited" or failed_query
        findings.append(
            {
                "level": "info",
                "metric": "no_entries",
                "value": total or 0,
                "threshold": "≥1",
                "hint": (
                    "窗口内没有返回日志，但来源受限（无权限、无可读文件或查询失败/超时）：不能据此判断没有异常"
                    if restricted
                    else "所选来源在该窗口内确实没有符合过滤条件（级别、unit、pid、keyword）的日志；"
                    "可放宽 priority 或去掉过滤条件再查"
                ),
            }
        )
    gaps = []
    if covers is False:
        gaps.append("journal 起点晚于窗口开始")
    if files is not None and name == "files":
        if files["starts_after"]:
            gaps.append("文件尾部 20MB 起点晚于窗口开始")
        if files["tz"]:
            gaps.append("文件时间戳时区 " + files["tz"] + " 与主机不同")
        if "NO_TIME_FILTER" in files["flags"] or "NO_TIMESTAMPS" in files["flags"]:
            gaps.append("无法按时间过滤文件")
    if gaps:
        findings.append(
            {
                "level": "info",
                "metric": "window_not_covered",
                "value": gaps,
                "threshold": "窗口完整覆盖",
                "hint": "日志来源没有完整覆盖所选窗口（易失 journal、轮转或只读取文件尾部）：窗口前段的事件可能缺失，"
                "必要时查看轮转文件或缩小窗口",
            }
        )
    if summary["source"]["priority_approx"]:
        findings.append(
            {
                "level": "info",
                "metric": "priority_approx",
                "value": "keyword",
                "threshold": "journalctl -p",
                "hint": "文件日志没有级别字段：priority 按 error/fail/warn/denied/timeout/oom/panic 等关键字近似筛选，"
                "可能漏掉或多出部分行",
            }
        )


register(
    ActionSpec(
        id="syslog",
        tool="ssh_diagnose_syslog",
        title="系统日志检索",
        question="时间窗口内系统日志有哪些错误、OOM、I/O、服务失败或登录失败线索？",
        category="服务与日志",
        description="journalctl 优先、/var/log 回退的系统日志检索与分类统计",
        params=WINDOW_PARAMS
        + (
            Param(
                "unit",
                "str",
                "只看该 systemd 单元（如 nginx.service）",
                pattern=SERVICE_RE,
                max_length=64,
            ),
            Param(
                "priority",
                "enum",
                "最低级别（journalctl -p）；回退到文件日志时按关键字近似",
                default="warning",
                choices=PRIORITIES,
            ),
            Param(
                "keyword",
                "str",
                "按子串过滤（不区分大小写）",
                pattern=KEYWORD_RE,
                max_length=64,
            ),
            Param("pid", "int", "只看该进程的日志", minimum=1, maximum=4194304),
            Param(
                "lines",
                "int",
                "返回的代表性日志上限（20–300）",
                default=120,
                minimum=20,
                maximum=300,
            ),
        ),
        script=script,
        parse=parse,
        sensitive=True,
        risk="low",
        timeout=30,
        output_limit=49152,
        estimated_seconds=8,
        notes=(
            "journal 缺失、无权限或未覆盖窗口时回退到 /var/log/messages 或 syslog 尾部 20MB，级别按关键字近似。",
            "条目受 lines 与约 16KB 字节上限约束；分类计数与单元排行覆盖窗口内全部匹配行。",
        ),
    )
)
