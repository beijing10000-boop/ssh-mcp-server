"""Nginx diagnostics: discovery/status/error log (``nginx``) and access-log analysis (``nginx_access``).

两个动作都是固定只读模板：

- ``nginx``：发现 nginx/openresty/tengine 二进制、版本与编译路径；nginx -T 输出经 awk
  只保留日志、upstream、监听、超时等指令（-T 失败或无权限时回退读取主配置与
  conf.d/sites-enabled）；读取进程、systemd、监听端口、日志文件与轮转；对最多 2 个
  error.log 的尾部 20 MB 按最近 minutes 分钟聚合级别、上游错误、TOP 与样本行。
- ``nginx_access``：在远端用 awk 聚合 access.log 尾部约 30 MB（窗口跨轮转时先读未压缩
  轮转文件尾部 10 MB），combined 与 JSON 混合格式逐行识别，只返回计数、TOP、
  分钟趋势、耗时统计与少量样本，不返回整份日志。

脚本头部只有变量赋值：整数经 str(int())，字符串经 Param 校验后 quote()；其余模板固定，
awk 程序体不拼接任何参数（一律 -v），不出现任何写重定向。
"""

from __future__ import annotations

import re

from .. import observations
from . import (
    KEYWORD_RE,
    PATH_RE,
    WINDOW_PARAMS,
    ActionSpec,
    Param,
    quote,
    register,
    resolve_window,
    timed,
)

# Discovery order of the nginx binary: PATH first, then common install prefixes.
NGINX_COMMANDS = ("nginx", "openresty", "tengine")
NGINX_BINARIES = (
    "/usr/sbin/nginx",
    "/usr/local/nginx/sbin/nginx",
    "/usr/local/openresty/nginx/sbin/nginx",
    "/usr/local/openresty/bin/openresty",
    "/opt/nginx/sbin/nginx",
)
SYSTEMD_UNITS = ("nginx", "openresty", "tengine")
DEFAULT_CONF = "/etc/nginx/nginx.conf"
DEFAULT_ACCESS_LOG = "/var/log/nginx/access.log"
DEFAULT_ERROR_LOG = "/var/log/nginx/error.log"
# A user-given access log must be one of these (checked again on the host, for the
# given and the symlink-resolved path) unless nginx's own config declares it.
ALLOWED_LOG_PATTERNS = (
    "/var/log/nginx/*",
    "/var/log/openresty/*",
    "/usr/local/nginx/logs/*",
    "/usr/local/openresty/nginx/logs/*",
    "/data/logs/*access*.log",
    "/opt/logs/*access*.log",
    "/home/logs/*access*.log",
    "/srv/logs/*access*.log",
    "/app/logs/*access*.log",
    "/data/*/logs/*access*.log",
    "/opt/*/logs/*access*.log",
    "/home/*/logs/*access*.log",
    "/srv/*/logs/*access*.log",
    "/app/*/logs/*access*.log",
)
_PATTERN_RE = re.compile(r"^/[A-Za-z0-9._/*-]+$")
STATUS_RE = re.compile(r"^(all|[2-5]xx|[1-5][0-9][0-9])$")
ERROR_TAIL_BYTES = 20000000
ERROR_READ_SECONDS = 4
ACCESS_TAIL_BYTES = 30000000
ROTATED_TAIL_BYTES = 10000000
# Total seconds the access-log reads may take; the remaining budget is passed to
# each `timeout` so the whole action stays under its 40 s limit.
ACCESS_READ_BUDGET = 24

# ---------------------------------------------------------------------------
# awk programs (POSIX/mawk: no strftime/mktime/gensub/asort/length(array),
# no regex intervals, no \s \d; parameters only through -v).
# ---------------------------------------------------------------------------

# nginx -T (or raw config files) -> only the directives the parser needs.
CONFIG_AWK = r"""
function emit(line_) {
    if (line_ in seen) return
    seen[line_] = 1
    if (shown < 190) print substr(line_, 1, 300)
    shown++
}
{
    sub(/^[ \t]+/, "")
    sub(/[ \t\r]+$/, "")
}
/^nginx: / {
    if (tests < 10) print substr($0, 1, 300)
    tests++
    next
}
/^# configuration file / { files++; next }
/^#/ || $0 == "" { next }
inlf {
    lf = lf " " $0
    if (index($0, ";")) {
        emit(lf)
        inlf = 0
    }
    next
}
inup {
    if ($0 ~ /^(server|keepalive)[ \t]/ && shown < 190) {
        print substr($0, 1, 300)
        shown++
    }
    if (index($0, "}")) inup = 0
    next
}
/^upstream[ \t]/ {
    name = $2
    sub(/[{].*$/, "", name)
    if (shown < 190) {
        print "UPSTREAM " substr(name, 1, 100)
        shown++
    }
    ups++
    inup = 1
    if (index($0, "}")) inup = 0
    next
}
/^log_format[ \t]/ {
    if (index($0, ";")) emit($0)
    else {
        lf = $0
        inlf = 1
    }
    next
}
/^(access_log|error_log|listen|worker_processes|worker_connections|proxy_connect_timeout|proxy_read_timeout|proxy_send_timeout|keepalive_timeout|client_max_body_size)[ \t]/ {
    emit($0)
    next
}
/^server_name[ \t]/ { names++; next }
/^proxy_pass[ \t]/ { passes++; next }
/^include[ \t]/ { includes++; next }
END {
    print "COUNT server_name " names + 0
    print "COUNT proxy_pass " passes + 0
    print "COUNT include " includes + 0
    print "COUNT upstream " ups + 0
    print "COUNT config_files " files + 0
    print "COUNT input_lines " NR
    if (shown > 190) print "CONFIG_TRUNCATED " shown
}
"""

# Keep the `lim_` largest entries of an array without asort (single pass).
# Function locals end in "_" so they never shadow a global name (mawk/gawk alike).
_TOPK_AWK = r"""
function topk(arr_, tag_, lim_,    key_, pos_, cnt_, val_, keys_, vals_) {
    cnt_ = 0
    for (key_ in arr_) {
        val_ = arr_[key_]
        if (cnt_ < lim_) {
            cnt_++
            pos_ = cnt_
        } else if (val_ > vals_[cnt_]) {
            pos_ = cnt_
        } else {
            continue
        }
        while (pos_ > 1 && vals_[pos_ - 1] < val_) {
            vals_[pos_] = vals_[pos_ - 1]
            keys_[pos_] = keys_[pos_ - 1]
            pos_--
        }
        vals_[pos_] = val_
        keys_[pos_] = key_
    }
    for (pos_ = 1; pos_ <= cnt_; pos_++) print tag_, vals_[pos_], keys_[pos_]
}
"""

# error.log lines "YYYY/MM/DD HH:MM:SS [level] pid#tid: *conn message, client: ..."
# filtered by -v since/until (same format, host local time).
ERROR_AWK = (
    _TOPK_AWK
    + r"""
substr($0, 1, 1) == "\001" { next }
{
    t = substr($0, 1, 19)
    if (t !~ /^[0-9][0-9][0-9][0-9]\/[0-9][0-9]\/[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]$/) next
    seen++
    if (first == "") first = t
    if (t < since || t > until) next
    n++
    lv = substr($3, 2, length($3) - 2)
    lvl[lv]++
    err = (lv == "error" || lv == "crit" || lv == "alert" || lv == "emerg")
    msg = $0
    p = index(msg, "] ")
    if (p) msg = substr(msg, p + 2)
    sub(/^[0-9]+#[0-9]+: /, "", msg)
    sub(/^[*][0-9]+ /, "", msg)
    p = index(msg, ", client: ")
    if (p) msg = substr(msg, 1, p - 1)
    kind = ""
    if (index(msg, "no live upstreams")) kind = "no_live_upstreams"
    else if (index(msg, "worker_connections are not enough")) kind = "worker_connections"
    else if (index(msg, "Too many open files")) kind = "too_many_open_files"
    else if (index(msg, "upstream timed out")) kind = "timed_out"
    else if (index(msg, "connect()") && index(msg, "Connection refused")) kind = "connection_refused"
    else if (index(msg, "connect()") && index(msg, "failed")) kind = "connect_failed"
    else if (index(msg, "upstream prematurely closed")) kind = "prematurely_closed"
    else if (index(msg, "client prematurely closed") || index(msg, "client closed")) kind = "client_closed"
    else if (err && index($0, "upstream")) kind = "other_upstream"
    if (kind != "") up[kind]++
    if (kind != "" && kind != "client_closed" && kind != "worker_connections" && kind != "too_many_open_files") {
        p = index($0, "upstream: \"")
        if (p) {
            u = substr($0, p + 11)
            p = index(u, "\"")
            if (p) u = substr(u, 1, p - 1)
            sub(/^[a-z]+:\/\//, "", u)
            if (substr(u, 1, 5) != "unix:") {
                p = index(u, "/")
                if (p) u = substr(u, 1, p - 1)
            }
            tu[substr(u, 1, 120)]++
        }
    }
    if (!err) next
    tm[substr(msg, 1, 160)]++
    p = index($0, ", client: ")
    if (p) {
        c = substr($0, p + 10)
        p = index(c, ",")
        if (p) c = substr(c, 1, p - 1)
        tc[substr(c, 1, 64)]++
    }
    p = index($0, ", request: \"")
    if (p) {
        r = substr($0, p + 12)
        p = index(r, "\"")
        if (p) r = substr(r, 1, p - 1)
        split(r, rq, " ")
        x = rq[2]
        p = index(x, "?")
        if (p) x = substr(x, 1, p - 1)
        tr[substr(rq[1], 1, 16) " " substr(x, 1, 120)]++
    }
    smp[ns % 20] = substr($0, 1, 240)
    ns++
}
END {
    print "LINES", n + 0, seen + 0
    if (n == 0) print "NO_ENTRIES"
    if (first != "" && first > since) print "COVERAGE_FROM", first
    for (k in lvl) print "LEVEL", k, lvl[k]
    for (k in up) print "UPSTREAM", k, up[k]
    topk(tu, "TOP_UPSTREAM", 10)
    topk(tc, "TOP_CLIENT", 10)
    topk(tr, "TOP_REQUEST", 10)
    topk(tm, "TOP_MESSAGE", 10)
    for (i = (ns > 20 ? ns - 20 : 0); i < ns; i++) print "SAMPLE", i, smp[i % 20]
}
"""
)

# access_log paths from an nginx -T dump or raw config files.
ALOG_AWK = r"""
$1 == "access_log" && NF >= 2 {
    p = $2
    sub(/;$/, "", p)
    gsub(/"/, "", p)
    if (p == "" || p == "off" || p ~ /^(syslog|memory):/ || index(p, "$")) next
    if (substr(p, 1, 1) != "/") p = pfx "/" p
    if (!seen[p]++) print p
}
"""

# access.log lines: JSON ({...}) or combined-like; window keys are yyyymmddHHMMSS
# strings from -v skey/ukey. "\001AIOPS_*" marker lines come from the shell.
ACCESS_AWK = (
    _TOPK_AWK
    + r"""
function key_clf(ts_,    mo_) {
    mo_ = mon[substr(ts_, 4, 3)]
    if (mo_ == "" || substr(ts_, 3, 1) != "/" || substr(ts_, 12, 1) != ":") return ""
    return substr(ts_, 8, 4) mo_ substr(ts_, 1, 2) substr(ts_, 13, 2) substr(ts_, 16, 2) substr(ts_, 19, 2)
}
function tkey(ts_) {
    if (ts_ ~ /^[0-9][0-9]\/[A-Z][a-z][a-z]\/[0-9][0-9][0-9][0-9]:[0-9][0-9]:[0-9][0-9]:[0-9][0-9]/) return key_clf(ts_)
    if (ts_ ~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9][T ][0-9][0-9]:[0-9][0-9]:[0-9][0-9]/)
        return substr(ts_, 1, 4) substr(ts_, 6, 2) substr(ts_, 9, 2) substr(ts_, 12, 2) substr(ts_, 15, 2) substr(ts_, 18, 2)
    return ""
}
function jv(src_, name_,    at_, rest_, cut_, acc_) {
    at_ = index(src_, "\"" name_ "\":")
    if (at_ == 0) return ""
    rest_ = substr(src_, at_ + length(name_) + 3)
    while (substr(rest_, 1, 1) == " ") rest_ = substr(rest_, 2)
    if (substr(rest_, 1, 1) != "\"") {
        cut_ = match(rest_, /[,} ]/)
        return cut_ ? substr(rest_, 1, cut_ - 1) : rest_
    }
    rest_ = substr(rest_, 2)
    acc_ = ""
    while (1) {
        cut_ = index(rest_, "\"")
        if (cut_ == 0) return acc_ rest_
        if (cut_ > 1 && substr(rest_, cut_ - 1, 1) == "\\") {
            acc_ = acc_ substr(rest_, 1, cut_)
            rest_ = substr(rest_, cut_ + 1)
            continue
        }
        return acc_ substr(rest_, 1, cut_ - 1)
    }
}
function lastnum(src_,    cnt_, parts_, idx_, val_) {
    cnt_ = split(src_, parts_, /[^0-9.]+/)
    val_ = ""
    for (idx_ = 1; idx_ <= cnt_; idx_++) if (parts_[idx_] ~ /^[0-9]+[.]?[0-9]*$/) val_ = parts_[idx_]
    return val_
}
BEGIN {
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", mn, " ")
    for (i = 1; i <= 12; i++) mon[mn[i]] = sprintf("%02d", i)
    nf = 0
    ns = 0
}
substr($0, 1, 8) == "\001AIOPS_F" {
    nf++
    fp[nf] = substr($0, 10)
    next
}
substr($0, 1, 11) == "\001AIOPS_SKIP" { print "SKIPPED", substr($0, 13); next }
substr($0, 1, 11) == "\001AIOPS_SLOW" { print "READ_TIMEOUT", substr($0, 13); next }
substr($0, 1, 1) == "\001" { next }
{
    lines++
    k = ""
    st = ""
    rt = ""
    ut = ""
    nou = 0
    ip = "-"
    uri = "-"
    ua = "-"
    if (substr($0, 1, 1) == "{") {
        t = jv($0, "time_local")
        if (t == "") t = jv($0, "time_iso8601")
        if (t == "") t = jv($0, "@timestamp")
        if (t == "") t = jv($0, "time")
        k = tkey(t)
        st = jv($0, "status")
        rt = jv($0, "request_time")
        if (index($0, "\"upstream_response_time\":")) {
            ut = lastnum(jv($0, "upstream_response_time"))
            if (ut == "") nou = 1
        }
        ip = jv($0, "remote_addr")
        uri = jv($0, "request_uri")
        if (uri == "") uri = jv($0, "uri")
        if (uri == "") {
            r = jv($0, "request")
            n = split(r, rq, " ")
            uri = (n >= 2) ? rq[2] : r
        }
        ua = jv($0, "http_user_agent")
        if (ua == "") ua = jv($0, "user_agent")
    } else {
        n = split($0, q, "\"")
        b = index(q[1], "[")
        if (b) k = tkey(substr(q[1], b + 1, 25))
        split(q[3], sb, " ")
        st = sb[1]
        ip = $1
        m = split(q[2], rq, " ")
        uri = (m >= 2) ? rq[2] : q[2]
        if (n >= 6) ua = q[6]
        rest = ""
        for (i = 7; i <= n; i++) rest = rest " " q[i]
        if (match(rest, /[ \t](rt|request_time)=[0-9]+[.][0-9]+/)) {
            v = substr(rest, RSTART, RLENGTH)
            sub(/^[ \t]*[a-z_]+=/, "", v)
            rt = v
            if (match(rest, /(urt|upstream_response_time)=[ \t]*[0-9.,: -]+/)) {
                v = substr(rest, RSTART, RLENGTH)
                sub(/^[a-z_]+=/, "", v)
                ut = lastnum(v)
                if (ut == "") nou = 1
            }
        } else {
            m = split(rest, tok, " ")
            for (i = 1; i <= m; i++) {
                if (tok[i] !~ /^[0-9]+[.][0-9]+$/) continue
                rt = tok[i]
                if (i < m && tok[i + 1] == "-") nou = 1
                else {
                    v = ""
                    for (j = i + 1; j <= m && tok[j] ~ /^([0-9]+[.][0-9]+,?|:|-,?)$/; j++) v = v " " tok[j]
                    ut = lastnum(v)
                }
                break
            }
        }
    }
    if (k == "") {
        bad++
        next
    }
    if (!(nf in ff)) ff[nf] = k
    fl[nf] = k
    if (k < skey || k > ukey) {
        out++
        next
    }
    tot++
    c = substr(st, 1, 1)
    cl = (st ~ /^[2-5][0-9][0-9]$/) ? c "xx" : "other"
    cls[cl]++
    code[(st ~ /^[0-9][0-9][0-9]$/) ? st : "-"]++
    mk = substr(k, 1, 12)
    if (bucket > 1) mk = substr(k, 1, 10) sprintf("%02d", int(substr(k, 11, 2) / bucket) * bucket)
    mreq[mk]++
    if (cl == "5xx") m5[mk]++
    if (rt ~ /^[0-9]+([.][0-9]+)?$/) {
        v = rt + 0
        rc++
        rs += v
        if (v > rmax) rmax = v
        if (v > 1) r1++
        if (v > 3) r3++
        if (v > 10) r10++
    }
    if (ut != "") {
        v = ut + 0
        uc++
        us += v
        if (v > umax) umax = v
        if (v > 1) u1++
        if (v > 3) u3++
    }
    if (nou) nn++
    if (sel == "all" || st == sel || (substr(sel, 2) == "xx" && cl == substr(sel, 1, 1) "xx")) {
        selc++
        x = uri
        p = index(x, "?")
        if (p) x = substr(x, 1, p - 1)
        turi[substr(x, 1, 120)]++
        tip[substr(ip, 1, 64)]++
        tua[substr(ua, 1, 80)]++
        smp[ns % 10] = substr($0, 1, 240)
        ns++
    }
}
END {
    print "LINES", lines + 0, bad + 0, out + 0
    print "TOTAL", tot + 0
    print "CLASS", "2xx", cls["2xx"] + 0
    print "CLASS", "3xx", cls["3xx"] + 0
    print "CLASS", "4xx", cls["4xx"] + 0
    print "CLASS", "5xx", cls["5xx"] + 0
    print "CLASS", "other", cls["other"] + 0
    print "SELECTED", selc + 0
    for (s in code) print "CODE", s, code[s]
    topk(turi, "TOP_URI", topn)
    topk(tip, "TOP_IP", topn)
    topk(tua, "TOP_UA", topn)
    for (s in mreq) print "MINUTE", s, mreq[s], m5[s] + 0
    if (rc) printf "REQ %d %.3f %.3f %d %d %d\n", rc, rs / rc, rmax, r1, r3, r10
    else print "UNAVAILABLE request_time"
    if (uc) printf "UPS %d %.3f %.3f %d %d\n", uc, us / uc, umax, u1, u3
    else print "UNAVAILABLE upstream_time"
    print "NOUPSTREAM", nn + 0
    for (i = (ns > 10 ? ns - 10 : 0); i < ns; i++) print "SAMPLE", i, smp[i % 10]
    first = ""
    last = ""
    for (i = 0; i <= nf; i++) {
        if (!(i in ff)) continue
        print "RANGE", ff[i], fl[i], ((i in fp) ? fp[i] : "-")
        if (first == "" || ff[i] < first) first = ff[i]
        if (fl[i] > last) last = fl[i]
    }
    print "FIRST", (first == "" ? "-" : first), "LAST", (last == "" ? "-" : last)
}
"""
)

# ---------------------------------------------------------------------------
# Shell templates. Only the assignments at the top differ between requests.
# ---------------------------------------------------------------------------

_DISCOVER = r"""
NGX=''
for c in $cmds; do
  b=$(command -v "$c" 2>/dev/null)
  case "$b" in
    /*) if [ -f "$b" ] && [ -x "$b" ]; then NGX=$b; break; fi ;;
  esac
done
if [ -z "$NGX" ]; then
  for b in $bins; do
    if [ -f "$b" ] && [ -x "$b" ]; then NGX=$b; break; fi
  done
fi
"""

_OPT = r"""
opt() {
  printf '%s\n' "$ver" | tr ' ' '\n' | awk -v k="--$1=" 'index($0, k) == 1 {print substr($0, length(k) + 1); exit}'
}
"""

NGINX_TEMPLATE = (
    r"""
minutes=__MINUTES__
cmds=__CMDS__
bins=__BINS__
units=__UNITS__
dconf=__DCONF__
dacc=__DACC__
derr=__DERR__
now=$(date +%s)
since=$((now - minutes * 60))
skey=$(date -d "@$since" '+%Y/%m/%d %H:%M:%S' 2>/dev/null)
ukey=$(date -d "@$now" '+%Y/%m/%d %H:%M:%S' 2>/dev/null)
procs=''
margs=''
if command -v ps >/dev/null 2>&1; then
  procs=$(ps -e -o pid= -o ppid= -o user= -o etimes= -o rss= -o pcpu= -o comm= -o args= 2>/dev/null | awk '
    $7 == "nginx" || $7 == "openresty" || $7 == "tengine" || $8 ~ /^(nginx|openresty|tengine):$/ {
      a = $8
      for (i = 9; i <= NF; i++) a = a " " $i
      print $1, $2, $3, $4, $5, $6, $7, substr(a, 1, 120)
    }' | head -n 40)
  margs=$(ps -eo args= 2>/dev/null | awk '$1 ~ /^(nginx|openresty|tengine):$/ && $2 == "master" {print; exit}')
fi
mbin=$(printf '%s\n' "$margs" | awk '{print $4}')
mpfx=$(printf '%s\n' "$margs" | awk '{for (i = 5; i < NF; i++) if ($i == "-p") {print $(i + 1); exit}}')
mconf=$(printf '%s\n' "$margs" | awk '{for (i = 5; i < NF; i++) if ($i == "-c") {print $(i + 1); exit}}')
"""
    + _DISCOVER
    + r"""
how=''
if [ -z "$NGX" ]; then
  case "$mbin" in
    /*) if [ -f "$mbin" ] && [ -x "$mbin" ]; then NGX=$mbin; how=' running'; fi ;;
  esac
fi
printf '[AIOPS_BIN]\n'
if [ -n "$NGX" ]; then printf 'BIN %s%s\n' "$NGX" "$how"; else printf 'CAPABILITY_MISSING:nginx\n'; fi
set --
if [ -n "$NGX" ] && [ -n "$mbin" ] && { [ "$NGX" = "$mbin" ] || [ "${NGX##*/}" = "$mbin" ]; }; then
  case "$mpfx" in
    /*) set -- -p "$mpfx"; printf 'PREFIX_ARG %s\n' "$mpfx" ;;
    *) mpfx='' ;;
  esac
  case "$mconf" in
    /*) ;;
    ?*) if [ -n "$mpfx" ]; then mconf=${mpfx%/}/$mconf; fi ;;
  esac
  case "$mconf" in
    /*) set -- "$@" -c "$mconf"; printf 'CONF_ARG %s\n' "$mconf" ;;
    *) mconf='' ;;
  esac
else
  case "$mbin" in /*) printf 'MASTER_BIN %s\n' "$mbin" ;; esac
  mpfx=''
  mconf=''
fi
printf '[AIOPS_VERSION]\n'
ver=''
if [ -n "$NGX" ]; then
  ver=$(__TIMED_V__)
  printf '%s\n' "$ver" | head -n 3 | cut -c1-300
  printf '%s\n' "$ver" | tr ' ' '\n' | grep -E '^--(prefix|conf-path|error-log-path|http-log-path)=' | head -n 4 | cut -c1-300
fi
"""
    + _OPT
    + r"""
pfx=$(opt prefix)
[ -n "$pfx" ] || pfx=/usr/local/nginx
if [ -n "$mpfx" ]; then pfx=$mpfx; fi
pfx=${pfx%/}
confp=$(opt conf-path)
if [ -z "$confp" ]; then
  if [ -n "$ver" ]; then confp=conf/nginx.conf; else confp=$dconf; fi
fi
case "$confp" in /*) ;; *) confp=$pfx/$confp ;; esac
if [ -n "$mconf" ]; then confp=$mconf; fi
berr=$(opt error-log-path)
bacc=$(opt http-log-path)
printf '[AIOPS_CONFIG]\n'
CFG_AWK='__CONFIG_AWK__'
cfg=''
if [ -n "$NGX" ]; then
  cfg=$(__TIMED_T__ | awk "$CFG_AWK" | head -n 200)
fi
case "$cfg" in
  *'test is successful'*) printf 'CONFIG_SOURCE=T\n' ;;
  *)
    printf '%s\n' "$cfg" | grep '^nginx: ' | head -n 10
    cdir=${confp%/*}
    ddir=${dconf%/*}
    set -- "$confp" "$cdir"/conf.d/*.conf "$cdir"/sites-enabled/* "$cdir"/vhost/*.conf "$cdir"/vhosts/*.conf
    if [ "$cdir" != "$ddir" ]; then set -- "$@" "$ddir"/conf.d/*.conf "$ddir"/sites-enabled/*; fi
    if [ -r "$confp" ]; then
      printf 'CONFIG_SOURCE=file\n'
      cfg=$(__TIMED_CAT__ | awk "$CFG_AWK" | head -n 200)
    else
      printf 'CONFIG_SOURCE=none\n'
      cfg=''
    fi
    ;;
esac
printf '%s\n' "$cfg" | grep -v '^$'
logs=$(printf '%s\n' "$cfg" | awk -v pfx="$pfx" '
  ($1 == "access_log" || $1 == "error_log") && NF >= 2 {
    p = $2
    sub(/;$/, "", p)
    gsub(/"/, "", p)
    if (p == "" || p == "off" || p == "stderr" || p ~ /^(syslog|memory):/ || index(p, "$")) next
    if (substr(p, 1, 1) != "/") p = pfx "/" p
    if (!seen[p]++) print $1, p
  }' | head -n 6)
cands=$(printf '%s\nerror_log %s\naccess_log %s\naccess_log %s\nerror_log %s\n' "$logs" "$berr" "$bacc" "$dacc" "$derr" | awk -v pfx="$pfx" '
  NF >= 2 && $2 != "stderr" {
    p = $2
    if (substr(p, 1, 1) != "/") p = pfx "/" p
    if (!seen[p]++) print $1, p
  }')
printf '[AIOPS_PROCESS]\n'
if command -v ps >/dev/null 2>&1; then
  printf '%s\n' "$procs" | grep -v '^$'
else
  printf 'CAPABILITY_MISSING:ps\n'
fi
printf '[AIOPS_SYSTEMD]\n'
if command -v systemctl >/dev/null 2>&1; then
  __TIMED_SYSTEMCTL__ 2>/dev/null | awk '
    BEGIN { RS = "" }
    {
      n = split($0, l, "\n")
      id = ""
      ok = 0
      for (i = 1; i <= n; i++) {
        if (substr(l[i], 1, 3) == "Id=") id = substr(l[i], 4)
        if (l[i] == "LoadState=loaded") ok = 1
      }
      if (!ok) next
      print "UNIT " substr(id, 1, 80)
      for (i = 1; i <= n; i++) print substr(l[i], 1, 200)
    }'
else
  printf 'CAPABILITY_MISSING:systemctl\n'
fi
printf '[AIOPS_LISTEN]\n'
if command -v ss >/dev/null 2>&1; then
  lrows=$(__TIMED_SS_L__ 2>/dev/null | awk '
    $1 == "LISTEN" {
      p = "-"
      i = index($0, "users:((\"")
      if (i) {
        p = substr($0, i + 9)
        j = index(p, "\"")
        if (j) p = substr(p, 1, j - 1)
      }
      print "LISTEN", $4, p
    }')
  if printf '%s\n' "$lrows" | awk '$1 == "LISTEN" && $3 != "-" {f = 1} END {exit !f}'; then
    printf 'LISTEN_SOURCE=proc\n'
    printf '%s\n' "$lrows" | awk '$3 ~ /^(nginx|openresty|tengine)/' | head -n 40
  else
    printf 'LISTEN_SOURCE=noproc\n'
    printf '%s\n' "$lrows" | grep '^LISTEN ' | head -n 40
  fi
  __TIMED_SS_E__ 2>/dev/null | awk '
    {
      if ($1 == "ESTAB") l = $4
      else if ($1 ~ /^[0-9]+$/) l = $3
      else next
      n = split(l, a, ":")
      c[a[n]]++
    }
    END { for (p in c) print c[p], p }' | sort -k1,1nr | head -n 10 | awk '{print "ESTAB", $2, $1}'
else
  printf 'CAPABILITY_MISSING:ss\n'
fi
printf '[AIOPS_LOGFILES]\n'
printf '%s\n' "$cands" | while read -r kind f; do
  if [ -z "$f" ] || [ ! -f "$f" ]; then continue; fi
  printf 'LOG %s %s\n' "$kind" "$f"
  ls -ldtL --time-style=+%s -- "$f" "$f".1 "$f".*.gz "$f"-* 2>/dev/null | head -n 6 | cut -c1-300
done | head -n 40
printf '[AIOPS_ERRORS]\n'
if [ -z "$skey" ] || [ -z "$ukey" ]; then
  printf 'CAPABILITY_MISSING:date\n'
else
  printf 'WINDOW %s %s %s %s\n' "$since" "$now" "$skey" "$ukey"
  elist=$(printf '%s\n' "$cands" | awk -v d="$derr" '$1 == "error_log" && !n {print $2; n = 1} END {print d}' | awk 'NF && !seen[$0]++')
  n=0
  printf '%s\n' "$elist" | while IFS= read -r f; do
    if [ -z "$f" ] || [ ! -f "$f" ]; then continue; fi
    n=$((n + 1))
    if [ "$n" -gt 2 ]; then break; fi
    printf 'FILE %s\n' "$f"
    if [ ! -r "$f" ]; then
      printf 'NOACCESS %s\nCAPABILITY_MISSING:log-permission\n' "$f"
      continue
    fi
    t0=$(date +%s)
    agg=$(__TIMED_TAIL__ | awk -v since="$skey" -v until="$ukey" '__ERROR_AWK__')
    t1=$(date +%s)
    if [ $((t1 - t0)) -ge __READ_SECONDS__ ]; then printf 'READ_TIMEOUT %s\n' "$f"; fi
    printf '%s\n' "$agg" | grep -E '^(LINES|LEVEL|UPSTREAM|COVERAGE_FROM) |^NO_ENTRIES$' | sort
    for t in TOP_UPSTREAM TOP_CLIENT TOP_REQUEST TOP_MESSAGE; do
      printf '%s\n' "$agg" | grep "^$t " | sort -k2,2nr | head -n 10
    done
    printf '%s\n' "$agg" | grep '^SAMPLE ' | sort -k2,2n | tail -n 20
  done
fi
exit 0
"""
)

ACCESS_TEMPLATE = (
    r"""
ws=__SINCE__
we=__UNTIL__
bucket=__BUCKET__
topn=__TOP__
sel=__STATUS__
p=__PATH__
kw=__KEYWORD__
cmds=__CMDS__
bins=__BINS__
dconf=__DCONF__
dacc=__DACC__
LIM=__LIMIT__
RLIM=__RLIMIT__
skey=$(date -d "@$ws" '+%Y%m%d%H%M%S' 2>/dev/null)
ukey=$(date -d "@$we" '+%Y%m%d%H%M%S' 2>/dev/null)
if [ "${#skey}" -ne 14 ] || [ "${#ukey}" -ne 14 ]; then
  printf 'CAPABILITY_MISSING:date\n'
  exit 69
fi
"""
    + _DISCOVER
    + r"""
ver=''
if [ -n "$NGX" ]; then ver=$(__TIMED_V__); fi
"""
    + _OPT
    + r"""
pfx=$(opt prefix)
[ -n "$pfx" ] || pfx=/usr/local/nginx
pfx=${pfx%/}
confp=$(opt conf-path)
if [ -z "$confp" ]; then
  if [ -n "$ver" ]; then confp=conf/nginx.conf; else confp=$dconf; fi
fi
case "$confp" in /*) ;; *) confp=$pfx/$confp ;; esac
bacc=$(opt http-log-path)
case "$bacc" in ''|/*) ;; *) bacc=$pfx/$bacc ;; esac
ALOG_AWK='__ALOG_AWK__'
alogs=''
loaded=''
alogs_load() {
  if [ -n "$loaded" ]; then return 0; fi
  loaded=1
  if [ -n "$NGX" ]; then
    alogs=$(__TIMED_T__ | awk -v pfx="$pfx" "$ALOG_AWK" | head -n 20)
  fi
  if [ -z "$alogs" ] && [ -r "$confp" ]; then
    cdir=${confp%/*}
    ddir=${dconf%/*}
    set -- "$confp" "$cdir"/conf.d/*.conf "$cdir"/sites-enabled/* "$cdir"/vhost/*.conf "$cdir"/vhosts/*.conf
    if [ "$cdir" != "$ddir" ]; then set -- "$@" "$ddir"/conf.d/*.conf "$ddir"/sites-enabled/*; fi
    alogs=$(__TIMED_CAT__ | awk -v pfx="$pfx" "$ALOG_AWK" | head -n 20)
  fi
}
okdir() {
  case "$1" in
    __ALLOWED__) return 0 ;;
  esac
  return 1
}
printf '[AIOPS_FILES]\n'
printf 'WINDOW %s %s %s %s\n' "$ws" "$we" "$skey" "$ukey"
if [ -n "$p" ]; then
  if [ ! -f "$p" ]; then
    printf 'AIOPS_REFUSED:path\n'
    exit 69
  fi
  r=$(readlink -f -- "$p" 2>/dev/null)
  [ -n "$r" ] || r=$p
  if ! { okdir "$p" && okdir "$r"; }; then
    alogs_load
    if ! printf '%s\n' "$alogs" | grep -Fqx -e "$p" -e "$r"; then
      printf 'AIOPS_REFUSED:path\n'
      exit 69
    fi
  fi
  files=$p
else
  alogs_load
  printf '%s\n' "$alogs" | head -n 10 | awk 'NF {print "CANDIDATE " $0}'
  files=$(printf '%s\n' "$alogs" | while IFS= read -r f; do if [ -n "$f" ] && [ -f "$f" ]; then printf '%s\n' "$f"; fi; done | head -n 3)
  if [ -z "$files" ]; then
    for f in "$bacc" "$dacc"; do
      if [ -n "$f" ] && [ -f "$f" ]; then files=$f; break; fi
    done
  fi
  [ -n "$files" ] || files=$dacc
fi
plan=$(printf '%s\n' "$files" | while IFS= read -r f; do
  [ -n "$f" ] || continue
  if [ ! -f "$f" ]; then printf 'M 0 0 %s\n' "$f"; continue; fi
  if [ ! -r "$f" ]; then printf 'N 0 0 %s\n' "$f"; continue; fi
  printf 'B 0 0 %s\n' "$f"
  if [ -f "$f.1" ]; then rot=$f.1; else rot=$(ls -td -- "$f"-[0-9]* 2>/dev/null | grep -v '[.]gz$' | head -n 1); fi
  if [ -n "$rot" ] && [ -r "$rot" ]; then
    info=$(ls -lLd --time-style=+%s -- "$rot" 2>/dev/null | awk '{print $5, $6}')
    rsz=${info%% *}
    rmt=${info##* }
    case "$rsz$rmt" in
      ''|*[!0-9]*) ;;
      *) if [ "$rmt" -ge "$ws" ]; then printf 'R %s %s %s\n' "$RLIM" "$rsz" "$rot"; fi ;;
    esac
  fi
  info=$(ls -lLd --time-style=+%s -- "$f" 2>/dev/null | awk '{print $5}')
  case "$info" in ''|*[!0-9]*) info=0 ;; esac
  printf 'C %s %s %s\n' "$LIM" "$info" "$f"
done)
printf '%s\n' "$plan" | while read -r k lim sz f; do
  case "$k" in
    M) printf 'MISSING %s\n' "$f" ;;
    N) printf 'NOACCESS %s\nCAPABILITY_MISSING:log-permission\n' "$f" ;;
    R|C)
      got=$sz
      if [ "$got" -gt "$lim" ]; then got=$lim; fi
      if [ "$k" = R ]; then printf 'FILE %s %s %s rotated\n' "$f" "$got" "$sz"; else printf 'FILE %s %s %s\n' "$f" "$got" "$sz"; fi
      if [ "$sz" -gt "$lim" ]; then printf 'TRUNCATED %s\n' "$f"; fi
      ;;
  esac
done
if ! printf '%s\n' "$plan" | grep -q '^C '; then printf 'NO_FILE\n'; fi
filt() {
  if [ -n "$kw" ]; then grep -a -F -- "$kw"; else cat; fi
}
# The read timeout is the remaining budget (not a fixed timed() value), so all
# files together stay inside the action timeout.
rd() {
  if [ "$3" -gt "$2" ]; then
    if command -v timeout >/dev/null 2>&1; then timeout -k 1 "$4" tail -c "$2" -- "$1" | sed 1d; else tail -c "$2" -- "$1" | sed 1d; fi
  elif command -v timeout >/dev/null 2>&1; then
    timeout -k 1 "$4" cat -- "$1"
  else
    cat -- "$1"
  fi
}
t0=$(date +%s)
end=$((t0 + __BUDGET__))
agg=$(printf '%s\n' "$plan" | while read -r k lim sz f; do
  case "$k" in
    B) printf '\001AIOPS_F %s\n' "$f" ;;
    R|C)
      t0=$(date +%s)
      left=$((end - t0))
      if [ "$left" -lt 1 ]; then printf '\001AIOPS_SKIP %s\n' "$f"; continue; fi
      rd "$f" "$lim" "$sz" "$left" | filt
      t1=$(date +%s)
      if [ $((t1 - t0)) -ge "$left" ]; then printf '\001AIOPS_SLOW %s\n' "$f"; fi
      ;;
  esac
done | awk -v skey="$skey" -v ukey="$ukey" -v sel="$sel" -v topn="$topn" -v bucket="$bucket" '__ACCESS_AWK__')
printf '%s\n' "$agg" | grep -E '^(RANGE|FIRST|SKIPPED|READ_TIMEOUT) '
printf '[AIOPS_TOTALS]\n'
printf '%s\n' "$agg" | grep -E '^(LINES|TOTAL|CLASS|SELECTED) '
printf '[AIOPS_CODES]\n'
printf '%s\n' "$agg" | grep '^CODE ' | sort -k3,3nr -k2,2 | head -n 10
printf '[AIOPS_TOP_URI]\n'
printf '%s\n' "$agg" | grep '^TOP_URI ' | sort -k2,2nr | head -n "$topn"
printf '[AIOPS_TOP_IP]\n'
printf '%s\n' "$agg" | grep '^TOP_IP ' | sort -k2,2nr | head -n "$topn"
printf '[AIOPS_TOP_UA]\n'
printf '%s\n' "$agg" | grep '^TOP_UA ' | sort -k2,2nr | head -n "$topn"
printf '[AIOPS_MINUTES]\n'
printf 'BUCKET %s\n' "$bucket"
printf '%s\n' "$agg" | grep '^MINUTE ' | sort -k2,2 | tail -n 120
printf '[AIOPS_TIMING]\n'
printf '%s\n' "$agg" | grep -E '^(REQ|UPS|NOUPSTREAM|UNAVAILABLE) '
printf '[AIOPS_SAMPLES]\n'
printf '%s\n' "$agg" | grep '^SAMPLE ' | sort -k2,2n | tail -n 10 | cut -c1-260
exit 0
"""
)


def _words(values) -> str:
    return quote(" ".join(values))


def _patterns() -> str:
    for pattern in ALLOWED_LOG_PATTERNS:
        if not _PATTERN_RE.fullmatch(pattern):
            raise ValueError("日志目录白名单含有不安全的字符")
    return "|".join(ALLOWED_LOG_PATTERNS)


_PLACEHOLDER = re.compile(r"__([A-Z][A-Z_]*?)__")


def _fill(template: str, values: dict) -> str:
    """Single pass: inserted values (paths, keywords, awk) are never re-scanned."""
    return _PLACEHOLDER.sub(lambda match: values[match[1]], template)


def nginx_script(options: dict) -> str:
    minutes = int(options.get("minutes") or 30)
    return _fill(
        NGINX_TEMPLATE,
        {
            "MINUTES": str(minutes),
            "CMDS": _words(NGINX_COMMANDS),
            "BINS": _words(NGINX_BINARIES),
            "UNITS": _words(SYSTEMD_UNITS),
            "DCONF": quote(DEFAULT_CONF),
            "DACC": quote(DEFAULT_ACCESS_LOG),
            "DERR": quote(DEFAULT_ERROR_LOG),
            "TIMED_V": timed(5, '"$NGX" -V 2>&1'),
            "TIMED_T": timed(8, '"$NGX" -T "$@" 2>&1'),
            "TIMED_CAT": timed(2, 'cat -- "$@" 2>/dev/null'),
            "TIMED_SYSTEMCTL": timed(
                2,
                "systemctl show -p Id,LoadState,ActiveState,SubState,Result,"
                "NRestarts,ExecMainStartTimestamp --no-pager -- $units",
            ),
            "TIMED_SS_L": timed(2, "ss -ltnp"),
            "TIMED_SS_E": timed(2, "ss -tn state established"),
            "TIMED_TAIL": timed(
                ERROR_READ_SECONDS,
                "tail -c " + str(int(ERROR_TAIL_BYTES)) + ' -- "$f"',
            ),
            "READ_SECONDS": str(int(ERROR_READ_SECONDS)),
            "CONFIG_AWK": CONFIG_AWK,
            "ERROR_AWK": ERROR_AWK,
        },
    )


def bucket_minutes(since: int, until: int) -> int:
    """1-minute rows up to 2 h; 10-minute buckets beyond (15 above 20 h, ≤ 120 rows)."""
    span = until - since
    return 1 if span <= 7200 else 10 if span <= 72000 else 15


def access_script(options: dict) -> str:
    since, until = resolve_window(options)
    path = options.get("path")
    keyword = options.get("keyword")
    return _fill(
        ACCESS_TEMPLATE,
        {
            "SINCE": str(int(since)),
            "UNTIL": str(int(until)),
            "BUCKET": str(int(bucket_minutes(since, until))),
            "TOP": str(int(options.get("top") or 10)),
            "STATUS": quote(options.get("status") or "all"),
            "PATH": quote(path) if path else "''",
            "KEYWORD": quote(keyword) if keyword else "''",
            "CMDS": _words(NGINX_COMMANDS),
            "BINS": _words(NGINX_BINARIES),
            "DCONF": quote(DEFAULT_CONF),
            "DACC": quote(DEFAULT_ACCESS_LOG),
            "LIMIT": str(int(ACCESS_TAIL_BYTES)),
            "RLIMIT": str(int(ROTATED_TAIL_BYTES)),
            "BUDGET": str(int(ACCESS_READ_BUDGET)),
            "ALLOWED": _patterns(),
            "TIMED_V": timed(3, '"$NGX" -V 2>&1'),
            "TIMED_T": timed(8, '"$NGX" -T 2>/dev/null'),
            "TIMED_CAT": timed(2, 'cat -- "$@" 2>/dev/null'),
            "ALOG_AWK": ALOG_AWK,
            "ACCESS_AWK": ACCESS_AWK,
        },
    )


# ---------------------------------------------------------------------------
# Parsers: tolerate any input, never raise; evidence lines are redacted again.
# ---------------------------------------------------------------------------

_SECRET_VALUE = re.compile(
    r"(?i)([\w.-]*(?:password|passwd|secret|token|key|credential)[\w.-]*)"
    r"(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s;,&\"']+)"
)
_URL_CREDENTIALS = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^\s/@:]*:[^\s/@]+@")
UPSTREAM_KINDS = (
    "timed_out",
    "connect_failed",
    "no_live_upstreams",
    "prematurely_closed",
    "connection_refused",
    "other_upstream",
)
ERROR_LEVELS = ("error", "crit", "alert", "emerg")


def _redact(value: str) -> str:
    value = _URL_CREDENTIALS.sub(r"\1[REDACTED]@", value)
    return _SECRET_VALUE.sub(lambda m: m[1] + m[2] + "[REDACTED]", value)


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _lines(text: str, name: str) -> list[str]:
    return [
        line.rstrip("\r")
        for line in observations.section(text, name).splitlines()
        if line.strip()
    ]


def _arg(line: str, directive: str) -> str:
    """Directive arguments without the name and the trailing semicolon."""
    value = line[len(directive) :].strip()
    return value[:-1].rstrip() if value.endswith(";") else value


def _add_unique(items: list, value, limit: int) -> None:
    if value and value not in items and len(items) < limit:
        items.append(value)


def _top(counter: dict, limit: int = 10) -> list[dict]:
    rows = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    return [{"value": value, "count": count} for value, count in rows[:limit]]


def _merge_top(counter: dict, line: str, tag: str) -> None:
    match = re.match(re.escape(tag) + r" (\d+) (.+)$", line)
    if match:
        value = _redact(match[2])[:200]
        counter[value] = counter.get(value, 0) + int(match[1])


def _key_time(key) -> str | None:
    if not isinstance(key, str) or not re.fullmatch(r"\d{14}", key):
        return None
    return f"{key[0:4]}-{key[4:6]}-{key[6:8]} {key[8:10]}:{key[10:12]}:{key[12:14]}"


def _slash_time(value) -> str | None:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"(\d{4})/(\d\d)/(\d\d) (\d\d:\d\d:\d\d)", value)
    return f"{match[1]}-{match[2]}-{match[3]} {match[4]}" if match else None


def _config(text: str) -> dict:
    lines = _lines(text, "CONFIG")
    source = "none"
    for line in lines:
        match = re.match(r"CONFIG_SOURCE=(T|file|none)$", line)
        if match:
            source = match[1]
    tests = [line for line in lines if line.startswith("nginx: ")]
    test = "unknown"
    test_reason = None
    if any("test is successful" in line for line in tests):
        test = "ok"
    elif any("test failed" in line for line in tests):
        emerg = [line for line in tests if "[emerg]" in line]
        if emerg and all(
            "Permission denied" in line or "(13:" in line for line in emerg
        ):
            test_reason = "permission"
        else:
            test = "failed"
    config = {
        "source": source,
        "test": test,
        "test_messages": [
            _redact(line)[:300]
            for line in tests
            if "[emerg]" in line or "[alert]" in line or "[warn]" in line
        ][:8],
        "access_logs": [],
        "error_logs": [],
        "log_formats": {},
        "upstreams": [],
        "listen": [],
        "server_names_count": None,
        "worker_processes": None,
        "worker_connections": None,
        "timeouts": {
            "proxy_connect": [],
            "proxy_read": [],
            "proxy_send": [],
            "keepalive": [],
        },
        "client_max_body_size": [],
        "proxy_pass_count": None,
    }
    if test_reason:
        config["test_reason"] = test_reason
    upstream = None
    timeouts = {
        "proxy_connect_timeout": "proxy_connect",
        "proxy_read_timeout": "proxy_read",
        "proxy_send_timeout": "proxy_send",
        "keepalive_timeout": "keepalive",
    }
    for line in lines:
        if line.startswith(("nginx: ", "CONFIG_SOURCE=")):
            continue
        words = line.split()
        name = words[0] if words else ""
        if name == "UPSTREAM" and len(words) >= 2:
            if len(config["upstreams"]) < 40:
                upstream = {"name": words[1][:100], "servers": [], "keepalive": None}
                config["upstreams"].append(upstream)
            else:
                upstream = None
            continue
        if name == "COUNT" and len(words) == 3:
            count = _int(words[2])
            if words[1] == "server_name":
                config["server_names_count"] = count
            elif words[1] == "proxy_pass":
                config["proxy_pass_count"] = count
            elif words[1] in {"include", "upstream", "config_files", "input_lines"}:
                config[words[1] + "_count"] = count
            continue
        if name == "CONFIG_TRUNCATED":
            config["truncated"] = True
            continue
        if name == "server" and upstream is not None:
            _add_unique(upstream["servers"], _redact(_arg(line, "server"))[:160], 50)
            continue
        if name == "keepalive" and upstream is not None:
            upstream["keepalive"] = _int(_arg(line, "keepalive"))
            continue
        upstream = None
        if name in {"access_log", "error_log"} and len(words) >= 2:
            path = words[1].rstrip(";").strip('"')
            key = "access_logs" if name == "access_log" else "error_logs"
            # Files only: off, stderr, syslog: and memory: are not readable logs.
            if path != "off" and not path.startswith(("stderr", "syslog:", "memory:")):
                _add_unique(config[key], _redact(path)[:200], 20)
        elif name == "log_format" and len(words) >= 3:
            fmt = _arg(line, "log_format")[len(words[1]) :].strip()
            if len(config["log_formats"]) < 10:
                config["log_formats"][words[1][:60]] = _redact(fmt)[:300]
        elif name == "listen":
            _add_unique(config["listen"], _arg(line, "listen")[:80], 40)
        elif name == "worker_processes" and config["worker_processes"] is None:
            config["worker_processes"] = _arg(line, name)[:20] or None
        elif name == "worker_connections" and config["worker_connections"] is None:
            config["worker_connections"] = _int(_arg(line, name))
        elif name in timeouts:
            _add_unique(config["timeouts"][timeouts[name]], _arg(line, name)[:40], 5)
        elif name == "client_max_body_size":
            _add_unique(config["client_max_body_size"], _arg(line, name)[:20], 5)
    return config


def _processes(text: str) -> list[dict]:
    rows = []
    for line in _lines(text, "PROCESS"):
        fields = line.split(None, 7)
        if len(fields) < 7 or not fields[0].isdigit():
            continue
        args = fields[7] if len(fields) > 7 else ""
        rows.append(
            {
                "pid": int(fields[0]),
                "ppid": _int(fields[1]),
                "role": "master"
                if "master process" in args
                else "worker"
                if "worker process" in args
                else "other",
                "user": fields[2][:32],
                "elapsed_seconds": _int(fields[3]),
                "rss_KiB": _int(fields[4]),
                "cpu_percent": observations.number(fields[5]),
                "command": _redact(args)[:120],
            }
        )
    return rows[:40]


SYSTEMD_KEYS = {
    "LoadState": "load",
    "ActiveState": "active",
    "SubState": "sub",
    "Result": "result",
    "NRestarts": "restarts",
    "ExecMainStartTimestamp": "started",
}


def _systemd(text: str) -> list[dict]:
    units = []
    current = None
    for line in _lines(text, "SYSTEMD"):
        if line.startswith("UNIT "):
            current = {"unit": line[5:].strip()[:80]}
            current.update(dict.fromkeys(SYSTEMD_KEYS.values()))
            if len(units) < 5:
                units.append(current)
            continue
        if current is None or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in SYSTEMD_KEYS:
            field = SYSTEMD_KEYS[key]
            current[field] = _int(value) if field == "restarts" else value[:80] or None
    return units


def _listening(text: str) -> tuple[list, dict, str | None]:
    rows, estab, source = [], {}, None
    for line in _lines(text, "LISTEN"):
        match = re.match(r"LISTEN_SOURCE=(proc|noproc)$", line)
        if match:
            source = match[1]
            continue
        fields = line.split()
        if len(fields) >= 3 and fields[0] == "LISTEN" and len(rows) < 40:
            port = fields[1].rsplit(":", 1)[-1]
            rows.append(
                {
                    "local": fields[1][:64],
                    "port": int(port) if port.isdigit() else None,
                    "process": None if fields[2] == "-" else fields[2][:32],
                }
            )
        elif len(fields) == 3 and fields[0] == "ESTAB":
            count = _int(fields[2])
            if count is not None and len(estab) < 10:
                estab[fields[1][:16]] = count
    return rows, estab, source


LS_ROW = re.compile(r"\s(\d+)\s+(\d{9,11})\s+(/\S.*)$")


def _log_files(text: str) -> list[dict]:
    files = []
    current = None
    for line in _lines(text, "LOGFILES"):
        match = re.match(r"LOG (access_log|error_log) (/\S.*)$", line)
        if match:
            current = None
            if len(files) < 10:
                current = {
                    "kind": match[1],
                    "path": match[2][:200],
                    "bytes": None,
                    "mtime": None,
                    "rotated": [],
                }
                files.append(current)
            continue
        match = LS_ROW.search(line)
        if not match or current is None:
            continue
        size, mtime, path = int(match[1]), int(match[2]), match[3][:200]
        if path == current["path"]:
            current["bytes"], current["mtime"] = size, mtime
        elif len(current["rotated"]) < 8:
            current["rotated"].append({"path": path, "bytes": size, "mtime": mtime})
    return files


def _errors(text: str) -> dict:
    errors = {
        "window": {"since": None, "until": None},
        "files": [],
        "lines_in_window": 0,
        "counts_by_level": {},
        "upstream_errors": {},
        "top_upstreams": [],
        "top_clients": [],
        "top_requests": [],
        "top_messages": [],
        "samples": [],
        "coverage_from": None,
    }
    tops = {
        "TOP_UPSTREAM": {},
        "TOP_CLIENT": {},
        "TOP_REQUEST": {},
        "TOP_MESSAGE": {},
    }
    samples = []
    current = None
    for line in _lines(text, "ERRORS"):
        fields = line.split()
        tag = fields[0] if fields else ""
        if tag == "WINDOW":
            match = re.match(
                r"WINDOW (\d+) (\d+) (\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) "
                r"(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d)$",
                line,
            )
            if match:
                errors["window"] = {
                    "since": int(match[1]),
                    "until": int(match[2]),
                    "since_local": _slash_time(match[3]),
                    "until_local": _slash_time(match[4]),
                }
        elif tag == "FILE" and len(fields) >= 2:
            current = {
                "path": line[5:].strip()[:200],
                "readable": True,
                "lines_in_window": None,
                "lines_read": None,
                "coverage_from": None,
                "read_timeout": False,
            }
            if len(errors["files"]) < 4:
                errors["files"].append(current)
        elif current is None:
            continue
        elif tag == "NOACCESS":
            current["readable"] = False
        elif tag == "READ_TIMEOUT":
            current["read_timeout"] = True
        elif tag == "LINES" and len(fields) == 3:
            current["lines_in_window"] = _int(fields[1])
            current["lines_read"] = _int(fields[2])
            errors["lines_in_window"] += _int(fields[1]) or 0
        elif tag == "COVERAGE_FROM":
            current["coverage_from"] = _slash_time(line[14:].strip())
        elif tag == "LEVEL" and len(fields) == 3:
            count = _int(fields[2])
            if count is not None and re.fullmatch(r"[a-z]{1,12}", fields[1]):
                levels = errors["counts_by_level"]
                levels[fields[1]] = levels.get(fields[1], 0) + count
        elif tag == "UPSTREAM" and len(fields) == 3:
            count = _int(fields[2])
            if count is not None and re.fullmatch(r"[a-z_]{1,32}", fields[1]):
                kinds = errors["upstream_errors"]
                kinds[fields[1]] = kinds.get(fields[1], 0) + count
        elif tag in tops:
            _merge_top(tops[tag], line, tag)
        elif tag == "SAMPLE":
            match = re.match(r"SAMPLE (\d+) (.*)$", line)
            if match:
                samples.append(_redact(match[2])[:240])
    errors["top_upstreams"] = _top(tops["TOP_UPSTREAM"])
    errors["top_clients"] = _top(tops["TOP_CLIENT"])
    errors["top_requests"] = _top(tops["TOP_REQUEST"])
    errors["top_messages"] = _top(tops["TOP_MESSAGE"])
    # Lines start with "YYYY/MM/DD HH:MM:SS": a stable sort keeps file order on ties.
    errors["samples"] = sorted(samples, key=lambda line: line[:19])[-20:]
    starts = [f["coverage_from"] for f in errors["files"] if f["coverage_from"]]
    errors["coverage_from"] = max(starts) if starts else None
    return errors


def parse_nginx(text, summary, findings, options) -> None:
    text = text if isinstance(text, str) else ""
    options = options if isinstance(options, dict) else {}
    binary = binary_source = master_bin = None
    running_args = {}
    for line in _lines(text, "BIN"):
        match = re.match(r"BIN (/\S+)( running)?$", line)
        if match:
            binary = match[1][:200]
            binary_source = "running_master" if match[2] else "discovered"
        match = re.match(r"MASTER_BIN (/\S+)$", line)
        if match:
            master_bin = match[1][:200]
        match = re.match(r"(PREFIX|CONF)_ARG (/\S+)$", line)
        if match:
            running_args["prefix" if match[1] == "PREFIX" else "conf"] = match[2][:200]
    version = None
    build = {
        "prefix": None,
        "conf_path": None,
        "error_log_path": None,
        "http_log_path": None,
    }
    for line in _lines(text, "VERSION"):
        match = re.search(r"version: (\S+)", line)
        if match and version is None:
            version = match[1][:80]
        match = re.match(
            r"--(prefix|conf-path|error-log-path|http-log-path)=(\S+)$", line
        )
        if match:
            key = match[1].replace("-", "_")
            build[key] = build[key] or match[2][:200]
    config = _config(text)
    processes = _processes(text)
    systemd = _systemd(text)
    listening, established, listen_source = _listening(text)
    errors = _errors(text)
    workers = sum(1 for row in processes if row["role"] == "worker")
    masters = [row for row in processes if row["role"] == "master"]
    summary.update(
        {
            "binary": binary,
            "binary_source": binary_source,
            "version": version,
            "build": build,
            "config": config,
            "processes": processes,
            "worker_count": workers,
            "systemd": systemd,
            "listening": listening,
            "listen_source": listen_source,
            "established_by_port": established,
            "log_files": _log_files(text),
            "errors": errors,
        }
    )
    if master_bin:
        summary["master_binary"] = master_bin
    if running_args:
        # -p/-c of the running master, reused for nginx -T.
        summary["running_args"] = running_args
    minutes = _int(options.get("minutes")) or 30
    summary["coverage"] = (
        "单次快照：进程、端口与 systemd 为采集瞬间状态；配置来自 nginx -T，"
        "失败或无权限时回退读取主配置与 conf.d/sites-enabled（include 的其他目录不在其中）；"
        f"error.log 只读每个文件尾部 20 MB、最多 2 个，按主机本地时间统计最近 {minutes} 分钟；"
        "无匹配不代表未发生故障"
    )
    observations.metric(summary, findings, "nginx_worker_count", workers)
    if established:
        observations.metric(
            summary, findings, "established_connections", sum(established.values())
        )
    if binary is None and not processes:
        findings.append(
            {
                "level": "info",
                "metric": "nginx_not_found",
                "value": "未发现 nginx/openresty/tengine",
                "threshold": "存在二进制或进程",
                "hint": "PATH、常见安装目录与进程中都没有 Nginx；若运行在容器内请改查容器，或确认主机是否部署了 Nginx",
            }
        )
    if master_bin and binary and master_bin != binary:
        findings.append(
            {
                "level": "info",
                "metric": "nginx_binary_mismatch",
                "value": {"running": master_bin, "discovered": binary},
                "threshold": "相同安装",
                "hint": "运行中的 master 与发现的二进制不是同一安装，配置测试与版本可能不对应正在服务的实例",
            }
        )
    if config["test"] == "failed":
        findings.append(
            {
                "level": "critical",
                "metric": "config_test_failed",
                "value": config["test_messages"][:3] or "test failed",
                "threshold": "test is successful",
                "hint": "nginx -T 配置测试失败：此时 reload 会被拒绝、重启会失败；按 [emerg] 行定位文件与行号，修复后再 reload",
            }
        )
    elif config.get("test_reason") == "permission":
        findings.append(
            {
                "level": "info",
                "metric": "config_test_unavailable",
                "value": config["test_messages"][:2] or "permission denied",
                "threshold": "可执行 nginx -T",
                "hint": "诊断账号无权完成 nginx -T（pid、日志或证书不可读），配置摘要来自只读文件回退，不能据此判断配置是否有效",
            }
        )
    active_unit = any(unit.get("active") == "active" for unit in systemd)
    # Without a process listing (ps missing, section absent) nothing is known.
    process_text = observations.section(text, "PROCESS")
    listed = "[AIOPS_PROCESS]" in text and "CAPABILITY_MISSING:ps" not in process_text
    if binary and not masters and listed:
        if active_unit:
            findings.append(
                {
                    "level": "info",
                    "metric": "nginx_process_not_visible",
                    "value": "systemd active，但进程列表中没有 master",
                    "threshold": "可见 master 进程",
                    "hint": "可能是 /proc 以 hidepid 挂载或进程在容器内；以 systemd 状态与监听端口为准",
                }
            )
        else:
            findings.append(
                {
                    "level": "critical",
                    "metric": "nginx_inactive",
                    "value": "无 nginx master 进程",
                    "threshold": "master 进程运行中",
                    "hint": "已安装 Nginx 但未运行：查看 systemd Result/日志与 error.log 中的 [emerg]（端口占用、配置错误、证书不可读）",
                }
            )
    for unit in systemd:
        if unit.get("restarts"):
            observations.metric(
                summary,
                findings,
                "systemd_restarts:" + unit["unit"],
                unit["restarts"],
                threshold=1,
                hint="systemd 自动重启过该单元（经验阈值 ≥1 即关注）；结合 Result、error.log 与 journal 查看重启原因",
            )
    _error_findings(summary, findings, errors)


def _error_findings(summary, findings, errors) -> None:
    kinds = errors["upstream_errors"]
    total = sum(kinds.get(kind, 0) for kind in UPSTREAM_KINDS)
    # Counts are only meaningful for logs that were actually read.
    read = any(f["lines_read"] is not None for f in errors["files"])
    if read:
        observations.metric(
            summary,
            findings,
            "upstream_errors",
            total,
            threshold=1,
            critical=20,
            hint="窗口内 error.log 的上游错误合计（经验阈值：≥1 关注，≥20 严重）；按 top_upstreams 定位后端，核查其健康、连接数与响应时间",
        )
    for kind, metric_name, hint in (
        (
            "timed_out",
            "upstream_timed_out",
            "上游响应超时（504 的常见来源）：核查后端耗时、proxy_read_timeout 与后端线程/连接池是否耗尽",
        ),
        (
            "connect_failed",
            "upstream_connect_failed",
            "连接上游失败（含拒绝连接、不可达、socket 不存在）：确认后端进程与端口在监听、防火墙与 unix socket 路径",
        ),
    ):
        count = kinds.get(kind, 0)
        if kind == "connect_failed":
            count += kinds.get("connection_refused", 0)
        if count:
            findings.append(
                {
                    "level": "warning",
                    "metric": metric_name,
                    "value": count,
                    "threshold": 1,
                    "hint": hint + "（经验阈值 ≥1 即关注）",
                }
            )
    for kind, metric_name, hint in (
        (
            "no_live_upstreams",
            "no_live_upstreams",
            "upstream 组内所有成员都被标记不可用（502）：检查 max_fails/fail_timeout 与各后端健康，出现即视为严重",
        ),
        (
            "worker_connections",
            "worker_connections_exhausted",
            "worker_connections 不足：调大 worker_connections/worker_rlimit_nofile，或排查连接泄漏与慢上游占用连接；出现即视为严重",
        ),
        (
            "too_many_open_files",
            "too_many_open_files",
            "文件句柄耗尽：核查 worker_rlimit_nofile、systemd LimitNOFILE 与系统 fs.file-max；出现即视为严重",
        ),
    ):
        observations.metric(
            summary,
            findings,
            metric_name,
            kinds.get(kind, 0) if read else None,
            threshold=1,
            critical=1,
            hint=hint,
        )
    levels = errors["counts_by_level"]
    if read:
        observations.metric(
            summary,
            findings,
            "error_log_errors",
            sum(levels.get(level, 0) for level in ERROR_LEVELS),
            threshold=10,
            critical=100,
            hint="窗口内 error 及以上级别日志条数（经验阈值：≥10 关注，≥100 严重）；先看 top_messages 与 samples 判断是否同一类问题",
        )
    since = errors["window"].get("since_local")
    if errors["coverage_from"] and since and errors["coverage_from"] > since:
        findings.append(
            {
                "level": "info",
                "metric": "error_log_window_not_covered",
                "value": errors["coverage_from"],
                "threshold": since,
                "hint": "读取的 error.log 尾部（或轮转后的新文件）晚于窗口开始，更早的日志未统计；必要时查看轮转文件",
            }
        )
    if any(f["read_timeout"] for f in errors["files"]):
        findings.append(
            {
                "level": "info",
                "metric": "error_log_read_timeout",
                "value": [f["path"] for f in errors["files"] if f["read_timeout"]],
                "threshold": "读取完成",
                "hint": "读取 error.log 达到时间上限，最新的日志可能未统计完整",
            }
        )


# ----------------------------- nginx_access -----------------------------------

MIN_RATIO_REQUESTS = 20


def _access_files(text: str) -> dict:
    result = {
        "window": None,
        "files": [],
        "candidates": [],
        "missing": [],
        "no_access": [],
        "truncated": [],
        "skipped": [],
        "read_timeout": [],
        "ranges": [],
        "first": None,
        "last": None,
        "no_file": False,
    }
    for line in _lines(text, "FILES"):
        match = re.match(r"WINDOW (\d+) (\d+) (\d{14}) (\d{14})$", line)
        if match:
            result["window"] = {
                "since": int(match[1]),
                "until": int(match[2]),
                "since_local": _key_time(match[3]),
                "until_local": _key_time(match[4]),
            }
            continue
        match = re.match(r"FILE (/\S.*?) (\d+) (\d+)( rotated)?$", line)
        if match:
            if len(result["files"]) < 8:
                result["files"].append(
                    {
                        "path": match[1][:200],
                        "bytes_read": int(match[2]),
                        "size": int(match[3]),
                        "rotated": bool(match[4]),
                    }
                )
            continue
        match = re.match(r"RANGE (\d{14}|-) (\d{14}|-) (.*)$", line)
        if match:
            if len(result["ranges"]) < 8:
                result["ranges"].append(
                    {
                        "path": match[3][:200],
                        "first_at": _key_time(match[1]),
                        "last_at": _key_time(match[2]),
                    }
                )
            continue
        match = re.match(r"FIRST (\d{14}|-) LAST (\d{14}|-)$", line)
        if match:
            result["first"], result["last"] = _key_time(match[1]), _key_time(match[2])
            continue
        for tag, key in (
            ("CANDIDATE ", "candidates"),
            ("MISSING ", "missing"),
            ("NOACCESS ", "no_access"),
            ("TRUNCATED ", "truncated"),
            ("SKIPPED ", "skipped"),
            ("READ_TIMEOUT ", "read_timeout"),
        ):
            if line.startswith(tag) and len(result[key]) < 10:
                result[key].append(line[len(tag) :].strip()[:200])
        if line == "NO_FILE":
            result["no_file"] = True
    return result


def _counted(text: str, tag: str, limit: int) -> list[dict]:
    """``TAG count value`` rows of the ``[AIOPS_TAG]`` block, largest first."""
    rows = []
    for line in _lines(text, tag):
        match = re.match(re.escape(tag) + r" (\d+) (.+)$", line)
        if match and len(rows) < limit:
            rows.append({"value": _redact(match[2])[:200], "count": int(match[1])})
    rows.sort(key=lambda row: -row["count"])
    return rows


def _timing(text: str) -> dict:
    timing = {"request_time": None, "upstream_time": None, "no_upstream": None}
    for line in _lines(text, "TIMING"):
        fields = line.split()
        if fields[:1] == ["REQ"] and len(fields) == 7:
            values = [observations.number(v) for v in fields[1:]]
            if None not in values:
                timing["request_time"] = {
                    "count": int(values[0]),
                    "avg": values[1],
                    "max": values[2],
                    "over_1s": int(values[3]),
                    "over_3s": int(values[4]),
                    "over_10s": int(values[5]),
                }
        elif fields[:1] == ["UPS"] and len(fields) == 6:
            values = [observations.number(v) for v in fields[1:]]
            if None not in values:
                timing["upstream_time"] = {
                    "count": int(values[0]),
                    "avg": values[1],
                    "max": values[2],
                    "over_1s": int(values[3]),
                    "over_3s": int(values[4]),
                }
        elif fields[:1] == ["NOUPSTREAM"] and len(fields) == 2:
            timing["no_upstream"] = _int(fields[1])
    return timing


def _ratio_finding(findings, name, count, total, warn, critical, hint) -> None:
    if not total:
        return
    percent = round(count * 100 / total, 2)
    if percent < warn:
        return
    findings.append(
        {
            "level": "critical"
            if critical is not None and percent >= critical
            else "warning",
            "metric": name,
            "value": {"percent": percent, "count": count, "requests": total},
            "threshold": {"warning_percent": warn, "critical_percent": critical}
            if critical is not None
            else {"warning_percent": warn},
            "hint": hint,
        }
    )


def parse_access(text, summary, findings, options) -> None:
    text = text if isinstance(text, str) else ""
    options = options if isinstance(options, dict) else {}
    files = _access_files(text)
    window = files["window"]
    if window is None and options.get("since") is not None:
        window = {
            "since": _int(options.get("since")),
            "until": _int(options.get("until")),
        }
    summary.update(
        {
            "window": window or {"since": None, "until": None},
            "selection": {
                "status": options.get("status") or "all",
                "keyword": options.get("keyword"),
                "top": _int(options.get("top")) or 10,
            },
            "files": files["files"],
            "first_at": files["first"],
            "last_at": files["last"],
        }
    )
    for key in ("candidates", "missing", "no_access", "truncated", "skipped"):
        if files[key]:
            summary[key] = files[key]
    if "AIOPS_REFUSED:path" in text:
        summary["refused"] = True
        summary["coverage"] = "路径未通过主机端二次校验，未读取任何日志"
        findings.append(
            {
                "level": "warning",
                "metric": "refused_path",
                "value": options.get("path") or "path",
                "threshold": "nginx access_log 或允许的日志目录",
                "hint": "path 必须是普通文件，且是 nginx 配置中的 access_log，或位于 /var/log/nginx、/var/log/openresty、"
                "/usr/local/nginx/logs、/usr/local/openresty/nginx/logs 下，或匹配 /data|/opt|/home|/srv|/app 下的 "
                "*/logs/*access*.log（符号链接按真实路径再校验）；不传 path 可自动选择配置中的访问日志",
            }
        )
        return
    totals = {"requests": 0, "by_class": {}, "selected": 0}
    lines_read = unparsed = None
    for line in _lines(text, "TOTALS"):
        fields = line.split()
        if fields[:1] == ["TOTAL"] and len(fields) == 2:
            totals["requests"] = _int(fields[1]) or 0
        elif fields[:1] == ["CLASS"] and len(fields) == 3:
            count = _int(fields[2])
            if count is not None and fields[1] in {"2xx", "3xx", "4xx", "5xx", "other"}:
                totals["by_class"][fields[1]] = count
        elif fields[:1] == ["SELECTED"] and len(fields) == 2:
            totals["selected"] = _int(fields[1]) or 0
        elif fields[:1] == ["LINES"] and len(fields) == 4:
            lines_read, unparsed = _int(fields[1]), _int(fields[2])
            totals["lines_read"] = lines_read
            totals["unparsed_lines"] = unparsed
            totals["outside_window"] = _int(fields[3])
    codes = []
    for line in _lines(text, "CODES"):
        fields = line.split()
        if len(fields) == 3 and fields[0] == "CODE" and _int(fields[2]) is not None:
            codes.append({"code": fields[1][:3], "count": int(fields[2])})
    codes = sorted(codes, key=lambda row: -row["count"])[:10]
    bucket = 1
    timeline = []
    for line in _lines(text, "MINUTES"):
        fields = line.split()
        if fields[:1] == ["BUCKET"] and len(fields) == 2:
            bucket = _int(fields[1]) or 1
        elif (
            len(fields) == 4
            and fields[0] == "MINUTE"
            and re.fullmatch(r"\d{12}", fields[1])
        ):
            requests, errors_5xx = _int(fields[2]), _int(fields[3])
            if requests is None:
                continue
            key = fields[1]
            timeline.append(
                {
                    "minute": f"{key[0:4]}-{key[4:6]}-{key[6:8]} {key[8:10]}:{key[10:12]}",
                    "requests": requests,
                    "errors_5xx": errors_5xx or 0,
                }
            )
    timeline = sorted(timeline, key=lambda row: row["minute"])[-120:]
    samples = []
    for line in _lines(text, "SAMPLES"):
        match = re.match(r"SAMPLE (\d+) (.*)$", line)
        if match:
            samples.append(_redact(match[2])[:240])
    timing = _timing(text)
    summary.update(
        {
            "totals": totals,
            "codes": codes,
            "top": {
                "uris": _counted(text, "TOP_URI", 30),
                "ips": _counted(text, "TOP_IP", 30),
                "uas": _counted(text, "TOP_UA", 30),
            },
            "timeline": timeline,
            "bucket_minutes": bucket,
            "timing": timing,
            "samples": samples[-10:],
        }
    )
    rotated = any(f["rotated"] for f in files["files"])
    summary["coverage"] = (
        "只读每个访问日志尾部约 30 MB"
        + ("，并读取了未压缩轮转文件尾部 10 MB" if rotated else "，未读取轮转文件")
        + "；按主机本地时间筛选窗口，status 只影响 TOP 与样本，"
        "总量、状态码、分钟趋势与耗时统计覆盖窗口内全部请求（keyword 先行过滤）；"
        "无法识别的日志格式计入 unparsed_lines"
    )
    requests = totals["requests"]
    classes = totals["by_class"]
    observations.metric(summary, findings, "requests_total", requests)
    if requests:
        observations.metric(
            summary,
            findings,
            "status_5xx_percent",
            classes.get("5xx", 0) * 100 / requests,
            "%",
        )
    if requests == 0:
        findings.append(
            {
                "level": "info",
                "metric": "no_requests",
                "value": 0,
                "threshold": "≥1",
                "hint": "窗口内没有可识别的请求：确认时间窗口、日志路径与 keyword；"
                + (
                    "读到的行均无法识别为 combined/JSON 访问日志"
                    if lines_read and unparsed == lines_read
                    else "该日志在窗口内可能确实没有流量"
                ),
            }
        )
    if lines_read and unparsed and unparsed * 2 > lines_read:
        findings.append(
            {
                "level": "info",
                "metric": "log_format_unrecognized",
                "value": {"unparsed": unparsed, "lines": lines_read},
                "threshold": "可识别 combined/JSON 时间字段",
                "hint": "超过一半的行无法识别时间字段（自定义 log_format）；统计只覆盖可识别的行",
            }
        )
    errors_5xx = classes.get("5xx", 0)
    if requests >= MIN_RATIO_REQUESTS:
        _ratio_finding(
            findings,
            "status_5xx_ratio",
            errors_5xx,
            requests,
            1,
            5,
            "5xx 占比偏高（经验阈值：≥1% 关注，≥5% 严重）：按 codes 区分 502/503/504，"
            "用 status=5xx 查看 TOP URI 与样本，并结合 ssh_diagnose_nginx 的上游错误定位后端",
        )
        _ratio_finding(
            findings,
            "status_4xx_ratio",
            classes.get("4xx", 0),
            requests,
            20,
            None,
            "4xx 占比 ≥20%（经验阈值）：常见于爬虫扫描、鉴权失败或前端调用错误路径，查看 TOP IP/UA 与 URI",
        )
    elif errors_5xx:
        findings.append(
            {
                "level": "warning",
                "metric": "status_5xx_count",
                "value": {"count": errors_5xx, "requests": requests},
                "threshold": 1,
                "hint": f"窗口内请求少于 {MIN_RATIO_REQUESTS} 条，不计算占比；出现 5xx 仍需查看样本与上游错误",
            }
        )
    closed = next((row["count"] for row in codes if row["code"] == "499"), 0)
    if closed >= 10:
        findings.append(
            {
                "level": "warning",
                "metric": "status_499",
                "value": closed,
                "threshold": 10,
                "hint": "499 表示客户端在响应前断开（经验阈值 ≥10）：常见原因是上游响应慢或客户端/网关超时更短，对照 request_time 与上游耗时",
            }
        )
    request_time = timing["request_time"]
    if request_time and request_time["count"] >= MIN_RATIO_REQUESTS:
        _ratio_finding(
            findings,
            "slow_requests_over_3s",
            request_time["over_3s"],
            request_time["count"],
            5,
            None,
            "request_time 超过 3 秒的请求占比 ≥5%（经验阈值）：对照 upstream_time 判断慢在后端还是客户端/网络",
        )
    upstream_time = timing["upstream_time"]
    if upstream_time and upstream_time["max"] >= 10:
        findings.append(
            {
                "level": "warning",
                "metric": "upstream_time_max",
                "value": upstream_time["max"],
                "threshold": 10,
                "hint": "上游最长响应 ≥10 秒（经验阈值）：检查后端慢接口、proxy_read_timeout 以及是否接近超时被切断",
            }
        )
    since = (window or {}).get("since_local")
    late = [
        r["path"]
        for r in files["ranges"]
        if r["first_at"] and since and r["first_at"] > since
    ]
    unknown = files["truncated"] and not any(r["first_at"] for r in files["ranges"])
    if late or unknown or files["skipped"] or files["read_timeout"]:
        findings.append(
            {
                "level": "info",
                "metric": "window_not_covered",
                "value": {
                    "first_at": files["first"],
                    "since": since,
                    "late_files": late[:5],
                    "truncated": files["truncated"][:5],
                    "skipped": (files["skipped"] + files["read_timeout"])[:5],
                },
                "threshold": "覆盖整个窗口",
                "hint": "读取的数据晚于窗口开始（尾部 30 MB 截断、刚轮转或轮转文件已压缩）或读取超时，窗口前段未统计；可缩短窗口或指定轮转前的文件",
            }
        )


register(
    ActionSpec(
        id="nginx",
        tool="ssh_diagnose_nginx",
        title="Nginx 运行状态与错误日志",
        question="Nginx 是否在运行、配置能否通过测试，最近 error.log 中上游超时、连接失败等错误集中在哪里？",
        category="应用与中间件",
        params=(
            Param(
                "minutes",
                "int",
                "error.log 回溯窗口（分钟，1–1440）",
                default=30,
                minimum=1,
                maximum=1440,
            ),
        ),
        script=nginx_script,
        parse=parse_nginx,
        sensitive=True,
        risk="low",
        timeout=30,
        output_limit=49152,
        estimated_seconds=8,
        notes=(
            "nginx -T 与 nginx -t 一样会解析全部配置、加载证书并解析 upstream 域名；以 root 运行时 nginx 可能创建缺失的空日志/pid 文件或临时目录（nginx 自身行为），不 reload、不改配置。",
            "error.log 只读每个文件尾部 20 MB、最多 2 个文件，按主机本地时间筛选窗口。",
        ),
    )
)

register(
    ActionSpec(
        id="nginx_access",
        tool="ssh_diagnose_nginx_access",
        title="Nginx 访问日志分析",
        question="时间窗口内 Nginx 请求量、状态码分布、错误请求 TOP URL/IP/UA 与耗时如何？",
        category="应用与中间件",
        params=WINDOW_PARAMS
        + (
            Param(
                "path",
                "str",
                "访问日志路径；只接受 Nginx 配置中声明的 access_log 或标准日志目录下的文件，缺省自动选择",
                pattern=PATH_RE,
                max_length=200,
            ),
            Param(
                "status",
                "str",
                "只统计该状态的请求 TOP：all、4xx、5xx 或具体状态码（如 502）",
                default="all",
                pattern=STATUS_RE,
                max_length=3,
            ),
            Param(
                "keyword",
                "str",
                "按原文子串过滤请求行（URL、IP、UA 等）",
                pattern=KEYWORD_RE,
                max_length=64,
            ),
            Param("top", "int", "TOP 条数", default=10, minimum=5, maximum=30),
        ),
        script=access_script,
        parse=parse_access,
        sensitive=True,
        risk="medium",
        timeout=40,
        output_limit=49152,
        estimated_seconds=15,
        notes=(
            "只读取每个访问日志尾部约 30 MB（窗口跨轮转时另读未压缩轮转文件尾部 10 MB），超大日志可能覆盖不到整个窗口。",
            "path 只接受 nginx 配置中的 access_log、标准 Nginx 日志目录，或 /data|/opt|/home|/srv|/app 下的 */logs/*access*.log；符号链接按真实路径再校验。",
        ),
    )
)
