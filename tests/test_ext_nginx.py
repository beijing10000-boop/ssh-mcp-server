"""Nginx extension: fixed read-only scripts, host-side path checks and parsers.

The end-to-end tests run the generated scripts under /bin/sh (dash + mawk on the
Ubuntu CI) against a fake nginx install whose ps/ss/systemctl/date output is
fixed. The parser fixtures below are that real script output (generated with
dash + gawk --posix and normalised), and the end-to-end tests assert the live
output still equals them, so fixtures and scripts cannot drift apart.
"""

import json
import os
import re
import shutil
import subprocess
import time

import pytest

from sshmcp import catalog, diagnostics, extensions, observations
from sshmcp.extensions import nginx

needs_sh = pytest.mark.skipif(not os.path.exists("/bin/sh"), reason="needs sh")
needs_awk = pytest.mark.skipif(shutil.which("awk") is None, reason="needs awk")

# 2026-10-29 23:20:00 UTC: the fake `date +%s` and every fixture timestamp.
NOW = 1793318400
SINCE = NOW - 1800


def _ts(epoch, fmt="%Y/%m/%d %H:%M:%S"):
    return time.strftime(fmt, time.gmtime(epoch))


# --------------------------------------------------------------------------
# Fake nginx install (binary, config, logs) and fixed system tool output.
# --------------------------------------------------------------------------

V_TEXT = (
    "nginx version: nginx/1.24.0\n"
    "built by gcc 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04)\n"
    "built with OpenSSL 3.0.2 15 Mar 2022\n"
    "TLS SNI support enabled\n"
    "configure arguments: --with-cc-opt='-g -O2' --prefix=/usr/share/nginx "
    "--conf-path={conf}/nginx.conf --http-log-path={logs}/access.log "
    "--error-log-path={logs}/error.log --lock-path=/var/lock/nginx.lock "
    "--pid-path=/run/nginx.pid --with-http_ssl_module --with-http_v2_module\n"
)
T_OK = (
    "nginx: the configuration file {conf}/nginx.conf syntax is ok\n"
    "nginx: configuration file {conf}/nginx.conf test is successful\n"
)
T_DENIED = (
    'nginx: [alert] could not open error log file: open() "{logs}/error.log" '
    "failed (13: Permission denied)\n"
    'nginx: [warn] the "user" directive makes sense only if the master process '
    "runs with super-user privileges, ignored in {conf}/nginx.conf:1\n"
    "nginx: the configuration file {conf}/nginx.conf syntax is ok\n"
    'nginx: [emerg] open() "/run/nginx.pid" failed (13: Permission denied)\n'
    "nginx: configuration file {conf}/nginx.conf test failed\n"
)
T_BROKEN = (
    'nginx: [emerg] unknown directive "proxy_passs" in {conf}/conf.d/api.conf:9\n'
    "nginx: configuration file {conf}/nginx.conf test failed\n"
)
MAIN_CONF = """user www-data;
worker_processes auto;
pid /run/nginx.pid;
error_log {logs}/error.log warn;
include /etc/nginx/modules-enabled/*.conf;

events {{
	worker_connections 1024;
}}

http {{
	sendfile on;
	keepalive_timeout 65;
	client_max_body_size 20m;
	log_format main '$remote_addr - $remote_user [$time_local] "$request" '
	                '$status $body_bytes_sent "$http_referer" '
	                '"$http_user_agent" $request_time $upstream_response_time';
	log_format json escape=json '{{"time_local":"$time_local","remote_addr":"$remote_addr",'
	                '"request_uri":"$request_uri","status":$status,"request_time":$request_time,'
	                '"upstream_response_time":"$upstream_response_time","http_user_agent":"$http_user_agent"}}';
	access_log {logs}/access.log main;
	proxy_connect_timeout 5s;
	proxy_read_timeout 60s;
	proxy_send_timeout 60s;
	# access_log /var/log/nginx/commented.log;
	upstream backend {{
		least_conn;
		server 10.0.0.21:8080 max_fails=3 fail_timeout=10s;
		server 10.0.0.22:8080 max_fails=3 fail_timeout=10s;
		keepalive 32;
	}}
	upstream php {{
		server unix:/run/php/php-fpm.sock;
	}}
	include {conf}/conf.d/*.conf;
}}
"""
API_CONF = """server {{
	listen 80;
	listen 443 ssl http2;
	server_name api.example.com;
	access_log {logs}/api.access.log json;
	location / {{
		proxy_pass http://backend;
		proxy_read_timeout 120s;
	}}
	location /php {{
		proxy_pass http://php;
	}}
	location /secret {{
		proxy_set_header Authorization "Basic dXNlcjpwYXNz";
	}}
}}
"""
WWW_CONF = """server {{
	listen 80 default_server;
	server_name www.example.com example.com;
	access_log off;
	access_log syslog:server=10.0.0.5:514,tag=nginx;
	root /usr/share/nginx/html;
}}
"""


def error_log_text(now=NOW):
    """error.log around `now` (UTC): a cut first line, one old line, noise."""
    up = 'upstream: "http://10.0.0.21:8080{0}", host: "api.example.com"'
    rows = [
        "ction timed out) while reading response header from upstream",
        f"{_ts(now - 3000)} [error] 1201#1201: *90 upstream timed out (110: "
        "Connection timed out) while reading response header from upstream, "
        "client: 10.0.0.9, server: api.example.com, "
        'request: "GET /api/v1/orders?id=1 HTTP/1.1", '
        + up.format("/api/v1/orders?id=1"),
        f"{_ts(now - 1200)} [warn] 1201#1201: *101 an upstream response is "
        "buffered to a temporary file /var/cache/nginx/proxy_temp/1/00/0000000001 "
        "while reading upstream, client: 10.0.0.10, server: api.example.com, "
        'request: "GET /export HTTP/1.1", ' + up.format("/export"),
    ]
    for i, (client, path) in enumerate(
        [
            ("10.0.0.9", "/api/v1/orders?id=2"),
            ("10.0.0.9", "/api/v1/orders?id=3"),
            ("10.0.0.11", "/api/v1/pay"),
        ]
    ):
        rows.append(
            f"{_ts(now - 1140 + i * 10)} [error] 1201#1201: *{110 + i} upstream "
            "timed out (110: Connection timed out) while reading response header "
            f"from upstream, client: {client}, server: api.example.com, "
            f'request: "GET {path} HTTP/1.1", ' + up.format(path)
        )
    rows += [
        f"{_ts(now - 900)} [error] 1202#1202: *130 connect() failed (111: "
        "Connection refused) while connecting to upstream, client: 10.0.0.12, "
        'server: api.example.com, request: "GET /api/v1/users HTTP/1.1", '
        'upstream: "http://10.0.0.23:8080/api/v1/users", host: "api.example.com"',
        f"{_ts(now - 840)} [error] 1202#1202: *131 connect() failed (113: No "
        "route to host) while connecting to upstream, client: 10.0.0.12, "
        'server: api.example.com, request: "GET /health HTTP/1.1", '
        'upstream: "http://10.0.0.24:8080/health", host: "api.example.com"',
        f"{_ts(now - 720)} [error] 1202#1202: *132 no live upstreams while "
        "connecting to upstream, client: 10.0.0.9, server: api.example.com, "
        'request: "GET /api/v1/orders HTTP/1.1", '
        'upstream: "http://backend/api/v1/orders", host: "api.example.com"',
        f"{_ts(now - 600)} [error] 1202#1202: *133 upstream prematurely closed "
        "connection while reading response header from upstream, "
        "client: 10.0.0.15, server: api.example.com, "
        'request: "GET /api/v1/report HTTP/1.1", ' + up.format("/api/v1/report"),
        f"{_ts(now - 540)} [alert] 1202#1202: 1024 worker_connections are not enough",
        f"{_ts(now - 480)} [crit] 1202#1202: accept4() failed (24: Too many open files)",
        f"{_ts(now - 420)} [info] 1202#1202: *140 client prematurely closed "
        "connection while sending to client, client: 10.0.0.13, "
        "server: www.example.com",
        f'{_ts(now - 360)} [error] 1202#1202: *141 open() "/usr/share/nginx/html/'
        'favicon.ico" failed (2: No such file or directory), client: 10.0.0.14, '
        'server: www.example.com, request: "GET /favicon.ico HTTP/1.1", '
        'host: "www.example.com"',
        f"{_ts(now - 300)} [error] 1202#1202: *142 recv() failed (104: Connection "
        "reset by peer) while reading response header from upstream, "
        "client: 10.0.0.16, server: api.example.com, "
        'request: "GET /php/index.php HTTP/1.1", '
        'upstream: "fastcgi://unix:/run/php/php-fpm.sock:", host: "api.example.com"',
        f"{_ts(now - 240)} [error] 1202#1202: *143 connect() to "
        "unix:/run/php/php-fpm.sock failed (2: No such file or directory) while "
        "connecting to upstream, client: 10.0.0.16, server: api.example.com, "
        'request: "GET /php/info.php HTTP/1.1", '
        'upstream: "fastcgi://unix:/run/php/php-fpm.sock:", host: "api.example.com"',
        f"{_ts(now - 120)} [error] 1202#1202: *150 upstream timed out (110: "
        "Connection timed out) while reading response header from upstream, "
        "client: 10.0.0.17, server: api.example.com, "
        'request: "GET /login?password=hunter2 HTTP/1.1", '
        + up.format("/login?password=hunter2"),
        "stack traceback:",
        "\tcoroutine 0:",
    ]
    return "\n".join(rows) + "\n"


UAS = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "curl/8.5.0",
    "Go-http-client/1.1",
)


def combined(epoch, ip, method, uri, status, size, ua, rt=None, urt=None, xff=None):
    clf = _ts(epoch, "%d/%b/%Y:%H:%M:%S +0000")
    line = f'{ip} - - [{clf}] "{method} {uri} HTTP/1.1" {status} {size} "-" "{ua}"'
    if xff is not None:
        line += f' "{xff}"'
    if rt is not None:
        line += f" {rt} {urt if urt is not None else '-'}"
    return line


def json_line(epoch, ip, uri, status, ua, rt, urt, key="time_local"):
    stamp = (
        _ts(epoch, "%d/%b/%Y:%H:%M:%S +0000")
        if key == "time_local"
        else _ts(epoch, "%Y-%m-%dT%H:%M:%S+00:00")
    )
    record = {
        key: stamp,
        "remote_addr": ip,
        "request_uri": uri,
        "status": status,
        "request_time": rt,
        "upstream_response_time": urt,
        "http_user_agent": ua,
    }
    return json.dumps(record, separators=(",", ":"))


def access_log_texts(since=SINCE):
    """(rotated, current) logs for the window [since, since + 1800]."""
    rotated = [
        combined(
            since - 600, "10.1.0.1", "GET", "/old", 200, 10, UAS[1], "0.010", "0.009"
        ),
        combined(
            since + 30,
            "10.1.0.2",
            "GET",
            "/api/v1/orders?id=7",
            200,
            512,
            UAS[0],
            "0.120",
            "0.118",
        ),
        combined(
            since + 45,
            "10.1.0.3",
            "GET",
            "/api/v1/orders?id=8",
            502,
            157,
            UAS[0],
            "0.002",
            "0.001",
        ),
    ]
    plan = [
        ("10.1.0.2", "GET", "/api/v1/orders?id=1", 200, "0.050", "0.048"),
        ("10.1.0.2", "GET", "/api/v1/orders?id=2", 200, "0.060", "0.058"),
        ("10.1.0.3", "POST", "/api/v1/pay", 504, "60.001", "60.000"),
        ("10.1.0.4", "GET", "/static/app.js", 200, "0.001", None),
        ("10.1.0.2", "GET", "/api/v1/orders?id=3", 502, "0.003", "0.002, 0.001"),
        ("10.1.0.5", "GET", "/wp-login.php", 404, "0.001", None),
        ("10.1.0.5", "GET", "/.env", 404, "0.001", None),
        ("10.1.0.3", "GET", "/api/v1/report", 499, "4.500", "-"),
        ("10.1.0.2", "GET", "/api/v1/orders?id=4", 200, "3.200", "3.100"),
        ("10.1.0.6", "GET", "/", 302, "0.002", "0.002"),
    ]
    current = ['3.4.5 - - [cut line from a previous write"']
    for i in range(4):
        for j, (ip, method, uri, status, rt, urt) in enumerate(plan):
            epoch = since + 60 + i * 300 + j * 20
            ua = UAS[(i + j) % 3]
            if (i + j) % 4 == 3:
                current.append(json_line(epoch, ip, uri, status, ua, rt, urt or "-"))
            else:
                current.append(
                    combined(epoch, ip, method, uri, status, 100 + j, ua, rt, urt)
                )
    current += [
        json_line(
            since + 1500,
            "10.1.0.7",
            "/api/v1/orders?token=abc123",
            502,
            UAS[2],
            "0.004",
            "0.003",
            key="time_iso8601",
        ),
        combined(
            since + 1700,
            "10.1.0.8",
            "GET",
            "/healthz",
            200,
            2,
            UAS[1],
            "0.001",
            "0.001",
            xff="1.2.3.4, 5.6.7.8",
        ),
        "garbage line without timestamp",
        combined(
            since + 4000, "10.1.0.9", "GET", "/future", 200, 1, UAS[1], "0.001", "0.001"
        ),
    ]
    return "\n".join(rotated) + "\n", "\n".join(current) + "\n"


def ps_text(binary):
    """(`ps -e -o pid= ... -o args=`, `ps -eo args=`) output.

    The listing shows the usual binary path (its args are cut at 120 chars and
    must not depend on the temp dir); the args-only call names the fake binary
    so the script treats the running master as the discovered installation.
    """
    master = "nginx: master process {} -g daemon on; master_process on;"
    rows = [
        (1, 0, "root", 86400, 11264, "0.0", "systemd", "/sbin/init splash"),
        (
            900,
            1,
            "root",
            86400,
            7680,
            "0.0",
            "sshd",
            "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups",
        ),
        (
            1201,
            1,
            "root",
            86000,
            8456,
            "0.0",
            "nginx",
            master.format("/usr/sbin/nginx"),
        ),
        (1202, 1201, "www-data", 86000, 52120, "1.5", "nginx", "nginx: worker process"),
        (1203, 1201, "www-data", 86000, 51876, "1.2", "nginx", "nginx: worker process"),
        (
            1204,
            1201,
            "www-data",
            86000,
            10240,
            "0.0",
            "nginx",
            "nginx: cache manager process",
        ),
        (
            2001,
            1,
            "app",
            3600,
            812000,
            "35.0",
            "java",
            "java -Dspring.datasource.password=Secret1 -jar /opt/app/app.jar",
        ),
        (2101, 2100, "ops", 1, 1024, "0.0", "grep", "grep nginx: master"),
    ]
    full = "".join(
        f"{p:>7} {pp:>7} {u:<8} {e:>8} {r:>6} {c:>4} {comm:<15} {args}\n"
        for p, pp, u, e, r, c, comm, args in rows
    )
    args = "".join(row[-1] + "\n" for row in rows)
    return full, args.replace(master.format("/usr/sbin/nginx"), master.format(binary))


SS_LISTEN = """State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
LISTEN 0      511          0.0.0.0:80         0.0.0.0:*    users:(("nginx",pid=1203,fd=6),("nginx",pid=1202,fd=6),("nginx",pid=1201,fd=6))
LISTEN 0      511          0.0.0.0:443        0.0.0.0:*    users:(("nginx",pid=1203,fd=7),("nginx",pid=1202,fd=7),("nginx",pid=1201,fd=7))
LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=900,fd=3))
LISTEN 0      511             [::]:80            [::]:*    users:(("nginx",pid=1203,fd=8),("nginx",pid=1202,fd=8),("nginx",pid=1201,fd=8))
LISTEN 0      100        127.0.0.1:8080       0.0.0.0:*    users:(("java",pid=2001,fd=45))
"""


def ss_established_text():
    rows = ["Recv-Q Send-Q   Local Address:Port    Peer Address:Port Process"]
    for port, count in ((443, 30), (80, 12), (22, 3)):
        rows += [
            f"0      0            10.0.0.5:{port}   203.0.113.{n}:{40000 + n}"
            for n in range(count)
        ]
    rows += [
        f"0      0           127.0.0.1:8080   127.0.0.1:{50000 + n}" for n in range(5)
    ]
    rows += [
        f"0      0            10.0.0.5:{43000 + n}   10.0.0.21:8080" for n in range(6)
    ]
    return "\n".join(rows) + "\n"


SYSTEMD_TEXT = """Id=nginx.service
LoadState=loaded
ActiveState=active
SubState=running
Result=success
NRestarts=2
ExecMainStartTimestamp=Wed 2026-10-28 23:26:40 UTC

Id=openresty.service
LoadState=not-found
ActiveState=inactive
SubState=dead
Result=success
NRestarts=0
ExecMainStartTimestamp=

Id=tengine.service
LoadState=not-found
ActiveState=inactive
SubState=dead
Result=success
NRestarts=0
ExecMainStartTimestamp=
"""


def _write(path, text, mode=0o644, mtime=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode())
    os.chmod(path, mode)
    if mtime is not None:
        os.utime(path, (mtime, mtime))


def install_fixture(base, shell_path=str, t_mode="ok"):
    """Fake nginx install under `base`; `shell_path` maps a path for the shell."""
    logs, conf, fix, fake = base / "logs", base / "conf", base / "fix", base / "bin"
    sh = {
        "logs": shell_path(logs),
        "conf": shell_path(conf),
        "fix": shell_path(fix),
        "bin": shell_path(fake),
        "nginx": shell_path(fake / "nginx"),
    }
    fill = {"logs": sh["logs"], "conf": sh["conf"]}
    main, api, www = (t.format(**fill) for t in (MAIN_CONF, API_CONF, WWW_CONF))
    _write(conf / "nginx.conf", main)
    _write(conf / "conf.d" / "api.conf", api)
    _write(conf / "conf.d" / "www.conf", www)
    dump = "".join(
        f"# configuration file {sh['conf']}/{name}:\n{text}\n"
        for name, text in (
            ("nginx.conf", main),
            ("conf.d/api.conf", api),
            ("conf.d/www.conf", www),
        )
    )
    _write(fix / "V.txt", V_TEXT.format(**fill))
    _write(fix / "T.txt", dump)
    stderr = {"ok": T_OK, "denied": T_DENIED, "broken": T_BROKEN}[t_mode]
    _write(fix / "T_stderr.txt", stderr.format(**fill))
    full, args = ps_text(sh["nginx"])
    _write(fix / "ps_full.txt", full)
    _write(fix / "ps_args.txt", args)
    _write(fix / "ss_listen.txt", SS_LISTEN)
    _write(fix / "ss_estab.txt", ss_established_text())
    _write(fix / "systemd.txt", SYSTEMD_TEXT)
    dump_cmd = f"cat '{sh['fix']}/T.txt'" if t_mode == "ok" else "exit 1"
    fakes = {
        "nginx": 'case "$1" in\n'
        f"  -V) cat '{sh['fix']}/V.txt' 1>&2 ;;\n"
        f"  -T) cat '{sh['fix']}/T_stderr.txt' 1>&2; {dump_cmd} ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n",
        "ps": 'case "$*" in\n'
        f"  *pid=*) cat '{sh['fix']}/ps_full.txt' ;;\n"
        f"  *) cat '{sh['fix']}/ps_args.txt' ;;\n"
        "esac\n",
        "ss": 'case "$*" in\n'
        f"  *-ltnp*) cat '{sh['fix']}/ss_listen.txt' ;;\n"
        f"  *established*) cat '{sh['fix']}/ss_estab.txt' ;;\n"
        "esac\n",
        "systemctl": f"[ \"$1\" = show ] && cat '{sh['fix']}/systemd.txt'\n",
        # Drops "-k 1 N" and runs the command, like timeout(1) that never fires.
        "timeout": 'shift 3\nexec "$@"\n',
        "date": f'if [ "$1" = "+%s" ]; then echo {NOW}; exit 0; fi\n'
        'for d in /usr/bin/date /bin/date; do [ -x "$d" ] && exec "$d" "$@"; done\n'
        "exit 1\n",
    }
    for name, body in fakes.items():
        _write(fake / name, "#!/bin/sh\n" + body, 0o755)
    _write(logs / "error.log", error_log_text(), mtime=NOW - 60)
    _write(logs / "error.log.1", error_log_text(NOW - 86400), mtime=NOW - 7200)
    rotated, current = access_log_texts()
    _write(logs / "access.log.1", rotated, mtime=SINCE + 100)
    _write(logs / "access.log", current, mtime=NOW - 30)
    _write(logs / "access.log.2.gz", "not really gzip\n", mtime=NOW - 86400)
    _write(logs / "api.access.log", current, mtime=NOW - 20)
    return sh


def use_fixture(monkeypatch, sh):
    """Point the fixed script constants at the fake install (tests only)."""
    monkeypatch.setattr(nginx, "NGINX_COMMANDS", ("aiops-fixture-no-such-nginx",))
    monkeypatch.setattr(nginx, "NGINX_BINARIES", (sh["nginx"],))
    monkeypatch.setattr(nginx, "DEFAULT_CONF", sh["conf"] + "/nginx.conf")
    monkeypatch.setattr(nginx, "DEFAULT_ACCESS_LOG", sh["logs"] + "/access.log")
    monkeypatch.setattr(nginx, "DEFAULT_ERROR_LOG", sh["logs"] + "/error.log")
    monkeypatch.setattr(nginx, "ALLOWED_LOG_PATTERNS", (sh["logs"] + "/*",))
    monkeypatch.setattr(
        nginx,
        "resolve_window",
        lambda options, now=None: extensions.resolve_window(options, NOW),
    )


def run_script(script, sh, timeout=60):
    prefix = (
        f"PATH={sh['bin']}:/usr/sbin:/usr/bin:/sbin:/bin; export PATH; "
        "LC_ALL=C; export LC_ALL; "
    )
    proc = subprocess.run(
        ["/bin/sh", "-c", prefix + script],
        capture_output=True,
        timeout=timeout,
        env={"TZ": "UTC", "PATH": "/usr/bin:/bin"},
        stdin=subprocess.DEVNULL,
    )
    return proc.returncode, proc.stdout.decode(), proc.stderr.decode()


LS_LINE = re.compile(r"(?m)^([-dl][-rwxsStT]{9})[.+]? +\d+ +\S+ +\S+ +(\d+) +(\d+) ")


def normalize(text, sh):
    """Fixture form: fake paths become the usual ones, ls owner/padding fixed."""
    text = text.replace(sh["nginx"], "/usr/sbin/nginx")
    text = text.replace(sh["logs"], "/var/log/nginx").replace(sh["conf"], "/etc/nginx")
    return LS_LINE.sub(r"\1 1 root adm \2 \3 ", text)


def options_for(action, **values):
    return extensions.validate_options(extensions.spec_for(action), values)


# --------------------------------------------------------------------------
# Real script output for the fake install above (normalised with normalize()).
# Regenerate by running the end-to-end tests' scripts and normalising stdout.
# --------------------------------------------------------------------------

# FIXTURES-BEGIN
NGINX_OUTPUT = """\
[AIOPS_BIN]
BIN /usr/sbin/nginx
[AIOPS_VERSION]
nginx version: nginx/1.24.0
built by gcc 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04)
built with OpenSSL 3.0.2 15 Mar 2022
--prefix=/usr/share/nginx
--conf-path=/etc/nginx/nginx.conf
--http-log-path=/var/log/nginx/access.log
--error-log-path=/var/log/nginx/error.log
[AIOPS_CONFIG]
CONFIG_SOURCE=T
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
worker_processes auto;
error_log /var/log/nginx/error.log warn;
worker_connections 1024;
keepalive_timeout 65;
client_max_body_size 20m;
log_format main '$remote_addr - $remote_user [$time_local] "$request" ' '$status $body_bytes_sent "$http_referer" ' '"$http_user_agent" $request_time $upstream_response_time';
log_format json escape=json '{"time_local":"$time_local","remote_addr":"$remote_addr",' '"request_uri":"$request_uri","status":$status,"request_time":$request_time,' '"upstream_response_time":"$upstream_response_time","http_user_agent":"$http_user_agent"}';
access_log /var/log/nginx/access.log main;
proxy_connect_timeout 5s;
proxy_read_timeout 60s;
proxy_send_timeout 60s;
UPSTREAM backend
server 10.0.0.21:8080 max_fails=3 fail_timeout=10s;
server 10.0.0.22:8080 max_fails=3 fail_timeout=10s;
keepalive 32;
UPSTREAM php
server unix:/run/php/php-fpm.sock;
listen 80;
listen 443 ssl http2;
access_log /var/log/nginx/api.access.log json;
proxy_read_timeout 120s;
listen 80 default_server;
access_log off;
access_log syslog:server=10.0.0.5:514,tag=nginx;
COUNT server_name 2
COUNT proxy_pass 2
COUNT include 2
COUNT upstream 2
COUNT config_files 3
COUNT input_lines 67
[AIOPS_PROCESS]
1201 1 root 86000 8456 0.0 nginx nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
1202 1201 www-data 86000 52120 1.5 nginx nginx: worker process
1203 1201 www-data 86000 51876 1.2 nginx nginx: worker process
1204 1201 www-data 86000 10240 0.0 nginx nginx: cache manager process
[AIOPS_SYSTEMD]
UNIT nginx.service
Id=nginx.service
LoadState=loaded
ActiveState=active
SubState=running
Result=success
NRestarts=2
ExecMainStartTimestamp=Wed 2026-10-28 23:26:40 UTC
[AIOPS_LISTEN]
LISTEN_SOURCE=proc
LISTEN 0.0.0.0:80 nginx
LISTEN 0.0.0.0:443 nginx
LISTEN [::]:80 nginx
ESTAB 443 30
ESTAB 80 12
ESTAB 8080 5
ESTAB 22 3
ESTAB 43000 1
ESTAB 43001 1
ESTAB 43002 1
ESTAB 43003 1
ESTAB 43004 1
ESTAB 43005 1
[AIOPS_LOGFILES]
LOG error_log /var/log/nginx/error.log
-rw-r--r-- 1 root adm 4101 1793318340 /var/log/nginx/error.log
-rw-r--r-- 1 root adm 4101 1793311200 /var/log/nginx/error.log.1
LOG access_log /var/log/nginx/access.log
-rw-r--r-- 1 root adm 6779 1793318370 /var/log/nginx/access.log
-rw-r--r-- 1 root adm 460 1793316700 /var/log/nginx/access.log.1
-rw-r--r-- 1 root adm 16 1793232000 /var/log/nginx/access.log.2.gz
LOG access_log /var/log/nginx/api.access.log
-rw-r--r-- 1 root adm 6779 1793318380 /var/log/nginx/api.access.log
[AIOPS_ERRORS]
WINDOW 1793316600 1793318400 2026/10/29 23:30:00 2026/10/30 00:00:00
FILE /var/log/nginx/error.log
LEVEL alert 1
LEVEL crit 1
LEVEL error 11
LEVEL info 1
LEVEL warn 1
LINES 15 16
UPSTREAM client_closed 1
UPSTREAM connect_failed 2
UPSTREAM connection_refused 1
UPSTREAM no_live_upstreams 1
UPSTREAM other_upstream 1
UPSTREAM prematurely_closed 1
UPSTREAM timed_out 4
UPSTREAM too_many_open_files 1
UPSTREAM worker_connections 1
TOP_UPSTREAM 5 10.0.0.21:8080
TOP_UPSTREAM 2 unix:/run/php/php-fpm.sock:
TOP_UPSTREAM 1 10.0.0.23:8080
TOP_UPSTREAM 1 10.0.0.24:8080
TOP_UPSTREAM 1 backend
TOP_CLIENT 3 10.0.0.9
TOP_CLIENT 2 10.0.0.12
TOP_CLIENT 2 10.0.0.16
TOP_CLIENT 1 10.0.0.11
TOP_CLIENT 1 10.0.0.14
TOP_CLIENT 1 10.0.0.15
TOP_CLIENT 1 10.0.0.17
TOP_REQUEST 3 GET /api/v1/orders
TOP_REQUEST 1 GET /api/v1/pay
TOP_REQUEST 1 GET /api/v1/report
TOP_REQUEST 1 GET /api/v1/users
TOP_REQUEST 1 GET /favicon.ico
TOP_REQUEST 1 GET /health
TOP_REQUEST 1 GET /login
TOP_REQUEST 1 GET /php/index.php
TOP_REQUEST 1 GET /php/info.php
TOP_MESSAGE 4 upstream timed out (110: Connection timed out) while reading response header from upstream
TOP_MESSAGE 1 1024 worker_connections are not enough
TOP_MESSAGE 1 accept4() failed (24: Too many open files)
TOP_MESSAGE 1 connect() failed (111: Connection refused) while connecting to upstream
TOP_MESSAGE 1 connect() failed (113: No route to host) while connecting to upstream
TOP_MESSAGE 1 connect() to unix:/run/php/php-fpm.sock failed (2: No such file or directory) while connecting to upstream
TOP_MESSAGE 1 no live upstreams while connecting to upstream
TOP_MESSAGE 1 open() "/usr/share/nginx/html/favicon.ico" failed (2: No such file or directory)
TOP_MESSAGE 1 recv() failed (104: Connection reset by peer) while reading response header from upstream
TOP_MESSAGE 1 upstream prematurely closed connection while reading response header from upstream
SAMPLE 0 2026/10/29 23:41:00 [error] 1201#1201: *110 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 10.0.0.9, server: api.example.com, request: "GET /api/v1/orders?id=2 HTTP/1.1", upstream: "http:
SAMPLE 1 2026/10/29 23:41:10 [error] 1201#1201: *111 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 10.0.0.9, server: api.example.com, request: "GET /api/v1/orders?id=3 HTTP/1.1", upstream: "http:
SAMPLE 2 2026/10/29 23:41:20 [error] 1201#1201: *112 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 10.0.0.11, server: api.example.com, request: "GET /api/v1/pay HTTP/1.1", upstream: "http://10.0.
SAMPLE 3 2026/10/29 23:45:00 [error] 1202#1202: *130 connect() failed (111: Connection refused) while connecting to upstream, client: 10.0.0.12, server: api.example.com, request: "GET /api/v1/users HTTP/1.1", upstream: "http://10.0.0.23:8080/api/v1/
SAMPLE 4 2026/10/29 23:46:00 [error] 1202#1202: *131 connect() failed (113: No route to host) while connecting to upstream, client: 10.0.0.12, server: api.example.com, request: "GET /health HTTP/1.1", upstream: "http://10.0.0.24:8080/health", host: 
SAMPLE 5 2026/10/29 23:48:00 [error] 1202#1202: *132 no live upstreams while connecting to upstream, client: 10.0.0.9, server: api.example.com, request: "GET /api/v1/orders HTTP/1.1", upstream: "http://backend/api/v1/orders", host: "api.example.com"
SAMPLE 6 2026/10/29 23:50:00 [error] 1202#1202: *133 upstream prematurely closed connection while reading response header from upstream, client: 10.0.0.15, server: api.example.com, request: "GET /api/v1/report HTTP/1.1", upstream: "http://10.0.0.21:
SAMPLE 7 2026/10/29 23:51:00 [alert] 1202#1202: 1024 worker_connections are not enough
SAMPLE 8 2026/10/29 23:52:00 [crit] 1202#1202: accept4() failed (24: Too many open files)
SAMPLE 9 2026/10/29 23:54:00 [error] 1202#1202: *141 open() "/usr/share/nginx/html/favicon.ico" failed (2: No such file or directory), client: 10.0.0.14, server: www.example.com, request: "GET /favicon.ico HTTP/1.1", host: "www.example.com"
SAMPLE 10 2026/10/29 23:55:00 [error] 1202#1202: *142 recv() failed (104: Connection reset by peer) while reading response header from upstream, client: 10.0.0.16, server: api.example.com, request: "GET /php/index.php HTTP/1.1", upstream: "fastcgi://
SAMPLE 11 2026/10/29 23:56:00 [error] 1202#1202: *143 connect() to unix:/run/php/php-fpm.sock failed (2: No such file or directory) while connecting to upstream, client: 10.0.0.16, server: api.example.com, request: "GET /php/info.php HTTP/1.1", upstr
SAMPLE 12 2026/10/29 23:58:00 [error] 1202#1202: *150 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 10.0.0.17, server: api.example.com, request: "GET /login?password=hunter2 HTTP/1.1", upstream: "
"""

NGINX_DENIED_CONFIG = """\
[AIOPS_BIN]
BIN /usr/sbin/nginx
[AIOPS_VERSION]
nginx version: nginx/1.24.0
built by gcc 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04)
built with OpenSSL 3.0.2 15 Mar 2022
--prefix=/usr/share/nginx
--conf-path=/etc/nginx/nginx.conf
--http-log-path=/var/log/nginx/access.log
--error-log-path=/var/log/nginx/error.log
[AIOPS_CONFIG]
nginx: [alert] could not open error log file: open() "/var/log/nginx/error.log" failed (13: Permission denied)
nginx: [warn] the "user" directive makes sense only if the master process runs with super-user privileges, ignored in /etc/nginx/nginx.conf:1
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: [emerg] open() "/run/nginx.pid" failed (13: Permission denied)
nginx: configuration file /etc/nginx/nginx.conf test failed
CONFIG_SOURCE=file
worker_processes auto;
error_log /var/log/nginx/error.log warn;
worker_connections 1024;
keepalive_timeout 65;
client_max_body_size 20m;
log_format main '$remote_addr - $remote_user [$time_local] "$request" ' '$status $body_bytes_sent "$http_referer" ' '"$http_user_agent" $request_time $upstream_response_time';
log_format json escape=json '{"time_local":"$time_local","remote_addr":"$remote_addr",' '"request_uri":"$request_uri","status":$status,"request_time":$request_time,' '"upstream_response_time":"$upstream_response_time","http_user_agent":"$http_user_agent"}';
access_log /var/log/nginx/access.log main;
proxy_connect_timeout 5s;
proxy_read_timeout 60s;
proxy_send_timeout 60s;
UPSTREAM backend
server 10.0.0.21:8080 max_fails=3 fail_timeout=10s;
server 10.0.0.22:8080 max_fails=3 fail_timeout=10s;
keepalive 32;
UPSTREAM php
server unix:/run/php/php-fpm.sock;
listen 80;
listen 443 ssl http2;
access_log /var/log/nginx/api.access.log json;
proxy_read_timeout 120s;
listen 80 default_server;
access_log off;
access_log syslog:server=10.0.0.5:514,tag=nginx;
COUNT server_name 2
COUNT proxy_pass 2
COUNT include 2
COUNT upstream 2
COUNT config_files 0
COUNT input_lines 59
"""

NGINX_BROKEN_CONFIG = """\
[AIOPS_BIN]
BIN /usr/sbin/nginx
[AIOPS_VERSION]
nginx version: nginx/1.24.0
built by gcc 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04)
built with OpenSSL 3.0.2 15 Mar 2022
--prefix=/usr/share/nginx
--conf-path=/etc/nginx/nginx.conf
--http-log-path=/var/log/nginx/access.log
--error-log-path=/var/log/nginx/error.log
[AIOPS_CONFIG]
nginx: [emerg] unknown directive "proxy_passs" in /etc/nginx/conf.d/api.conf:9
nginx: configuration file /etc/nginx/nginx.conf test failed
CONFIG_SOURCE=file
worker_processes auto;
error_log /var/log/nginx/error.log warn;
worker_connections 1024;
keepalive_timeout 65;
client_max_body_size 20m;
log_format main '$remote_addr - $remote_user [$time_local] "$request" ' '$status $body_bytes_sent "$http_referer" ' '"$http_user_agent" $request_time $upstream_response_time';
log_format json escape=json '{"time_local":"$time_local","remote_addr":"$remote_addr",' '"request_uri":"$request_uri","status":$status,"request_time":$request_time,' '"upstream_response_time":"$upstream_response_time","http_user_agent":"$http_user_agent"}';
access_log /var/log/nginx/access.log main;
proxy_connect_timeout 5s;
proxy_read_timeout 60s;
proxy_send_timeout 60s;
UPSTREAM backend
server 10.0.0.21:8080 max_fails=3 fail_timeout=10s;
server 10.0.0.22:8080 max_fails=3 fail_timeout=10s;
keepalive 32;
UPSTREAM php
server unix:/run/php/php-fpm.sock;
listen 80;
listen 443 ssl http2;
access_log /var/log/nginx/api.access.log json;
proxy_read_timeout 120s;
listen 80 default_server;
access_log off;
access_log syslog:server=10.0.0.5:514,tag=nginx;
COUNT server_name 2
COUNT proxy_pass 2
COUNT include 2
COUNT upstream 2
COUNT config_files 0
COUNT input_lines 59
"""

ACCESS_OUTPUT = """\
[AIOPS_FILES]
WINDOW 1793316600 1793318400 20261029233000 20261030000000
FILE /var/log/nginx/access.log.1 460 460 rotated
FILE /var/log/nginx/access.log 6779 6779
RANGE 20261029232000 20261030003640 /var/log/nginx/access.log
FIRST 20261029232000 LAST 20261030003640
[AIOPS_TOTALS]
LINES 48 2 2
TOTAL 44
CLASS 2xx 18
CLASS 3xx 4
CLASS 4xx 12
CLASS 5xx 10
CLASS other 0
SELECTED 10
[AIOPS_CODES]
CODE 200 18
CODE 404 8
CODE 502 6
CODE 302 4
CODE 499 4
CODE 504 4
[AIOPS_TOP_URI]
TOP_URI 6 /api/v1/orders
TOP_URI 4 /api/v1/pay
[AIOPS_TOP_IP]
TOP_IP 5 10.1.0.3
TOP_IP 4 10.1.0.2
TOP_IP 1 10.1.0.7
[AIOPS_TOP_UA]
TOP_UA 4 Go-http-client/1.1
TOP_UA 3 Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36
TOP_UA 3 curl/8.5.0
[AIOPS_MINUTES]
BUCKET 1
MINUTE 202610292330 2 1
MINUTE 202610292331 3 1
MINUTE 202610292332 3 1
MINUTE 202610292333 3 0
MINUTE 202610292334 1 0
MINUTE 202610292336 3 1
MINUTE 202610292337 3 1
MINUTE 202610292338 3 0
MINUTE 202610292339 1 0
MINUTE 202610292341 3 1
MINUTE 202610292342 3 1
MINUTE 202610292343 3 0
MINUTE 202610292344 1 0
MINUTE 202610292346 3 1
MINUTE 202610292347 3 1
MINUTE 202610292348 3 0
MINUTE 202610292349 1 0
MINUTE 202610292355 1 1
MINUTE 202610292358 1 0
[AIOPS_TIMING]
REQ 44 6.168 60.001 12 12 4
UPS 28 9.034 60.000 8 8
NOUPSTREAM 16
[AIOPS_SAMPLES]
SAMPLE 0 10.1.0.3 - - [29/Oct/2026:23:30:45 +0000] "GET /api/v1/orders?id=8 HTTP/1.1" 502 157 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36" 0.002 0.001
SAMPLE 1 10.1.0.3 - - [29/Oct/2026:23:31:40 +0000] "POST /api/v1/pay HTTP/1.1" 504 102 "-" "Go-http-client/1.1" 60.001 60.000
SAMPLE 2 10.1.0.2 - - [29/Oct/2026:23:32:20 +0000] "GET /api/v1/orders?id=3 HTTP/1.1" 502 104 "-" "curl/8.5.0" 0.003 0.002, 0.001
SAMPLE 3 {"time_local":"29/Oct/2026:23:36:40 +0000","remote_addr":"10.1.0.3","request_uri":"/api/v1/pay","status":504,"request_time":"60.001","upstream_response_time":"60.000","http_user_agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chr
SAMPLE 4 10.1.0.2 - - [29/Oct/2026:23:37:20 +0000] "GET /api/v1/orders?id=3 HTTP/1.1" 502 104 "-" "Go-http-client/1.1" 0.003 0.002, 0.001
SAMPLE 5 10.1.0.3 - - [29/Oct/2026:23:41:40 +0000] "POST /api/v1/pay HTTP/1.1" 504 102 "-" "curl/8.5.0" 60.001 60.000
SAMPLE 6 10.1.0.2 - - [29/Oct/2026:23:42:20 +0000] "GET /api/v1/orders?id=3 HTTP/1.1" 502 104 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36" 0.003 0.002, 0.001
SAMPLE 7 10.1.0.3 - - [29/Oct/2026:23:46:40 +0000] "POST /api/v1/pay HTTP/1.1" 504 102 "-" "Go-http-client/1.1" 60.001 60.000
SAMPLE 8 {"time_local":"29/Oct/2026:23:47:20 +0000","remote_addr":"10.1.0.2","request_uri":"/api/v1/orders?id=3","status":502,"request_time":"0.003","upstream_response_time":"0.002, 0.001","http_user_agent":"curl/8.5.0"}
SAMPLE 9 {"time_iso8601":"2026-10-29T23:55:00+00:00","remote_addr":"10.1.0.7","request_uri":"/api/v1/orders?token=abc123","status":502,"request_time":"0.004","upstream_response_time":"0.003","http_user_agent":"Go-http-client/1.1"}
"""
# FIXTURES-END


def analyze(action, text, **options):
    report = observations.analyze(action, text, options=options)
    json.dumps(report, allow_nan=False)
    return report


def by_metric(report):
    return {finding["metric"]: finding for finding in report["findings"]}


# --------------------------------------------------------------------------
# Registry, options and script shape
# --------------------------------------------------------------------------


def test_specs_follow_the_documented_contract():
    status = extensions.spec_for("nginx")
    access = extensions.spec_for("nginx_access")
    assert status.tool == "ssh_diagnose_nginx"
    assert access.tool == "ssh_diagnose_nginx_access"
    assert status.category == access.category == "应用与中间件"
    assert (status.risk, status.timeout, status.output_limit) == ("low", 30, 49152)
    assert (access.risk, access.timeout, access.output_limit) == ("medium", 40, 49152)
    assert status.sensitive and access.sensitive
    assert options_for("nginx") == {"minutes": 30}
    assert options_for("nginx_access") == {
        "minutes": 30,
        "since": None,
        "until": None,
        "path": None,
        "status": "all",
        "keyword": None,
        "top": 10,
    }
    entries = {entry["id"]: entry for entry in catalog.entries()}
    assert entries["nginx"]["category"] == "应用与中间件"
    assert entries["nginx_access"]["tool"] == "ssh_diagnose_nginx_access"
    assert entries["nginx_access"]["window_required"]
    assert entries["nginx_access"]["risk"] == "medium"


def test_mcp_tool_parameters_match_the_spec_options():
    import asyncio

    from sshmcp.mcp_tools import mcp

    tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
    for action in ("nginx", "nginx_access"):
        spec = extensions.spec_for(action)
        props = set(tools[spec.tool].inputSchema["properties"])
        assert props - {"host_id", "expected_revision", "detail"} == {
            param.name for param in spec.params
        }


BAD_OPTIONS = [
    ("nginx", {"minutes": 0}),
    ("nginx", {"minutes": 1441}),
    ("nginx", {"minutes": "30"}),
    ("nginx", {"minutes": True}),
    ("nginx", {"path": "/var/log/nginx/access.log"}),
    ("nginx_access", {"top": 4}),
    ("nginx_access", {"top": 31}),
    ("nginx_access", {"status": "6xx"}),
    ("nginx_access", {"status": "50"}),
    ("nginx_access", {"status": "5XX"}),
    ("nginx_access", {"status": "1000"}),
    ("nginx_access", {"status": "all;id"}),
    ("nginx_access", {"path": "var/log/nginx/access.log"}),
    ("nginx_access", {"path": "/var/log/nginx/../../etc/shadow"}),
    ("nginx_access", {"path": "/var/log/nginx/a b.log"}),
    ("nginx_access", {"path": "/var/log/nginx/$(id).log"}),
    ("nginx_access", {"path": "/var/log/nginx/x;id"}),
    ("nginx_access", {"path": "/var/log/nginx/x'y"}),
    ("nginx_access", {"path": "/var/log/nginx/"}),
    ("nginx_access", {"path": "/var/log/nginx/" + "a" * 190}),
    ("nginx_access", {"keyword": "`id`"}),
    ("nginx_access", {"keyword": "$(id)"}),
    ("nginx_access", {"keyword": "a\\b"}),
    ("nginx_access", {"keyword": "line\nbreak"}),
    ("nginx_access", {"keyword": "x" * 65}),
    ("nginx_access", {"keyword": ""}),
    ("nginx_access", {"since": 1, "until": 100000}),
    ("nginx_access", {"until": 4102444800}),
    ("nginx_access", {"since": 0}),
    ("nginx_access", {"shell": "id"}),
    ("nginx_access", "status=5xx"),
]


@pytest.mark.parametrize("action,options", BAD_OPTIONS)
def test_bad_options_are_refused_before_any_script(action, options):
    with pytest.raises(ValueError):
        diagnostics.command_for(action, options=options)


def test_extension_actions_take_no_classic_arguments():
    for action in ("nginx", "nginx_access"):
        with pytest.raises(ValueError):
            diagnostics.command_for(action, service="nginx")


def test_strings_reach_the_script_only_as_quoted_assignments():
    now = int(time.time())
    script = diagnostics.command_for(
        "nginx_access",
        options={
            "since": now - 600,
            "until": now,
            "path": "/var/log/nginx/__CMDS__.log",
            "status": "502",
            "keyword": 'it\'s ; rm -rf / && "x" | y <z>',
            "top": 7,
        },
    )
    assert script.startswith(diagnostics.PREFIX)
    assert "\nkw='it'\"'\"'s ; rm -rf / && \"x\" | y <z>'\n" in script
    # Placeholder-like values are inserted once and never expanded again
    # (shlex.quote leaves strings of safe characters unquoted).
    assert "\np=/var/log/nginx/__CMDS__.log\n" in script
    assert "\nsel=502\n" in script and "\ntopn=7\n" in script
    assert f"\nws={now - 600}\n" in script and f"\nwe={now}\n" in script
    assert "\nbucket=1\n" in script
    # The keyword only ever reaches grep -F as a literal.
    assert script.count('"$kw"') == 2 and 'grep -a -F -- "$kw"' in script
    assert re.search(r"__[A-Z_]+__", script.replace("__CMDS__.log", "")) is None
    status = diagnostics.command_for("nginx", options={"minutes": 45})
    assert "\nminutes=45\n" in status
    assert re.search(r"__[A-Z_]+__", status) is None


def test_bucket_size_keeps_the_timeline_under_120_rows():
    assert nginx.bucket_minutes(0, 7200) == 1
    assert nginx.bucket_minutes(0, 7201) == 10
    assert nginx.bucket_minutes(0, 72000) == 10
    assert nginx.bucket_minutes(0, 86400) == 15
    now = int(time.time())
    wide = diagnostics.command_for(
        "nginx_access", options={"since": now - 86400, "until": now}
    )
    assert "\nbucket=15\n" in wide


def _shell_only(script):
    """Shell code with every single-quoted literal (awk, printf formats) blanked."""
    return re.sub(r"'[^']*'", "''", script)


def _awk_programs(script):
    programs = [nginx.CONFIG_AWK, nginx.ERROR_AWK, nginx.ALOG_AWK, nginx.ACCESS_AWK]
    return programs + re.findall(r"awk (?:-v [^']+)?'([^']*)'", script)


def _scripts():
    now = int(time.time())
    return [
        diagnostics.command_for("nginx", options={"minutes": 30}),
        diagnostics.command_for(
            "nginx_access",
            options={
                "since": now - 3600,
                "until": now,
                "path": "/var/log/nginx/access.log",
                "status": "5xx",
                "keyword": "upstream",
            },
        ),
    ]


def test_scripts_are_read_only_bounded_and_portable():
    for program in (
        nginx.CONFIG_AWK,
        nginx.ERROR_AWK,
        nginx.ALOG_AWK,
        nginx.ACCESS_AWK,
    ):
        assert "'" not in program
    for script in _scripts():
        code = _shell_only(script)
        assert "timeout -k 1" in script
        # Only /dev/null redirections and 2>&1; nothing is ever written.
        assert set(re.findall(r"\d*>&?[^\s;|)]*", code)) <= {
            ">/dev/null",
            "2>/dev/null",
            "2>&1",
        }
        assert ">>" not in code and "<<" not in code
        assert not re.search(
            r"(?<![\w.-])(tee|touch|mkdir|rm|rmdir|mv|cp|chmod|chown|chgrp|kill|"
            r"pkill|killall|truncate|shred|dd|ln|install|eval|exec)(?![\w.-])",
            code,
        )
        assert not re.search(
            r"sed +-i|nginx[^\n|;]* -s |-s +(reload|stop|quit)", script
        )
        assert not re.search(
            r"systemctl[^\n|;]*\b(start|stop|restart|reload|enable|disable|mask|kill)\b",
            script,
        )
        # POSIX sh (dash): no bash-only syntax.
        assert not re.search(
            r"\[\[|\$'|\$\{[^}]*(//|\^\^|,,)|<<<|<\(|>\(|=~|pipefail|\$\{!", code
        )
        assert not re.search(
            r"(?m)(?:^|[;&|{(])\s*(local|function|declare|typeset|source)\s", code
        )
        assert not re.search(r"\[ [^]]*==", code)
        # POSIX/mawk awk: no gawk extensions, no output redirection, no commands.
        for program in _awk_programs(script):
            assert not re.search(
                r"\b(strftime|mktime|systime|gensub|asorti?|PROCINFO|BEGINFILE|"
                r"ENDFILE|nextfile|delete|system|getline|fflush|close)\b",
                program,
            )
            assert not re.search(r"\bprintf? [^\n;]*>|\|\s*\"|\|&|\*\*", program)
            assert not re.search(r"\{\d|\\[sdwSDW]", program)
            # match(s, /re/) only: the three-argument form is gawk-only.
            calls = re.findall(
                r"\bmatch\(\s*[\w$]+\s*,\s*/(?:[^/\\\n]|\\.)*/\s*([,)])", program
            )
            assert calls == [")"] * program.count("match(")
            assert set(re.findall(r"length\(([^)]*)\)", program)) <= {
                "$3",
                "name_",
                "k",
            }


@needs_sh
@pytest.mark.parametrize(
    "action,options",
    [
        ("nginx", {}),
        ("nginx", {"minutes": 1440}),
        ("nginx_access", {}),
        ("nginx_access", {"minutes": 1440, "status": "4xx", "top": 30}),
        ("nginx_access", {"status": "502", "keyword": 'it\'s "x" ; | & <a>'}),
        ("nginx_access", {"path": "/var/log/nginx/access.log", "keyword": "GET /"}),
        ("nginx_access", "23h-window-an-hour-ago"),
    ],
)
def test_scripts_pass_sh_syntax_check(action, options):
    if options == "23h-window-an-hour-ago":
        now = int(time.time())
        options = {"since": now - 86400, "until": now - 3600}
    script = diagnostics.command_for(action, options=options)
    subprocess.run(["/bin/sh", "-n"], input=script, text=True, check=True)


# --------------------------------------------------------------------------
# Parsers on real output
# --------------------------------------------------------------------------


def test_nginx_parser_reads_the_real_script_output():
    report = analyze("nginx", NGINX_OUTPUT, minutes=30)
    s = report["summary"]
    assert s["binary"] == "/usr/sbin/nginx" and s["binary_source"] == "discovered"
    assert s["version"] == "nginx/1.24.0"
    assert s["build"] == {
        "prefix": "/usr/share/nginx",
        "conf_path": "/etc/nginx/nginx.conf",
        "error_log_path": "/var/log/nginx/error.log",
        "http_log_path": "/var/log/nginx/access.log",
    }
    cfg = s["config"]
    assert (cfg["source"], cfg["test"]) == ("T", "ok")
    assert cfg["access_logs"] == [
        "/var/log/nginx/access.log",
        "/var/log/nginx/api.access.log",
    ]
    assert cfg["error_logs"] == ["/var/log/nginx/error.log"]
    assert cfg["log_formats"]["json"].startswith('escape=json \'{"time_local"')
    assert "$upstream_response_time" in cfg["log_formats"]["main"]
    assert cfg["upstreams"] == [
        {
            "name": "backend",
            "servers": [
                "10.0.0.21:8080 max_fails=3 fail_timeout=10s",
                "10.0.0.22:8080 max_fails=3 fail_timeout=10s",
            ],
            "keepalive": 32,
        },
        {"name": "php", "servers": ["unix:/run/php/php-fpm.sock"], "keepalive": None},
    ]
    assert cfg["listen"] == ["80", "443 ssl http2", "80 default_server"]
    assert (cfg["server_names_count"], cfg["proxy_pass_count"]) == (2, 2)
    assert (cfg["worker_processes"], cfg["worker_connections"]) == ("auto", 1024)
    assert cfg["timeouts"] == {
        "proxy_connect": ["5s"],
        "proxy_read": ["60s", "120s"],
        "proxy_send": ["60s"],
        "keepalive": ["65"],
    }
    assert cfg["client_max_body_size"] == ["20m"]
    assert [p["role"] for p in s["processes"]] == [
        "master",
        "worker",
        "worker",
        "other",
    ]
    assert s["processes"][1] == {
        "pid": 1202,
        "ppid": 1201,
        "role": "worker",
        "user": "www-data",
        "elapsed_seconds": 86000,
        "rss_KiB": 52120,
        "cpu_percent": 1.5,
        "command": "nginx: worker process",
    }
    assert s["worker_count"] == 2
    assert s["systemd"] == [
        {
            "unit": "nginx.service",
            "load": "loaded",
            "active": "active",
            "sub": "running",
            "result": "success",
            "restarts": 2,
            "started": "Wed 2026-10-28 23:26:40 UTC",
        }
    ]
    assert s["listen_source"] == "proc"
    assert [(row["port"], row["process"]) for row in s["listening"]] == [
        (80, "nginx"),
        (443, "nginx"),
        (80, "nginx"),
    ]
    assert s["established_by_port"]["443"] == 30
    assert len(s["established_by_port"]) == 10
    logs = {row["path"]: row for row in s["log_files"]}
    assert logs["/var/log/nginx/access.log"]["bytes"] == 6779
    assert [r["path"] for r in logs["/var/log/nginx/access.log"]["rotated"]] == [
        "/var/log/nginx/access.log.1",
        "/var/log/nginx/access.log.2.gz",
    ]
    assert logs["/var/log/nginx/error.log"]["rotated"][0]["mtime"] == NOW - 7200
    errors = s["errors"]
    assert errors["window"]["since"] == SINCE and errors["window"]["until"] == NOW
    assert errors["window"]["since_local"] == "2026-10-29 23:30:00"
    assert errors["files"][0]["path"] == "/var/log/nginx/error.log"
    assert errors["files"][0]["lines_in_window"] == 15
    assert errors["counts_by_level"] == {
        "alert": 1,
        "crit": 1,
        "error": 11,
        "info": 1,
        "warn": 1,
    }
    assert errors["upstream_errors"] == {
        "client_closed": 1,
        "connect_failed": 2,
        "connection_refused": 1,
        "no_live_upstreams": 1,
        "other_upstream": 1,
        "prematurely_closed": 1,
        "timed_out": 4,
        "too_many_open_files": 1,
        "worker_connections": 1,
    }
    assert errors["top_upstreams"][:2] == [
        {"value": "10.0.0.21:8080", "count": 5},
        {"value": "unix:/run/php/php-fpm.sock:", "count": 2},
    ]
    assert errors["top_clients"][0] == {"value": "10.0.0.9", "count": 3}
    assert errors["top_requests"][0] == {"value": "GET /api/v1/orders", "count": 3}
    assert errors["top_messages"][0]["count"] == 4
    assert len(errors["samples"]) == 13 and errors["coverage_from"] is None
    # Second redaction layer: the sampled query string loses its password.
    assert "hunter2" not in json.dumps(report)
    assert "20 MB" in s["coverage"] and "30 分钟" in s["coverage"]
    found = by_metric(report)
    for name in (
        "no_live_upstreams",
        "worker_connections_exhausted",
        "too_many_open_files",
    ):
        assert found[name]["level"] == "critical"
    assert (found["upstream_errors"]["level"], found["upstream_errors"]["value"]) == (
        "warning",
        10,
    )
    assert found["upstream_timed_out"]["value"] == 4
    assert found["upstream_connect_failed"]["value"] == 3
    assert (found["error_log_errors"]["level"], found["error_log_errors"]["value"]) == (
        "warning",
        13,
    )
    assert found["systemd_restarts:nginx.service"]["level"] == "warning"
    assert not {
        "nginx_inactive",
        "config_test_failed",
        "nginx_not_found",
        "error_log_window_not_covered",
        "collection_coverage",
    } & set(found)
    assert all("经验" in f["hint"] or "严重" in f["hint"] for f in report["findings"])


def test_nginx_parser_knows_failed_and_unavailable_config_tests():
    broken = analyze("nginx", NGINX_BROKEN_CONFIG, minutes=30)
    cfg = broken["summary"]["config"]
    assert (cfg["source"], cfg["test"]) == ("file", "failed")
    assert cfg["upstreams"][0]["name"] == "backend"
    failed = by_metric(broken)["config_test_failed"]
    assert failed["level"] == "critical" and "proxy_passs" in failed["value"][0]
    denied = analyze("nginx", NGINX_DENIED_CONFIG, minutes=30)
    cfg = denied["summary"]["config"]
    assert (cfg["source"], cfg["test"], cfg["test_reason"]) == (
        "file",
        "unknown",
        "permission",
    )
    found = by_metric(denied)
    assert "config_test_failed" not in found
    assert found["config_test_unavailable"]["level"] == "info"
    assert cfg["access_logs"] == [
        "/var/log/nginx/access.log",
        "/var/log/nginx/api.access.log",
    ]


def test_nginx_parser_separates_not_found_inactive_and_invisible():
    missing = analyze(
        "nginx",
        "[AIOPS_BIN]\nCAPABILITY_MISSING:nginx\n[AIOPS_VERSION]\n[AIOPS_CONFIG]\n"
        "CONFIG_SOURCE=none\nCOUNT input_lines 0\n[AIOPS_PROCESS]\n[AIOPS_SYSTEMD]\n"
        "[AIOPS_LISTEN]\nLISTEN_SOURCE=noproc\nLISTEN 0.0.0.0:22 -\n[AIOPS_LOGFILES]\n"
        "[AIOPS_ERRORS]\nWINDOW 1 2 2026/10/29 23:30:00 2026/10/30 00:00:00\n",
    )
    found = by_metric(missing)
    assert found["nginx_not_found"]["level"] == "info"
    assert found["collection_coverage"]["value"] == ["nginx"]
    assert not any(f["level"] == "critical" for f in missing["findings"])
    assert missing["summary"]["listening"] == [
        {"local": "0.0.0.0:22", "port": 22, "process": None}
    ]
    assert "upstream_errors" not in found  # no error log was read
    stopped = "[AIOPS_BIN]\nBIN /usr/sbin/nginx\n[AIOPS_PROCESS]\n[AIOPS_SYSTEMD]\n"
    found = by_metric(analyze("nginx", stopped))
    assert found["nginx_inactive"]["level"] == "critical"
    hidden = stopped + "UNIT nginx.service\nLoadState=loaded\nActiveState=active\n"
    found = by_metric(analyze("nginx", hidden))
    assert "nginx_inactive" not in found and "nginx_process_not_visible" in found
    no_ps = "[AIOPS_BIN]\nBIN /usr/sbin/nginx\n[AIOPS_PROCESS]\nCAPABILITY_MISSING:ps\n"
    assert "nginx_inactive" not in by_metric(analyze("nginx", no_ps))
    other = (
        "[AIOPS_BIN]\nBIN /usr/sbin/nginx\nMASTER_BIN /opt/openresty/nginx/sbin/nginx\n"
        "[AIOPS_PROCESS]\n1 0 root 5 100 0.0 nginx nginx: master process x\n"
    )
    mismatch = by_metric(analyze("nginx", other))["nginx_binary_mismatch"]
    assert mismatch["value"]["running"] == "/opt/openresty/nginx/sbin/nginx"


def test_nginx_parser_flags_partial_error_windows():
    text = (
        "[AIOPS_ERRORS]\nWINDOW 1793316600 1793318400 2026/10/29 23:30:00 "
        "2026/10/30 00:00:00\nFILE /var/log/nginx/error.log\nREAD_TIMEOUT "
        "/var/log/nginx/error.log\nCOVERAGE_FROM 2026/10/29 23:45:10\nLEVEL error 120\n"
        "LINES 120 120\nUPSTREAM timed_out 25\nFILE /var/log/nginx/other.log\n"
        "NOACCESS /var/log/nginx/other.log\nCAPABILITY_MISSING:log-permission\n"
    )
    report = analyze("nginx", text, minutes=30)
    errors = report["summary"]["errors"]
    assert errors["coverage_from"] == "2026-10-29 23:45:10"
    assert [f["readable"] for f in errors["files"]] == [True, False]
    found = by_metric(report)
    assert found["error_log_window_not_covered"]["level"] == "info"
    assert found["error_log_read_timeout"]["level"] == "info"
    assert found["upstream_errors"]["level"] == "critical"
    assert found["error_log_errors"]["level"] == "critical"
    assert found["collection_coverage"]["value"] == ["log-permission"]


def test_access_parser_reads_the_real_script_output():
    options = dict(options_for("nginx_access", status="5xx", top=5))
    options.update(since=SINCE, until=NOW, path="/var/log/nginx/access.log")
    report = analyze("nginx_access", ACCESS_OUTPUT, **options)
    s = report["summary"]
    assert s["window"] == {
        "since": SINCE,
        "until": NOW,
        "since_local": "2026-10-29 23:30:00",
        "until_local": "2026-10-30 00:00:00",
    }
    assert s["selection"] == {"status": "5xx", "keyword": None, "top": 5}
    assert s["files"] == [
        {
            "path": "/var/log/nginx/access.log.1",
            "bytes_read": 460,
            "size": 460,
            "rotated": True,
        },
        {
            "path": "/var/log/nginx/access.log",
            "bytes_read": 6779,
            "size": 6779,
            "rotated": False,
        },
    ]
    assert (s["first_at"], s["last_at"]) == (
        "2026-10-29 23:20:00",
        "2026-10-30 00:36:40",
    )
    assert s["totals"]["requests"] == 44 and s["totals"]["selected"] == 10
    assert s["totals"]["by_class"] == {
        "2xx": 18,
        "3xx": 4,
        "4xx": 12,
        "5xx": 10,
        "other": 0,
    }
    assert (s["totals"]["unparsed_lines"], s["totals"]["outside_window"]) == (2, 2)
    assert s["codes"][:3] == [
        {"code": "200", "count": 18},
        {"code": "404", "count": 8},
        {"code": "502", "count": 6},
    ]
    assert s["top"]["uris"] == [
        {"value": "/api/v1/orders", "count": 6},
        {"value": "/api/v1/pay", "count": 4},
    ]
    assert s["top"]["ips"][0] == {"value": "10.1.0.3", "count": 5}
    assert s["top"]["uas"][0] == {"value": "Go-http-client/1.1", "count": 4}
    assert s["bucket_minutes"] == 1 and len(s["timeline"]) == 19
    assert s["timeline"][0] == {
        "minute": "2026-10-29 23:30",
        "requests": 2,
        "errors_5xx": 1,
    }
    assert s["timing"] == {
        "request_time": {
            "count": 44,
            "avg": 6.168,
            "max": 60.001,
            "over_1s": 12,
            "over_3s": 12,
            "over_10s": 4,
        },
        "upstream_time": {
            "count": 28,
            "avg": 9.034,
            "max": 60.0,
            "over_1s": 8,
            "over_3s": 8,
        },
        "no_upstream": 16,
    }
    assert len(s["samples"]) == 10 and "abc123" not in json.dumps(report)
    assert "token=[REDACTED]" in s["samples"][-1]
    assert "30 MB" in s["coverage"] and "轮转文件尾部 10 MB" in s["coverage"]
    found = by_metric(report)
    assert found["status_5xx_ratio"]["level"] == "critical"
    assert found["status_5xx_ratio"]["value"] == {
        "percent": 22.73,
        "count": 10,
        "requests": 44,
    }
    assert found["status_4xx_ratio"]["level"] == "warning"
    assert found["slow_requests_over_3s"]["value"]["count"] == 12
    assert found["upstream_time_max"]["value"] == 60.0
    assert not {"status_499", "window_not_covered", "no_requests"} & set(found)


def test_access_parser_rules_for_small_partial_and_refused_runs():
    refused = analyze(
        "nginx_access",
        "[AIOPS_FILES]\nWINDOW 1 2 20261029233000 20261030000000\nAIOPS_REFUSED:path\n",
        path="/var/log/nginx/x.log",
    )
    assert refused["summary"]["refused"] is True
    hint = by_metric(refused)["refused_path"]
    assert hint["level"] == "warning" and "/var/log/nginx" in hint["hint"]
    empty = analyze(
        "nginx_access",
        "[AIOPS_FILES]\nWINDOW 1793316600 1793318400 20261029233000 20261030000000\n"
        "FILE /var/log/nginx/access.log 31 31\nRANGE - - /var/log/nginx/access.log\n"
        "FIRST - LAST -\n[AIOPS_TOTALS]\nLINES 3 3 0\nTOTAL 0\nSELECTED 0\n"
        "[AIOPS_TIMING]\nUNAVAILABLE request_time\nUNAVAILABLE upstream_time\n",
    )
    found = by_metric(empty)
    assert found["no_requests"]["level"] == "info"
    assert "无法识别" in found["no_requests"]["hint"]
    assert found["log_format_unrecognized"]["value"] == {"unparsed": 3, "lines": 3}
    assert empty["summary"]["timing"]["request_time"] is None
    partial = analyze(
        "nginx_access",
        "[AIOPS_FILES]\nWINDOW 1793316600 1793318400 20261029233000 20261030000000\n"
        "FILE /var/log/nginx/access.log 30000000 90000000\n"
        "TRUNCATED /var/log/nginx/access.log\n"
        "RANGE 20261029234510 20261030000000 /var/log/nginx/access.log\n"
        "FIRST 20261029234510 LAST 20261030000000\n[AIOPS_TOTALS]\nLINES 9 0 0\n"
        "TOTAL 9\nCLASS 2xx 7\nCLASS 5xx 2\nSELECTED 9\n[AIOPS_CODES]\nCODE 200 7\n"
        "CODE 502 2\nCODE 499 12\n",
    )
    found = by_metric(partial)
    late = found["window_not_covered"]
    assert late["level"] == "info"
    assert late["value"]["late_files"] == ["/var/log/nginx/access.log"]
    assert late["value"]["truncated"] == ["/var/log/nginx/access.log"]
    # Fewer than 20 requests: no percentage, but 5xx still matter.
    assert (
        "status_5xx_ratio" not in found
        and found["status_5xx_count"]["level"] == "warning"
    )
    assert found["status_499"]["value"] == 12


GARBAGE = [
    "",
    "unexpected\x00output\n�\n",
    "CAPABILITY_MISSING:nginx\n",
    "CAPABILITY_MISSING:date\n",
    "AIOPS_REFUSED:path\n",
    "[AIOPS_FILES]\n[AIOPS_TOTALS]\n[AIOPS_CODES]\n[AIOPS_TIMING]\n[AIOPS_SAMPLES]\n",
    "[AIOPS_BIN]\nBIN\n[AIOPS_ERRORS]\nFILE\nLINES - -\nLEVEL error -\n",
    "[AIOPS_TOTALS]\nTOTAL -\nCLASS 5xx -\nLINES - - -\n[AIOPS_CODES]\nCODE 502 -\n"
    "[AIOPS_MINUTES]\nBUCKET -\nMINUTE 202610292330 - 1\n[AIOPS_TOP_URI]\nTOP_URI - /x\n"
    "[AIOPS_TIMING]\nREQ - - - - - -\nUPS 1 nan inf 0 0\nNOUPSTREAM -\n",
    "[AIOPS_LISTEN]\nESTAB 443 -\nLISTEN\n[AIOPS_SYSTEMD]\nUNIT x\nNRestarts=-\n"
    "[AIOPS_PROCESS]\n1 2\nx y z a b c d e\n[AIOPS_LOGFILES]\nLOG access_log /x\n"
    "-rw-r--r-- 1 a b - - /x\n[AIOPS_CONFIG]\nCOUNT server_name -\nworker_connections -;\n"
    "keepalive x;\nUPSTREAM\nserver;\nlog_format;\n",
]


@pytest.mark.parametrize("action", ["nginx", "nginx_access"])
def test_parsers_never_raise_on_garbage_or_truncation(action):
    texts = list(GARBAGE)
    for fixture in (NGINX_OUTPUT, ACCESS_OUTPUT):
        texts += [fixture[:cut] for cut in range(0, len(fixture), 97)]
        texts.append(re.sub(r"\d", "-", fixture))
    for text in texts:
        for options in (None, {}, {"minutes": "x", "top": None, "status": 5}):
            report = observations.analyze(
                action, text, options=options, status="partial", truncated=True
            )
            json.dumps(report, allow_nan=False)
            assert all(
                set(f) >= {"level", "metric", "value", "threshold", "hint"}
                and f["level"] in {"critical", "warning", "info"}
                for f in report["findings"]
            )


@needs_awk
def test_access_awk_handles_json_spacing_labels_and_upstream_lists():
    lines = [
        '{"time_local": "29/Oct/2026:23:40:00 +0000", "status": 503, '
        '"request_time": 1.5, "upstream_response_time": "1.400", '
        '"remote_addr": "10.9.0.1", "request": "GET /a?b=1 HTTP/1.1", '
        '"http_user_agent": "x \\"quoted\\" ua"}',
        '10.9.0.2 - - [29/Oct/2026:23:41:00 +0000] "GET /b HTTP/1.1" 200 5 "-" "ua" '
        'rt=0.250 uct="0.001" uht="0.200" urt="0.240"',
        '10.9.0.3 - - [29/Oct/2026:23:42:00 +0000] "GET /c HTTP/1.1" 200 5 "-" "ua" '
        'rt=0.010 urt="-"',
        '10.9.0.4 - - [2026-10-29T23:43:00+00:00] "GET /d HTTP/1.1" 404 0 "-" "ua"',
        '10.9.0.5 - - [29/Oct/2026:23:44:00 +0000] "GET /e HTTP/1.1" 101 0 "-" "ua" '
        "0.040 0.010 : 0.015",
        '10.9.0.6 - - [29/Oct/2026:22:00:00 +0000] "GET /old HTTP/1.1" 500 0 "-" "ua"',
    ]
    proc = subprocess.run(
        [
            "awk",
            "-v",
            "skey=20261029233000",
            "-v",
            "ukey=20261030000000",
            "-v",
            "sel=all",
            "-v",
            "topn=10",
            "-v",
            "bucket=10",
            nginx.ACCESS_AWK,
        ],
        input="\n".join(lines) + "\n",
        capture_output=True,
        text=True,
        check=True,
    )
    out = proc.stdout.splitlines()
    assert "LINES 6 0 1" in out and "TOTAL 5" in out
    assert {"CLASS 2xx 2", "CLASS 4xx 1", "CLASS 5xx 1", "CLASS other 1"} <= set(out)
    assert "REQ 4 0.450 1.500 1 0 0" in out
    assert "UPS 3 0.552 1.400 1 0" in out and "NOUPSTREAM 1" in out
    assert "TOP_URI 1 /a" in out and 'TOP_UA 1 x \\"quoted\\" ua' in out
    assert {"MINUTE 202610292340 5 1"} == {l for l in out if l.startswith("MINUTE")}


# --------------------------------------------------------------------------
# End to end under /bin/sh (dash + mawk on CI) against the fake install
# --------------------------------------------------------------------------


@needs_sh
def test_nginx_script_end_to_end_matches_the_fixture(tmp_path, monkeypatch):
    sh = install_fixture(tmp_path.resolve())
    use_fixture(monkeypatch, sh)
    code, out, err = run_script(nginx.nginx_script({"minutes": 30}), sh)
    assert code == 0, err
    assert normalize(out, sh) == NGINX_OUTPUT
    assert max(map(len, out.splitlines())) <= 300
    assert len(out.encode()) <= 24 * 1024


@needs_sh
@pytest.mark.parametrize("mode", ["denied", "broken"])
def test_nginx_script_falls_back_to_config_files(tmp_path, monkeypatch, mode):
    sh = install_fixture(tmp_path.resolve(), t_mode=mode)
    use_fixture(monkeypatch, sh)
    code, out, err = run_script(nginx.nginx_script({"minutes": 30}), sh)
    assert code == 0, err
    expected = NGINX_DENIED_CONFIG if mode == "denied" else NGINX_BROKEN_CONFIG
    assert normalize(out, sh).startswith(expected)


@needs_sh
def test_access_script_end_to_end_matches_the_fixture(tmp_path, monkeypatch):
    sh = install_fixture(tmp_path.resolve())
    use_fixture(monkeypatch, sh)
    options = options_for(
        "nginx_access",
        since=SINCE,
        until=NOW,
        path=sh["logs"] + "/access.log",
        status="5xx",
        top=5,
    )
    code, out, err = run_script(nginx.access_script(options), sh)
    assert code == 0, err
    assert normalize(out, sh) == ACCESS_OUTPUT
    assert max(map(len, out.splitlines())) <= 300


@needs_sh
def test_access_script_selects_config_logs_and_filters_keyword(tmp_path, monkeypatch):
    sh = install_fixture(tmp_path.resolve())
    use_fixture(monkeypatch, sh)
    auto = options_for("nginx_access", since=SINCE, until=NOW, top=10)
    code, out, err = run_script(nginx.access_script(auto), sh)
    assert code == 0, err
    report = analyze("nginx_access", out, **auto)
    s = report["summary"]
    assert s["candidates"] == [
        sh["logs"] + "/access.log",
        sh["logs"] + "/api.access.log",
    ]
    assert [(f["path"].rsplit("/", 1)[1], f["rotated"]) for f in s["files"]] == [
        ("access.log.1", True),
        ("access.log", False),
        ("api.access.log", False),
    ]
    assert s["totals"]["requests"] == 86 and s["totals"]["selected"] == 86
    assert s["top"]["uris"][0] == {"value": "/api/v1/orders", "count": 36}
    late = by_metric(report)["window_not_covered"]["value"]["late_files"]
    assert late == [sh["logs"] + "/api.access.log"]
    keyword = options_for("nginx_access", since=SINCE, until=NOW, keyword="orders")
    code, out, err = run_script(nginx.access_script(keyword), sh)
    assert code == 0, err
    totals = analyze("nginx_access", out, **keyword)["summary"]["totals"]
    assert totals["requests"] == 36 and totals["by_class"]["5xx"] == 11


@needs_sh
def test_access_script_refuses_paths_outside_nginx_logs(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    sh = install_fixture(base)
    use_fixture(monkeypatch, sh)
    _write(base / "outside" / "access.log", "x\n")
    _write(base / "outside" / "secret.txt", "root:x:0:0\n")
    os.symlink(base / "outside" / "secret.txt", base / "logs" / "link.log")
    for path in (
        str(base / "outside" / "access.log"),
        sh["logs"] + "/link.log",
        sh["logs"] + "/missing.log",
        sh["logs"],
    ):
        options = options_for("nginx_access", since=SINCE, until=NOW, path=path)
        code, out, _ = run_script(nginx.access_script(options), sh)
        assert code == 69 and "AIOPS_REFUSED:path" in out, path
        assert "root:x" not in out
        refused = analyze("nginx_access", out, **options)
        assert by_metric(refused)["refused_path"]["level"] == "warning"
    # A log declared by nginx's own config is accepted outside the usual dirs.
    monkeypatch.setattr(nginx, "ALLOWED_LOG_PATTERNS", ("/var/log/nginx/*",))
    declared = options_for(
        "nginx_access", since=SINCE, until=NOW, path=sh["logs"] + "/api.access.log"
    )
    code, out, err = run_script(nginx.access_script(declared), sh)
    assert code == 0 and "AIOPS_REFUSED" not in out, err
    assert (
        analyze("nginx_access", out, **declared)["summary"]["totals"]["requests"] == 42
    )
