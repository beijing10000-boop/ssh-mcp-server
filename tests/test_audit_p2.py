"""Regressions for the remaining P2 findings of the 2026-11 audit (v0.10.0).

Unknown counts are null, not 0 (SSH-DIAG-12); time_sync works without
`timedatectl show` (SSH-DIAG-16); unhealthy containers are reported
(SSH-DIAG-17); the jvm probe's side effects are written down (SSH-DIAG-15);
nginx_access finds request_time through the log_format (SSH-NGX-06); MCP
authentication is a read off the event loop (SSH-CORE-02); SSH tools have a
pool of their own (SSH-CORE-03); a client that leaves frees its slot
(SSH-CORE-04); the Origin check follows a trusted proxy (SSH-CORE-10).

Parser, API and awk tests run everywhere awk is installed; the script runs
need /bin/sh (dash on CI). The EL7 run of time_sync is in
test_audit_followup.py (-k el7).
"""

from concurrent.futures import ThreadPoolExecutor
import asyncio
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time

import anyio
import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request

from sshmcp import access, auth, catalog, diagnostics, jobs, mcp_tools, store
from sshmcp import observations, operations
from sshmcp.extensions import nginx
from sshmcp.main import app
from test_console import mcp_call, ready_host
from test_core import auth as csrf

HAS_SH = os.path.exists("/bin/sh")
needs_sh = pytest.mark.skipif(not HAS_SH, reason="needs /bin/sh")


def metrics(report):
    return {m["metric"]: m for m in report["summary"]["metrics"]}


def by_metric(report):
    return {f["metric"]: f for f in report["findings"]}


def awk_commands():
    """Every awk on this machine: the default, POSIX gawk and mawk."""
    found = [["awk"]] if shutil.which("awk") else []
    if shutil.which("gawk"):
        found.append(["gawk", "--posix"])
    if shutil.which("mawk"):
        found.append(["mawk"])
    return found


def run_awk(command, program, data, *variables):
    """The program from a file: MSYS awk on Windows garbles a command-line
    program longer than about 8 KB (ACCESS_AWK is); on Linux it is the same."""
    with tempfile.NamedTemporaryFile(
        "w", suffix=".awk", delete=False, encoding="utf-8", newline="\n"
    ) as fh:
        fh.write(program)
    try:
        args = [arg for name in variables for arg in ("-v", name)]
        return subprocess.run(
            [*command, *args, "-f", fh.name], input=data, capture_output=True
        )
    finally:
        os.unlink(fh.name)


# ------------------------------------------- SSH-DIAG-12: null, not 0 ------


def test_failed_service_count_is_unknown_without_systemctl():
    for text in (
        "CAPABILITY_MISSING:systemctl\n",
        # systemctl ran but could not reach systemd (exit 1).
        "",
    ):
        report = observations.analyze("failed_services", text, status="partial")
        assert metrics(report)["failed_service_count"]["value"] is None, text
        assert "failed_service_count" not in by_metric(report)
        assert by_metric(report)["collection_coverage"]["level"] == "info"


def test_log_counts_are_unknown_when_the_journal_is_not_readable():
    for text in (
        "CAPABILITY_MISSING:journalctl\n",
        # An account outside the journal groups sees its own lines only.
        "CAPABILITY_MISSING:journal-permission\n",
    ):
        for action in ("logs", "kernel", "log_errors", "oom"):
            report = observations.analyze(action, text, status="partial")
            found = metrics(report)
            assert found["observed_log_lines"]["value"] is None, (action, text)
            assert found["oom_matches"]["value"] is None, (action, text)
            assert report["summary"]["entries_total"] is None
            assert report["summary"]["entries"] == []


def test_counts_seen_in_an_incomplete_run_are_kept():
    text = (
        "CAPABILITY_MISSING:journal-permission\n"
        "2026-11-01T10:00:00+0800 h kernel: Killed process 4242 (java)\n"
    )
    report = observations.analyze("oom", text, status="partial")
    found = metrics(report)
    # Seen is seen: a lower bound, and still the critical finding.
    assert found["oom_matches"]["value"] == 1
    assert found["observed_log_lines"]["value"] == 1
    assert by_metric(report)["oom_matches"]["level"] == "critical"
    assert report["summary"]["entries_total"] == 1


def test_complete_runs_keep_their_zero_counts():
    clean = observations.analyze("failed_services", "")
    assert metrics(clean)["failed_service_count"]["value"] == 0
    quiet = observations.analyze("logs", "-- No entries --\n")
    assert metrics(quiet)["observed_log_lines"]["value"] == 0
    assert quiet["summary"]["entries_total"] == 0
    timers = observations.analyze("timers", "", status="partial", truncated=True)
    assert metrics(timers)["observed_rows"]["value"] is None


def test_service_action_has_no_failed_service_count():
    text = (
        "Id=nginx.service\nLoadState=loaded\nActiveState=failed\nSubState=failed\n"
        "Result=exit-code\nNRestarts=0\nFragmentPath=/usr/lib/systemd/system/nginx.service\n"
    )
    report = observations.analyze("service", text)
    summary = report["summary"]
    # Still listed (clients may read it), but null: one unit has no count.
    assert metrics(report)["failed_service_count"]["value"] is None
    assert summary["failed_services"] is None
    assert "failed_service_count" not in by_metric(report)
    assert by_metric(report)["service_active_state"]["value"] == "failed"
    # The actions that do list failed services are unchanged.
    listed = observations.analyze(
        "failed_services", "nginx.service loaded failed failed Nginx\n"
    )
    assert metrics(listed)["failed_service_count"]["value"] == 1
    assert listed["summary"]["failed_services"] == ["nginx.service"]
    inventory = observations.analyze(
        "service_inventory",
        "nginx.service loaded failed failed Nginx\nsshd.service loaded active running OpenSSH\n",
    )
    assert metrics(inventory)["failed_service_count"]["value"] == 1


# ------------------------------------- SSH-DIAG-16: time_sync without show --

STATUS_219 = """      Local time: Sun 2026-11-01 12:00:00 CST
  Universal time: Sun 2026-11-01 04:00:00 UTC
        RTC time: Sun 2026-11-01 04:00:00
       Time zone: Asia/Shanghai (CST, +0800)
     NTP enabled: yes
NTP synchronized: no
 RTC in local TZ: no
      DST active: n/a
"""
STATUS_237 = """                      Local time: Tue 2026-11-03 10:00:00 UTC
                  Universal time: Tue 2026-11-03 10:00:00 UTC
                        RTC time: Tue 2026-11-03 10:00:01
                       Time zone: Etc/UTC (UTC, +0000)
       System clock synchronized: yes
systemd-timesyncd.service active: yes
                 RTC in local TZ: no
"""
STATUS_239 = """               Local time: Tue 2026-11-03 18:00:00 CST
           Universal time: Tue 2026-11-03 10:00:00 UTC
                 RTC time: Tue 2026-11-03 10:00:00
                Time zone: Asia/Shanghai (CST, +0800)
System clock synchronized: yes
              NTP service: inactive
          RTC in local TZ: no
"""
CHRONY = """Reference ID    : C0A80101 (192.0.2.1)
Stratum         : 3
Ref time (UTC)  : Sun Nov 01 04:00:00 2026
System time     : 0.000012345 seconds fast of NTP time
Last offset     : +0.000001234 seconds
RMS offset      : 0.000023456 seconds
Frequency       : 1.234 ppm slow
Leap status     : {leap}
"""
DATE = "2026-11-01T04:00:00Z\n"


def time_sync(text, status="success"):
    report = observations.analyze("time_sync", text, status=status)
    return report["summary"], by_metric(report)


def test_time_sync_reads_timedatectl_status_of_systemd_219():
    summary, found = time_sync(
        DATE + "[AIOPS_TIMEDATECTL_STATUS]\n" + STATUS_219 + "[AIOPS_CHRONYC]\n"
        "506 Cannot talk to daemon\nAIOPS_RC 1\n"
    )
    assert summary["sync_source"] == "timedatectl status"
    assert summary["properties"] == {
        "Timezone": "Asia/Shanghai",
        "NTP": "yes",
        "NTPSynchronized": "no",
        "LocalRTC": "no",
    }
    assert found["NTPSynchronized"]["level"] == "warning"
    assert "timedatectl status" in found["NTPSynchronized"]["hint"]
    # chronyc failed (rc 1): no chrony data, the status answer stands.
    assert "chrony" not in summary


@pytest.mark.parametrize(
    "status,expected",
    [
        (STATUS_237, {"Timezone": "Etc/UTC", "NTPSynchronized": "yes", "NTP": "yes"}),
        (
            STATUS_239,
            {"Timezone": "Asia/Shanghai", "NTPSynchronized": "yes", "NTP": "no"},
        ),
    ],
)
def test_time_sync_reads_later_status_labels(status, expected):
    summary, found = time_sync(DATE + "[AIOPS_TIMEDATECTL_STATUS]\n" + status)
    assert summary["sync_source"] == "timedatectl status"
    assert {k: summary["properties"][k] for k in expected} == expected
    assert "NTPSynchronized" not in found


def test_time_sync_falls_back_to_chronyc_then_ntpstat():
    summary, found = time_sync(
        DATE + "[AIOPS_CHRONYC]\n" + CHRONY.format(leap="Normal") + "AIOPS_RC 0\n"
    )
    assert summary["sync_source"] == "chronyc tracking"
    assert summary["properties"] == {"NTPSynchronized": "yes"}
    assert summary["chrony"]["stratum"] == 3
    assert summary["chrony"]["system_time"].startswith("0.000012345 seconds fast")
    summary, found = time_sync(
        DATE
        + "[AIOPS_CHRONYC]\n"
        + CHRONY.format(leap="Not synchronised")
        + "AIOPS_RC 0\n"
    )
    assert summary["properties"]["NTPSynchronized"] == "no"
    assert "chronyc tracking" in found["NTPSynchronized"]["hint"]
    for code, synced in (("0", "yes"), ("1", "no")):
        summary, _ = time_sync(
            DATE + "[AIOPS_NTPSTAT]\nsynchronised to NTP server (192.0.2.1) at "
            f"stratum 3\n   time correct to within 45 ms\nAIOPS_RC {code}\n"
        )
        assert summary["sync_source"] == "ntpstat"
        assert summary["properties"]["NTPSynchronized"] == synced
        assert summary["ntpstat"]["exit_code"] == int(code)
    # ntpstat 2: the daemon could not be asked, so nothing is known.
    summary, found = time_sync(
        DATE + "[AIOPS_NTPSTAT]\nUnable to talk to NTP daemon. Is it running?\n"
        "AIOPS_RC 2\n",
        status="partial",
    )
    assert summary["sync_source"] is None and summary["properties"] == {}
    assert "NTPSynchronized" not in found


def test_time_sync_keeps_reading_timedatectl_show():
    summary, found = time_sync(
        DATE + "Timezone=UTC\nLocalRTC=no\nNTP=yes\nNTPSynchronized=no\n"
        "Reference ID    : 00000000 ()\nLeap status     : Not synchronised\n"
    )
    assert summary["sync_source"] == "timedatectl show"
    assert summary["properties"]["NTPSynchronized"] == "no"
    assert found["NTPSynchronized"]["value"] == "no"
    # An older stored result (bare chronyc lines) still yields the chrony data.
    assert summary["chrony"]["leap_status"] == "Not synchronised"


def test_time_sync_script_has_its_fallbacks():
    script = operations.SCRIPTS["time_sync"]
    assert "timedatectl show" in script and "timedatectl status" in script
    assert "[AIOPS_TIMEDATECTL_STATUS]" in script
    assert "chronyc tracking" in script and "ntpstat" in script
    # Every external command is bounded when the host has timeout(1).
    assert script.count("timeout -k 1 5") == 3
    assert "CAPABILITY_MISSING:timedatectl" in script
    shell = shutil.which("dash") or shutil.which("sh")
    if shell:
        subprocess.run(
            [shell, "-n"],
            input=diagnostics.command_for("time_sync"),
            text=True,
            check=True,
        )


TIMEDATECTL_219 = (
    'case "$1" in\n'
    "show) echo 'Unknown operation show' >&2; exit 1;;\n"
    "status) cat <<'EOF'\n" + STATUS_219 + "EOF\n;;\n"
    "esac\n"
)
NO_BUS = (
    "echo 'Failed to create bus connection: No such file or directory' >&2; exit 1\n"
)


@needs_sh
@pytest.mark.parametrize(
    "tools,code,source,synced",
    [
        ({"timedatectl": TIMEDATECTL_219}, 0, "timedatectl status", "no"),
        (
            {
                "timedatectl": NO_BUS,
                "chronyc": "cat <<'EOF'\n" + CHRONY.format(leap="Normal") + "EOF\n",
            },
            0,
            "chronyc tracking",
            "yes",
        ),
        (
            {
                "timedatectl": NO_BUS,
                "chronyc": "echo '506 Cannot talk to daemon'; exit 1\n",
                "ntpstat": "printf 'unsynchronised\\n'; exit 1\n",
            },
            0,
            "ntpstat",
            "no",
        ),
        ({"timedatectl": NO_BUS}, 1, None, None),
        ({}, 69, None, None),
    ],
    ids=["el7", "no-bus-chrony", "no-bus-ntpstat", "no-bus", "nothing"],
)
def test_time_sync_script_runs_each_fallback(tmp_path, tools, code, source, synced):
    for name in ("date", "cat", "timeout"):
        (tmp_path / name).symlink_to(shutil.which(name))
    for name, body in tools.items():
        path = tmp_path / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)
    result = subprocess.run(
        ["/bin/sh", "-c", operations.SCRIPTS["time_sync"]],
        capture_output=True,
        text=True,
        env={"PATH": str(tmp_path), "LC_ALL": "C"},
        timeout=30,
    )
    assert result.returncode == code, result.stdout + result.stderr
    summary, _ = time_sync(result.stdout, "success" if code == 0 else "partial")
    assert summary["sync_source"] == source
    assert summary["properties"].get("NTPSynchronized") == synced
    if code == 1:  # timedatectl's own error stays visible
        assert "bus connection" in result.stderr


# --------------------------------------- SSH-DIAG-17: unhealthy containers --


def test_unhealthy_container_is_a_warning():
    text = (
        "a1\tweb\tnginx:1.25\tUp 2 hours (unhealthy)\n"
        "b2\tapi\tapp:3\tUp 5 minutes (healthy)\n"
        "c3\tjob\tapp:3\tUp 3 seconds (health: starting)\n"
    )
    findings = observations.analyze("containers", text)["findings"]
    states = [f for f in findings if f["metric"] == "container_state"]
    assert [f["value"] for f in states] == ["web: Up 2 hours (unhealthy)"]
    assert states[0]["level"] == "warning" and "健康检查" in states[0]["hint"]


# -------------------------------------------- SSH-DIAG-15: jvm side effects --

JVM_EFFECTS = (".attach_pid", ".java_pid", "Attach Listener", "SIGQUIT", "runuser")


def test_jvm_side_effects_are_written_down():
    tool = mcp_tools.mcp._tool_manager._tools["ssh_diagnose_jvm"].description
    notes = "".join(next(e for e in catalog.entries() if e["id"] == "jvm")["notes"])
    for effect in JVM_EFFECTS:
        assert effect in tool, effect
        assert effect in notes, effect
    assert "hsperfdata" in notes and "安全点" in notes


# ------------------------------- SSH-NGX-06: request_time via the log_format --

NGINX_DUMP = r"""# configuration file /etc/nginx/nginx.conf:
http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" $request_time $upstream_response_time';
    log_format upfirst '$remote_addr - $remote_user [$time_local] "$request" '
                       '$status $body_bytes_sent "$http_referer" "$http_user_agent" '
                       '$upstream_response_time $request_time';
    # nginx's own example: $gzip_ratio is a decimal, not a duration.
    log_format compression '$remote_addr - $remote_user [$time_local] '
                           '"$request" $status $bytes_sent '
                           '"$http_referer" "$http_user_agent" "$gzip_ratio"';
    log_format timed "$remote_addr [$time_local] \"$request\" $status $msec rt=${request_time}s";
    log_format json escape=json '{"time_local":"$time_local","request_time":$request_time}';
    access_log /var/log/nginx/main.log main;
    access_log /var/log/nginx/up.log upfirst buffer=32k flush=5s;
    access_log /var/log/nginx/gz.log compression;
    access_log /var/log/nginx/timed.log timed;
    access_log /var/log/nginx/json.log json;
    access_log /var/log/nginx/default.log;
    access_log logs/rel.log main;
    access_log /var/log/nginx/nofmt.log undefined_format;
    #access_log /var/log/nginx/commented.log main;
    access_log off;
    access_log syslog:server=192.0.2.5 main;
}
"""
LAYOUTS = [
    "/var/log/nginx/main.log K 7 7 0 -1 0 0 7 1 0 0 0",
    "/var/log/nginx/up.log K 7 7 -1 0 0 0 7 0 1 0 0",
    "/var/log/nginx/gz.log K 9 0 0 0 0 0 0 0 0 0 0",
    "/var/log/nginx/timed.log K 3 3 2 0 3 1 0 0 0 0 0",
    "/var/log/nginx/json.log U",
    "/var/log/nginx/default.log K 7 0 0 0 0 0 0 0 0 0 0",
    "/usr/share/nginx/logs/rel.log K 7 7 0 -1 0 0 7 1 0 0 0",
    "/var/log/nginx/nofmt.log U",
]


def test_access_log_layouts_come_from_the_log_format():
    commands = awk_commands()
    if not commands:
        pytest.skip("needs awk")
    for command in commands:
        result = run_awk(
            command, nginx.ALOG_AWK, NGINX_DUMP.encode(), "pfx=/usr/share/nginx"
        )
        assert result.returncode == 0, (command, result.stderr)
        assert result.stdout.decode().splitlines() == LAYOUTS, command
    # Embedded in single quotes in the script.
    assert "'" not in nginx.ALOG_AWK


def access_awk(lines, command):
    result = run_awk(
        command,
        nginx.ACCESS_AWK,
        ("\n".join(lines) + "\n").encode(),
        "skey=20261029233000",
        "ukey=20261030000000",
        "sel=all",
        "topn=10",
        "bucket=10",
        "tz=+0000",
    )
    assert result.returncode == 0, (command, result.stderr)
    return result.stdout.decode().splitlines()


def marker(path):
    layout = next(line for line in LAYOUTS if line.startswith(path + " "))
    return ["\x01AIOPS_F " + path, "\x01AIOPS_L " + layout.split(" ", 1)[1]]


CLF = "[29/Oct/2026:23:4{}:00 +0000]"


def test_request_time_is_read_at_its_log_format_position():
    lines = (
        marker("/var/log/nginx/up.log")
        # Upstream first, two upstream attempts: the guess took 0.020.
        + [
            f'10.0.0.1 - - {CLF.format(0)} "GET /a HTTP/1.1" 200 5 "-" "ua" 0.010, 0.020 0.050'
        ]
        + marker("/var/log/nginx/gz.log")
        # No $request_time in the format: "3.50" is $gzip_ratio.
        + [f'10.0.0.2 - - {CLF.format(1)} "GET /b HTTP/1.1" 200 5 "-" "ua" "3.50"']
        + marker("/var/log/nginx/timed.log")
        # $msec first, then rt=${request_time}s.
        + [f'10.0.0.3 {CLF.format(2)} "GET /c HTTP/1.1" 200 1793318400.123 rt=0.250s']
    )
    for command in awk_commands() or pytest.skip("needs awk"):
        out = access_awk(lines, command)
        assert "TOTAL 3" in out, (command, out)
        assert "REQ 2 0.150 0.250 0 0 0" in out, (command, out)
        assert "UPS 1 0.020 0.020 0 0" in out, (command, out)
        assert "REQ_SOURCE 2 0 0 1" in out, (command, out)


def test_request_time_is_guessed_and_counted_without_a_layout():
    gz = f'10.0.0.2 - - {CLF.format(1)} "GET /b HTTP/1.1" 200 5 "-" "ua" "3.50"'
    for command in awk_commands() or pytest.skip("needs awk"):
        # No marker (older script) or an unknown format: the positional guess.
        for prefix in ([], ["\x01AIOPS_F /x.log", "\x01AIOPS_L U"]):
            out = access_awk(prefix + [gz], command)
            assert "REQ 1 3.500 3.500 1 1 0" in out, (command, out)
            assert "REQ_SOURCE 0 0 1 0" in out, (command, out)
        # A line that does not have its format's shape is guessed too.
        odd = f'10.0.0.4 - - {CLF.format(3)} "GET /d HTTP/1.1" 200 5 "-" "ua" "x" 0.040'
        out = access_awk(marker("/var/log/nginx/main.log") + [odd], command)
        assert "REQ_SOURCE 0 0 1 0" in out, (command, out)


def test_access_summary_names_the_request_time_source():
    def report(sources):
        return observations.analyze(
            "nginx_access",
            "[AIOPS_FILES]\nWINDOW 1793316600 1793318400 20261029233000 20261030000000\n"
            "FILE /var/log/nginx/access.log 10 10\n"
            "[AIOPS_TOTALS]\nLINES 40 0 0\nTOTAL 40\nCLASS 2xx 40\nSELECTED 40\n"
            "[AIOPS_TIMING]\nREQ 40 4.000 9.000 30 30 0\n"
            f"REQ_SOURCE {sources}\nUNAVAILABLE upstream_time\nNOUPSTREAM 0\n",
            options={},
        )

    exact = report("40 0 0 0")
    timing = exact["summary"]["timing"]
    assert timing["request_time_source"] == {
        "log_format": 40,
        "field_name": 0,
        "heuristic": 0,
        "not_in_log_format": 0,
    }
    assert "推测" not in exact["summary"]["coverage"]
    guessed = report("0 0 40 0")
    assert guessed["summary"]["timing"]["request_time_source"]["heuristic"] == 40
    assert "40 条请求的 request_time 是按位置推测的" in guessed["summary"]["coverage"]
    assert "log_format" in by_metric(guessed)["slow_requests_over_3s"]["hint"]
    # Results of older servers have no REQ_SOURCE line.
    old = observations.analyze(
        "nginx_access", "[AIOPS_TIMING]\nREQ 1 0.1 0.1 0 0 0\n", options={}
    )
    assert old["summary"]["timing"]["request_time_source"] is None


@needs_sh
def test_access_script_reads_the_layout_of_a_given_path(tmp_path, monkeypatch):
    import test_ext_nginx as fixture

    sh = fixture.install_fixture(tmp_path.resolve())
    fixture.use_fixture(monkeypatch, sh)
    options = fixture.options_for(
        "nginx_access",
        since=fixture.SINCE,
        until=fixture.NOW,
        path=sh["logs"] + "/access.log",
    )
    code, out, err = fixture.run_script(nginx.access_script(options), sh)
    assert code == 0, err
    sources = re.search(r"(?m)^REQ_SOURCE (\d+) (\d+) (\d+) (\d+)$", out)
    # nginx -T names the file's format (main) even for an explicit path: its
    # combined lines are read at their position, JSON lines by key, and the
    # one line with an extra quoted field is guessed.
    assert sources and int(sources[1]) > 0 and int(sources[3]) == 1, out


# --------------------------------- SSH-CORE-02: authentication is a read ----


def new_client(client, name="p2-client", actions=("cpu",)):
    created = client.post(
        "/api/v1/mcp/clients",
        headers=csrf(),
        json={"name": name, "all_hosts": True, "actions": list(actions)},
    ).json()
    return created["id"], created["token"]


def last_used(ident):
    with store.db() as c:
        return c.execute(
            "SELECT last_used_at FROM mcp_clients WHERE id=?", (ident,)
        ).fetchone()[0]


def test_mcp_authentication_runs_off_the_event_loop(client, monkeypatch):
    _, token = new_client(client)
    seen = []
    original = access.authenticate

    def observed(authorization):
        try:
            asyncio.get_running_loop()
            seen.append("event loop")
        except RuntimeError:
            seen.append("worker thread")
        return original(authorization)

    monkeypatch.setattr(access, "authenticate", observed)
    status, result = mcp_call(client, token, "ssh_list_groups")
    assert status == 200 and seen == ["worker thread"], (seen, result)


def test_last_used_is_written_at_most_once_a_minute(client, monkeypatch):
    ident, token = new_client(client)
    access._last_used.pop(ident, None)
    access.authenticate("Bearer " + token)
    assert last_used(ident) is not None
    with store.db() as c:
        c.execute(
            "UPDATE mcp_clients SET last_used_at='2000-01-01' WHERE id=?", (ident,)
        )
    access.authenticate("Bearer " + token)
    assert last_used(ident) == "2000-01-01"  # not a write per request
    monkeypatch.setattr(access, "LAST_USED_INTERVAL", 0)
    access.authenticate("Bearer " + token)
    assert last_used(ident) != "2000-01-01"


def test_a_locked_database_does_not_fail_authentication(client):
    ident, token = new_client(client)
    access._last_used.pop(ident, None)
    holder = sqlite3.connect(str(store.DATA_DIR / "ssh-mcp.sqlite3"), timeout=1)
    try:
        holder.execute("BEGIN IMMEDIATE")  # e.g. VACUUM or a 100-host batch
        started = time.monotonic()
        who = access.authenticate("Bearer " + token)
        took = time.monotonic() - started
    finally:
        holder.rollback()
        holder.close()
    assert who["id"] == ident and took < 5, took
    assert last_used(ident) is None  # skipped, written at the next interval


# ------------------------------ SSH-CORE-03: SSH tools have their own pool --


def test_ssh_tools_run_in_their_own_pool(client, key_pair, monkeypatch):
    hid = ready_host(client, key_pair)
    threads = {}

    def inline(*args, **kwargs):
        threads["ssh"] = threading.current_thread().name
        return {"status": "success", "summary": {}, "findings": []}

    def catalog_entries():
        threads["catalog"] = threading.current_thread().name
        return []

    monkeypatch.setattr(jobs, "run_inline", inline)
    monkeypatch.setattr(mcp_tools, "entries", catalog_entries)
    token = store.token("mcp.token")
    assert mcp_call(client, token, "ssh_diagnose_cpu", {"host_id": hid})[0] == 200
    assert mcp_call(client, token, "ssh_list_tool_catalog")[0] == 200
    assert threads["ssh"].startswith("ssh-inline"), threads
    assert not threads["catalog"].startswith("ssh-inline"), threads


def test_time_queued_for_a_thread_counts_toward_the_slot_wait(monkeypatch):
    monkeypatch.setattr(
        diagnostics, "_execute_inner", lambda *a, **k: pytest.fail("not its turn")
    )
    # Accepted 30 s ago, all of it queued for a thread of the pool.
    token = diagnostics.CALL_ACCEPTED_AT.set(
        time.monotonic() - diagnostics.INLINE_WAIT_SECONDS
    )
    with diagnostics._SLOTS:
        diagnostics._ACTIVE_HOSTS.add(9)  # the host is busy
    try:
        started = time.monotonic()
        with pytest.raises(diagnostics.SSHDiagnosticError, match="繁忙"):
            diagnostics.execute(9, "cpu")
        assert time.monotonic() - started < 3  # not another 30 s
    finally:
        diagnostics.CALL_ACCEPTED_AT.reset(token)
        with diagnostics._SLOTS:
            diagnostics._ACTIVE_HOSTS.discard(9)
            diagnostics._SLOTS.notify_all()


def test_light_tools_answer_while_ssh_calls_fill_every_thread(
    client, key_pair, monkeypatch
):
    hid = ready_host(client, key_pair)
    token = store.token("mcp.token")
    release, entered = threading.Event(), []

    def slow(*args, **kwargs):
        entered.append(1)
        release.wait(60)
        return {"status": "success", "summary": {}, "findings": []}

    monkeypatch.setattr(jobs, "run_inline", slow)
    # More waiting SSH calls than asyncio's default pool has threads.
    calls = min(32, (os.cpu_count() or 1) + 4) + 2
    with ThreadPoolExecutor(max_workers=calls + 2) as pool:
        try:
            blocked = [
                pool.submit(
                    mcp_call, client, token, "ssh_diagnose_cpu", {"host_id": hid}
                )
                for _ in range(calls)
            ]
            for _ in range(200):
                if len(entered) >= mcp_tools.INLINE_WORKERS:
                    break
                time.sleep(0.05)
            catalog_call = pool.submit(mcp_call, client, token, "ssh_list_tool_catalog")
            status, result = catalog_call.result(timeout=10)
            assert status == 200 and result["result"], result
        finally:
            release.set()
        assert all(task.result(timeout=60)[0] == 200 for task in blocked)


# ------------------------- SSH-CORE-04: a client that leaves frees its slot --


def mcp_scope(token, body):
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "root_path": "",
        "query_string": b"",
        "headers": [
            (b"host", b"testserver"),
            (b"authorization", ("Bearer " + token).encode()),
            (b"content-type", b"application/json"),
            (b"accept", b"application/json, text/event-stream"),
            (b"content-length", str(len(body)).encode()),
        ],
        "client": ("127.0.0.1", 50000),
        "server": ("testserver", 80),
    }


def test_client_leaving_while_waiting_for_the_slot_gives_up(
    client, key_pair, monkeypatch
):
    hid = ready_host(client, key_pair)
    token = store.token("mcp.token")
    monkeypatch.setattr(
        diagnostics,
        "_execute_inner",
        lambda *a, **k: pytest.fail("a call whose client left reached SSH"),
    )
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "ssh_diagnose_cpu", "arguments": {"host_id": hid}},
        }
    ).encode()
    pending = [{"type": "http.request", "body": body, "more_body": False}]
    sent = []

    async def receive():
        if pending:
            return pending.pop()
        await anyio.sleep(0.5)  # the client gives up while the call waits
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    async def call():
        await app(mcp_scope(token, body), receive, send)

    with diagnostics._SLOTS:
        diagnostics._ACTIVE_HOSTS.add(hid)  # another diagnostic holds the host
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            started = time.monotonic()
            pool.submit(client.portal.call, call).result(timeout=10)
            took = time.monotonic() - started
    finally:
        with diagnostics._SLOTS:
            diagnostics._ACTIVE_HOSTS.discard(hid)
            diagnostics._SLOTS.notify_all()
    # Well within the 30 s slot wait: it gave up instead of holding on.
    assert took < 8, took
    with store.db() as c:
        job = c.execute(
            "SELECT status,error FROM diagnostic_jobs WHERE host_id=?", (hid,)
        ).fetchone()
    assert tuple(job) == ("cancelled", diagnostics.CALLER_GONE_ERROR)


def test_running_ssh_read_stops_when_the_client_leaves(monkeypatch):
    captured = {}

    def inner(host_id, action, *args, cancelled, **kwargs):
        captured["before"] = cancelled()
        gone.set()  # the client disconnects while the output is read
        captured["after"] = cancelled()
        return {"status": "success"}

    monkeypatch.setattr(diagnostics, "_execute_inner", inner)
    gone = threading.Event()
    token = diagnostics.CALLER_GONE.set(gone)
    try:
        diagnostics.execute(7, "cpu", cancelled=lambda: False)
    finally:
        diagnostics.CALLER_GONE.reset(token)
    assert captured == {"before": False, "after": True}
    # Background jobs carry no event: only their own cancel flag counts.
    diagnostics.execute(7, "cpu", cancelled=lambda: False)
    assert captured == {"before": False, "after": False}


def test_a_queued_call_whose_client_left_does_not_start():
    gone = threading.Event()
    gone.set()
    token = diagnostics.CALLER_GONE.set(gone)
    try:
        result = asyncio.run(
            mcp_tools.run_inline_tool(
                lambda: pytest.fail("started after the client left")
            )
        )
    finally:
        diagnostics.CALLER_GONE.reset(token)
    assert result["status"] == "cancelled" and result["error_code"] == "cancelled"


# ------------------------------- SSH-CORE-10: Origin behind a trusted proxy --


def origin_request(peer, **headers):
    raw = [(k.replace("_", "-").encode(), v.encode()) for k, v in headers.items()]
    return Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "http",
            "path": "/api/v1/groups",
            "query_string": b"",
            "headers": raw,
            "client": (peer, 40000),
            "server": ("10.0.0.5", 9099),
        }
    )


PROXIED = {
    "host": "10.0.0.5:9099",
    "origin": "https://ssh.example.com",
    "x_forwarded_proto": "https",
    "x_forwarded_host": "ssh.example.com",
}


def test_origin_check_follows_a_trusted_proxy_only(monkeypatch):
    monkeypatch.delenv(auth.TRUSTED_PROXIES_ENV, raising=False)
    # Default: a direct deployment is checked as before.
    assert not auth.trusted_origin(origin_request("172.18.0.1", **PROXIED))
    direct = {"host": "10.0.0.5:9099", "origin": "http://10.0.0.5:9099"}
    assert auth.trusted_origin(origin_request("192.0.2.9", **direct))
    monkeypatch.setenv(auth.TRUSTED_PROXIES_ENV, "172.16.0.0/12, 192.0.2.1")
    assert auth.trusted_origin(origin_request("172.18.0.1", **PROXIED))
    assert auth.trusted_origin(origin_request("192.0.2.1", **PROXIED))
    # The request's own origin still counts behind the proxy.
    assert auth.trusted_origin(origin_request("172.18.0.1", **direct))
    # A peer outside the list cannot forge the forwarded headers.
    assert not auth.trusted_origin(origin_request("192.0.2.9", **PROXIED))
    # The forwarded origin must still be the one the browser sent.
    assert not auth.trusted_origin(
        origin_request("172.18.0.1", **{**PROXIED, "origin": "https://evil.example"})
    )
    # Without X-Forwarded-Host the proxy's Host header is used.
    host_kept = {**PROXIED, "host": "ssh.example.com"}
    host_kept.pop("x_forwarded_host")
    assert auth.trusted_origin(origin_request("172.18.0.1", **host_kept))
    monkeypatch.setenv(auth.TRUSTED_PROXIES_ENV, "not-an-address")
    assert not auth.trusted_origin(origin_request("172.18.0.1", **PROXIED))


def test_console_writes_work_through_a_trusted_https_proxy(client, monkeypatch):
    proxy = TestClient(app, client=("172.18.0.1", 40000))
    proxy.cookies.update(client.cookies)
    headers = {
        **csrf(),
        "Origin": "https://ssh.example.com",
        "X-Forwarded-Proto": "https",
        "X-Forwarded-Host": "ssh.example.com",
    }
    monkeypatch.delenv(auth.TRUSTED_PROXIES_ENV, raising=False)
    refused = proxy.post("/api/v1/groups", headers=headers, json={"name": "via-proxy"})
    assert refused.status_code == 403 and "来源" in refused.json()["detail"]
    monkeypatch.setenv(auth.TRUSTED_PROXIES_ENV, "172.16.0.0/12")
    created = proxy.post("/api/v1/groups", headers=headers, json={"name": "via-proxy"})
    assert created.status_code == 201, created.text
