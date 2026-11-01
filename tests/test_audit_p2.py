"""Regressions for the remaining P2 findings of the 2026-11 audit (v0.10.0).

Unknown counts are null, not 0 (SSH-DIAG-12); time_sync works without
`timedatectl show` (SSH-DIAG-16); unhealthy containers are reported
(SSH-DIAG-17); the jvm probe's side effects are written down (SSH-DIAG-15);
nginx_access finds request_time through the log_format (SSH-NGX-06).

Parser and awk tests run everywhere awk is installed; the script runs need
/bin/sh (dash on CI). The EL7 run of time_sync is in test_audit_followup.py
(-k el7).
"""

import os
import re
import shutil
import subprocess
import tempfile

import pytest

from sshmcp import catalog, diagnostics, mcp_tools, observations, operations
from sshmcp.extensions import nginx

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
