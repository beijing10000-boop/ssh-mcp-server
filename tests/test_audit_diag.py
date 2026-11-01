"""Regressions for the 2026-11 audit of the diagnostics core.

SSH-DIAG-01..09, SSH-CORE-01 and the redact_output part of SSH-NGX-01: GC log
reads never follow symlinks, single-state ss output, comm names with spaces,
collect status / time bounds, redaction gaps, service_detail unknowns, restart
loop and OOM rules, and a long stderr that must not cut stdout short.
"""

import json
import os
import re
import shutil
import subprocess
import time
import types

import pytest

from sshmcp import diagnostics, extensions, insights, observations, store, triage
from sshmcp.extensions import collect, services
from sshmcp.extensions import java as java_ext

HAS_SH = os.path.exists("/bin/sh")
HAS_AWK = shutil.which("awk") is not None
needs_sh = pytest.mark.skipif(not HAS_SH, reason="needs /bin/sh")
needs_awk = pytest.mark.skipif(not HAS_AWK, reason="needs awk")
needs_linux = pytest.mark.skipif(
    not (HAS_SH and os.path.exists("/proc/self/stat")),
    reason="needs /bin/sh and Linux /proc",
)
SINCE, UNTIL = 1793253600, 1793255400  # 2026-10-29 14:00–14:30 +08:00


@pytest.fixture(autouse=True)
def reset_tables():
    """Pure script, parser and executor tests: the console database is not needed."""
    yield


def awk(program, text, *args):
    """Run an awk program on text (bytes in and out: no newline translation)."""
    result = subprocess.run(
        ["awk", *args, program], input=text.encode(), capture_output=True
    )
    return result.returncode, result.stdout.decode()


def by_metric(report):
    return {f["metric"]: f for f in report["findings"]}


# --------------------------------------------------------------- executor --


class Chan:
    """A paramiko channel stand-in whose data is all ready at once."""

    def __init__(self, out=b"", err=b"", code=0, slow=False):
        self.out, self.err, self.code, self.slow = out, err, code, slow

    def settimeout(self, value):
        pass

    def exec_command(self, command):
        self.command = command

    def recv_ready(self):
        return bool(self.out)

    def recv(self, size):
        data, self.out = self.out[:size], self.out[size:]
        return data

    def recv_stderr_ready(self):
        return bool(self.err)

    def recv_stderr(self, size):
        data, self.err = self.err[:size], self.err[size:]
        return data

    def exit_status_ready(self):
        return not self.slow

    def recv_exit_status(self):
        return self.code

    def close(self):
        pass


def fake_ssh(monkeypatch, chan):
    """Route _execute_inner to `chan`; returns the handshake timeouts used."""
    host = {
        "id": 1,
        "name": "h",
        "address": "10.0.0.1",
        "port": 22,
        "username": "root",
        "host_key": "k",
        "credential_id": 1,
        "proxy_id": None,
        "revision": 1,
        "mode": "standard",
    }
    seen = {}

    class Transport:
        def open_session(self, timeout):
            seen["session"] = timeout
            return chan

    class Client:
        def get_transport(self):
            return Transport()

        def close(self):
            pass

    def connect(target, key, **kwargs):
        seen["connect"] = kwargs.get("timeout")
        return Client()

    monkeypatch.setattr(store, "get_host", lambda hid: host)
    monkeypatch.setattr(diagnostics, "private_key", lambda cid: object())
    monkeypatch.setattr(diagnostics, "_route", lambda host: (None, None))
    monkeypatch.setattr(diagnostics, "client_connect", connect)
    return seen


def test_long_stderr_is_drained_without_cutting_stdout_short(monkeypatch):
    # SSH-CORE-01: a non-root du/df writes one error line per unreadable path;
    # stdout must still be read to its end and not be reported as output_limit.
    out = "".join(f"{4096 * i}\t/data/dir{i}\n" for i in range(400)).encode()
    err = b"du: cannot read directory '/data/private': Permission denied\n" * 300
    fake_ssh(monkeypatch, Chan(out, err))
    result = diagnostics._execute_inner(1, "disk")
    assert result["truncated"] is False and result["exit_code"] == 0
    assert result["output"] == out.decode()
    assert result["incomplete_reason"] == "stderr"  # permission denied, not size
    assert result["stderr_truncated"] is True
    assert 0 < len(result["stderr"].encode()) <= diagnostics.STDERR_LIMIT
    # A short stderr carries no new field.
    fake_ssh(monkeypatch, Chan(b"x\n", b"df: /run/user/1000/gvfs: Permission denied\n"))
    assert "stderr_truncated" not in diagnostics._execute_inner(1, "disk")


COLLECT_OUTPUT = (
    "\n__SSHMCP_BEGIN_cpu__\nCPU_COUNT=2\n0.10 0.20 0.30 1/100 99\n\n__SSHMCP_END_cpu__:0\n"
    "\n__SSHMCP_BEGIN_time_sync__\nTimezone=Asia/Shanghai\n\n__SSHMCP_END_time_sync__:{code}\n"
)


def test_collect_with_a_failed_step_is_partial(monkeypatch):
    # SSH-DIAG-04: the script ends with printf, so its own exit code is 0.
    options = {"actions": ["cpu", "time_sync"]}
    fake_ssh(monkeypatch, Chan(COLLECT_OUTPUT.format(code=1).encode()))
    result = diagnostics._execute_inner(1, "collect", options=options)
    assert result["exit_code"] == 0 and result["status"] == "partial"
    # Kept compatible with the AI platform's host_limits (None / exit_code).
    assert result["incomplete_reason"] is None
    steps = {step["action"]: step["status"] for step in result["summary"]["steps"]}
    assert steps == {"cpu": "success", "time_sync": "partial"}
    assert result["summary"]["completed"] == 1
    fake_ssh(monkeypatch, Chan(COLLECT_OUTPUT.format(code=0).encode()))
    assert diagnostics._execute_inner(1, "collect", options=options)["status"] == (
        "success"
    )


def test_collect_timeout_seconds_is_optional_and_bounded():
    # SSH-DIAG-05: a new optional parameter; without it nothing changes.
    spec = extensions.spec_for("collect")
    assert "timeout_seconds" in {param.name for param in spec.params}
    plain = extensions.validate_options(spec, {"actions": ["cpu"]})
    assert plain["timeout_seconds"] is None
    good = {"actions": ["cpu"], "timeout_seconds": 60}
    assert extensions.validate_options(spec, good)["timeout_seconds"] == 60
    for bad in (9, 121, "60", True, 1.5):
        with pytest.raises(ValueError):
            extensions.validate_options(
                spec, {"actions": ["cpu"], "timeout_seconds": bad}
            )
    six = ["cpu", "memory", "disk", "io", "network", "system"]
    assert collect.step_seconds({"actions": six, "timeout_seconds": 60}) == 9
    assert collect.step_seconds({"actions": ["cpu"], "timeout_seconds": 120}) == 20
    assert collect.step_seconds({"actions": six, "timeout_seconds": 10}) == 5
    assert collect.step_seconds({"actions": six}) is None


def test_collect_steps_get_their_own_timeout_only_when_bounded():
    plain = diagnostics.command_for("collect", options={"actions": ["cpu", "memory"]})
    assert "aiops_step" not in plain and "( " + diagnostics.PREFIX in plain
    bounded = diagnostics.command_for(
        "collect", options={"actions": ["cpu", "memory"], "timeout_seconds": 60}
    )
    assert bounded.count("aiops_step 20 ") == 2
    assert 'timeout -k 1 "$1" sh -c "$2"' in bounded
    assert bounded.count("__SSHMCP_BEGIN_") == 2


def test_collect_marks_a_step_ended_by_its_timeout():
    text = (
        "\n__SSHMCP_BEGIN_cpu__\nCPU_COUNT=2\n0.10 0.20 0.30 1/100 99\n\n__SSHMCP_END_cpu__:0\n"
        "\n__SSHMCP_BEGIN_disk__\n\n__SSHMCP_END_disk__:124\n"
        "\n__SSHMCP_BEGIN_memory__\nMemTotal: 1000 kB\nMemAvailable: 900 kB\n"
        "\n__SSHMCP_END_memory__:0\n"
    )
    options = {"actions": ["cpu", "disk", "memory"], "timeout_seconds": 60}
    report = observations.analyze("collect", text, options=options)
    steps = {step["action"]: step for step in report["summary"]["steps"]}
    assert steps["disk"]["status"] == "partial" and steps["disk"]["timed_out"] is True
    assert "被终止" in steps["disk"]["error"]
    assert steps["cpu"]["status"] == steps["memory"]["status"] == "success"
    assert report["summary"]["completed"] == 2
    # Without a bound, exit 124 is an ordinary failed step.
    unbounded = observations.analyze(
        "collect", text, options={"actions": options["actions"]}
    )
    assert "timed_out" not in unbounded["summary"]["steps"][1]


def stepping_clock(step=1.0):
    now = [1000.0]

    def monotonic():
        now[0] += step
        return now[0]

    return monotonic


def test_timeout_seconds_bounds_the_slot_wait_and_the_run(monkeypatch):
    seen = {}

    def inner(host_id, action, *args, **kwargs):
        seen.update(kwargs)
        return {"status": "success"}

    monkeypatch.setattr(diagnostics, "_execute_inner", inner)
    before = time.monotonic()
    diagnostics.execute(
        7, "collect", options={"actions": ["cpu"], "timeout_seconds": 10}
    )
    assert before + 10 <= seen["finish_by"] <= time.monotonic() + 10
    diagnostics.execute(7, "collect", options={"actions": ["cpu"]})
    assert seen["finish_by"] is None
    # A busy host: the wait gives up at half of the bound (5 s), not after 30 s.
    # Only the executor's clock steps (1 s per reading); the module stays real.
    clock = types.SimpleNamespace(monotonic=stepping_clock(), sleep=time.sleep)
    monkeypatch.setattr(diagnostics, "time", clock)
    with diagnostics._SLOTS:
        diagnostics._ACTIVE_HOSTS.add(7)
    try:
        began = time.perf_counter()
        with pytest.raises(diagnostics.SSHDiagnosticError, match="繁忙"):
            diagnostics.execute(
                7, "collect", options={"actions": ["cpu"], "timeout_seconds": 10}
            )
        assert time.perf_counter() - began < 3
    finally:
        with diagnostics._SLOTS:
            diagnostics._ACTIVE_HOSTS.discard(7)
            diagnostics._SLOTS.notify_all()


def test_bounded_run_returns_what_it_has_at_the_callers_deadline(monkeypatch):
    out = (
        "\n__SSHMCP_BEGIN_cpu__\nCPU_COUNT=2\n0.10 0.20 0.30 1/100 99\n\n__SSHMCP_END_cpu__:0\n"
        "\n__SSHMCP_BEGIN_disk__\nFilesystem 1024-blocks Used\n"
    )
    seen = fake_ssh(monkeypatch, Chan(out.encode(), slow=True))
    options = {"actions": ["cpu", "disk"], "timeout_seconds": 10}
    began = time.perf_counter()
    result = diagnostics._execute_inner(
        1, "collect", options=options, finish_by=time.monotonic() + 3
    )
    assert time.perf_counter() - began < 6
    assert result["timed_out"] and result["status"] == "partial"
    steps = {step["action"]: step["status"] for step in result["summary"]["steps"]}
    assert steps == {"cpu": "success", "disk": "partial"}
    # The handshake stages share the remaining time (at most 6 s each).
    assert seen["connect"] == seen["session"] and 1 <= seen["connect"] < 6
    # Nothing produced before the deadline: a timeout naming the caller's bound.
    fake_ssh(monkeypatch, Chan(b"", slow=True))
    with pytest.raises(diagnostics.SSHDiagnosticError, match="timeout_seconds"):
        diagnostics._execute_inner(
            1, "collect", options=options, finish_by=time.monotonic() + 2
        )


@needs_sh
def test_a_stuck_step_is_ended_and_the_next_step_still_runs():
    if shutil.which("timeout") is None:
        pytest.skip("needs timeout")
    steps = {"stuck": "sleep 30", "after": "printf 'still here\\n'"}
    script = triage.command_many(
        list(steps), None, 30, lambda action, *_: steps[action], step_seconds=1
    )
    began = time.monotonic()
    result = subprocess.run(
        ["/bin/sh", "-c", script], capture_output=True, text=True, timeout=30
    )
    assert time.monotonic() - began < 10
    assert re.search(r"__SSHMCP_END_stuck__:(124|137)", result.stdout), result.stdout
    assert "still here" in result.stdout and "__SSHMCP_END_after__:0" in result.stdout
    parsed = triage.parse_many(result.stdout, list(steps), step_seconds=1)
    assert parsed["steps"][0]["timed_out"] and parsed["steps"][1]["status"] == "success"


@needs_sh
def test_bounded_collect_script_parses_under_sh():
    script = diagnostics.command_for(
        "collect",
        options={
            "actions": ["processes", "logs", "failed_services"],
            "service": "nginx.service",
            "timeout_seconds": 90,
        },
    )
    subprocess.run(["/bin/sh", "-n"], input=script, text=True, check=True)


# ------------------------------------------------------- ss / ps parsing --


def peer_awk():
    source = diagnostics.PEER_TRAFFIC_CMD
    return source.split("state established | awk '", 1)[1].split("'\n}", 1)[0]


@needs_awk
def test_peer_traffic_reads_single_state_ss_lines_without_a_state_column():
    # SSH-DIAG-02: `ss -t -n -i state established` selects one state, so ss
    # prints no State column; lines start with Recv-Q and Send-Q.
    sample = (
        "0      0      10.0.0.10:443       198.51.100.3:55000\n"
        "\t cubic wscale:7,7 rto:204 rtt:0.5/0.25 bytes_sent:1500 bytes_acked:1501 "
        "bytes_received:900 segs_out:10\n"
        "0      36     10.0.0.10:22        198.51.100.4:61000\n"
        "\t cubic bytes_sent:300 bytes_received:200\n"
    )
    code, out = awk(peer_awk(), sample)
    assert code == 0
    assert out.splitlines() == [
        "10.0.0.10:443\t198.51.100.3:55000\t1500\t900",
        "10.0.0.10:22\t198.51.100.4:61000\t300\t200",
    ]
    later = out.replace("\t1500\t900", "\t2500\t1900")
    data = insights.parse_tcp_samples("__SAMPLE_A__\n" + out + "__SAMPLE_B__\n" + later)
    assert data["matched_sockets"] == 2
    assert data["ranking"][0]["peer_ip"] == "198.51.100.3"
    assert data["ranking"][0]["total_bytes"] == 2000
    # An ss that still prints the state keeps working.
    code, out = awk(
        peer_awk(),
        "ESTAB 0 0 10.0.0.10:443 198.51.100.3:55000\n\t cubic bytes_sent:1 bytes_received:2\n",
    )
    assert out == "10.0.0.10:443\t198.51.100.3:55000\t1\t2\n"


def test_process_names_with_spaces_keep_the_numeric_columns():
    # SSH-DIAG-03: comm sits between ppid and %CPU (A mode and the gateway).
    text = (
        "    PID    PPID COMMAND         %CPU %MEM   RSS     ELAPSED S\n"
        "   4242       1 PM2 v5.3.0: God  3.5  1.2 52340  2-03:04:05 S\n"
        "   5151    4242 node            12.0  8.4 345678   01:02:03 R\n"
    )
    rows = observations.analyze("memory_processes", text)["summary"]["processes"]
    assert rows[0] == {
        "pid": 4242,
        "ppid": 1,
        "name": "PM2 v5.3.0: God",
        "cpu_percent": 3.5,
        "memory_percent": 1.2,
        "rss_KiB": 52340,
        "elapsed": "2-03:04:05",
        "state": "S",
    }
    assert rows[1]["name"] == "node" and rows[1]["rss_KiB"] == 345678
    health = observations.analyze(
        "health",
        "[高 CPU 进程]\n  PID COMMAND %CPU %MEM\n 4242 PM2 v5.3.0: God 85.0 20.0\n",
    )
    assert health["summary"]["top_processes"] == [
        {
            "pid": 4242,
            "name": "PM2 v5.3.0: God",
            "cpu_percent": 85.0,
            "memory_percent": 20.0,
        }
    ]


# -------------------------------------------------------------- redaction --

LEAKS = {
    # SSH-DIAG-06: *_PASS names, redis options, client passwords.
    "Environment=DB_PASS=Hunter01 LANG=C": "Hunter01",
    'Environment="RABBITMQ_DEFAULT_PASS=Hunter02"': "Hunter02",
    "java -Dredis.pass=Hunter03 -jar app.jar": "Hunter03",
    "ExecStart=/usr/bin/redis-server /etc/redis.conf --requirepass Hunter04": "Hunter04",
    "redis-server --masterauth Hunter05 --port 6380": "Hunter05",
    "CROND[1]: (root) CMD (/usr/bin/mysqldump -h db -P3306 -uroot -pHunter06 x)": "Hunter06",
    "redis-cli -h 10.0.0.5 -a 'Hunter 07' ping": "Hunter 07",
    # java argv: the value of a bare secret option sits on the next ARG line,
    # and -D keys naming a key are masked as in the summary.
    "ARG --password\nARG Hunter08\nARG --port": "Hunter08",
    "ARG -Dapp.signing.key=Hunter09": "Hunter09",
    "ARG --db-token\nARG Hunter10": "Hunter10",
    # SSH-NGX-01: log samples.
    "GET /login?user=a&pwd=Hunter11&next=/ HTTP/1.1": "Hunter11",
    "userpwd=Hunter12 loginPwd=Hunter13": "Hunter12",
    '{"loginPwd":"Hunter14","user":"bob"}': "Hunter14",
    "GET /x?user=a&pass=Hunter15 HTTP/1.1": "Hunter15",
    "Cookie: JSESSIONID=Hunter16; PHPSESSID=Hunter17; theme=dark": "Hunter16",
    "sessionid=Hunter18 sid=Hunter19 connect.sid=Hunter20": "Hunter18",
    "Authorization: Basic SHVudGVyMjE6eA==": "SHVudGVyMjE6eA==",
    'authorization="Basic SHVudGVyMjI6eA=="': "SHVudGVyMjI6eA==",
}


def test_redaction_covers_pass_names_client_passwords_and_log_secrets():
    for source, secret in LEAKS.items():
        result = diagnostics.redact_output(source)
        assert secret not in result and "REDACTED" in result, (source, result)
    cookies = diagnostics.redact_output(
        "Cookie: JSESSIONID=a1; PHPSESSID=b2; theme=dark"
    )
    assert "b2" not in cookies and "theme=dark" in cookies
    many = diagnostics.redact_output(
        "sessionid=s1 sid=s2 connect.sid=s3 ORACLE_SID=ORCL"
    )
    assert many == (
        "sessionid=[REDACTED] sid=[REDACTED] connect.sid=[REDACTED] ORACLE_SID=ORCL"
    )
    argv = diagnostics.redact_output("ARG --password\nARG Hunter\nARG --port\nARG 8080")
    assert argv == "ARG --password\nARG [REDACTED]\nARG --port\nARG 8080"


def test_redaction_masks_phone_and_id_numbers_but_not_machine_counters():
    masked = {
        "GET /sms/send?mobile=13800138000&x=1": "138****8000",
        "GET /api/user/13800138000/profile": "138****8000",
        "用户手机号13800138000登录失败": "138****8000",
        '{"phone":"13912345678"}': "139****5678",
        "tel: +86 13800138000": "138****8000",
        "contact_phone: 15012345678": "150****5678",
        "idcard=110101199003071234 name=x": "110101********1234",
        "身份证号11010119900307123X": "110101********123X",
    }
    for source, expected in masked.items():
        result = diagnostics.redact_output(source)
        assert expected in result and "13800138000" not in result, (source, result)
    kept = (
        "MemoryCurrent=13958643712\nCPUUsageNSec=13958643712\n"
        "ExecMainStartTimestampMonotonic=15958643712\n"
        "  eth0: 13958643712 1234 0 0 0 0 0 0 15958643712 4567 0 0 0 0 0 0\n"
        "13958643712\t/data/x\n"
        "some avg10=0.00 avg60=0.00 avg300=0.00 total=13958643712\n"
        "CGMEM 13958643712\n"
        "bytes_sent:13958643712 bytes_received:15958643712\n"
        "PWD=/opt/app OLDPWD=/root\n"
        "sudo: bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/ls\n"
        "bypass=1 passive=yes --bypass-cache true\n"
        "pam_unix(sshd:session): session opened for user root by (uid=0)\n"
        "ssl_session_cache shared:SSL:10m;\n"
        "pigz -p 4 backup.sql\n"
        "ARG -Xlog:gc*:file=/var/log/key-store/gc.log\n"
    )
    assert diagnostics.redact_output(kept) == kept


def test_second_layer_redaction_knows_pass_names():
    assert java_ext.redact_args(
        ["java", "-Dredis.pass=Hunter1", "--requirepass", "Hunter2", "-Dbypass.x=on"]
    ) == [
        "java",
        "-Dredis.pass=[REDACTED]",
        "--requirepass",
        "[REDACTED]",
        "-Dbypass.x=on",
    ]
    unit = services._unit_file('Environment=DB_PASS=Hunter3 "MQ_PASS=a b" LANG=C')
    assert unit["lines"] == ["Environment=DB_PASS=[REDACTED] MQ_PASS=[REDACTED] LANG=C"]
    argv = services._argv(
        "{ path=/usr/bin/redis-server ; argv[]=/usr/bin/redis-server --db.pass=Hunter4 ; "
        "ignore_errors=no }"
    )
    assert argv == "/usr/bin/redis-server --db.pass=[REDACTED]"


# ------------------------------------------------------------- service_detail --

SHOW = (
    "[AIOPS_SHOW]\nId=app.service\nLoadState=loaded\nActiveState=active\n"
    "SubState=running\nResult=success\nMainPID=10\nNRestarts=0\n"
    "ExecMainStartTimestampMonotonic=86400000000\n"
)
CLOCK = f"[AIOPS_CLOCK]\nNOW {UNTIL}\nUPTIME 172800.42\nWINDOW {SINCE} {UNTIL}\n"
HISTORY = (
    "[AIOPS_HISTORY]\nHCOUNT starts 1\nHCOUNT failures 0\nHCOUNT restarts {r}\n"
    "HCOUNT oom 0\nHCOUNT start_limit 0\n"
)


def detail(text):
    report = observations.analyze("service_detail", text, options={"service": "app"})
    json.dumps(report, allow_nan=False)
    return report


def test_service_detail_counts_are_unknown_without_full_journal_access():
    # SSH-DIAG-07: an account outside the journal groups sees no PID 1 records.
    full = detail(SHOW + CLOCK + "[AIOPS_JOURNAL]\n" + HISTORY.format(r=0))
    assert full["summary"]["counts"] == {
        "restarts_24h": 0,
        "failures_24h": 0,
        "starts_24h": 1,
    }
    limited = detail(
        SHOW
        + CLOCK
        + "[AIOPS_JOURNAL]\nCAPABILITY_MISSING:journal-permission\n"
        + HISTORY.format(r=0)
    )
    assert limited["summary"]["counts"] == {
        "restarts_24h": None,
        "failures_24h": None,
        "starts_24h": None,
    }
    assert "次数未知" in limited["summary"]["coverage"]
    timed_out = detail(
        SHOW
        + CLOCK
        + "[AIOPS_JOURNAL]\n[AIOPS_HISTORY]\nH started 2026-10-29T14:01:00+0800 h "
        "systemd[1]: Started app.\nHCOUNT_INCOMPLETE 124\n"
    )
    assert timed_out["summary"]["counts"]["restarts_24h"] is None
    assert timed_out["summary"]["history"][0]["kind"] == "started"
    assert "超时或失败" in timed_out["summary"]["coverage"]


def test_service_detail_without_unit_properties_is_unknown_not_healthy():
    report = detail(
        "[AIOPS_SHOW]\n\nSHOW_FAILED 124\n"
        + CLOCK
        + "[AIOPS_JOURNAL]\n"
        + HISTORY.format(r=0)
    )
    found = by_metric(report)
    assert found["unit_state_unknown"]["level"] == "warning"
    assert found["unit_state_unknown"]["value"] == {"systemctl_show_exit": 124}
    script = diagnostics.command_for("service_detail", options={"service": "nginx"})
    assert "SHOW_FAILED" in script and "src=$?" in script
    assert "AIOPS_RC %s" in script and script.rstrip().endswith('exit "$rc"')


@needs_awk
def test_history_awk_prints_no_counts_for_an_incomplete_read():
    lines = (
        "2026-10-29T13:00:05+0800 h systemd[1]: app.service: Scheduled restart job, "
        "restart counter is at 1.\n"
    )
    code, out = awk(services.HISTORY_AWK, lines + "\nAIOPS_RC 124\n")
    assert code == 1
    assert out.splitlines()[-1] == "HCOUNT_INCOMPLETE 124"
    assert "HCOUNT restarts" not in out and out.startswith("H restart_scheduled")
    code, out = awk(services.HISTORY_AWK, lines + "\nAIOPS_RC 0\n")
    assert code == 0 and "HCOUNT restarts 1" in out and "INCOMPLETE" not in out


@needs_sh
def test_service_detail_script_reports_failed_show_and_history(tmp_path):
    stubs = {
        "id": 'case "$1" in -u) echo 0;; -nG) echo root;; esac\n',
        "systemctl": 'case "$1" in show) exit 1;; esac\n',
        "journalctl": 'case "$*" in *_PID=1*) exit 124;; esac\n',
    }
    for name, body in stubs.items():
        path = tmp_path / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)
    spec = extensions.spec_for("service_detail")
    options = extensions.validate_options(spec, {"service": "app"})
    result = subprocess.run(
        ["/bin/sh", "-c", spec.script(options)],
        capture_output=True,
        text=True,
        env={"PATH": f"{tmp_path}:/usr/bin:/bin", "LC_ALL": "C"},
        timeout=60,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert "SHOW_FAILED 1" in result.stdout and "HCOUNT_INCOMPLETE 124" in result.stdout
    report = observations.analyze(
        "service_detail", result.stdout, status="partial", options=options
    )
    assert "unit_state_unknown" in by_metric(report)
    assert report["summary"]["counts"]["restarts_24h"] is None


def test_restart_loop_needs_restarts_in_the_last_24_hours():
    # SSH-DIAG-08: NRestarts counts since the last manual start.
    old = detail(
        SHOW.replace("NRestarts=0", "NRestarts=5")
        + CLOCK
        + "[AIOPS_JOURNAL]\n"
        + HISTORY.format(r=0)
    )
    loop = by_metric(old)["restart_loop"]
    assert loop["level"] == "info" and loop["value"] == {
        "NRestarts": 5,
        "restarts_24h": 0,
    }
    recent = detail(SHOW + CLOCK + "[AIOPS_JOURNAL]\n" + HISTORY.format(r=4))
    assert by_metric(recent)["restart_loop"]["level"] == "critical"
    # Journal unreadable: NRestarts plus a pending restart still counts.
    limited = (
        SHOW.replace("NRestarts=0", "NRestarts=5")
        + CLOCK
        + (
            "[AIOPS_JOURNAL]\nCAPABILITY_MISSING:journal-permission\n"
            + HISTORY.format(r=0)
        )
    )
    pending = detail(limited.replace("SubState=running", "SubState=auto-restart"))
    assert by_metric(pending)["restart_loop"]["level"] == "critical"
    assert by_metric(detail(limited))["restart_loop"]["level"] == "info"
    started = detail(
        limited.replace(
            "ExecMainStartTimestampMonotonic=86400000000",
            "ExecMainStartTimestampMonotonic=172200000000",
        )
    )
    assert by_metric(started)["restart_loop"]["level"] == "critical"


def test_kernel_rule_ignores_debug_lines_and_oom_needs_the_killer():
    # SSH-DIAG-09.
    kernel = dict(observations.LOG_PATTERNS)["kernel"]
    assert not re.search(kernel, "app[1]: DEBUG:root:starting worker")
    assert re.search(kernel, "kernel: BUG: unable to handle kernel NULL pointer")
    assert re.search(kernel, "kernel: kernel BUG at mm/slub.c:3901!")
    debug = observations.analyze(
        "logs", "2026-10-29T10:00:00+0800 h app[1]: DEBUG:root:starting worker\n"
    )
    assert "log_kernel" not in by_metric(debug)
    journal = (
        "[AIOPS_JOURNAL]\n2026-10-29T14:05:00+0800 db mysqld[10]: [ERROR] "
        "Out of memory (Needed 1234 bytes)\n"
    )
    clue = by_metric(detail(SHOW + CLOCK + journal + HISTORY.format(r=0)))
    assert "oom_killed" not in clue
    assert clue["oom_log_clue"]["level"] == "warning"
    killed = journal + (
        "2026-10-29T14:06:00+0800 db systemd[1]: app.service: A process of this "
        "unit has been killed by the OOM killer.\n"
    )
    found = by_metric(detail(SHOW + CLOCK + killed + HISTORY.format(r=0)))
    assert found["oom_killed"]["level"] == "critical"
    assert "oom_log_clue" not in found


# ---------------------------------------------------------------- jvm gc_log --


def gc_filter():
    script = java_ext.PROBE_SCRIPTS["gc_log"]
    return script.split("2>/dev/null | awk '", 1)[1].split("'\n", 1)[0]


def test_gc_log_probe_never_follows_symlinks():
    script = java_ext.PROBE_SCRIPTS["gc_log"]
    assert '[ -L "$rt$gq" ]' in script and "gq=${gq%/*}" in script
    assert "cut -c1-300" not in script and "| awk '/^[[]/" in script
    assert "runuser" not in script and "jcmd" not in script


GC_LINES = [
    "[0.100s][info][gc] GC(0) Pause Young (Normal) (G1 Evacuation Pause) 24M->4M(256M) 3.456ms",
    "[2026-10-30T10:00:00.123+0800][info][gc,heap] GC(1) Eden regions: 12->0(13)",
    "2026-10-30T10:00:00.123+0800: 1.234: [GC (Allocation Failure) 33280K->5096K(125952K), 0.0040000 secs]",
    "1.234: [Full GC (Ergonomics)  5096K->4000K(125952K), 0.0400000 secs]",
    "   [Parallel Time: 10.5 ms, GC Workers: 4]",
    "{Heap before GC invocations=1 (full 0):",
    " PSYoungGen      total 38400K, used 5088K [0x00000000d5580000, 0x00000000d8000000)",
    "  eden space 33280K, 0% used [0x00000000d5580000,0x00000000d5580000)",
    "}",
    "GC(3) Pause Young (Normal) 1M->0M(8M) 0.5ms",
]
NOT_GC = [
    "root:$6$Hunter$Hunter:19000:0:99999:7:::",
    "root:x:0:0:root:/root:/bin/bash",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
    "spring.datasource.password=Hunter",
    '{"password": "Hunter"}',
    "  password: Hunter",
]


@needs_awk
def test_gc_log_probe_prints_only_gc_shaped_lines():
    code, out = awk(gc_filter(), "\n".join(NOT_GC + GC_LINES) + "\n")
    assert code == 0 and out.splitlines() == GC_LINES


@needs_linux
def test_gc_log_probe_refuses_symlinked_files_and_directories(tmp_path):
    from test_ext_java import run_sh, spawn_java

    secret = tmp_path / "secret.txt"
    secret.write_text("root:$6$Hunter$Hunter:19000:0:99999:7:::\n")
    real = tmp_path / "real"
    real.mkdir()
    (real / "gc.log").write_text(
        "[5.000s][info][gc] GC(1) Pause Full (System.gc()) 10M->2M(256M) 15.000ms\n"
        "password=Hunter\n"
    )
    (tmp_path / "logs").mkdir()
    (tmp_path / "logs" / "gc.log").symlink_to(secret)
    (tmp_path / "linkdir").symlink_to(real)
    for target, expected in (
        (tmp_path / "logs" / "gc.log", "unreadable"),
        (tmp_path / "linkdir" / "gc.log", "unreadable"),
        (real / "gc.log", "ok"),
    ):
        proc = spawn_java(tmp_path, "-Xloggc:" + str(target))
        options = {"pid": proc.pid, "probes": ["gc_log"]}
        try:
            result = run_sh(diagnostics.command_for("jvm", options=options))
        finally:
            proc.kill()
            proc.wait()
        assert "Hunter" not in result.stdout, (target, result.stdout)
        summary = observations.analyze("jvm", result.stdout, options=options)["summary"]
        assert summary["probes"] == {"gc_log": expected}, (target, result.stdout)
    assert summary["gc_log"]["full_pauses"] == 1
    assert summary["gc_log"]["lines"] == [
        "[5.000s][info][gc] GC(1) Pause Full (System.gc()) 10M->2M(256M) 15.000ms"
    ]


@needs_sh
def test_changed_scripts_parse_under_sh():
    scripts = [
        diagnostics.command_for("peer_traffic"),
        diagnostics.command_for("service_detail", options={"service": "nginx"}),
        diagnostics.command_for("jvm", options={"pid": 4242, "probes": ["gc_log"]}),
        diagnostics.command_for(
            "collect", options={"actions": ["cpu", "disk"], "timeout_seconds": 30}
        ),
    ]
    for script in scripts:
        subprocess.run(["/bin/sh", "-n"], input=script, text=True, check=True)
