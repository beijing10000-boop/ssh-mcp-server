"""Regressions for the independent review of the 2026-11 audit fixes.

Each block turns one confirmed defect into tests, with the negative cases next
to it: a journal the account may not read stays a host limit, JDK 8 GC
records keep their continuation lines, routine info lines raise no syslog
findings, syslog evidence keeps ordinary "key" words readable, a jump host
shares the caller's time budget, the nginx master lookup is bounded, GC log
symlinks are refused only for a JVM with a root of its own and the file is
checked on the descriptor that is read, ss runs without -H (EL7's iproute
4.11), and more client passwords on command lines are masked while ports,
PIDs and counters stay.

Parser tests run everywhere; awk tests need awk, script tests /bin/sh (dash
on CI), descriptor tests Linux /proc; the EL7 tests (-k el7) run in
SSHMCP_OLD_PROCPS_IMAGE (centos:7.9.2009 in the old-procps CI job).
"""

import json
import os
import re
import shutil
import subprocess
import time

import pytest

from sshmcp import diagnostics, extensions, insights, observations, operations, store
from sshmcp.extensions import java as java_ext
from sshmcp.extensions import nginx, services, syslog

HAS_SH = os.path.exists("/bin/sh")
HAS_AWK = shutil.which("awk") is not None
needs_sh = pytest.mark.skipif(not HAS_SH, reason="needs /bin/sh")
needs_awk = pytest.mark.skipif(not HAS_AWK, reason="needs awk")
needs_linux = pytest.mark.skipif(
    not (HAS_SH and os.path.exists("/proc/self/stat")),
    reason="needs /bin/sh and Linux /proc",
)
IMAGE = os.environ.get("SSHMCP_OLD_PROCPS_IMAGE", "")
needs_image = pytest.mark.skipif(
    not IMAGE, reason="set SSHMCP_OLD_PROCPS_IMAGE to an EL7 image (centos:7.9.2009)"
)
SINCE, UNTIL = 1793253600, 1793255400  # 2026-10-29 14:00–14:30 +08:00


@pytest.fixture(autouse=True)
def reset_tables():
    """Script, parser and executor tests only: no console database needed."""
    yield


def awk_commands():
    """Every awk this machine has: the default, POSIX gawk and mawk."""
    found = [["awk"]] if HAS_AWK else []
    if shutil.which("gawk"):
        found.append(["gawk", "--posix"])
    if shutil.which("mawk"):
        found.append(["mawk"])
    return found


def run_awk(command, program, text, *args):
    """Bytes in and out (no newline translation); returns (code, stdout)."""
    result = subprocess.run(
        [*command, *args, program], input=text.encode(), capture_output=True
    )
    return result.returncode, result.stdout.decode()


def by_metric(report):
    return {finding["metric"]: finding for finding in report["findings"]}


def write_stubs(directory, stubs):
    for name, body in stubs.items():
        path = directory / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)


# ------------------------------------------- 1. journal access is a host limit --

# systemctl show of a running unit; MainPID=0 keeps ps and ss out of the run.
SHOW_STUB = (
    'case "$1" in\n'
    "show) printf 'Id=app.service\\nLoadState=loaded\\nActiveState=active\\n"
    "SubState=running\\nResult=success\\nMainPID=0\\nNRestarts=0\\n';;\n"
    "cat) printf '[Service]\\nExecStart=/usr/bin/app\\n';;\n"
    "esac\n"
)
# EL7, volatile journal, an account outside the journal groups.
NO_JOURNAL_ACCESS = (
    "echo 'No journal files were opened due to insufficient permissions.' >&2\nexit 1\n"
)


@needs_awk
def test_history_awk_fails_the_run_only_for_a_timeout():
    lines = (
        "2026-10-29T13:00:05+0800 h systemd[1]: app.service: Scheduled restart job, "
        "restart counter is at 1.\n"
    )
    for command in awk_commands():
        # Exit 1 is how journalctl says "insufficient permissions": unknown
        # counts, but a host limit, not a failed step.
        code, out = run_awk(command, services.HISTORY_AWK, lines + "\nAIOPS_RC 1\n")
        assert code == 0, command
        assert out.splitlines()[-1] == "HCOUNT_INCOMPLETE 1", command
        assert "HCOUNT restarts" not in out and out.startswith("H restart_scheduled")
        for timeout in ("124", "137"):  # TERM, or KILL a second later
            code, out = run_awk(
                command, services.HISTORY_AWK, lines + f"\nAIOPS_RC {timeout}\n"
            )
            assert code == 1 and f"HCOUNT_INCOMPLETE {timeout}" in out, command
        code, out = run_awk(command, services.HISTORY_AWK, lines + "\nAIOPS_RC 0\n")
        assert code == 0 and "HCOUNT restarts 1" in out and "INCOMPLETE" not in out


def run_detail(tmp_path, stubs):
    write_stubs(tmp_path, stubs)
    spec = extensions.spec_for("service_detail")
    options = extensions.validate_options(spec, {"service": "app"})
    result = subprocess.run(
        ["/bin/sh", "-c", spec.script(options)],
        capture_output=True,
        text=True,
        env={"PATH": f"{tmp_path}:/usr/bin:/bin", "LC_ALL": "C"},
        timeout=60,
    )
    return result, options


@needs_sh
def test_service_detail_without_journal_access_stays_a_host_limit(tmp_path):
    # The reviewer's repro_service_detail.py: a non-root account outside the
    # journal groups made the branch exit 1, so the AI platform no longer saw
    # a host limit (it accepts exit 0 or 69 plus collection_coverage names).
    result, options = run_detail(
        tmp_path,
        {
            "id": 'case "$1" in -u) echo 1000;; -nG) echo diag;; esac\n',
            "systemctl": SHOW_STUB,
            "journalctl": NO_JOURNAL_ACCESS,
            "ss": "exit 0\n",
        },
    )
    out = result.stdout
    assert result.returncode == 0, out + result.stderr
    assert "CAPABILITY_MISSING:journal-permission" in out
    assert "HCOUNT_INCOMPLETE 1" in out and "SHOW_FAILED" not in out
    # What the executor makes of it: partial because of the marker, no exit code.
    report = observations.analyze(
        "service_detail", out, status="partial", options=options
    )
    json.dumps(report, allow_nan=False)
    found = by_metric(report)
    assert found["collection_coverage"]["value"] == ["journal-permission"]
    assert found["journal_access"]["value"] == "limited"
    assert report["summary"]["counts"] == {
        "restarts_24h": None,
        "failures_24h": None,
        "starts_24h": None,
    }
    assert report["summary"]["unit"]["active"] == "active"
    assert "unit_state_unknown" not in found and "restart_loop" not in found


@needs_sh
def test_service_detail_history_timeout_still_fails_the_run(tmp_path):
    if shutil.which("timeout") is None:
        pytest.skip("needs timeout")
    # Root, unit properties fine: only the PID 1 history read times out.
    result, options = run_detail(
        tmp_path,
        {
            "id": 'case "$1" in -u) echo 0;; -nG) echo root;; esac\n',
            "systemctl": SHOW_STUB,
            "journalctl": 'case "$*" in *_PID=1*) exit 124;; esac\n',
            "ss": "exit 0\n",
        },
    )
    out = result.stdout
    assert result.returncode == 1, out + result.stderr
    assert "HCOUNT_INCOMPLETE 124" in out and "SHOW_FAILED" not in out
    assert "CAPABILITY_MISSING" not in out
    report = observations.analyze(
        "service_detail", out, status="partial", options=options
    )
    assert report["summary"]["counts"]["restarts_24h"] is None
    assert "超时或失败" in report["summary"]["coverage"]


# --------------------------------------------- 2. JDK 8 GC continuation lines --


def gc_filter():
    """The probe's line filter (the awk program after the descriptor read)."""
    script = java_ext.PROBE_SCRIPTS["gc_log"]
    return script.split("2>/dev/null | awk '", 1)[1].split("'\n", 1)[0]


# JDK 8 CMS: promotion failure, then a concurrent mode failure whose Full GC
# pause ends on the second line (5.68 s, as the unfiltered log reports it).
# Uptime stamps only (no -XX:+PrintGCDateStamps): every line fits 300 chars.
CMS_RECORD = [
    "2026-11-01T09:59:50.000+0800: 90.000: [GC (Allocation Failure) 2026-11-01T09:59:50.000+0800:"
    " 90.000: [ParNew: 306688K->34048K(306688K), 0.0456789 secs] 3000000K->2800000K(4146688K),"
    " 0.0460000 secs] [Times: user=0.10 sys=0.00, real=0.05 secs]",
    "100.123: [GC (Allocation Failure) 100.123: [ParNew (promotion failed):"
    " 306688K->306688K(306688K), 0.1234567 secs]100.247: [CMS100.900:"
    " [CMS-concurrent-mark: 1.234/1.300 secs] [Times: user=2.00 sys=0.10, real=1.30 secs]",
    " (concurrent mode failure): 3800000K->2900000K(3840000K), 5.6789012 secs]"
    " 4106688K->2900000K(4146688K), [Metaspace: 90000K->90000K(1130496K)], 5.8023579 secs]"
    " [Times: user=5.70 sys=0.05, real=5.80 secs]",
]
# -XX:+PrintTenuringDistribution splits a ParNew record over several lines.
TENURING_RECORD = [
    "2026-11-01T10:01:00.000+0800: 160.000: [GC (Allocation Failure) 2026-11-01T10:01:00.000+0800:"
    " 160.000: [ParNew",
    "Desired survivor size 17432576 bytes, new threshold 6 (max 6)",
    "- age   1:    1234567 bytes,    1234567 total",
    "- age   2:     234567 bytes,    1469134 total",
    ": 306688K->34048K(306688K), 0.0456789 secs] 3000000K->2800000K(4146688K),"
    " 0.0460000 secs] [Times: user=0.10 sys=0.00, real=0.05 secs]",
    "2026-11-01T10:02:00.000+0800: 220.000: [GC (Allocation Failure) 2026-11-01T10:02:00.000+0800:"
    " 220.000: [ParNew",
    "Desired survivor size 17432576 bytes, new threshold 1 (max 6)",
    " (promotion failed): 314560K->314560K(314560K), 0.2345678 secs]"
    "2026-11-01T10:02:00.300+0800: 220.300: [CMS: 3800000K->2900000K(3840000K), 4.5678901 secs]"
    " 4106688K->2900000K(4146688K), 4.8123456 secs] [Times: user=4.70 sys=0.05, real=4.81 secs]",
]
COLLECTOR_LINES = [
    "Using G1",  # -Xlog:gc:file=...:none (no decorations)
    "Using Parallel",
    "Using Concurrent Mark Sweep",
    "2026-11-01 10:00:00 GC log file created /var/log/app/gc.log.0",
    "[0.010s][info][gc] Using G1",
]
# Never GC records, whatever file the argv points at.
NOT_GC = [
    "root:$6$Hunter$Hunter:19000:0:99999:7:::",
    "root:x:0:0:root:/root:/bin/bash",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW",
    "spring.datasource.password=Hunter",
    '{"password": "Hunter"}',
    "  password: Hunter",
    "Using password authentication for Hunter",
    "Desired: Hunter",
    "- agent Hunter: 1",
    " (Hunter) secrets",
    "2026-11-01 10:00:00 Hunter logged in",
]


@needs_awk
def test_gc_filter_keeps_jdk8_continuation_tenuring_and_collector_lines():
    kept = CMS_RECORD + TENURING_RECORD + COLLECTOR_LINES
    text = "FILE /var/log/app/gc.log\n" + "\n".join(NOT_GC + kept) + "\n"
    for command in awk_commands():
        code, out = run_awk(command, gc_filter(), text)
        assert code == 0, command
        assert out.splitlines() == ["FILE /var/log/app/gc.log"] + kept, command
        assert "Hunter" not in out


@needs_awk
def test_gc_filter_prints_the_file_line_only_as_the_first_line():
    # The FILE line comes from the descriptor checks, before tail: a log line
    # shaped like it never passes, and no FILE line means no state "ok".
    text = "[0.1s][info][gc] GC(0) Pause Young 3.0ms\nFILE /etc/shadow\n"
    for command in awk_commands():
        code, out = run_awk(command, gc_filter(), text)
        assert code == 0 and out == "", command


def test_gc_summary_reports_the_cms_concurrent_mode_failure_pause():
    # The reviewer's gc_summary_check.py: base 5678.9 ms, branch 123.457 ms.
    body = "FILE /var/log/app/gc.log\n" + "\n".join(CMS_RECORD) + "\n"
    summary = java_ext.gc_log_summary(body)
    assert summary["last_pause_ms"] == 5678.901
    assert any("concurrent mode failure" in line for line in summary["lines"])
    tenuring = java_ext.gc_log_summary(
        "FILE /var/log/app/gc.log\n" + "\n".join(TENURING_RECORD) + "\n"
    )
    assert tenuring["lines"] == TENURING_RECORD and tenuring["last_pause_ms"]


# ------------------------------------------- 3. one set of log-kind patterns --

STAMP = "2026-10-29T14:0{}:{}+0800 web01"
# Info-level lines no kind may claim (the syslog kinds pass reads info too).
ROUTINE_INFO = [
    STAMP.format(1, f"{index:02d}") + " " + message
    for index, message in enumerate(
        (
            "kernel: e1000e: eth0 NIC Link is Up 1000 Mbps Full Duplex,"
            " Flow Control: Rx/Tx",
            "kernel: NMI watchdog: Enabled. Permanently consumes one hw-PMU counter.",
            "app[7]: DEBUG:root:cache miss for key 42",
            "app[7]: DEBUG: x",
            "kernel: igb 0000:01:00.0: Intel(R) Gigabit Ethernet Network",
        )
    )
]
# Real events, each of exactly one kind.
EVENT_KINDS = (
    ("kernel: e1000e: eth0 NIC Link is Down", "network"),
    (
        "kernel: bond0: link status definitely down for interface eth1,"
        " disabling it; carrier lost",
        "network",
    ),
    ("kernel: NMI watchdog: Watchdog detected hard LOCKUP on cpu 3", "kernel"),
    ("kernel: BUG: unable to handle kernel NULL pointer dereference", "kernel"),
    ("kernel: kernel BUG at mm/slub.c:3901!", "kernel"),
    ("kernel: java[4242]: segfault at 0 ip 00007f3c error 4", "kernel"),
    ("kernel: Out of memory: Killed process 4242 (java)", "oom"),
    ("kernel: blk_update_request: I/O error, dev sda, sector 1", "io_error"),
    ("systemd[1]: app.service: Main process exited, code=exited", "service"),
    ("sshd[3001]: Failed password for root from 203.0.113.9", "auth"),
)
EVENTS = {
    STAMP.format(2, f"{index:02d}") + " " + message: kind
    for index, (message, kind) in enumerate(EVENT_KINDS)
}


def python_kinds(line):
    return {
        kind for kind, pattern in observations.LOG_PATTERNS if re.search(pattern, line)
    }


@needs_awk
def test_log_patterns_and_awk_patterns_classify_the_same_lines():
    assert syslog.AWK_PATTERNS == observations.LOG_KINDS
    assert [kind for kind, _ in observations.LOG_PATTERNS] == list(syslog.KINDS)
    lines = ROUTINE_INFO + list(EVENTS)
    # The host matches the lower-cased line, the parsers the line itself.
    program = (
        '{ low = tolower($0); s = ""\n'
        + "".join(
            f'  if (low ~ "{pattern}") s = s " {kind}"\n'
            for kind, pattern in syslog.AWK_PATTERNS.items()
        )
        + "  print s }"
    )
    for command in awk_commands():
        code, out = run_awk(command, program, "\n".join(lines) + "\n")
        assert code == 0, command
        host = [set(row.split()) for row in out.splitlines()]
        assert host == [python_kinds(line) for line in lines], command
    for line in ROUTINE_INFO:
        assert python_kinds(line) == set(), line
    for line, kind in EVENTS.items():
        assert python_kinds(line) == {kind}, line


def syslog_info_text(entries):
    return (
        "[AIOPS_SOURCE]\n"
        f"WINDOW {SINCE} {UNTIL}\nNOW {UNTIL}\nJOURNAL=available\n"
        "JOURNAL_COVERS_WINDOW=yes\nFILES /var/log/messages\n"
        "[AIOPS_JOURNAL]\nPRIORITY info\n"
        + "".join(line + "\n" for line in entries)
        + f"LINES_TOTAL {len(entries)}\n"
        "COUNT crit 0 0\nCOUNT err 0 0\nCOUNT warning 0 0\n"
        "[AIOPS_AUTH]\nAUTH_UNAVAILABLE\n[AIOPS_BOOT]\nBOOT_AT 1793253700\n"
    )


def test_syslog_info_entries_raise_no_link_or_kernel_findings():
    # The reviewer's repro_syslog_info.py: the host-side kinds matched nothing,
    # parse() re-classified "NIC Link is Up" and "NMI watchdog: Enabled".
    report = observations.analyze(
        "syslog", syslog_info_text(ROUTINE_INFO), options={"priority": "info"}
    )
    counts = report["summary"]["matched_counts"]
    assert counts["network"] == counts["kernel"] == 0
    assert report["summary"]["matched"] == {}
    found = by_metric(report)
    assert "log_network" not in found and "log_kernel" not in found
    # Real events in the same entries still count.
    events = observations.analyze(
        "syslog",
        syslog_info_text(ROUTINE_INFO + list(EVENTS)),
        options={"priority": "info"},
    )
    counts = events["summary"]["matched_counts"]
    assert (counts["network"], counts["kernel"], counts["oom"]) == (2, 4, 1)
    assert by_metric(events)["log_network"]["level"] == "warning"


def test_classic_log_actions_use_the_same_kinds():
    text = "\n".join(ROUTINE_INFO) + "\n"
    for action in ("kernel", "log_errors"):
        found = by_metric(observations.analyze(action, text))
        assert "log_kernel" not in found, action
    bug = STAMP.format(3, "00") + " kernel: BUG: soft lockup - CPU#1 stuck for 22s!"
    assert "log_kernel" in by_metric(observations.analyze("kernel", bug + "\n"))


# ------------------------------------------------ 4. syslog evidence redaction --

READABLE = [
    "sshd[1]: error: Could not load host key: /etc/ssh/ssh_host_ed25519_key",
    "sshd[1]: error: key_load_public: invalid format",
    "redis[9]: Background saving terminated with success, keys: 123456",
    'auditd[1]: type=SYSCALL arch=c000003e syscall=59 success=yes key="privileged"',
    "app[7]: Basic authentication succeeded for user administrator",
    "app[7]: using basic configuration profile defaults",
    "app[7]: bearer token missing; basic settings ok",
    'httpd[8]: WWW-Authenticate: Basic realm="Restricted"',
    "kernel: tpm_tis: TPM key size: 2048",
    "app[7]: cache key: user_profile_42 miss; monkey: 5, donkey: 6",
    "kernel: Key type dns_resolver registered",
    "systemd-logind[700]: New session 13812345678 of user root.",
]
MASKED = {
    "app[7]: proxy sent Basic dXNlcjpwYXNzd29yZA== upstream": "dXNlcjpwYXNzd29yZA==",
    "app[7]: upstream replied to Bearer abcDEFghiJKLmno": "abcDEFghiJKLmno",
    "app[7]: retry with bearer 0a1b2c3d4e5f6a7b": "0a1b2c3d4e5f6a7b",
    "app[7]: forward basic YWxhZGRpbjpvcGVu+/x": "YWxhZGRpbjpvcGVu+/x",
    "app[7]: login failed mobile=13812345678 pass=letmein999": "letmein999",
    "app[7]: Authorization: Basic SHVudGVyMjE6eA==": "SHVudGVyMjE6eA==",
}


def test_syslog_redaction_keeps_key_words_and_masks_bare_credentials():
    stamp = "2026-10-29T14:00:05+0800 web01 "
    for line in READABLE:
        assert syslog.redact_line(stamp + line) == stamp + line, line
    for line, secret in MASKED.items():
        out = syslog.redact_line(stamp + line)
        assert secret not in out and "[REDACTED]" in out, out
    # nginx keeps its broad key rule: the same text is masked there.
    assert "privileged" not in nginx.redact_log('key="privileged"')
    assert "invalid" not in nginx.redact_log("key_load_public: invalid format")


def test_syslog_entries_and_samples_use_the_syslog_redaction():
    stamp = "2026-10-29T14:00:05+0800 web01 "
    entries = [stamp + line for line in READABLE + list(MASKED)]
    oom = (
        stamp + "kernel: Out of memory: Killed process 4242 (java) Bearer Zx9Yw8Vu7Ts6"
    )
    text = syslog_info_text(entries + [oom]).replace(
        "COUNT crit", f"MATCH oom 1\nMATCHLINE oom {oom}\nCOUNT crit", 1
    )
    for raw in (text, diagnostics.redact_output(text)):
        summary = observations.analyze("syslog", raw, options={"priority": "info"})[
            "summary"
        ]
        dumped = json.dumps(summary, ensure_ascii=False)
        for secret in [*MASKED.values(), "Zx9Yw8Vu7Ts6"]:
            assert secret not in dumped, secret
        for line in READABLE:
            assert stamp + line in summary["entries"], line
        assert "mobile=138****5678" in dumped
        assert "Bearer [REDACTED]" in summary["matched"]["oom"][0]


# ------------------------------------------ 5. jump host within the time budget --


class Chan:
    def __init__(self, out):
        self.out = out

    def settimeout(self, value):
        pass

    def exec_command(self, command):
        pass

    def recv_ready(self):
        return bool(self.out)

    def recv(self, size):
        data, self.out = self.out[:size], self.out[size:]
        return data

    def recv_stderr_ready(self):
        return False

    def exit_status_ready(self):
        return True

    def recv_exit_status(self):
        return 0

    def close(self):
        pass


def via_jump_host(monkeypatch):
    """_execute_inner over a jump host; the real _route runs, only the
    paramiko layer below it is replaced and records its timeouts."""
    host = {
        "id": 1,
        "name": "h",
        "address": "10.0.0.1",
        "port": 22,
        "username": "app",
        "host_key": "k",
        "credential_id": 1,
        "proxy_id": 7,
        "revision": 1,
        "mode": "standard",
    }
    proxy = {
        "id": 7,
        "address": "10.0.0.254",
        "port": 22,
        "username": "jump",
        "host_key": "k",
        "credential_id": 2,
    }
    calls = []
    out = (
        "\n__SSHMCP_BEGIN_cpu__\nCPU_COUNT=2\n0.10 0.20 0.30 1/100 99\n"
        "\n__SSHMCP_END_cpu__:0\n"
    ).encode()

    class Transport:
        def open_channel(self, kind, dest, src, timeout=None):
            calls.append(("jump.open_channel", timeout))
            return object()

        def open_session(self, timeout=None):
            calls.append(("target.open_session", timeout))
            return Chan(out)

    class Client:
        def get_transport(self):
            return Transport()

        def close(self):
            pass

    def connect(target, key, *, sock=None, timeout=6):
        calls.append((target["username"] + ".connect", timeout))
        return Client()

    monkeypatch.setattr(store, "get_host", lambda host_id: host)
    monkeypatch.setattr(store, "get_proxy", lambda pid: proxy if pid == 7 else None)
    monkeypatch.setattr(diagnostics, "private_key", lambda cid: object())
    monkeypatch.setattr(diagnostics, "client_connect", connect)
    return calls


def test_jump_host_handshake_shares_the_callers_time_budget(monkeypatch):
    # The reviewer's jump_budget.py: the jump host still waited 6 s per stage
    # with 8 s left in total.
    calls = via_jump_host(monkeypatch)
    options = {"actions": ["cpu"], "timeout_seconds": 10}
    result = diagnostics._execute_inner(
        1, "collect", options=options, finish_by=time.monotonic() + 8
    )
    assert result["status"] == "success", result.get("summary")
    names = [name for name, _ in calls]
    assert names == [
        "jump.connect",
        "jump.open_channel",
        "app.connect",
        "target.open_session",
    ]
    stages = {timeout for _, timeout in calls}
    assert len(stages) == 1, calls
    (stage,) = stages
    assert 1 <= stage <= 8 / 5


def test_jump_host_keeps_six_seconds_per_stage_without_a_budget(monkeypatch):
    calls = via_jump_host(monkeypatch)
    diagnostics._execute_inner(1, "collect", options={"actions": ["cpu"]})
    assert [timeout for _, timeout in calls] == [6, 6, 6, 6]


# --------------------------------------------------- 6. bounded master lookup --

TIMED_PS = (
    "margs=$( { if command -v timeout >/dev/null 2>&1; then timeout -k 1 3 ps -eo args=;"
    " else ps -eo args=; fi; } 2>/dev/null | awk"
)


def nginx_scripts():
    yield "nginx", nginx.nginx_script({"minutes": 30})
    yield (
        "nginx_access",
        nginx.access_script({"since": int(time.time()) - 1800}),
    )


def test_nginx_master_lookup_runs_under_timeout():
    for name, script in nginx_scripts():
        assert TIMED_PS in script, name
        # No ps -eo args= outside that timeout wrapper.
        assert script.count("ps -eo args=") == 2, name


@needs_sh
def test_nginx_master_lookup_gives_up_on_a_stuck_ps(tmp_path):
    if shutil.which("timeout") is None:
        pytest.skip("needs timeout")
    write_stubs(tmp_path, {"ps": "exec sleep 30\n"})
    script = "NGX=''\n" + nginx._MASTER + "printf 'MARGS=[%s]\\n' \"$margs\"\n"
    began = time.monotonic()
    result = subprocess.run(
        ["/bin/sh", "-c", script],
        capture_output=True,
        text=True,
        env={"PATH": f"{tmp_path}:/usr/bin:/bin", "LC_ALL": "C"},
        timeout=60,
    )
    assert time.monotonic() - began < 15
    assert "MARGS=[]" in result.stdout, result.stdout + result.stderr


# --------------------------------- 7./8. GC log symlinks and descriptor checks --


def test_gc_log_state_tells_a_refused_symlink_from_unreadable():
    def state(body):
        return java_ext.gc_log_state("[AIOPS_GC_LOG]\n" + body)

    assert state("GC_LOG_SYMLINK\n") == "symlink_refused"
    assert state("GC_LOG_UNREADABLE\n") == "unreadable"
    assert state("GC_LOG_FOREIGN_OWNER\n") == "foreign_owner"
    assert state("GC_LOG_NOT_CONFIGURED\n") == "not_configured"
    assert state("FILE /var/log/app/gc.log\n") == "ok"
    assert state("") == "failed"
    # Markers count as whole lines only: a GC-shaped log line cannot forge one.
    assert state("FILE /x\n[0.1s][info][gc] GC_LOG_UNREADABLE GC_LOG_SYMLINK\n") == "ok"
    report = observations.analyze(
        "jvm",
        "[AIOPS_PROC]\nPID 7\nUSER app\n[AIOPS_GC_LOG]\nGC_LOG_SYMLINK\n",
        options={"pid": 7, "probes": ["gc_log"]},
    )
    assert report["summary"]["probes"] == {"gc_log": "symlink_refused"}
    assert "symlink_refused" in report["summary"]["coverage"]


def test_gc_log_probe_reads_only_the_descriptor_it_checked():
    script = java_ext.PROBE_SCRIPTS["gc_log"]
    # Same root as ours: device and inode of /proc/<pid>/root/ and /.
    assert 'stat -L -c %d:%i "/proc/$pid/root/"' in script
    assert "stat -L -c %d:%i / 2>/dev/null" in script
    # One open; type, owner (and outside our root the path's own inode) are
    # checked on that descriptor, and tail reads it, never the path again.
    inner = descriptor_program()
    assert inner.startswith('exec 3<"$1" && [ -f /proc/self/fd/3 ]')
    assert '[ "$(stat -L -c %u /proc/self/fd/3)" = "$2" ]' in inner
    assert inner.endswith("exec tail -n 40 <&3")
    assert 'tail -n 40 "$rt' not in script and "tail -n 40 <&3" in script


def descriptor_program():
    script = java_ext.PROBE_SCRIPTS["gc_log"]
    return re.search(r"tmo3 sh -c '([^']*)' sh ", script)[1]


@needs_linux
def test_descriptor_checks_refuse_other_owners_directories_and_swapped_links(
    tmp_path,
):
    log = tmp_path / "gc.log"
    log.write_text("[0.1s][info][gc] GC(0) Pause Young 3.0ms\n")
    (tmp_path / "dir").mkdir()
    (tmp_path / "link.log").symlink_to(log)
    uid = str(os.getuid())

    def read(path, owner=uid, same="1"):
        result = subprocess.run(
            ["/bin/sh", "-c", descriptor_program(), "sh", str(path), owner, "/x", same],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout

    assert read(log) == "FILE /x\n[0.1s][info][gc] GC(0) Pause Young 3.0ms\n"
    assert read(log, same="") == read(log)  # a plain file outside our root too
    assert read(log, owner=str(int(uid) + 1)) == ""  # not the JVM's file
    assert read(tmp_path / "dir") == ""  # opened, but not a regular file
    assert read(tmp_path / "missing.log") == ""
    # A link: followed for a JVM sharing our root; outside it the path must
    # name the inode that was opened, so a link swapped in reads nothing.
    assert read(tmp_path / "link.log") == read(log)
    assert read(tmp_path / "link.log", same="") == ""


def run_gc_probe(tmp_path, target, other_root=False):
    """The jvm gc_log probe against a fake JVM whose argv names `target`;
    `other_root` makes stat report a different root for /proc/<pid>/root/."""
    from test_ext_java import run_sh, spawn_java

    script_path = "PATH=/usr/sbin:/usr/bin:/sbin:/bin;"
    stubs = tmp_path / "stubs"
    stubs.mkdir(exist_ok=True)
    write_stubs(
        stubs,
        {
            "stat": 'case "$*" in\n'
            '"-L -c %d:%i /proc/"*"/root/") echo 0:1; exit 0;;\n'
            "esac\n"
            'for s in /usr/bin/stat /bin/stat; do [ -x "$s" ] && exec "$s" "$@"; done\n'
            "exit 1\n"
        },
    )
    proc = spawn_java(tmp_path, "-Xloggc:" + str(target))
    options = {"pid": proc.pid, "probes": ["gc_log"]}
    script = diagnostics.command_for("jvm", options=options)
    assert script_path in script
    if other_root:
        script = script.replace(
            script_path, f"PATH={stubs}:/usr/sbin:/usr/bin:/sbin:/bin;"
        )
    try:
        result = run_sh(script)
    finally:
        proc.kill()
        proc.wait()
    summary = observations.analyze("jvm", result.stdout, options=options)["summary"]
    return result, summary


@needs_linux
def test_gc_log_symlinks_are_refused_only_for_a_jvm_with_its_own_root(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("root:$6$Hunter$Hunter:19000:0:99999:7:::\n")
    real = tmp_path / "apache-tomcat-9" / "logs"
    real.mkdir(parents=True)
    gc_line = "[5.000s][info][gc] GC(1) Pause Full (System.gc()) 10M->2M(256M) 15.000ms"
    (real / "gc.log").write_text(gc_line + "\npassword=Hunter\n")
    (tmp_path / "tomcat").symlink_to(tmp_path / "apache-tomcat-9")  # /opt/tomcat
    (tmp_path / "evil").mkdir()
    (tmp_path / "evil" / "gc.log").symlink_to(secret)
    linked = tmp_path / "tomcat" / "logs" / "gc.log"
    # A container (stat says another root): no symlink anywhere in the path.
    for target in (linked, tmp_path / "evil" / "gc.log"):
        result, summary = run_gc_probe(tmp_path, target, other_root=True)
        assert "GC_LOG_SYMLINK" in result.stdout, result.stdout + result.stderr
        assert summary["probes"] == {"gc_log": "symlink_refused"}
        assert "Hunter" not in result.stdout and "FILE " not in result.stdout
    result, summary = run_gc_probe(tmp_path, real / "gc.log", other_root=True)
    assert summary["probes"] == {"gc_log": "ok"}, result.stdout + result.stderr
    assert summary["gc_log"]["lines"] == [gc_line]
    # Our own root: the deployment's links are followed.
    result, summary = run_gc_probe(tmp_path, linked)
    assert summary["probes"] == {"gc_log": "ok"}, result.stdout + result.stderr
    assert summary["gc_log"]["file"] == str(linked)
    assert summary["gc_log"]["lines"] == [gc_line] and "Hunter" not in result.stdout


# ------------------------------------------------------- 10. ss without -H --

SS_SCRIPTS = {
    "tcp_states": operations.SCRIPTS["tcp_states"],
    "peer_connections": diagnostics.PEER_CONNECTIONS_CMD,
    "peer_traffic": diagnostics.PEER_TRAFFIC_CMD,
}
# iproute2 4.11 (EL7) prints a header and has no -H; newer ones print the
# same rows. One state selected: no State column, the header starts Recv-Q.
TAN_HEADER = (
    "State      Recv-Q Send-Q Local Address:Port               Peer Address:Port\n"
)
TAN_ROWS = (
    "LISTEN     0      128          *:22                       *:*\n"
    "ESTAB      0      0      10.0.0.5:22             198.51.100.9:51234\n"
    "ESTAB      0      36     10.0.0.5:22             198.51.100.9:51240\n"
    "TIME-WAIT  0      0      10.0.0.5:80             198.51.100.7:40000\n"
    "LISTEN     0      128       [::]:22                    [::]:*\n"
)
ESTAB_HEADER = "Recv-Q Send-Q Local Address:Port               Peer Address:Port\n"
ESTAB_ROWS = (
    "0      0      10.0.0.5:22             198.51.100.9:51234\n"
    "\t cubic wscale:7,7 rto:204 bytes_sent:1500 bytes_received:900 segs_out:12\n"
)


@needs_sh
def test_ss_header_is_skipped_and_rows_are_unchanged(tmp_path):
    def run(name, command, fixture):
        """The fixed script with `command` replaced by the fixture's text."""
        path = tmp_path / "ss.txt"
        path.write_text(fixture)
        script = SS_SCRIPTS[name]
        assert command in script
        script = (
            script.replace(command, f"cat '{path}'")
            .replace("command -v ss ", "command -v cat ")
            .replace("sleep 3", "true")
        )
        result = subprocess.run(
            ["/bin/sh", "-c", script], capture_output=True, text=True, timeout=30
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    for name, command, header, rows in (
        ("tcp_states", "ss -tan", TAN_HEADER, TAN_ROWS),
        ("peer_connections", "ss -t -a -n", TAN_HEADER, TAN_ROWS),
        ("peer_traffic", "ss -t -n -i state established", ESTAB_HEADER, ESTAB_ROWS),
    ):
        old, new = run(name, command, header + rows), run(name, command, rows)
        assert old == new, name  # EL7 with a header == newer iproute2 with -H
        assert "State" not in old and "Recv-Q" not in old and "Address" not in old
    states = observations.analyze(
        "tcp_states", run("tcp_states", "ss -tan", TAN_HEADER + TAN_ROWS)
    )["summary"]["states"]
    assert states == {"ESTAB": 2, "LISTEN": 2, "TIME-WAIT": 1}
    peers = insights.parse_peer_connections(
        run("peer_connections", "ss -t -a -n", TAN_HEADER + TAN_ROWS)
    )["ranking"]
    assert [(p["peer_ip"], p["tcp_connections"]) for p in peers] == [
        ("198.51.100.9", 2),
        ("198.51.100.7", 1),
    ]
    samples = insights.parse_tcp_samples(
        run(
            "peer_traffic",
            "ss -t -n -i state established",
            ESTAB_HEADER + ESTAB_ROWS,
        )
    )
    assert samples["supported"] and samples["matched_sockets"] == 1


def all_scripts():
    """Every fixed script the server can send (as test_procps_compat lists them)."""
    from test_procps_compat import scripts

    return list(scripts())


def test_no_script_asks_ss_for_its_header_option():
    for action, script in all_scripts():
        assert not re.search(r"\bss\b[^|;\n]*[ \t]-[A-Za-z]*H", script), action


# ----------------------------------------------- 11. command-line passwords --

PASSWORDS = {
    "sshpass -p Hunter01 ssh -p 2222 root@10.0.0.5": "Hunter01",
    "sshpass -pHunter02 scp -P 2222 a.tar 10.0.0.5:/tmp": "Hunter02",
    "CMD (/usr/bin/sshpass -e -v -p 'Hunter 03' rsync -e 'ssh -p 2222' /a h:/b)": (
        "Hunter 03"
    ),
    "curl -s -u alice:Hunter04 'https://api.example.com/x?a=1&b=2'": "Hunter04",
    "curl --user alice:Hunter05 https://api.example.com/": "Hunter05",
    "curl -ualice:Hunter06 https://api.example.com/": "Hunter06",
    "curl -u 'alice:Hunter 07' https://api.example.com/": "Hunter 07",
    'curl --proxy-user "bob:Hunter 08" http://example.com/': "Hunter 08",
    "mongo admin -u root -p Hunter09 --authenticationDatabase admin": "Hunter09",
    "mongosh mongodb://db:27017/?replicaSet=rs0&authSource=admin -u a -p Hunter10": (
        "Hunter10"
    ),
    "mongodump -u backup -pHunter11 -o /backup": "Hunter11",
    "mongo --password Hunter12 --port 27017": "Hunter12",
    "docker login -u bob -p Hunter13 registry.example.com": "Hunter13",
    "docker login -pHunter14 registry.example.com": "Hunter14",
    "docker login --password Hunter15 registry.example.com": "Hunter15",
    "podman login --tls-verify=false -p Hunter16 quay.io": "Hunter16",
    # The password as the first option after the client.
    "mysql -pHunter17 appdb": "Hunter17",
    "redis-cli -a Hunter18 ping": "Hunter18",
}
# Ports, PIDs, byte counts and ssh/scp/docker port flags stay as they are.
KEPT_COMMAND_LINES = (
    "ssh -p 22 root@10.0.0.1\n"
    "scp -P 2222 backup.tar 10.0.0.5:/data\n"
    "sshpass -f /root/.ssh/pw ssh -p 2222 root@10.0.0.5\n"
    "/usr/sbin/sshd -D -p 2222\n"
    "docker run -d -p 8080:80 --name web nginx\n"
    "docker login registry.example.com && docker run -p 8080:80 nginx\n"
    "mongod --port 27017 --bind_ip 0.0.0.0\n"
    "mongo --port 27017 -u admin -p --authenticationDatabase admin\n"
    "curl -u alice https://api.example.com:8443/\n"
    "curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/health | sort -u\n"
    "mysql -p appdb\n"
    "/usr/bin/mysql-proxy -p8080 --admin-port 4041\n"
    "redis-server *:6379\n"
    'ESTAB 0 0 10.0.0.5:22 10.0.0.9:51234 users:(("sshd",pid=13812,fd=3))'
    " bytes_sent:13421772800 bytes_received:17179869184\n"
    "  PID  PPID COMMAND  %CPU %MEM   RSS\n 1234     1 java  12.0  3.2 13421772\n"
    "intel_pstate: telemetry_bytes=13421772800\n"
    "hotel_rooms=13812345678 intel_x=13812345678 TELEMETRY_BYTES=13812345678\n"
    "MemoryCurrent=13958643712\nCPUUsageNSec=13958643712\n"
)


def test_client_passwords_on_command_lines_are_masked():
    for line, secret in PASSWORDS.items():
        out = diagnostics.redact_output(line)
        assert secret not in out and "[REDACTED]" in out, (line, out)
    # The user of curl -u stays, ports of the commands sshpass runs too.
    assert "-u alice:[REDACTED] " in diagnostics.redact_output(
        "curl -s -u alice:Hunter04 'https://x/'"
    )
    assert diagnostics.redact_output("curl -u 'alice:Hunter 07' https://x/") == (
        "curl -u 'alice:[REDACTED]' https://x/"
    )
    assert diagnostics.redact_output(
        "sshpass -p Hunter01 ssh -p 2222 root@10.0.0.5"
    ) == ("sshpass -p [REDACTED] ssh -p 2222 root@10.0.0.5")


def test_ports_pids_and_counters_stay_on_command_lines():
    assert diagnostics.redact_output(KEPT_COMMAND_LINES) == KEPT_COMMAND_LINES


def test_phone_keys_need_a_name_of_their_own():
    masked = {
        "tel=13812345678": "tel=138****5678",
        "tel_no: 13812345678": "tel_no: 138****5678",
        "telNo=13812345678": "telNo=138****5678",
        "userTel=13812345678": "userTel=138****5678",
        "telephone=13812345678": "telephone=138****5678",
        "TEL_NO=13812345678": "TEL_NO=138****5678",
        "userPhone=13812345678": "userPhone=138****5678",
        "hotel.phone=13812345678": "hotel.phone=138****5678",
        "contact_mobile: 15012345678": "contact_mobile: 150****5678",
    }
    for line, expected in masked.items():
        assert diagnostics.redact_output(line) == expected, line
    for line in (
        "intel_pstate: telemetry_bytes=13421772800",
        "telemetry.rx=13812345678",
        "hotel_guests=13812345678",
        "TELEMETRY_BYTES=13812345678",
        "telnet_sessions=13812345678",
    ):
        assert diagnostics.redact_output(line) == line, line


# ------------------------------------------------------------ scripts parse --


@needs_sh
def test_changed_scripts_parse_under_sh():
    scripts = [
        diagnostics.command_for("service_detail", options={"service": "nginx"}),
        diagnostics.command_for("jvm", options={"pid": 4242, "probes": ["gc_log"]}),
        diagnostics.command_for("tcp_states"),
        diagnostics.command_for("peer_connections"),
        diagnostics.command_for("peer_traffic"),
        diagnostics.command_for("syslog", options={}),
        diagnostics.command_for(
            "collect", options={"actions": ["tcp_states", "cpu"], "timeout_seconds": 30}
        ),
        diagnostics.command_for("time_sync"),
        *(script for _, script in nginx_scripts()),
    ]
    for script in scripts:
        subprocess.run(["/bin/sh", "-n"], input=script, text=True, check=True)


def test_changed_awk_programs_run_on_every_awk():
    programs = [
        services.HISTORY_AWK,
        syslog.AGG_AWK,
        re.search(r"awk '([^']*)' \| sort", operations.SCRIPTS["tcp_states"])[1],
        re.search(r"awk '([^']*)'", diagnostics.PEER_CONNECTIONS_CMD)[1],
        re.search(r"awk '([^']*)'", diagnostics.PEER_TRAFFIC_CMD)[1],
    ]
    if not awk_commands():
        pytest.skip("needs awk")
    for command in awk_commands():
        for program in programs + [gc_filter()]:
            result = subprocess.run(
                [*command, program], input=b"", capture_output=True, timeout=30
            )
            assert result.returncode == 0, (command, program[:60], result.stderr)


# --------------------------------------------------------- EL7 (CI image) --

# Fallback when the image lacks iproute: CentOS 7's mirrors moved to vault.
EL7_SS = r"""
if ! command -v ss >/dev/null 2>&1; then
  sed -i -e 's/^mirrorlist=/#mirrorlist=/' \
    -e 's|^#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|' \
    /etc/yum.repos.d/CentOS-*.repo
  yum -y -q install iproute >/dev/null 2>&1
fi
# Two connected loopback sockets that sent and received (ss shows non-zero
# byte counters only) and a listener; python 2 ships with yum.
python -c 'import socket, sys, time
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
s.listen(5)
c = socket.create_connection(s.getsockname())
a = s.accept()[0]
c.sendall(b"x" * 4096)
a.sendall(b"y" * 4096)
a.recv(4096)
c.recv(4096)
sys.stdout.write("READY\n")
sys.stdout.flush()
time.sleep(120)' >/tmp/peers.out 2>&1 &
i=0
while [ "$i" -lt 50 ] && ! grep -q READY /tmp/peers.out 2>/dev/null; do sleep 0.2; i=$((i + 1)); done
printf '@@PEERS %s\n' "$(cat /tmp/peers.out)"
printf '@@VERSION %s\n' "$(ss -V 2>&1 | head -n 1)"
printf '@@HEAD tan %s\n' "$(ss -tan | head -n 1)"
printf '@@HEAD estab %s\n' "$(ss -t -n -i state established | head -n 1)"
"""


@needs_image
def test_el7_ss_commands_run_without_the_header_option():
    from test_procps_compat import in_container

    body = EL7_SS
    for name in SS_SCRIPTS:
        body += (
            f"printf '@@BEGIN {name}\\n'\n(\n{diagnostics.command_for(name)}\n) "
            f"</dev/null 2>/tmp/{name}.err\nprintf '@@RC %s\\n' \"$?\"\n"
            f"sed 's/^/@@ERR /' /tmp/{name}.err\n"
        )
    result = in_container(body)
    text = result.stdout
    assert "@@PEERS READY" in text, text + result.stderr
    version = re.search(r"(?m)^@@VERSION (.*)$", text)[1]
    for kind in ("tan", "estab"):
        head = re.search(rf"(?m)^@@HEAD {kind} (\S*)", text)[1]
        assert head in ("State", "Recv-Q", "Netid"), (version, kind, head)
    parts = dict(re.findall(r"(?ms)^@@BEGIN (\w+)\n(.*?)(?=^@@BEGIN |\Z)", text))
    outputs = {}
    for name in SS_SCRIPTS:
        part = parts[name]
        code = re.search(r"(?m)^@@RC (\d+)$", part)
        errors = re.findall(r"(?m)^@@ERR (.*)$", part)
        assert code and code[1] == "0", (version, name, part)
        assert not any(re.search(r"(?i)usage|invalid|unrecognized", e) for e in errors)
        outputs[name] = part[: code.start()]
    states = outputs["tcp_states"].splitlines()
    assert states and all(re.fullmatch(r"[A-Z][A-Z0-9-]* \d+", row) for row in states)
    counts = observations.analyze("tcp_states", outputs["tcp_states"])["summary"]
    assert (
        counts["states"].get("ESTAB", 0) >= 2 and counts["states"].get("LISTEN", 0) >= 1
    )
    rows = [row for row in outputs["peer_connections"].splitlines() if row]
    assert rows and all(re.fullmatch(r"[^\t]+\t\d+\t\d+", row) for row in rows)
    ranking = insights.parse_peer_connections(outputs["peer_connections"])["ranking"]
    loopback = [row for row in ranking if row["peer_ip"] == "127.0.0.1"]
    assert loopback and loopback[0]["established_connections"] >= 2, ranking
    traffic = outputs["peer_traffic"].splitlines()
    assert "__SAMPLE_A__" in traffic and "__SAMPLE_B__" in traffic
    assert all(
        row in ("__SAMPLE_A__", "__SAMPLE_B__")
        or re.fullmatch(r"[^\t]+\t[^\t]+\t\d+\t\d+", row)
        for row in traffic
        if row
    )
    # iproute2 4.11 prints no bytes_sent: sampled, without rows there.
    assert insights.parse_tcp_samples(outputs["peer_traffic"])["supported"]


# A tomcat-style deployment: the GC log path runs through a directory link.
EL7_JVM = r"""
d=$(mktemp -d)
mkdir -p "$d/apache-tomcat-9/logs"
ln -s "$d/apache-tomcat-9" "$d/tomcat"
cat > "$d/apache-tomcat-9/logs/gc.log" <<'AIOPS_GC_END'
@GC@
AIOPS_GC_END
ln -s "$(command -v python)" "$d/java"
"$d/java" -c 'import time; time.sleep(120)' "-Xloggc:$d/tomcat/logs/gc.log" &
jpid=$!
i=0
while [ "$i" -lt 50 ] && [ "$(cat "/proc/$jpid/comm" 2>/dev/null)" != java ]; do
  sleep 0.2; i=$((i + 1))
done
cat > "$d/jvm.sh" <<'AIOPS_SCRIPT_END'
@JVM@
AIOPS_SCRIPT_END
printf '@@JVM\n'
sh "$d/jvm.sh" "$jpid" </dev/null
printf '@@JVMRC %s\n' "$?"
"""


@needs_image
def test_el7_gc_log_probe_follows_a_deployment_link_and_reads_the_descriptor():
    from test_procps_compat import in_container

    options = {"pid": 4242, "probes": ["gc_log"]}
    script = diagnostics.command_for("jvm", options=options)
    assert script.count("pid=4242\n") == 1
    body = EL7_JVM.replace("@GC@", "\n".join(CMS_RECORD + NOT_GC)).replace(
        "@JVM@", script.replace("pid=4242\n", 'pid="$1"\n')
    )
    # Every script changed here parses under EL7's sh (bash 4.2).
    changed = [
        diagnostics.command_for("service_detail", options={"service": "nginx"}),
        diagnostics.command_for("tcp_states"),
        diagnostics.command_for("syslog", options={}),
        diagnostics.command_for("time_sync"),
        *(text for _, text in nginx_scripts()),
    ]
    for index, text in enumerate(changed):
        body += (
            f"cat > /tmp/s{index}.sh <<'AIOPS_SCRIPT_END'\n{text}\nAIOPS_SCRIPT_END\n"
            f"if sh -n /tmp/s{index}.sh; then echo '@@SYNTAX {index} ok'; "
            f"else echo '@@SYNTAX {index} failed'; fi\n"
        )
    result = in_container(body)
    text = result.stdout
    assert "@@JVMRC 0" in text, text + result.stderr
    out = text.split("@@JVM\n", 1)[1].split("@@JVMRC", 1)[0]
    assert "Hunter" not in out and "root:" not in out, out
    summary = observations.analyze("jvm", out, options=options)["summary"]
    assert summary["probes"] == {"gc_log": "ok"}, out
    assert summary["gc_log"]["file"].endswith("/tomcat/logs/gc.log")
    assert summary["gc_log"]["lines"] == CMS_RECORD
    assert summary["gc_log"]["last_pause_ms"] == 5678.901
    assert re.findall(r"(?m)^@@SYNTAX \d+ (\w+)$", text) == ["ok"] * len(changed)


# systemd 219 has no `timedatectl show` (SSH-DIAG-16). The image has systemd
# but no running bus: a private system bus with timedated answers
# `timedatectl status` when the image can start them, otherwise the script
# must end with timedatectl's own error. Then stubs (no bus, chronyc of EL7's
# chrony 3.4) take the chronyc path under bash 4.2 and coreutils' timeout.
EL7_TIME = r"""
printf '@@VERSION %s\n' "$(timedatectl --version 2>&1 | head -n 1)"
if command -v dbus-daemon >/dev/null 2>&1 && [ -x /usr/lib/systemd/systemd-timedated ]; then
  mkdir -p /var/run/dbus
  dbus-uuidgen --ensure >/dev/null 2>&1
  dbus-daemon --system --fork >/dev/null 2>&1
  i=0
  while [ "$i" -lt 25 ] && [ ! -S /var/run/dbus/system_bus_socket ]; do sleep 0.2; i=$((i + 1)); done
  /usr/lib/systemd/systemd-timedated >/dev/null 2>&1 &
  i=0
  while [ "$i" -lt 25 ] && ! timedatectl status >/dev/null 2>&1; do sleep 0.2; i=$((i + 1)); done
fi
timedatectl show >/dev/null 2>&1
printf '@@SHOW %s\n' "$?"
timedatectl status >/dev/null 2>&1
printf '@@STATUS %s\n' "$?"
cat > /tmp/time_sync.sh <<'AIOPS_SCRIPT_END'
@SCRIPT@
AIOPS_SCRIPT_END
cat > /tmp/time_sync_raw.sh <<'AIOPS_SCRIPT_END'
@RAW@
AIOPS_SCRIPT_END
printf '@@REAL\n'
sh /tmp/time_sync.sh 2>/tmp/time_sync.err </dev/null
printf '@@RC %s\n' "$?"
sed 's/^/@@ERR /' /tmp/time_sync.err
mkdir -p /tmp/stubs
for t in date timeout cat; do ln -s "$(command -v "$t")" "/tmp/stubs/$t"; done
printf '#!/bin/sh\necho "Failed to create bus connection: No such file or directory" >&2\nexit 1\n' > /tmp/stubs/timedatectl
cat > /tmp/stubs/chronyc <<'AIOPS_STUB_END'
#!/bin/sh
cat <<'EOF'
Reference ID    : C0A80101 (192.0.2.1)
Stratum         : 3
Ref time (UTC)  : Sun Nov 01 04:00:00 2026
System time     : 0.000012345 seconds fast of NTP time
Last offset     : +0.000001234 seconds
RMS offset      : 0.000023456 seconds
Frequency       : 1.234 ppm slow
Residual freq   : +0.000 ppm
Skew            : 0.012 ppm
Root delay      : 0.001234567 seconds
Root dispersion : 0.000123456 seconds
Update interval : 64.2 seconds
Leap status     : Normal
EOF
AIOPS_STUB_END
chmod 755 /tmp/stubs/timedatectl /tmp/stubs/chronyc
printf '@@STUB\n'
PATH=/tmp/stubs /bin/sh /tmp/time_sync_raw.sh </dev/null
printf '@@STUBRC %s\n' "$?"
"""


@needs_image
def test_el7_time_sync_falls_back_from_timedatectl_show():
    from test_procps_compat import in_container

    body = EL7_TIME.replace("@SCRIPT@", diagnostics.command_for("time_sync")).replace(
        "@RAW@", operations.SCRIPTS["time_sync"]
    )
    result = in_container(body)
    text = result.stdout
    assert "systemd 219" in re.search(r"(?m)^@@VERSION (.*)$", text)[1], text
    assert re.search(r"(?m)^@@SHOW (\d+)$", text)[1] != "0"  # no show on 219
    status = re.search(r"(?m)^@@STATUS (\d+)$", text)[1]
    real = text.split("@@REAL\n", 1)[1].split("@@RC ", 1)[0]
    code = re.search(r"(?m)^@@RC (\d+)$", text)[1]
    errors = re.findall(r"(?m)^@@ERR (.*)$", text)
    summary = observations.analyze(
        "time_sync", real, status="success" if code == "0" else "partial"
    )["summary"]
    if status == "0":
        # The real `timedatectl status` of systemd 219, parsed.
        assert code == "0", text
        assert summary["sync_source"] == "timedatectl status", real
        assert summary["properties"]["NTPSynchronized"] in ("yes", "no"), real
        assert (
            "Timezone" in summary["properties"] and "LocalRTC" in summary["properties"]
        )
    else:
        # No bus: timedatectl's error is the result, not an empty success.
        assert code in ("1", "69"), text
        assert errors or "CAPABILITY_MISSING:timedatectl" in real, text
        assert summary["sync_source"] is None and summary["properties"] == {}
    stub = text.split("@@STUB\n", 1)[1].split("@@STUBRC ", 1)[0]
    assert re.search(r"(?m)^@@STUBRC 0$", text), text
    stubbed = observations.analyze("time_sync", stub)["summary"]
    assert stubbed["sync_source"] == "chronyc tracking", stub
    assert stubbed["properties"] == {"NTPSynchronized": "yes"}
    assert stubbed["chrony"]["leap_status"] == "Normal"
