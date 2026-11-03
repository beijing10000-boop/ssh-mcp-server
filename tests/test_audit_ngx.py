"""Regressions for the SSH-NGX audit fixes in the nginx and syslog extensions.

Parser tests run everywhere; the awk tests need awk and the end-to-end tests
/bin/sh (dash + mawk on CI), reusing the fake nginx install of test_ext_nginx.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile

import pytest

from sshmcp import diagnostics, extensions, observations
from sshmcp.extensions import nginx, syslog
from test_ext_nginx import (
    NOW,
    SINCE,
    _write,
    access_log_texts,
    install_fixture,
    options_for,
    run_script,
    use_fixture,
)

needs_sh = pytest.mark.skipif(not os.path.exists("/bin/sh"), reason="needs sh")
needs_awk = pytest.mark.skipif(shutil.which("awk") is None, reason="needs awk")
needs_grep = pytest.mark.skipif(shutil.which("grep") is None, reason="needs grep")
WINDOW = "WINDOW 1793316600 1793318400 20261029233000 20261030000000\n"
# 2026-10-29 14:00–14:30 +08:00, as in test_ext_syslog.
SYSLOG_SINCE, SYSLOG_UNTIL = 1793253600, 1793255400


def analyze(action, text, run_status="success", **options):
    """observations.analyze with the executor's status (options hold status=)."""
    report = observations.analyze(action, text, status=run_status, options=options)
    json.dumps(report, allow_nan=False)
    return report


def by_metric(report):
    return {finding["metric"]: finding for finding in report["findings"]}


def metric_names(report):
    return {row["metric"] for row in report["summary"]["metrics"]}


def awk(program, text, **variables):
    args = ["awk"]
    for key, value in variables.items():
        args += ["-v", f"{key}={value}"]
    # From a file: MSYS awk on Windows garbles a command-line program longer
    # than about 8 KB (ACCESS_AWK is longer); on Linux both are the same.
    with tempfile.NamedTemporaryFile(
        "w", suffix=".awk", delete=False, encoding="utf-8", newline="\n"
    ) as fh:
        fh.write(program)
    try:
        result = subprocess.run(
            args + ["-f", fh.name],
            input=text,
            capture_output=True,
            text=True,
            check=True,
        )
    finally:
        os.unlink(fh.name)
    return result.stdout.splitlines()


# --------------------------------------------------------------------------
# SSH-NGX-01: log samples lose session ids, bare pwd/pass, Basic credentials
# and personal data, in nginx and in syslog alike. The shared rules live in
# diagnostics.redact_output; nginx.redact_log reapplies them to the evidence
# lines (syslog included) and adds bare Basic/Bearer credentials.
# --------------------------------------------------------------------------

SECRETS = (
    "s3cretPwd1",
    "hunter2222",
    "letmein999",
    "ABCDEF0123456789",
    "SESS998877aa",
    "dXNlcjpwYXNzd29yZA==",
    "13812345678",
    "110101199003071234",
)


def access_with_secrets():
    clf = "[29/Oct/2026:23:40:00 +0000]"
    rows = [
        f'10.0.0.1 - - {clf} "GET /login?user=a&pwd=s3cretPwd1 HTTP/1.1" 200 5 "-" "ua"',
        f'10.0.0.2 - - {clf} "POST /api/auth?loginPwd=hunter2222&x=1 HTTP/1.1" 200 5 "-" "ua"',
        f'10.0.0.3 - - {clf} "GET /x?pass=letmein999&theme=dark HTTP/1.1" 200 5 "-" "ua"',
        f'10.0.0.4 - - {clf} "GET /app;jsessionid=ABCDEF0123456789 HTTP/1.1" 200 5 "-" "ua"',
        '{"time_local":"29/Oct/2026:23:40:01 +0000","request_uri":"/a",'
        '"sessionid":"SESS998877aa","status":200}',
        # log_format with "$http_authorization": the credential stands alone.
        f'10.0.0.5 - - {clf} "GET /b HTTP/1.1" 401 5 "-" "ua" "Basic dXNlcjpwYXNzd29yZA=="',
        f'10.0.0.6 - - {clf} "GET /user/13812345678/orders HTTP/1.1" 200 5 "-" "ua"',
        f'10.0.0.7 - - {clf} "GET /verify?id=110101199003071234 HTTP/1.1" 200 5 "-" "ua"',
    ]
    samples = "".join(f"SAMPLE {i} {row}\n" for i, row in enumerate(rows))
    return (
        "[AIOPS_FILES]\n" + WINDOW + "FILE /var/log/nginx/access.log 900 900\n"
        "[AIOPS_TOTALS]\nLINES 8 0 0\nTOTAL 8\nCLASS 2xx 7\nSELECTED 8\n"
        "[AIOPS_TOP_URI]\nTOP_URI 3 /user/13812345678/orders\n"
        "[AIOPS_SAMPLES]\n" + samples
    )


@pytest.mark.parametrize("executor_first", [True, False])
def test_access_samples_lose_sessions_passwords_and_personal_data(executor_first):
    text = access_with_secrets()
    if executor_first:  # production: the executor redacts stdout before parsing
        text = diagnostics.redact_output(text)
    report = analyze("nginx_access", text)
    dumped = json.dumps(report, ensure_ascii=False)
    for secret in SECRETS:
        assert secret not in dumped, secret
    samples = report["summary"]["samples"]
    assert len(samples) == 8
    assert "theme=dark" in samples[2] and "/user/138" in samples[6]
    assert samples[5].endswith('"Basic [REDACTED]"')
    assert report["summary"]["top"]["uris"][0]["value"].startswith("/user/138")


def test_log_layer_masks_bare_basic_and_bearer_credentials(monkeypatch):
    # nginx.redact_log on its own (the shared redact_output switched off).
    monkeypatch.setattr(diagnostics, "redact_output", lambda text: text)
    masked = {
        '"ua" "Basic dXNlcjpwYXNzd29yZA=="': '"ua" "Basic [REDACTED]"',
        "auth=Bearer abcdefghijklmnop end": "auth=Bearer [REDACTED] end",
        "upstream sent basic    QWxhZGRpbjpvcGVuIHNlc2FtZQ== header": (
            "upstream sent basic    [REDACTED] header"
        ),
    }
    for line, expected in masked.items():
        assert nginx.redact_log(line) == expected
    kept = (
        "kernel: Linux version 5.14.0, Basic realm",
        "bearer token missing; basic settings ok",
        "sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls",
        "log_format main '$remote_addr $http_authorization';",
    )
    for line in kept:
        assert nginx.redact_log(line) == line, line


def test_authorization_header_loses_the_credential_in_both_layers():
    header = "Authorization: Basic dXNlcjpwYXNzd29yZA=="
    for text in (header, diagnostics.redact_output(header)):
        assert "dXNlcjpwYXNzd29yZA==" not in nginx.redact_log(text)


def test_error_log_samples_and_tops_are_redacted_too():
    line = (
        "2026/10/29 23:41:00 [error] 1201#1201: *110 upstream timed out, client: 10.0.0.9,"
        ' request: "GET /pay?mobile=13812345678&passwd=hunter2222&sid=ABCDEF0123456789 '
        'HTTP/1.1", upstream: "http://10.0.0.21:8080/pay"'
    )
    text = (
        "[AIOPS_BIN]\nBIN /usr/sbin/nginx\n[AIOPS_ERRORS]\n"
        "WINDOW 1793316600 1793318400 2026/10/29 23:30:00 2026/10/30 00:00:00\n"
        "FILE /var/log/nginx/error.log\nLINES 1 1\nLEVEL error 1\n"
        f"TOP_REQUEST 1 GET /user/13812345678/orders\nSAMPLE 0 {line}\n"
    )
    dumped = json.dumps(analyze("nginx", text), ensure_ascii=False)
    for secret in ("13812345678", "hunter2222", "ABCDEF0123456789"):
        assert secret not in dumped, secret


def syslog_text(entries, matchlines=(), kinds=""):
    """Journal output of the default priority (warning) with an AGG block."""
    matched = ""
    for kind in dict.fromkeys(kind for kind, _ in matchlines):
        lines = [line for name, line in matchlines if name == kind]
        matched += f"MATCH {kind} {len(lines)}\n"
        matched += "".join(f"MATCHLINE {kind} {line}\n" for line in lines)
    return (
        "[AIOPS_SOURCE]\n"
        f"WINDOW {SYSLOG_SINCE} {SYSLOG_UNTIL}\nNOW {SYSLOG_UNTIL}\n"
        "JOURNAL=available\nJOURNAL_COVERS_WINDOW=yes\nFILES /var/log/messages\n"
        "[AIOPS_JOURNAL]\nPRIORITY warning\n"
        + "".join(line + "\n" for line in entries)
        + f"LINES_TOTAL {len(entries)}\n"
        + matched
        + "UNIT kernel 1\nCOUNT crit 1 0\nCOUNT err 2 0\nCOUNT warning 0 0\n"
        + kinds
        + "[AIOPS_AUTH]\nAUTH_SOURCE journal\nFAILED 0\nINVALID 0\nACCEPTED 0\n"
        f"[AIOPS_BOOT]\nBOOT_AT {SYSLOG_SINCE - 86400}\n"
    )


def test_syslog_entries_and_matched_lines_are_redacted():
    stamp = "2026-10-29T14:00:05+0800 web01"
    entries = [
        f"{stamp} app[77]: login failed mobile=13812345678 sessionid=SESS998877aa",
        f"{stamp} app[77]: proxy sent Basic dXNlcjpwYXNzd29yZA== upstream",
        f"{stamp} app[77]: id card 110101199003071234 rejected, pass=letmein999",
        f"{stamp} sudo[9]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ;"
        " COMMAND=/bin/ls",
    ]
    oom = (
        f"{stamp} kernel: Out of memory: Killed process 4242 (java)"
        " JSESSIONID=ABCDEF0123456789"
    )
    text = syslog_text(entries + [oom], [("oom", oom)])
    for raw in (text, diagnostics.redact_output(text)):
        summary = analyze("syslog", raw, priority="warning")["summary"]
        dumped = json.dumps(summary, ensure_ascii=False)
        for secret in SECRETS:
            assert secret not in dumped, secret
        assert "PWD=/home/alice" in summary["entries"][3]
        assert "Basic [REDACTED]" in summary["entries"][1]
        assert summary["matched"]["oom"] and summary["matched_counts"]["oom"] == 1


# --------------------------------------------------------------------------
# SSH-NGX-02: no readable access log is a host limit, never "no traffic".
# --------------------------------------------------------------------------


def test_access_without_a_readable_log_is_not_reported_as_no_traffic():
    missing = (
        "[AIOPS_FILES]\n" + WINDOW + "CANDIDATE /var/log/nginx/access.log\n"
        "MISSING /var/log/nginx/access.log\nNO_FILE\n"
        "CAPABILITY_MISSING:nginx-access-log\n"
    )
    report = analyze("nginx_access", missing, run_status="partial")
    found = by_metric(report)
    summary = report["summary"]
    assert found["access_log_not_found"]["level"] == "warning"
    assert found["access_log_not_found"]["value"] == {
        "missing": ["/var/log/nginx/access.log"],
        "no_access": [],
    }
    assert "不能据此判断" in found["access_log_not_found"]["hint"]
    assert found["collection_coverage"]["value"] == ["nginx-access-log"]
    assert "no_requests" not in found and "requests_total" not in metric_names(report)
    assert "totals" not in summary and "不能据此判断流量" in summary["coverage"]
    assert summary["missing"] == ["/var/log/nginx/access.log"]
    unreadable = (
        "[AIOPS_FILES]\n" + WINDOW + "NOACCESS /var/log/nginx/access.log\n"
        "CAPABILITY_MISSING:log-permission\nNO_FILE\n"
        "CAPABILITY_MISSING:nginx-access-log\n"
    )
    report = analyze("nginx_access", unreadable, run_status="partial")
    found = by_metric(report)
    assert found["access_log_not_found"]["value"]["no_access"] == [
        "/var/log/nginx/access.log"
    ]
    assert found["collection_coverage"]["value"] == [
        "log-permission",
        "nginx-access-log",
    ]
    assert "no_requests" not in found


@needs_sh
def test_access_script_without_any_log_exits_69(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    sh = install_fixture(base)
    use_fixture(monkeypatch, sh)
    for name in ("access.log", "access.log.1", "access.log.2.gz", "api.access.log"):
        (base / "logs" / name).unlink()
    options = options_for("nginx_access", since=SINCE, until=NOW)
    code, out, err = run_script(nginx.access_script(options), sh)
    assert code == 69, err
    assert "NO_FILE\nCAPABILITY_MISSING:nginx-access-log\n" in out
    assert "[AIOPS_TOTALS]" not in out
    report = analyze("nginx_access", out, run_status="partial", **options)
    found = by_metric(report)
    assert found["access_log_not_found"]["value"]["missing"] == [
        sh["logs"] + "/access.log"
    ]
    assert report["summary"]["candidates"] == [
        sh["logs"] + "/access.log",
        sh["logs"] + "/api.access.log",
    ]
    assert "no_requests" not in found


# --------------------------------------------------------------------------
# SSH-NGX-03: journal classification is not filtered by the priority.
# --------------------------------------------------------------------------

STAMP = "2026-10-29T14:0{}:{}+0800 web01"
OOM = STAMP.format(0, "05") + " kernel: Out of memory: Killed process 4242 (java)"
LINK = STAMP.format(1, "30") + " kernel: e1000e: eth0 NIC Link is Down"
LINK2 = STAMP.format(1, "31") + " kernel: igb 0000:01:00.1 eth1: NIC Link is Down"
SEGV = STAMP.format(2, "10") + " kernel: java[4242]: segfault at 0 ip 00007f3c error 4"
# Routine info lines the priority-free classification must not count.
NOISE = (
    STAMP.format(1, "40")
    + " kernel: e1000e: eth0 NIC Link is Up 1000 Mbps Full Duplex",
    STAMP.format(0, "01") + " kernel: NMI watchdog: Enabled. Permanently consumes"
    " one hw-PMU counter.",
    STAMP.format(2, "20") + " app[7]: DEBUG:root:cache miss for key 42",
    STAMP.format(2, "21") + " app[7]: DEBUG: x",
)
# Real kernel events, each matching only one kernel pattern.
KERNEL_EVENTS = (
    SEGV,
    STAMP.format(2, "30") + " kernel: BUG: unable to handle kernel NULL pointer"
    " dereference at 0000000000000008",
    STAMP.format(2, "35") + " kernel: kernel BUG at mm/slub.c:3901!",
    STAMP.format(2, "40") + " kernel: NMI watchdog: Watchdog detected hard"
    " LOCKUP on cpu 3",
)


def test_kind_patterns_tell_kernel_bugs_from_debug_and_link_up():
    # The host matches the lower-cased line; these ERE patterns read the same
    # in Python's re.
    def kind(name, line):
        return re.search(syslog.AWK_PATTERNS[name], line.lower()) is not None

    for line in KERNEL_EVENTS:
        assert kind("kernel", line), line
    for line in NOISE:
        assert not kind("kernel", line) and not kind("network", line), line
    assert kind("network", LINK) and kind("network", LINK2)


@needs_awk
@needs_grep
def test_kind_patterns_skip_routine_info_lines():
    lines = [LINK, *KERNEL_EVENTS, *NOISE]
    out = awk(
        syslog.AGG_AWK,
        "\n".join(lines) + "\n",
        n="10",
        b="16000",
        w="240",
        tf="0",
        jr="0",
        approx="0",
    )
    assert "MATCH network 1" in out
    assert f"MATCH kernel {len(KERNEL_EVENTS)}" in out
    # The kinds pass hands awk only what grep -i -E KIND_WORDS lets through.
    kept = subprocess.run(
        ["grep", "-i", "-E", "-e", syslog.KIND_WORDS],
        input="\n".join(lines) + "\n",
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert kept == [LINK, *KERNEL_EVENTS]


def test_syslog_kinds_pass_counts_info_level_events():
    kinds = (
        "[AIOPS_JOURNAL_KINDS]\n"
        f"MATCH oom 1\nMATCHLINE oom {OOM}\nMATCH network 2\nMATCHLINE network {LINK}\n"
        f"MATCHLINE network {LINK2}\nMATCH kernel 1\nMATCHLINE kernel {SEGV}\n"
    )
    # -p warning really returns only the OOM line: link-down/segfault are info.
    text = syslog_text([OOM], [("oom", OOM)], kinds)
    report = analyze("syslog", text, priority="warning")
    summary = report["summary"]
    assert summary["entries"] == [OOM]  # the priority still filters the entries
    assert summary["matched_counts"]["network"] == 2
    assert summary["matched_counts"]["kernel"] == 1
    assert summary["matched_counts"]["oom"] == 1
    assert summary["matched"]["network"] == [LINK, LINK2]
    assert "不受 priority 限制" in summary["coverage"]
    found = by_metric(report)
    assert found["log_network"]["level"] == "warning"
    assert found["log_kernel"]["level"] == "warning"
    assert "journal_query_incomplete" not in found
    # Without the kinds pass the same journal shows no link-down at all.
    blind = analyze("syslog", syslog_text([OOM], [("oom", OOM)]), priority="warning")
    assert blind["summary"]["matched_counts"]["network"] == 0
    assert "不受 priority 限制" not in blind["summary"]["coverage"]
    # A timed-out kinds pass leaves the counts partial.
    slow = analyze(
        "syslog",
        syslog_text([OOM], [("oom", OOM)], kinds + "EXIT 124\n"),
        priority="warning",
    )
    assert by_metric(slow)["journal_query_incomplete"]["value"] == 124


def test_syslog_script_adds_the_kinds_pass_below_info():
    default = syslog.script({})
    assert "printf '[AIOPS_JOURNAL_KINDS]\\n'" in default
    assert re.search(r"--until @\d+ -p info; else", default)
    assert "grep -i -E -e 'AIOPS_RC ' -e '" + syslog.KIND_WORDS + "'" in default
    assert "-v n=1 -v b=0" in default
    filtered = syslog.script(
        {"priority": "err", "unit": "nginx.service", "pid": 42, "keyword": "upstream"}
    )
    kinds = filtered.split("[AIOPS_JOURNAL_KINDS]", 1)[1].split("\n", 2)[1]
    assert "-p info -u nginx.service _PID=42" in kinds
    assert "grep -i -F -e upstream -e 'AIOPS_RC '" in kinds
    for priority in ("info", "debug"):
        # The entries already hold every info line: no second pass.
        assert "AIOPS_JOURNAL_KINDS" not in syslog.script({"priority": priority})
    # Embedded in single quotes in a script that never writes (no ">").
    assert "'" not in syslog.KIND_WORDS and ">" not in syslog.KIND_WORDS


@needs_sh
def test_syslog_script_counts_kinds_the_priority_would_hide(tmp_path):
    (tmp_path / "warning.txt").write_bytes((OOM + "\n").encode())
    info = [
        OOM,
        LINK,
        SEGV,
        STAMP.format(3, "00") + " sshd[3001]: Failed password for root from"
        " 203.0.113.9 port 50022 ssh2",
        STAMP.format(3, "10") + " systemd[1]: app.service: Main process exited,"
        " code=exited, status=1/FAILURE",
        STAMP.format(3, "20") + " app[7]: plain info line",
        *NOISE,
    ]
    (tmp_path / "info.txt").write_bytes(("\n".join(info) + "\n").encode())
    stubs = {
        "id": 'case "$1" in -u) echo 0;; -nG) echo root;; esac\n',
        "uptime": 'if [ "$1" = -s ]; then echo "2026-10-01 08:00:00"; fi\n',
        "journalctl": 'd=$(dirname "$0")\ncase "$*" in\n'
        '*" -r "*) echo "2026-10-29T13:00:00+0800 web01 systemd[1]: probe";;\n'
        '*"-p 0..2"*|*"-p 3..3"*|*"-p 4..4"*|*"-u sshd"*) ;;\n'
        '*"-p info"*) cat "$d/info.txt";;\n'
        '*) cat "$d/warning.txt";;\nesac\n',
    }
    for name, body in stubs.items():
        _write(tmp_path / name, "#!/bin/sh\n" + body, 0o755)
    options = extensions.validate_options(extensions.spec_for("syslog"), {})
    result = subprocess.run(
        ["/bin/sh", "-c", syslog.script(options)],
        capture_output=True,
        text=True,
        env={"PATH": f"{tmp_path}:/usr/bin:/bin", "LC_ALL": "C"},
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "[AIOPS_JOURNAL_KINDS]\n" in result.stdout
    report = analyze("syslog", result.stdout, **options)
    summary = report["summary"]
    assert summary["entries"] == [OOM]
    counts = summary["matched_counts"]
    assert (counts["oom"], counts["network"], counts["kernel"]) == (1, 1, 1)
    assert (counts["auth"], counts["service"]) == (1, 1)
    assert summary["matched"]["network"] == [LINK]
    found = by_metric(report)
    assert {"log_network", "log_kernel", "log_service"} <= set(found)
    assert "journal_query_incomplete" not in found


# --------------------------------------------------------------------------
# SSH-NGX-08: the level counts say they ignore the keyword.
# --------------------------------------------------------------------------


def test_syslog_level_counts_state_they_ignore_the_keyword():
    text = syslog_text([OOM], [("oom", OOM)])
    plain = analyze("syslog", text, priority="warning")
    narrowed = analyze("syslog", text, priority="warning", keyword="nginx")
    for report in (plain, narrowed):
        assert report["summary"]["counts_filters"] == {
            "total": ["priority", "unit", "pid", "keyword"],
            "levels": ["unit", "pid"],
        }
        # Same whole-window level counts with and without the keyword.
        assert report["summary"]["counts"]["crit"] == 1
    assert "keyword" not in by_metric(plain)["crit_entries"]["hint"]
    assert "未按 keyword 过滤" in by_metric(narrowed)["crit_entries"]["hint"]
    assert "不受 keyword 过滤" in narrowed["summary"]["coverage"]
    assert "不受 keyword 过滤" not in plain["summary"]["coverage"]


# --------------------------------------------------------------------------
# SSH-NGX-07: a failed or restricted ps listing never reads as "not running";
# masters survive the 40-row cap.
# --------------------------------------------------------------------------

STOPPED = "[AIOPS_BIN]\nBIN /usr/sbin/nginx\n[AIOPS_PROCESS]\n{}[AIOPS_SYSTEMD]\n"


def test_nginx_process_listing_states():
    failed = analyze("nginx", STOPPED.format("CAPABILITY_MISSING:ps-columns\n"))
    found = by_metric(failed)
    assert "nginx_inactive" not in found and "nginx_process_not_visible" not in found
    assert found["collection_coverage"]["value"] == ["ps-columns"]
    assert failed["summary"]["process_listing"] == "failed"
    assert failed["summary"]["worker_count"] is None
    assert "nginx_worker_count" not in metric_names(failed)
    limited = analyze("nginx", STOPPED.format("PS_LIMITED\n"))
    found = by_metric(limited)
    assert "nginx_inactive" not in found
    assert found["nginx_process_not_visible"]["level"] == "info"
    assert "PID 1" in found["nginx_process_not_visible"]["value"]
    assert limited["summary"]["process_listing"] == "limited"
    missing = analyze("nginx", STOPPED.format("CAPABILITY_MISSING:ps\n"))
    assert missing["summary"]["process_listing"] == "missing"
    assert "nginx_inactive" not in by_metric(missing)
    # A complete listing without a master still means "installed, not running".
    stopped = analyze("nginx", STOPPED.format(""))
    assert by_metric(stopped)["nginx_inactive"]["level"] == "critical"
    assert stopped["summary"]["process_listing"] == "ok"
    assert stopped["summary"]["worker_count"] == 0


def nginx_ps(sh, rows, args):
    """Replace the fake ps output and drop every systemd unit."""
    fix = sh["fix_dir"]
    _write(fix / "ps_full.txt", "".join(row + "\n" for row in rows))
    _write(fix / "ps_args.txt", "".join(arg + "\n" for arg in args))
    # The master lookup's `pid uid args`: every process run by root here.
    _write(
        fix / "ps_uid.txt",
        "".join(f"{900 + i} 0 {arg}\n" for i, arg in enumerate(args)),
    )
    _write(fix / "systemd.txt", "")


@needs_sh
def test_nginx_script_ps_failure_and_hidepid_are_not_inactive(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    sh = install_fixture(base)
    sh["fix_dir"] = base / "fix"
    use_fixture(monkeypatch, sh)
    # BusyBox-like ps: the column list is refused, the args-only call works.
    _write(
        base / "bin" / "ps",
        '#!/bin/sh\ncase "$*" in\n  *pid=*) echo "ps: bad -o argument" 1>&2; exit 1 ;;\n'
        "  *) exit 0 ;;\nesac\n",
        0o755,
    )
    _write(base / "fix" / "systemd.txt", "")
    code, out, err = run_script(nginx.nginx_script({"minutes": 30}), sh)
    assert code == 0, err
    assert "[AIOPS_PROCESS]\nCAPABILITY_MISSING:ps-columns\n[AIOPS_SYSTEMD]" in out
    report = analyze("nginx", out, run_status="partial", minutes=30)
    assert "nginx_inactive" not in by_metric(report)
    assert report["summary"]["process_listing"] == "failed"
    assert "ps-columns" in by_metric(report)["collection_coverage"]["value"]
    # /proc hidepid: only the account's own shell and ps are visible.
    _write(
        base / "bin" / "ps",
        '#!/bin/sh\ncase "$*" in\n'
        f"  *pid=*) cat '{sh['fix']}/ps_full.txt' ;;\n"
        f"  *) cat '{sh['fix']}/ps_args.txt' ;;\nesac\n",
        0o755,
    )
    nginx_ps(
        sh,
        [
            "   4242    4241 ops            12   3000  0.0 sh              -sh",
            "   4300    4242 ops             0   1500  0.0 ps              ps -e",
        ],
        ["-sh", "ps -eo args="],
    )
    code, out, err = run_script(nginx.nginx_script({"minutes": 30}), sh)
    assert code == 0, err
    assert "[AIOPS_PROCESS]\nPS_LIMITED\n[AIOPS_SYSTEMD]" in out
    report = analyze("nginx", out, minutes=30)
    found = by_metric(report)
    assert "nginx_inactive" not in found
    assert found["nginx_process_not_visible"]["level"] == "info"


@needs_sh
def test_nginx_script_keeps_the_master_beyond_40_workers(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    sh = install_fixture(base)
    sh["fix_dir"] = base / "fix"
    use_fixture(monkeypatch, sh)
    master = f"nginx: master process {sh['nginx']} -g daemon on;"
    # PID wrap-around: 45 workers listed before their master.
    rows = ["      1       0 root        86400  11264  0.0 systemd         /sbin/init"]
    rows += [
        f"{100 + i:>7} {30000:>7} www-data      500  50000  0.1 nginx"
        "           nginx: worker process"
        for i in range(45)
    ]
    rows.append(
        f"{30000:>7} {1:>7} root          900   8000  0.0 nginx           {master}"
    )
    nginx_ps(sh, rows, ["/sbin/init"] + ["nginx: worker process"] * 45 + [master])
    code, out, err = run_script(nginx.nginx_script({"minutes": 30}), sh)
    assert code == 0, err
    report = analyze("nginx", out, minutes=30)
    processes = report["summary"]["processes"]
    assert processes[0]["pid"] == 30000 and processes[0]["role"] == "master"
    assert len(processes) == 40 and report["summary"]["worker_count"] == 39
    assert "nginx_inactive" not in by_metric(report)
    assert report["summary"]["process_listing"] == "ok"


# --------------------------------------------------------------------------
# SSH-NGX-11: no error.log read is "unknown", not zero lines.
# --------------------------------------------------------------------------

ERRORS_HEAD = (
    "[AIOPS_ERRORS]\n"
    "WINDOW 1793316600 1793318400 2026/10/29 23:30:00 2026/10/30 00:00:00\n"
)


def test_nginx_without_a_readable_error_log_says_so():
    none = analyze("nginx", "[AIOPS_BIN]\nBIN /usr/sbin/nginx\n" + ERRORS_HEAD)
    errors = none["summary"]["errors"]
    assert errors["files"] == [] and errors["lines_in_window"] is None
    found = by_metric(none)["error_log_not_read"]
    assert found["level"] == "info" and found["value"] == "未找到 error.log 文件"
    assert "未读取到任何 error.log" in none["summary"]["coverage"]
    denied = analyze(
        "nginx",
        "[AIOPS_BIN]\nBIN /usr/sbin/nginx\n"
        + ERRORS_HEAD
        + "FILE /var/log/nginx/error.log\nNOACCESS /var/log/nginx/error.log\n"
        "CAPABILITY_MISSING:log-permission\n",
        run_status="partial",
    )
    assert denied["summary"]["errors"]["lines_in_window"] is None
    assert by_metric(denied)["error_log_not_read"]["value"] == [
        "/var/log/nginx/error.log"
    ]
    quiet = analyze(
        "nginx",
        "[AIOPS_BIN]\nBIN /usr/sbin/nginx\n"
        + ERRORS_HEAD
        + "FILE /var/log/nginx/error.log\nLINES 0 5\nNO_ENTRIES\n",
    )
    assert quiet["summary"]["errors"]["lines_in_window"] == 0
    assert "error_log_not_read" not in by_metric(quiet)
    # No nginx at all: nothing to say about its error log.
    absent = analyze("nginx", "[AIOPS_BIN]\nCAPABILITY_MISSING:nginx\n" + ERRORS_HEAD)
    assert "error_log_not_read" not in by_metric(absent)


# --------------------------------------------------------------------------
# SSH-NGX-13: the COUNT and CONFIG_TRUNCATED lines survive head -n 200.
# --------------------------------------------------------------------------


@needs_awk
@pytest.mark.parametrize("directives,servers", [(250, 0), (175, 20), (100, 150)])
def test_config_summary_keeps_counts_and_truncation_within_200_lines(
    directives, servers
):
    lines = [f"nginx: [warn] warning number {i}" for i in range(12)]
    lines.append("# configuration file /etc/nginx/nginx.conf:")
    lines += [f"listen {8000 + i};" for i in range(directives)]
    lines.append("upstream big {")
    lines += [f"server 10.0.{i // 250}.{i % 250 + 1}:80;" for i in range(servers)]
    lines.append("}")
    out = awk(nginx.CONFIG_AWK, "\n".join(lines) + "\n")
    assert len(out) <= 200  # head -n 200 drops nothing
    shown = directives + 1 + servers
    assert out[-1] == f"CONFIG_TRUNCATED {shown}"
    assert f"COUNT input_lines {len(lines)}" in out
    config = analyze("nginx", "[AIOPS_CONFIG]\n" + "\n".join(out) + "\n")
    cfg = config["summary"]["config"]
    assert cfg["truncated"] is True and cfg["input_lines_count"] == len(lines)
    assert cfg["upstream_count"] == 1


# --------------------------------------------------------------------------
# SSH-NGX-04: nginx_access follows the running master's -c like nginx does.
# --------------------------------------------------------------------------


@needs_sh
def test_access_and_status_follow_the_running_master_config(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    sh = install_fixture(base)
    use_fixture(monkeypatch, sh)
    root = sh["logs"].rsplit("/", 1)[0]
    custom_conf = sh["conf"] + "/custom.conf"
    custom_log = root + "/data/custom.access.log"
    _write(base / "data" / "custom.access.log", access_log_texts()[1], mtime=NOW - 10)
    _write(
        base / "fix" / "T_custom.txt",
        f"# configuration file {custom_conf}:\nhttp {{\n"
        f"\taccess_log {custom_log} main;\n}}\n",
    )
    _write(
        base / "fix" / "ps_args.txt",
        f"nginx: master process {sh['nginx']} -c {custom_conf}\nnginx: worker process\n",
    )
    fix = sh["fix"]
    _write(
        base / "bin" / "nginx",
        '#!/bin/sh\ncase "$1" in\n'
        f"  -V) cat '{fix}/V.txt' 1>&2 ;;\n"
        f"  -T) cat '{fix}/T_stderr.txt' 1>&2\n"
        '    case "$*" in\n'
        f"      *\"-c {custom_conf}\"*) cat '{fix}/T_custom.txt' ;;\n"
        f"      *) cat '{fix}/T.txt' ;;\n"
        "    esac ;;\n  *) exit 1 ;;\nesac\n",
        0o755,
    )
    auto = options_for("nginx_access", since=SINCE, until=NOW)
    code, out, err = run_script(nginx.access_script(auto), sh)
    assert code == 0, err
    summary = analyze("nginx_access", out, **auto)["summary"]
    assert summary["candidates"] == [custom_log]
    assert [f["path"] for f in summary["files"]] == [custom_log]
    assert summary["totals"]["requests"] == 42
    # Declared only by the running config, outside the allowed directories.
    given = options_for("nginx_access", since=SINCE, until=NOW, path=custom_log)
    code, out, err = run_script(nginx.access_script(given), sh)
    assert code == 0 and "AIOPS_REFUSED" not in out, err
    code, out, err = run_script(nginx.nginx_script({"minutes": 30}), sh)
    assert code == 0, err
    assert f"\nCONF_ARG {custom_conf}\n" in out
    status = analyze("nginx", out, minutes=30)["summary"]
    assert status["running_args"] == {"conf": custom_conf}
    assert status["config"]["access_logs"] == [custom_log]


# --------------------------------------------------------------------------
# SSH-NGX-05: a log written in another time zone is flagged, not mistaken
# for an empty window.
# --------------------------------------------------------------------------


@needs_awk
def test_access_awk_reports_the_log_offset_when_it_differs():
    clf = '10.0.0.1 - - [29/Oct/2026:23:40:00 +0000] "GET / HTTP/1.1" 200 5 "-" "ua"\n'
    iso = '{"time_iso8601":"2026-10-30T07:40:00.123+08:00","status":200}\n'
    zulu = '{"@timestamp":"2026-10-29T23:40:00.000Z","status":200}\n'
    common = {
        "skey": "20261029233000",
        "ukey": "20261030000000",
        "sel": "all",
        "topn": "10",
        "bucket": "1",
    }
    cases = (
        (clf, "+0800", "TZ_MISMATCH +0000 +0800"),
        (clf, "+0000", None),
        (clf, "", None),
        (iso, "+0800", None),
        (iso, "-0500", "TZ_MISMATCH +0800 -0500"),
        (zulu, "+0800", "TZ_MISMATCH +0000 +0800"),
        (zulu, "+0000", None),
    )
    for text, tz, expected in cases:
        out = awk(nginx.ACCESS_AWK, text, tz=tz, **common)
        flagged = [line for line in out if line.startswith("TZ_MISMATCH")]
        assert flagged == ([expected] if expected else []), (text, tz, out)


def test_access_parser_flags_a_shifted_window():
    text = (
        "[AIOPS_FILES]\n" + WINDOW + "FILE /var/log/nginx/access.log 900 900\n"
        "RANGE 20261029153000 20261029160000 /var/log/nginx/access.log\n"
        "FIRST 20261029153000 LAST 20261029160000\nTZ_MISMATCH +0000 +0800\n"
        "[AIOPS_TOTALS]\nLINES 40 0 40\nTOTAL 0\nSELECTED 0\n"
    )
    report = analyze("nginx_access", text)
    summary = report["summary"]
    assert summary["tz_mismatch"] == {
        "log_offset": "+0000",
        "host_offset": "+0800",
        "shift_seconds": -28800,
    }
    found = by_metric(report)
    assert found["log_timezone_mismatch"]["level"] == "warning"
    assert "shift_seconds" in found["log_timezone_mismatch"]["hint"]
    assert "时区" in found["no_requests"]["hint"]
    assert "确实没有流量" not in found["no_requests"]["hint"]
    assert "tz_mismatch" in summary["coverage"]


@needs_sh
def test_access_script_passes_the_host_offset_to_awk(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    sh = install_fixture(base)
    use_fixture(monkeypatch, sh)
    _write(
        base / "bin" / "date",
        f'#!/bin/sh\nif [ "$1" = "+%s" ]; then echo {NOW}; exit 0; fi\n'
        'if [ "$1" = "+%z" ]; then echo +0800; exit 0; fi\n'
        'for d in /usr/bin/date /bin/date; do [ -x "$d" ] && exec "$d" "$@"; done\n'
        "exit 1\n",
        0o755,
    )
    options = options_for(
        "nginx_access", since=SINCE, until=NOW, path=sh["logs"] + "/access.log"
    )
    code, out, err = run_script(nginx.access_script(options), sh)
    assert code == 0, err
    assert "\nTZ_MISMATCH +0000 +0800\n[AIOPS_TOTALS]\n" in out
    report = analyze("nginx_access", out, **options)
    assert report["summary"]["tz_mismatch"]["shift_seconds"] == -28800
    assert by_metric(report)["log_timezone_mismatch"]["level"] == "warning"
    assert report["summary"]["totals"]["requests"] == 44
