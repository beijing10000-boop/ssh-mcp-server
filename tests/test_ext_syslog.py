"""syslog extension: validated options, fixed read-only script, conservative parser."""

import json
import os
import re
import shutil
import subprocess
import time

import pytest

from sshmcp import catalog, diagnostics, extensions, observations
from sshmcp.extensions import syslog

# 2026-10-29 14:00–14:30 +08:00, the window every fixture below talks about.
SINCE, UNTIL = 1793253600, 1793255400
HAS_SH = os.path.exists("/bin/sh")
HAS_AWK = shutil.which("awk") is not None


@pytest.fixture(autouse=True)
def reset_tables():
    """Pure script and parser tests: the console database and app are not needed."""
    yield


FORBIDDEN = re.compile(
    r"(?:^|[;&|({]\s*|\b(?:then|do|else)\s+)"
    r"(?:rm|mv|cp|tee|touch|mkdir|chmod|chown|kill|pkill|killall|truncate|dd)\b"
    r"|\bsystemctl\s+(?:--?[\w-]+\s+)*(?:start|stop|restart|reload|enable|disable"
    r"|reset-failed|daemon-reload|kill|mask|isolate)\b"
    r"|--vacuum|--rotate|--flush|\bsed\s+-i|short-unix|--grep|--value",
    re.M,
)


def assert_read_only(script):
    assert not FORBIDDEN.search(script), FORBIDDEN.search(script)
    # Only /dev/null redirections; awk comparisons are written with < / <=.
    assert ">" not in script.replace(">/dev/null", "").replace("2>&1", "")
    assert "timeout -k 1" in script


def options_sets(now):
    return (
        None,
        {
            "unit": "nginx.service",
            "priority": "err",
            "keyword": 'it\'s "quoted" ; | & * ?',
            "pid": 1234,
            "lines": 300,
        },
        {"priority": "debug", "minutes": 1440, "unit": "app@1"},
        {
            "priority": "emerg",
            "keyword": "-n",
            "since": now - 7200,
            "until": now - 3600,
        },
    )


def test_syslog_spec_is_registered_with_the_mcp_parameters():
    spec = extensions.spec_for("syslog")
    assert spec.tool == "ssh_diagnose_syslog" and spec.category == "服务与日志"
    assert spec.sensitive and spec.risk == "low"
    assert (spec.timeout, spec.output_limit) == (30, 49152)
    assert [p.name for p in spec.params] == [
        "minutes",
        "since",
        "until",
        "unit",
        "priority",
        "keyword",
        "pid",
        "lines",
    ]
    defaults = extensions.validate_options(spec, None)
    assert defaults["priority"] == "warning" and defaults["lines"] == 120
    assert defaults["minutes"] == 30 and defaults["unit"] is None
    entry = next(e for e in catalog.entries() if e["id"] == "syslog")
    assert entry["tool"] == "ssh_diagnose_syslog" and entry["window_required"]
    assert entry["params"][4]["choices"] == list(syslog.PRIORITIES)
    for program in (syslog.AGG_AWK, syslog.AUTH_AWK, syslog.COUNT_AWK):
        # Embedded in single quotes; comparisons never use ">".
        assert "'" not in program and ">" not in program


def test_syslog_rejects_bad_options_before_building_a_script():
    now = int(time.time())
    for bad in (
        {"unit": "nginx;reboot"},
        {"unit": "nginx service"},
        {"unit": "-nginx"},
        {"unit": "x" * 65},
        {"keyword": "`id`"},
        {"keyword": "a\\b"},
        {"keyword": "$(id)"},
        {"keyword": "line\nbreak"},
        {"keyword": ""},
        {"keyword": "../etc"},
        {"keyword": "k" * 65},
        {"priority": "warn"},
        {"priority": "WARNING"},
        {"priority": 4},
        {"lines": 19},
        {"lines": 301},
        {"lines": "120"},
        {"lines": True},
        {"pid": 0},
        {"pid": 4194305},
        {"minutes": 0},
        {"minutes": 1441},
        {"since": now - 90000, "until": now},
        {"since": now, "until": now - 1},
        {"until": now + 3600},
        {"since": now - 40 * 86400},
        {"command": "id"},
    ):
        with pytest.raises(ValueError):
            diagnostics.command_for("syslog", options=bad)
    with pytest.raises(ValueError):
        diagnostics.command_for("syslog", service="nginx")


def test_syslog_script_is_fixed_read_only_and_bounded():
    now = int(time.time())
    default, full, wide, strict = (
        diagnostics.command_for("syslog", options=options)
        for options in options_sets(now)
    )
    for script in (default, full, wide, strict):
        assert script.startswith(diagnostics.PREFIX)
        assert_read_only(script)
        assert len(script) < 16000
        for marker in ("SOURCE", "AUTH", "BOOT"):
            assert "printf '[AIOPS_" + marker + "]\\n'" in script
    window = re.search(r"WINDOW %s %s\\n' (\d+) (\d+)", default)
    since, until = int(window[1]), int(window[2])
    assert until - since == 1800 and abs(until - now) < 120
    assert f"--since @{since} --until @{until} -p warning" in default
    assert f"-r -o short-iso --until @{since} -n 1" in default
    for span in ("0..2", "3..3", "4..4"):
        assert "-p " + span in default
    assert "-u sshd -u ssh" in default and "uptime -s" in default
    assert "tail -c 20000000" in default and "tail -c 5000000" in default
    assert "-v approx=1" in default and "grep -i -F" not in default
    # Parameters reach the shell only quoted, the awk programs only via -v.
    assert "-p err -u nginx.service _PID=1234" in full
    quoted = "'it'\"'\"'s \"quoted\" ; | & * ?'"
    assert "grep -i -F -e " + quoted + " -e 'AIOPS_RC '" in full
    assert "-v kw=" + quoted in full
    assert "-v tag=nginx -v unit=nginx.service -v pid=1234 -v approx=1" in full
    assert "-p 3..3" in full and "-p 4..4" not in full
    assert "-v tag=app@1 -v unit=app@1.service" in wide and "-v approx=0" in wide
    assert "-p 0..2" in strict and "-p 3..3" not in strict
    assert "grep -i -F -e -n -e 'AIOPS_RC '" in strict


@pytest.mark.skipif(not os.path.exists("/bin/sh"), reason="needs sh")
def test_syslog_scripts_parse_under_sh():
    for options in options_sets(int(time.time())):
        script = diagnostics.command_for("syslog", options=options)
        result = subprocess.run(
            ["/bin/sh", "-n"], input=script, capture_output=True, text=True
        )
        assert result.returncode == 0, (options, result.stderr)


JOURNAL_OUTPUT = f"""[AIOPS_SOURCE]
WINDOW {SINCE} {UNTIL}
NOW {UNTIL}
JOURNAL=available
JOURNAL_COVERS_WINDOW=yes
FILES /var/log/messages /var/log/secure
[AIOPS_JOURNAL]
PRIORITY warning
2026-10-29T14:00:05+0800 web01 kernel: Out of memory: Killed process 4242 (java) total-vm:8123456kB, anon-rss:4012345kB, file-rss:0kB
2026-10-29T14:01:10+0800 web01 kernel: blk_update_request: I/O error, dev sdb, sector 123456 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 0
2026-10-29T14:01:30+0800 web01 kernel: e1000e: eth0 NIC Link is Down
2026-10-29T14:02:00+0800 web01 systemd[1]: nginx.service: Failed with result 'exit-code'.
2026-10-29T14:03:00+0800 web01 kernel: watchdog: BUG: soft lockup - CPU#2 stuck for 22s! [kworker/2:1:999]
2026-10-29T14:03:30+0800 web01 sshd[3001]: Failed password for root from 203.0.113.9 port 50022 ssh2
LINES_TOTAL 236
MATCH oom 3
MATCHLINE oom 2026-10-29T14:00:05+0800 web01 kernel: Out of memory: Killed process 4242 (java) total-vm:8123456kB
MATCH io_error 1
MATCHLINE io_error 2026-10-29T14:01:10+0800 web01 kernel: blk_update_request: I/O error, dev sdb, sector 123456
MATCH service 1
MATCHLINE service 2026-10-29T14:02:00+0800 web01 systemd[1]: nginx.service: Failed with result 'exit-code'.
MATCH kernel 1
MATCHLINE kernel 2026-10-29T14:03:00+0800 web01 kernel: watchdog: BUG: soft lockup - CPU#2 stuck for 22s!
MATCH auth 1
MATCHLINE auth 2026-10-29T14:03:30+0800 web01 sshd[3001]: Failed password for root from 203.0.113.9 port 50022 ssh2
UNIT kernel 120
UNIT nginx 80
UNIT systemd 36
FIRST_AT 2026-10-29T14:00:01+0800
LAST_AT 2026-10-29T14:03:30+0800
COUNT crit 2 0
COUNT err 57 0
COUNT warning 177 0
[AIOPS_AUTH]
AUTH_SOURCE journal
FAILED 180
INVALID 45
ACCEPTED 3
TOP_SOURCE 150 203.0.113.9
TOP_SOURCE 30 198.51.100.7
[AIOPS_BOOT]
BOOT_AT {SINCE + 400}
"""


def findings_by_metric(report):
    return {f["metric"]: f for f in report["findings"]}


def test_syslog_parses_journal_counts_classes_auth_and_reboot():
    report = observations.analyze(
        "syslog", JOURNAL_OUTPUT, options={"priority": "warning", "lines": 120}
    )
    json.dumps(report, allow_nan=False)
    summary = report["summary"]
    assert summary["source"]["journal"] == "available"
    assert summary["source"]["journal_covers_window"] is True
    assert summary["source"]["entries_from"] == "journal"
    assert summary["source"]["files_used"] == []
    assert summary["source"]["priority_approx"] is False
    assert summary["window"] == {"since": SINCE, "until": UNTIL, "host_now": UNTIL}
    assert summary["counts"] == {"total": 236, "crit": 2, "err": 57, "warning": 177}
    assert summary["top_units"][0] == {"unit": "kernel", "lines": 120}
    assert len(summary["entries"]) == 6
    assert summary["entries"][0].startswith("2026-10-29T14:00:05+0800 web01 kernel")
    assert summary["first_at"] == "2026-10-29T14:00:01+0800"
    assert summary["matched_counts"]["oom"] == 3
    assert summary["matched_counts"]["network"] == 1  # found among the entries
    assert len(summary["matched"]["oom"]) == 2  # host sample + entry, deduped
    assert summary["auth"]["available"] and summary["auth"]["failed"] == 180
    assert summary["auth"]["top_sources"][0] == {"ip": "203.0.113.9", "count": 150}
    assert summary["boot"] == {"booted_at": SINCE + 400, "rebooted_in_window": True}
    assert "journalctl" in summary["coverage"] and "236" in summary["coverage"]
    found = findings_by_metric(report)
    for name in (
        "crit_entries",
        "err_entries",
        "log_oom",
        "log_io_error",
        "auth_failures",
        "reboot_in_window",
    ):
        assert found[name]["level"] == "critical", name
    for name in ("log_service", "log_kernel", "log_network"):
        assert found[name]["level"] == "warning", name
    assert not {"journal_access", "no_entries", "window_not_covered"} & set(found)
    assert all(re.search("[一-鿿]", f["hint"]) for f in report["findings"])
    assert summary["assessment"] == "发现排查线索"
    # Fewer errors stay below the empirical err threshold of 10 / 50.
    calm = JOURNAL_OUTPUT.replace("COUNT err 57 0", "COUNT err 12 0")
    assert findings_by_metric(observations.analyze("syslog", calm))["err_entries"][
        "level"
    ] == ("warning")


FILE_OUTPUT = f"""[AIOPS_SOURCE]
WINDOW {SINCE} {UNTIL}
NOW {UNTIL}
JOURNAL=missing
FILES /var/log/messages /var/log/secure
[AIOPS_FILES]
FILE_SOURCE /var/log/messages
Oct 29 14:00:00 web01 nginx[2210]: 2026/10/29 14:00:00 [error] 2210#0: *1 connect() failed (111: Connection refused) while connecting to upstream
Oct 29 14:00:05 web01 kernel: [123456.789] Out of memory: Killed process 4242 (java) total-vm:8123456kB, anon-rss:4012345kB
Oct 29 14:02:00 web01 systemd[1]: nginx.service: Main process exited, code=exited, status=1/FAILURE
Oct 29 14:05:01 web01 app[77]: payment worker timeout calling bank api
LINES_TOTAL 4
MATCH oom 1
MATCHLINE oom Oct 29 14:00:05 web01 kernel: [123456.789] Out of memory: Killed process 4242 (java)
MATCH service 1
MATCHLINE service Oct 29 14:02:00 web01 systemd[1]: nginx.service: Main process exited, code=exited, status=1/FAILURE
UNIT app 1
UNIT kernel 1
UNIT nginx 1
UNIT systemd 1
FIRST_AT Oct 29 14:00:00
LAST_AT Oct 29 14:05:01
STARTS_AFTER_SINCE 1029140000
PRIORITY_APPROX=keyword
[AIOPS_AUTH]
AUTH_SOURCE /var/log/secure
FAILED 3
INVALID 2
ACCEPTED 1
TOP_SOURCE 3 203.0.113.9
TOP_SOURCE 1 192.0.2.44
TOP_SOURCE 1 2001:db8::5
[AIOPS_BOOT]
BOOT_AT 1790000000
"""

RFC3339_OUTPUT = f"""[AIOPS_SOURCE]
WINDOW {SINCE} {UNTIL}
NOW {UNTIL}
JOURNAL=available
JOURNAL_COVERS_WINDOW=no
FILES /var/log/syslog /var/log/auth.log /var/log/kern.log
[AIOPS_JOURNAL]
PRIORITY warning
2026-10-29T14:20:00+08:00 web02 systemd[1]: app.service: Start request repeated too quickly.
LINES_TOTAL 1
MATCH service 1
MATCHLINE service 2026-10-29T14:20:00+08:00 web02 systemd[1]: app.service: Start request repeated too quickly.
UNIT systemd 1
COUNT crit 0 0
COUNT err 1 124
COUNT warning 0 0
[AIOPS_FILES]
FILE_SOURCE /var/log/syslog
2026-10-29T14:00:01.123456+08:00 web02 kernel: [ 5000.1] nfs: server 10.0.0.5 not responding, timed out
2026-10-29T14:10:00.500000+08:00 web02 systemd[1]: app.service: Start request repeated too quickly.
2026-10-29T14:10:00.600000+08:00 web02 systemd[1]: app.service: Failed with result 'start-limit-hit'.
LINES_TOTAL 3
MATCH service 2
MATCHLINE service 2026-10-29T14:10:00.500000+08:00 web02 systemd[1]: app.service: Start request repeated too quickly.
UNIT systemd 2
UNIT kernel 1
FIRST_AT 2026-10-29T14:00:01.123456+08:00
LAST_AT 2026-10-29T14:10:00.600000+08:00
TZ_MISMATCH +0800
PRIORITY_APPROX=keyword
[AIOPS_AUTH]
AUTH_SOURCE /var/log/auth.log
FAILED 0
INVALID 0
ACCEPTED 2
[AIOPS_BOOT]
BOOT_AT 1790000000
"""


def test_syslog_parses_rsyslog_file_fallbacks():
    report = observations.analyze("syslog", FILE_OUTPUT, options={"lines": 120})
    json.dumps(report, allow_nan=False)
    summary = report["summary"]
    assert summary["source"] == {
        "journal": "missing",
        "journal_covers_window": None,
        "files_used": ["/var/log/messages", "/var/log/secure"],
        "priority_approx": True,
        "entries_from": "files",
        "files_readable": ["/var/log/messages", "/var/log/secure"],
        "files_unreadable": [],
    }
    assert summary["counts"] == {
        "total": 4,
        "crit": None,
        "err": None,
        "warning": None,
    }
    assert summary["entries"][-1].endswith("calling bank api")
    assert summary["first_at"] == "Oct 29 14:00:00"
    assert summary["auth"]["source"] == "/var/log/secure"
    assert summary["auth"]["invalid_users"] == 2
    assert summary["boot"]["rebooted_in_window"] is False
    assert "主机没有 journalctl" in summary["coverage"]
    found = findings_by_metric(report)
    assert found["log_oom"]["level"] == "critical"
    assert found["log_service"]["level"] == "warning"
    assert found["priority_approx"]["level"] == "info"
    assert found["window_not_covered"]["value"] == ["文件尾部 20MB 起点晚于窗口开始"]
    assert "crit_entries" not in found and "auth_failures" not in found
    assert "journal_access" not in found and "log_source_unavailable" not in found
    # Ubuntu RFC 3339 syslog, journal present but not reaching the window start.
    report = observations.analyze("syslog", RFC3339_OUTPUT)
    summary = report["summary"]
    assert summary["source"]["journal_covers_window"] is False
    assert summary["source"]["entries_from"] == "files"
    assert summary["source"]["files_used"] == ["/var/log/syslog", "/var/log/auth.log"]
    assert summary["counts"] == {"total": 3, "crit": 0, "err": 1, "warning": 0}
    # Journal and file report the same event: the larger count, not the sum.
    assert summary["matched_counts"]["service"] == 2
    assert summary["first_at"] == "2026-10-29T14:00:01.123456+08:00"
    found = findings_by_metric(report)
    assert found["window_not_covered"]["value"] == [
        "journal 起点晚于窗口开始",
        "文件时间戳时区 +0800 与主机不同",
    ]
    assert found["journal_query_incomplete"]["value"] == 124
    metrics = {m["metric"]: m for m in summary["metrics"]}
    assert metrics["auth_failures"]["value"] == 0
    assert metrics["auth_failures"]["level"] == "info" and "auth_failures" not in found
    assert "journal 未覆盖窗口起点" in summary["coverage"]


LIMITED_OUTPUT = f"""[AIOPS_SOURCE]
WINDOW {SINCE} {UNTIL}
NOW {UNTIL}
JOURNAL=available
CAPABILITY_MISSING:journal-permission
JOURNAL_COVERS_WINDOW=no
FILES
FILES_UNREADABLE /var/log/messages /var/log/secure
[AIOPS_JOURNAL]
PRIORITY warning
LINES_TOTAL 0
COUNT crit 0 0
COUNT err 0 0
COUNT warning 0 0
[AIOPS_FILES]
FILE_SOURCE none
CAPABILITY_MISSING:log-files
[AIOPS_AUTH]
AUTH_UNAVAILABLE
[AIOPS_BOOT]
BOOT_AT 1790000000
"""


def test_syslog_never_reports_a_blind_source_as_healthy():
    report = observations.analyze("syslog", LIMITED_OUTPUT, status="partial")
    json.dumps(report, allow_nan=False)
    summary = report["summary"]
    assert summary["source"]["journal"] == "limited"
    assert summary["source"]["journal_covers_window"] is None
    assert summary["source"]["files_unreadable"] == [
        "/var/log/messages",
        "/var/log/secure",
    ]
    # A limited journal only shows the account's own entries: no level counts.
    assert summary["counts"] == {"total": 0, "crit": None, "err": None, "warning": None}
    assert summary["auth"]["available"] is False
    found = findings_by_metric(report)
    assert found["journal_access"]["level"] == "warning"
    assert found["log_source_unavailable"]["level"] == "warning"
    assert "来源受限" in found["no_entries"]["hint"]
    assert found["collection_coverage"]["value"] == ["journal-permission", "log-files"]
    assert summary["assessment"] == "发现排查线索"
    # journalctl missing and no readable file at all.
    blind = observations.analyze(
        "syslog",
        LIMITED_OUTPUT.replace(
            "JOURNAL=available\nCAPABILITY_MISSING:journal-permission\n"
            "JOURNAL_COVERS_WINDOW=no",
            "JOURNAL=missing",
        ).replace(
            "[AIOPS_JOURNAL]\nPRIORITY warning\nLINES_TOTAL 0\n"
            "COUNT crit 0 0\nCOUNT err 0 0\nCOUNT warning 0 0\n",
            "",
        ),
    )
    assert "没有可读取的日志来源" in blind["summary"]["coverage"]
    assert blind["summary"]["counts"]["total"] is None
    assert "log_source_unavailable" in findings_by_metric(blind)
    # A readable journal that really has nothing in the window says so.
    quiet = observations.analyze(
        "syslog",
        f"[AIOPS_SOURCE]\nWINDOW {SINCE} {UNTIL}\nJOURNAL=available\n"
        "JOURNAL_COVERS_WINDOW=yes\nFILES\n[AIOPS_JOURNAL]\nPRIORITY warning\n"
        "LINES_TOTAL 0\nCOUNT crit 0 0\nCOUNT err 0 0\nCOUNT warning 0 0\n"
        "[AIOPS_AUTH]\nAUTH_SOURCE journal\nFAILED 0\nINVALID 0\nACCEPTED 0\n"
        f"[AIOPS_BOOT]\nBOOT_AT {SINCE - 86400}\n",
    )
    found = findings_by_metric(quiet)
    assert "确实没有" in found["no_entries"]["hint"]
    assert all(f["level"] == "info" for f in quiet["findings"])
    assert quiet["summary"]["counts"] == {
        "total": 0,
        "crit": 0,
        "err": 0,
        "warning": 0,
    }


def test_syslog_parser_survives_garbage_and_missing_sections():
    for text in (
        "",
        "unexpected version output\npassword=[REDACTED]",
        "[AIOPS_SOURCE]\n",
        "[AIOPS_SOURCE]\nWINDOW x y\nJOURNAL=maybe\n[AIOPS_JOURNAL]\nLINES_TOTAL x\n"
        "UNIT\nMATCH bogus 3\nMATCHLINE oom\nCOUNT crit\n[AIOPS_AUTH]\nFAILED 3\n"
        "TOP_SOURCE 1 not-an-ip\n[AIOPS_BOOT]\nBOOT_AT soon\n",
        JOURNAL_OUTPUT[:700],
        "CAPABILITY_MISSING:timeout\n",
    ):
        for options in (None, {}, {"lines": "x", "priority": 3}):
            report = observations.analyze(
                "syslog", text, status="partial", options=options
            )
            json.dumps(report, allow_nan=False)
            assert "coverage" in report["summary"]


@pytest.mark.skipif(not HAS_AWK, reason="needs awk")
def test_syslog_awk_programs_filter_files_by_window_and_count_logins():
    def agg(text, **variables):
        values = {
            "n": "120",
            "b": "16000",
            "w": "240",
            "tf": "1",
            "kw": "",
            "tag": "",
            "unit": "",
            "pid": "",
            "approx": "1",
            "sk": "1029140000",
            "uk": "1029143000",
            "tz": "+0800",
        }
        values.update(variables)
        args = ["awk"]
        for key, value in values.items():
            args += ["-v", key + "=" + value]
        result = subprocess.run(
            args + [syslog.AGG_AWK], input=text, capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr
        return result.stdout

    messages = (
        "tial line cut by tail -c\n"
        "Oct 29 13:59:59 web01 kernel: e1000e: eth0 NIC Link is Down\n"
        "Oct 29 14:00:00 web01 nginx[2210]: [error] connect() failed (111: Connection refused)\n"
        "Oct 29 14:00:05 web01 kernel: Out of memory: Killed process 4242 (java)\n"
        "Oct  9 14:01:12 web01 app[77]: single digit day error, other month\n"
        "Oct 29 14:02:00 web01 systemd[1]: nginx.service: Failed with result 'exit-code'.\n"
        "Oct 29 14:04:00 web01 crond[555]: (root) CMD (run-parts /etc/cron.hourly)\n"
        "Oct 29 14:05:00 web01 app[77]: CAPABILITY_MISSING:journal-permission spoof warn\n"
        "Oct 29 14:31:00 web01 nginx[2210]: after the window error\n"
    )
    out = agg(messages)
    lines = out.splitlines()
    assert lines[0].startswith("Oct 29 14:00:00 web01 nginx[2210]")
    assert "LINES_TOTAL 4" in lines and "MATCH oom 1" in lines
    assert "UNIT kernel 1" in lines and "PRIORITY_APPROX=keyword" in lines
    assert "FIRST_AT Oct 29 14:00:00" in lines and "LAST_AT Oct 29 14:05:00" in lines
    assert "CAPABILITY_MISSING" not in out and "after the window" not in out
    assert "cron.hourly" not in out and "Link is Down" not in out
    # unit / pid / keyword filters and the byte budget.
    unit = agg(messages, tag="nginx", unit="nginx.service", approx="0")
    assert "LINES_TOTAL 2" in unit and "UNIT nginx 1" in unit
    picked = agg(messages, pid="77", kw="SPOOF", approx="0")
    assert "LINES_TOTAL 1" in picked
    clipped = agg(messages, b="100")
    assert "ENTRIES_CLIPPED 1" in clipped
    # RFC 3339 lines (Ubuntu) with another offset than the host's.
    rfc = agg(
        "2026-10-29T13:59:00.000001+08:00 web02 systemd[1]: probe failed\n"
        "2026-10-29T14:10:00.5+08:00 web02 systemd[1]: app.service: Start request "
        "repeated too quickly.\n"
        "2026-10-29T14:40:00+08:00 web02 kernel: after window error\n",
        tz="+0000",
        sk="1029130000",
    )
    assert "LINES_TOTAL 2" in rfc and "TZ_MISMATCH +0800" in rfc
    assert "STARTS_AFTER_SINCE 1029135900" in rfc
    # Window across new year; missing date keys disable the filter loudly.
    wrap = agg(
        "Dec 31 23:49:59 h a[1]: before error\nDec 31 23:55:00 h a[1]: in error\n"
        "Jan  1 00:05:00 h b[2]: in error\nJan  1 00:15:00 h b[2]: after error\n",
        sk="1231235000",
        uk="0101001000",
    )
    assert "LINES_TOTAL 2" in wrap and "YEAR_WRAP" in wrap
    assert "NO_TIME_FILTER" in agg("Oct 29 14:00:00 h a[1]: error\n", sk="", uk="")
    # Journal stream: exit-code marker, injected markers neutralised.
    journal = agg(
        "2026-10-29T14:00:05+0800 web01 kernel: Out of memory: Killed process 1\n"
        "    continuation line\n[AIOPS_UNITS] injected\nLINES_TOTAL 99999\n"
        "\nAIOPS_RC 124\n",
        tf="0",
        jr="1",
        approx="0",
    )
    assert "LINES_TOTAL 4" in journal and "EXIT 124" in journal
    assert " [AIOPS_UNITS] injected" in journal and " LINES_TOTAL 99999" in journal
    auth = subprocess.run(
        ["awk", "-v", "tf=1", "-v", "sk=1029140000", "-v", "uk=1029143000"]
        + [syslog.AUTH_AWK],
        input=(
            "Oct 29 13:50:00 h sshd[1]: Failed password for root from 198.51.100.7 port 1 ssh2\n"
            "Oct 29 14:00:10 h sshd[2]: Invalid user admin from 203.0.113.9 port 2\n"
            "Oct 29 14:00:11 h sshd[2]: Failed password for invalid user admin from 203.0.113.9 port 2 ssh2\n"
            "Oct 29 14:00:13 h sshd[3]: Failed password for root from 192.0.2.44 port 3 ssh2\n"
            "Oct 29 14:00:20 h sshd[4]: Accepted publickey for deploy from 10.0.0.8 port 4 ssh2\n"
            "Oct 29 14:00:30 h sshd[5]: Invalid user oracle from 2001:db8::5 port 5\n"
        ),
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert auth[:3] == ["FAILED 2", "INVALID 2", "ACCEPTED 1"]
    assert auth[3] == "TOP_SOURCE 2 203.0.113.9"
    assert len(auth) == 6


@pytest.mark.skipif(not HAS_SH, reason="needs sh")
def test_syslog_script_runs_against_stub_journal(tmp_path):
    fixture = tmp_path / "journal.txt"
    fixture.write_text(
        "2026-10-29T14:00:05+0800 web01 kernel: Out of memory: Killed process 4242 (java)\n"
        "2026-10-29T14:02:01+0800 web01 nginx[2210]: [emerg] bind() to 0.0.0.0:80 failed "
        "(98: Address already in use)\n"
        "2026-10-29T14:03:00+0800 web01 kernel: BUG: soft lockup - CPU#2 stuck for 22s!\n"
    )
    stubs = {
        "id": 'case "$1" in -u) echo 0;; -nG) echo root;; esac\n',
        "uptime": 'if [ "$1" = -s ]; then echo "2026-10-01 08:00:00"; fi\n',
        "journalctl": f"""case "$*" in
*" -r "*) echo "2026-10-29T13:00:00+0800 web01 systemd[1]: probe";;
*"-p 0..2"*) echo "2026-10-29T14:00:05+0800 web01 kernel: Out of memory";;
*"-p 3..3"*) i=0; while [ "$i" -lt 12 ]; do echo "2026-10-29T14:01:00+0800 web01 app[7]: err $i"; i=$((i + 1)); done;;
*"-p 4..4"*) echo "2026-10-29T14:02:00+0800 web01 app[7]: warn";;
*"-u sshd"*) printf 'Failed password for root from 203.0.113.9 port 1 ssh2\\nInvalid user x from 203.0.113.9 port 2\\n';;
*) cat {fixture};;
esac
""",
    }
    for name, body in stubs.items():
        path = tmp_path / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)
    spec = extensions.spec_for("syslog")
    env = {"PATH": f"{tmp_path}:/usr/bin:/bin", "LC_ALL": "C"}
    for options, total in (({}, 3), ({"keyword": "ADDRESS ALREADY"}, 1)):
        options = extensions.validate_options(spec, options)
        result = subprocess.run(
            ["/bin/sh", "-c", spec.script(options)],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        report = observations.analyze("syslog", result.stdout, options=options)
        summary = report["summary"]
        assert summary["source"]["journal"] == "available", result.stdout
        assert summary["source"]["journal_covers_window"] is True
        assert summary["counts"] == {
            "total": total,
            "crit": 1,
            "err": 12,
            "warning": 1,
        }
        assert summary["auth"]["failed"] == 1 and summary["auth"]["invalid_users"] == 1
        assert (
            summary["boot"]["booted_at"] and not summary["boot"]["rebooted_in_window"]
        )
        found = findings_by_metric(report)
        assert found["crit_entries"]["level"] == "critical"
        assert found["err_entries"]["level"] == "warning"
        assert "journal_query_incomplete" not in found
    assert summary["entries"] == [
        "2026-10-29T14:02:01+0800 web01 nginx[2210]: [emerg] bind() to 0.0.0.0:80 "
        "failed (98: Address already in use)"
    ]
