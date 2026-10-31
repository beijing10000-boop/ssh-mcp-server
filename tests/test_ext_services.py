"""service_detail / service_map: validated options, read-only scripts, parsers."""

import json
import os
import re
import shutil
import subprocess

import pytest

from sshmcp import catalog, diagnostics, extensions, observations
from sshmcp.extensions import services

SINCE, UNTIL = 1793253600, 1793255400  # 2026-10-29 14:00–14:30 +08:00
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
    r"|reset-failed|daemon-reload|kill|mask|isolate|edit|set-property)\b"
    r"|--vacuum|--rotate|--flush|\bsed\s+-i|--value",
    re.M,
)


def assert_read_only(script):
    assert not FORBIDDEN.search(script), FORBIDDEN.search(script)
    assert ">" not in script.replace(">/dev/null", "").replace("2>&1", "")
    assert "timeout -k 1" in script


def findings_by_metric(report):
    return {f["metric"]: f for f in report["findings"]}


DETAIL_OPTIONS = (
    {"service": "nginx.service"},
    {"service": "app@1", "minutes": 1440},
    {"service": "a"},
)


def test_service_specs_are_registered_with_the_mcp_parameters():
    detail = extensions.spec_for("service_detail")
    assert detail.tool == "ssh_diagnose_service_detail"
    assert (detail.category, detail.sensitive, detail.risk) == (
        "服务与日志",
        True,
        "low",
    )
    assert (detail.timeout, detail.output_limit) == (25, 49152)
    assert [(p.name, p.required, p.default) for p in detail.params] == [
        ("service", True, None),
        ("minutes", False, 30),
    ]
    assert (detail.params[1].minimum, detail.params[1].maximum) == (1, 1440)
    mapping = extensions.spec_for("service_map")
    assert mapping.tool == "ssh_diagnose_service_map" and mapping.params == ()
    assert (mapping.category, mapping.sensitive, mapping.risk) == ("网络", False, "low")
    assert (mapping.timeout, mapping.output_limit) == (15, 32768)
    entries = {e["id"]: e for e in catalog.entries()}
    assert entries["service_detail"]["service_required"]
    assert (
        entries["service_map"]["params"] == [] and entries["service_map"]["extension"]
    )
    for name in (
        "HEAD_AWK",
        "TAIL_AWK",
        "PORT_AWK",
        "HISTORY_AWK",
        "LISTEN_AWK",
        "PIDS_AWK",
        "CGROUP_AWK",
        "JOIN_AWK",
    ):
        program = getattr(services, name)
        assert "'" not in program and ">" not in program, name


def test_service_options_are_validated_before_any_script():
    for bad in (
        None,
        {},
        {"service": "nginx;reboot"},
        {"service": "nginx service"},
        {"service": "-nginx"},
        {"service": "../etc/passwd"},
        {"service": "$(id)"},
        {"service": "x" * 65},
        {"service": "nginx", "minutes": 0},
        {"service": "nginx", "minutes": 1441},
        {"service": "nginx", "minutes": "30"},
        {"service": "nginx", "since": SINCE},
    ):
        with pytest.raises(ValueError):
            diagnostics.command_for("service_detail", options=bad)
    with pytest.raises(ValueError):
        diagnostics.command_for("service_detail", service="nginx")
    with pytest.raises(ValueError):
        diagnostics.command_for("service_map", options={"service": "nginx"})


def test_service_scripts_are_fixed_and_read_only():
    nginx, instance, short = (
        diagnostics.command_for("service_detail", options=options)
        for options in DETAIL_OPTIONS
    )
    mapping = diagnostics.command_for("service_map")
    for script in (nginx, instance, short, mapping):
        assert script.startswith(diagnostics.PREFIX)
        assert_read_only(script)
        assert len(script) < 12000
    assert "CAPABILITY_MISSING:systemctl" in nginx and "exit 69" in nginx
    assert (
        "systemctl show --no-pager -p " + services.SHOW_PROPERTIES + ","
    ) in nginx and " -- nginx.service" in nginx
    assert "systemctl cat -- nginx.service" in nginx
    assert "cgroup.procs" in nginx and "/sys/fs/cgroup/systemd$cg" in nginx
    assert (
        "ps -o pid= -o ppid= -o user:32= -o etimes= -o rss= -o pcpu= -o nlwp= -o comm="
    ) in nginx
    assert "ss -ltnup" in nginx and "ss -ltnupH" not in nginx
    assert "journal-permission" in nginx and '-u "$id" --since @' in nginx
    assert '_PID=1 "UNIT=$id" + "COREDUMP_UNIT=$id"' in nginx
    window = re.search(r"WINDOW %s %s\\n' (\d+) (\d+)", nginx)
    assert int(window[2]) - int(window[1]) == 1800
    assert f"--since @{int(window[2]) - 86400} --until @{window[2]}" in nginx
    assert "id=app@1.service" in instance and " -- app@1" in instance
    assert "id=a.service" in short
    assert "CAPABILITY_MISSING:ss" in mapping and "PROCESS_UNAVAILABLE" in mapping
    assert "/proc/$p/cgroup" in mapping and "/proc/$p/comm" in mapping


@pytest.mark.skipif(not os.path.exists("/bin/sh"), reason="needs sh")
def test_service_scripts_parse_under_sh():
    scripts = [
        diagnostics.command_for("service_detail", options=options)
        for options in DETAIL_OPTIONS
    ] + [diagnostics.command_for("service_map")]
    for script in scripts:
        result = subprocess.run(
            ["/bin/sh", "-n"], input=script, capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr


HEALTHY = f"""[AIOPS_SHOW]
Id=nginx.service
Description=The nginx HTTP and reverse proxy server
LoadState=loaded
UnitFileState=enabled
ActiveState=active
SubState=running
Result=success
MainPID=1234
ExecMainPID=1234
ExecMainStartTimestamp=Wed 2026-10-28 14:03:21 CST
ExecMainExitTimestamp=
ExecMainCode=0
ExecMainStatus=0
NRestarts=0
Restart=on-failure
RestartUSec=100ms
TimeoutStartUSec=1min 30s
TimeoutStopUSec=5s
MemoryCurrent=[not set]
MemoryMax=infinity
MemoryLimit=infinity
TasksCurrent=18446744073709551615
TasksMax=infinity
CPUUsageNSec=[not set]
ActiveEnterTimestamp=Wed 2026-10-28 14:03:21 CST
InactiveEnterTimestamp=
StateChangeTimestamp=Wed 2026-10-28 14:03:21 CST
ExecStart={{ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -g daemon on; master_process on; ; ignore_errors=no ; start_time=[Wed 2026-10-28 14:03:21 CST] ; stop_time=[n/a] ; pid=1234 ; code=(null) ; status=0/0 }}
ExecStartPre={{ path=/usr/bin/rm ; argv[]=/usr/bin/rm -f /run/nginx.pid ; ignore_errors=no ; start_time=[Wed 2026-10-28 14:03:20 CST] ; stop_time=[Wed 2026-10-28 14:03:20 CST] ; pid=1230 ; code=exited ; status=0 }}
ExecStartPre={{ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -t ; ignore_errors=no ; start_time=[Wed 2026-10-28 14:03:20 CST] ; stop_time=[Wed 2026-10-28 14:03:21 CST] ; pid=1231 ; code=exited ; status=0 }}
User=
Group=
WorkingDirectory=
FragmentPath=/usr/lib/systemd/system/nginx.service
DropInPaths=/etc/systemd/system/nginx.service.d/limits.conf /run/systemd/system/nginx.service.d/50-cpu.conf
LimitNOFILE=1024
ControlGroup=/system.slice/nginx.service
StatusText=
Type=forking
KillMode=process
ExecMainStartTimestampMonotonic=86400000000
ExecMainExitTimestampMonotonic=0
ActiveEnterTimestampMonotonic=86400000000
InactiveEnterTimestampMonotonic=0
[AIOPS_CLOCK]
NOW {UNTIL}
UPTIME 172800.42
WINDOW {SINCE} {UNTIL}
[AIOPS_CAT]
[Unit]
Description=The nginx HTTP and reverse proxy server
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target
[Service]
Type=forking
ExecStartPre=/usr/bin/rm -f /run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/usr/sbin/nginx -s reload
KillMode=process
Environment="DB_PASSWORD=hunter2 two" API_TOKEN=abc123 LANG=C
Environment=TZ=Asia/Shanghai
EnvironmentFile=-/etc/sysconfig/nginx
[Install]
WantedBy=multi-user.target
[AIOPS_PROCS]
PROCS_SOURCE /sys/fs/cgroup/system.slice/nginx.service/cgroup.procs
   1234       1 root                       86400   2348  0.0     1 nginx
   1235    1234 nginx                      86400   9472  0.3     1 nginx
[AIOPS_PORTS]
tcp   LISTEN 0      511          0.0.0.0:80        0.0.0.0:*    users:(("nginx",pid=1235,fd=6),("nginx",pid=1234,fd=6))
tcp   LISTEN 0      511             [::]:80           [::]:*    users:(("nginx",pid=1235,fd=7),("nginx",pid=1234,fd=7))
[AIOPS_JOURNAL]
2026-10-29T14:05:00+0800 web01 nginx[1235]: 2026/10/29 14:05:00 [warn] 1235#1235: *77 an upstream response is buffered to a temporary file
[AIOPS_HISTORY]
H started 2026-10-28T14:03:21+0800 web01 systemd[1]: Started The nginx HTTP and reverse proxy server.
HCOUNT starts 1
HCOUNT failures 0
HCOUNT restarts 0
HCOUNT oom 0
HCOUNT start_limit 0
"""


def test_service_detail_parses_a_healthy_unit_without_findings():
    report = observations.analyze(
        "service_detail", HEALTHY, options={"service": "nginx", "minutes": 30}
    )
    json.dumps(report, allow_nan=False)
    summary = report["summary"]
    unit = summary["unit"]
    assert (unit["id"], unit["load"], unit["active"], unit["sub"]) == (
        "nginx.service",
        "loaded",
        "active",
        "running",
    )
    assert unit["main_pid"] == 1234 and unit["exit_code"] is None
    assert unit["exit_status"] == 0 and unit["restarts"] == 0
    assert unit["restart_policy"] == "on-failure" and unit["restart_delay"] == "100ms"
    assert unit["timeout_start"] == "1min 30s" and unit["type"] == "forking"
    # "[not set]", "infinity", 18446744073709551615 and "" all mean unknown.
    for key in (
        "memory_bytes",
        "memory_max",
        "tasks",
        "tasks_max",
        "cpu_seconds",
        "inactive_since",
        "exited_at",
        "user",
        "group",
        "cwd",
        "status_text",
    ):
        assert unit[key] is None, key
    assert unit["exec_start"] == "/usr/sbin/nginx -g daemon on; master_process on;"
    assert unit["exec_start_pre"] == [
        "/usr/bin/rm -f /run/nginx.pid",
        "/usr/sbin/nginx -t",
    ]
    assert unit["drop_ins"] == [
        "/etc/systemd/system/nginx.service.d/limits.conf",
        "/run/systemd/system/nginx.service.d/50-cpu.conf",
    ]
    assert unit["limit_nofile"] == 1024 and unit["kill_mode"] == "process"
    assert unit["started_epoch"] == UNTIL - 172800 + 86400
    lines = summary["unit_file"]["lines"]
    assert "Environment=DB_PASSWORD=[REDACTED] API_TOKEN=[REDACTED] LANG=C" in lines
    assert "Environment=TZ=Asia/Shanghai" in lines and "hunter2" not in json.dumps(
        report
    )
    assert summary["unit_file"]["environment_files"] == ["-/etc/sysconfig/nginx"]
    assert [p["pid"] for p in summary["processes"]] == [1234, 1235]
    assert summary["processes"][1] == {
        "pid": 1235,
        "ppid": 1234,
        "user": "nginx",
        "elapsed_seconds": 86400,
        "rss_KiB": 9472,
        "cpu_percent": 0.3,
        "threads": 1,
        "name": "nginx",
    }
    assert summary["listening"] == [
        {"proto": "tcp", "address": "0.0.0.0", "port": 80, "pid": 1234},
        {"proto": "tcp", "address": "::", "port": 80, "pid": 1234},
    ]
    assert summary["ports_available"] is True
    assert summary["journal"]["journal_access"] == "available"
    assert (
        len(summary["journal"]["entries"]) == 1 and summary["journal"]["matched"] == {}
    )
    assert summary["history"] == [
        {
            "time": "2026-10-28T14:03:21+0800",
            "kind": "started",
            "line": "2026-10-28T14:03:21+0800 web01 systemd[1]: Started The nginx HTTP "
            "and reverse proxy server.",
        }
    ]
    assert summary["counts"] == {"restarts_24h": 0, "failures_24h": 0, "starts_24h": 1}
    assert "不重启" in summary["coverage"]
    assert report["findings"] == []


RESTART_LOOP = f"""[AIOPS_SHOW]
Id=billing.service
Description=Billing API
LoadState=loaded
UnitFileState=enabled
ActiveState=activating
SubState=auto-restart
Result=exit-code
MainPID=0
ExecMainPID=4321
ExecMainStartTimestamp=Thu 2026-10-29 14:20:00 CST
ExecMainExitTimestamp=Thu 2026-10-29 14:20:03 CST
ExecMainCode=1
ExecMainStatus=1
Restart=always
RestartUSec=5s
TimeoutStartUSec=1min 30s
TimeoutStopUSec=1min 30s
MemoryCurrent=18446744073709551615
MemoryLimit=18446744073709551615
ActiveEnterTimestamp=Thu 2026-10-29 13:10:00 CST
InactiveEnterTimestamp=Thu 2026-10-29 14:20:03 CST
ExecStart={{ path=/usr/bin/java ; argv[]=/usr/bin/java -Xmx2g -Dspring.datasource.password=s3cret -jar /opt/billing/app.jar --api-key=k123 ; ignore_errors=no ; start_time=[Thu 2026-10-29 14:20:00 CST] ; stop_time=[Thu 2026-10-29 14:20:03 CST] ; pid=4321 ; code=exited ; status=1/FAILURE }}
User=billing
Group=billing
WorkingDirectory=/opt/billing
FragmentPath=/etc/systemd/system/billing.service
DropInPaths=
LimitNOFILE=4096
ControlGroup=/system.slice/billing.service
Type=simple
KillMode=control-group
ExecMainStartTimestampMonotonic=599400000000
[AIOPS_CLOCK]
NOW {UNTIL}
UPTIME 600000.11
WINDOW {SINCE} {UNTIL}
[AIOPS_CAT]
[Service]
User=billing
ExecStart=/usr/bin/java -Xmx2g -jar /opt/billing/app.jar
Restart=always
RestartSec=5
[AIOPS_PROCS]
PROCS_NONE
[AIOPS_PORTS]
PORTS_UNAVAILABLE no-process
[AIOPS_JOURNAL]
2026-10-29T14:20:03+0800 web01 java[4321]: Exception in thread "main" java.lang.OutOfMemoryError: Java heap space
2026-10-29T14:20:03+0800 web01 systemd[1]: billing.service: main process exited, code=exited, status=1/FAILURE
2026-10-29T14:20:03+0800 web01 systemd[1]: Unit billing.service entered failed state.
2026-10-29T14:20:03+0800 web01 systemd[1]: billing.service failed.
[AIOPS_HISTORY]
H exited 2026-10-29T14:15:03+0800 web01 systemd[1]: billing.service: main process exited, code=exited, status=1/FAILURE
H failed 2026-10-29T14:15:03+0800 web01 systemd[1]: Unit billing.service entered failed state.
H restart_scheduled 2026-10-29T14:15:08+0800 web01 systemd[1]: billing.service holdoff time over, scheduling restart.
H exited 2026-10-29T14:20:03+0800 web01 systemd[1]: billing.service: main process exited, code=exited, status=1/FAILURE
H failed 2026-10-29T14:20:03+0800 web01 systemd[1]: Unit billing.service entered failed state.
HCOUNT starts 4
HCOUNT failures 4
HCOUNT restarts 4
HCOUNT oom 0
HCOUNT start_limit 0
"""


def detail(text):
    report = observations.analyze("service_detail", text, options={"service": "x"})
    json.dumps(report, allow_nan=False)
    return report


def test_service_detail_flags_failures_restarts_oom_limits_and_pressure():
    report = detail(RESTART_LOOP)
    found = findings_by_metric(report)
    unit = report["summary"]["unit"]
    assert unit["restarts"] is None and unit["main_pid"] is None  # systemd 219
    assert unit["exit_code"] == "exited" and unit["exit_status"] == 1
    assert unit["exec_start"] == (
        "/usr/bin/java -Xmx2g -Dspring.datasource.password=[REDACTED] "
        "-jar /opt/billing/app.jar --api-key=[REDACTED]"
    )
    assert unit["user"] == "billing" and unit["cwd"] == "/opt/billing"
    assert report["summary"]["ports_available"] is False
    assert report["summary"]["counts"] == {
        "restarts_24h": 4,
        "failures_24h": 4,
        "starts_24h": 4,
    }
    assert [h["kind"] for h in report["summary"]["history"]][:3] == [
        "exited",
        "failed",
        "restart_scheduled",
    ]
    assert found["service_failed"]["level"] == "critical"
    assert found["service_failed"]["value"] == "activating/exit-code"
    assert found["restart_loop"]["level"] == "critical"
    assert found["restart_loop"]["value"] == {"NRestarts": None, "restarts_24h": 4}
    assert found["recent_restart"]["level"] == "warning"
    assert found["exit_nonzero"]["value"] == 1
    # A Java OutOfMemoryError is not the kernel OOM killer.
    assert not {"oom_killed", "start_limit_hit", "unit_not_found"} & set(found)

    base = RESTART_LOOP.split("[AIOPS_CAT]")[0]
    oom = detail(
        base.replace("ActiveState=activating", "ActiveState=failed")
        .replace("SubState=auto-restart", "SubState=failed")
        .replace("Result=exit-code", "Result=oom-kill")
        .replace("ExecMainCode=1", "ExecMainCode=2")
        .replace("ExecMainStatus=1", "ExecMainStatus=9")
        + "[AIOPS_JOURNAL]\nCAPABILITY_MISSING:journal-permission\n"
        "[AIOPS_HISTORY]\nHCOUNT starts 0\nHCOUNT failures 0\nHCOUNT restarts 0\n"
        "HCOUNT oom 0\nHCOUNT start_limit 0\n"
    )
    found = findings_by_metric(oom)
    assert found["oom_killed"]["level"] == "critical"
    assert found["oom_killed"]["value"] == "oom-kill"
    assert found["service_failed"]["value"] == "failed/oom-kill"
    assert found["journal_access"]["level"] == "warning"
    assert oom["summary"]["unit"]["exit_code"] == "killed"
    assert oom["summary"]["journal"]["journal_access"] == "limited"
    assert "exit_nonzero" not in found and "restart_loop" not in found

    limited = detail(
        base.replace("Result=exit-code", "Result=start-limit-hit").replace(
            "ActiveState=activating", "ActiveState=failed"
        )
    )
    found = findings_by_metric(limited)
    assert found["start_limit_hit"]["value"] == "start-limit-hit"
    assert "reset-failed" in found["start_limit_hit"]["hint"]
    history_hit = detail(
        HEALTHY.replace("HCOUNT start_limit 0", "HCOUNT start_limit 1").replace(
            "[AIOPS_HISTORY]\n",
            "[AIOPS_HISTORY]\nH start_limit 2026-10-29T14:10:00+0800 web01 systemd[1]: "
            "nginx.service: Start request repeated too quickly.\n",
        )
    )
    assert findings_by_metric(history_hit)["start_limit_hit"]["value"] == 1

    pressure = detail(
        HEALTHY.replace("MemoryCurrent=[not set]", "MemoryCurrent=1019215872")
        .replace("MemoryMax=infinity", "MemoryMax=1073741824")
        .replace("TasksCurrent=18446744073709551615", "TasksCurrent=4800")
        .replace("TasksMax=infinity", "TasksMax=4915")
        .replace("CPUUsageNSec=[not set]", "CPUUsageNSec=987654321000")
        .replace("NRestarts=0", "NRestarts=5")
        .replace("Result=success", "Result=timeout")
    )
    found = findings_by_metric(pressure)
    assert found["memory_near_max"]["value"] == 94.9
    assert found["tasks_near_max"]["value"] == 97.7
    assert found["restart_loop"]["value"]["NRestarts"] == 5
    assert found["start_timeout"]["level"] == "critical"
    metrics = {m["metric"]: m["value"] for m in pressure["summary"]["metrics"]}
    assert metrics["memory_percent_of_max"] == 94.9
    assert pressure["summary"]["unit"]["cpu_seconds"] == 987.654

    ghost = detail(
        "[AIOPS_SHOW]\nId=ghost.service\nDescription=ghost.service\nLoadState=not-found\n"
        "UnitFileState=\nActiveState=inactive\nSubState=dead\nResult=success\n"
        "MainPID=0\nNRestarts=0\nExecMainStatus=0\n[AIOPS_CAT]\n[AIOPS_PROCS]\n"
        "PROCS_NONE\n[AIOPS_PORTS]\nPORTS_UNAVAILABLE no-process\n[AIOPS_JOURNAL]\n"
        "[AIOPS_HISTORY]\nHCOUNT starts 0\n"
    )
    assert [f["metric"] for f in ghost["findings"]] == ["unit_not_found"]
    assert "不能据此判定服务已停止" in ghost["findings"][0]["hint"]
    stopped = detail(
        HEALTHY.replace("ActiveState=active", "ActiveState=inactive").replace(
            "SubState=running", "SubState=dead"
        )
    )
    assert [f["metric"] for f in stopped["findings"]] == ["service_inactive"]
    missing = detail("CAPABILITY_MISSING:systemctl\n")
    assert "没有 systemctl" in missing["summary"]["coverage"]
    assert {f["metric"] for f in missing["findings"]} == {"collection_coverage"}


def test_service_detail_survives_garbage():
    for text in (
        "",
        "unexpected version output\npassword=[REDACTED]",
        "[AIOPS_SHOW]\nNRestarts=many\nMemoryCurrent=-1\nMemoryMax=0\nTasksMax=0\n"
        "ExecStart={ path=/x ; argv[]=\n[AIOPS_CLOCK]\nNOW soon\nUPTIME x\n"
        "[AIOPS_PROCS]\n1 2 3\n[AIOPS_PORTS]\ntcp LISTEN 0 1 :::x *:* users:((\n"
        "[AIOPS_HISTORY]\nH bogus\nH weird line\nHCOUNT starts x\n",
        HEALTHY[:900],
    ):
        for options in (None, {}, {"service": "x", "minutes": "y"}):
            report = observations.analyze(
                "service_detail", text, status="partial", options=options
            )
            json.dumps(report, allow_nan=False)
            assert "coverage" in report["summary"]


MAP_OUTPUT = """[AIOPS_LISTEN]
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*    users:(("systemd-resolve",pid=600,fd=13))
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*    users:(("nginx",pid=1235,fd=6),("nginx",pid=1234,fd=6))
tcp   LISTEN 0      511             [::]:80            [::]:*    users:(("nginx",pid=1235,fd=7),("nginx",pid=1234,fd=7))
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=900,fd=3))
tcp   LISTEN 0      4096               *:8080             *:*    users:(("java",pid=2000,fd=50))
tcp   LISTEN 0      4096       127.0.0.1:8080       0.0.0.0:*    users:(("envoy",pid=3000,fd=20))
tcp   LISTEN 0      100        127.0.0.1:25         0.0.0.0:*    users:(("master",3100,13))
tcp   LISTEN 0      511        127.0.0.1:6379       0.0.0.0:*
[AIOPS_PIDS]
PID 600 systemd-resolve systemd-resolve 99999 12000 systemd-resolved.service -
PID 1235 nginx nginx 86000 9472 nginx.service -
PID 1234 nginx root 86000 2348 nginx.service -
PID 900 sshd root 99999 7000 sshd.service -
PID 2000 java app 3600 2048000 - 0123456789ab
PID 3000 envoy envoy 3600 50000 - fedcba987654
PID 3100 master root 99999 4000 postfix.service -
"""


def test_service_map_joins_ports_processes_units_and_containers():
    report = observations.analyze("service_map", MAP_OUTPUT)
    json.dumps(report, allow_nan=False)
    summary = report["summary"]
    assert [(r["proto"], r["port"]) for r in summary["listeners"]] == [
        ("tcp", 22),
        ("tcp", 25),
        ("udp", 53),
        ("tcp", 80),
        ("tcp", 80),
        ("tcp", 6379),
        ("tcp", 8080),
        ("tcp", 8080),
    ]
    web = summary["listeners"][3]
    assert web == {
        "proto": "tcp",
        "address": "0.0.0.0",
        "port": 80,
        "pid": 1234,
        "process": "nginx",
        "user": "root",
        "unit": "nginx.service",
        "container": None,
        "elapsed_seconds": 86000,
        "rss_KiB": 2348,
    }
    assert summary["listeners"][1]["process"] == "master"  # old iproute2 format
    assert summary["listeners"][6]["container"] == "0123456789ab"
    assert summary["by_unit"] == {
        "container:0123456789ab": [8080],
        "container:fedcba987654": [8080],
        "nginx.service": [80],
        "postfix.service": [25],
        "sshd.service": [22],
        "systemd-resolved.service": [53],
    }
    assert summary["ports_without_process"] == [6379]
    assert summary["process_info_available"] is True
    found = findings_by_metric(report)
    assert found["duplicate_port"]["value"] == ["tcp/8080: envoy/java"]
    assert found["duplicate_port"]["level"] == "info"
    assert "process_info_unavailable" not in found and "many_listeners" not in found
    # A non-root account sees the sockets but not who owns them.
    plain = re.sub(r"\s+users:\(\(.*", "", MAP_OUTPUT.split("[AIOPS_PIDS]")[0])
    report = observations.analyze(
        "service_map", plain + "[AIOPS_PIDS]\nPROCESS_UNAVAILABLE\n"
    )
    summary = report["summary"]
    assert summary["process_info_available"] is False
    assert summary["ports_without_process"] == [22, 25, 53, 80, 6379, 8080]
    assert summary["by_unit"] == {}
    assert findings_by_metric(report)["process_info_unavailable"]["level"] == "info"
    many = "[AIOPS_LISTEN]\n" + "".join(
        f'tcp LISTEN 0 128 0.0.0.0:{port} 0.0.0.0:* users:(("app",pid={port},fd=3))\n'
        for port in range(9000, 9065)
    )
    report = observations.analyze("service_map", many)
    assert findings_by_metric(report)["many_listeners"]["value"] == 65
    assert len(report["summary"]["listeners"]) == 65
    for text in ("", "garbage\n[AIOPS_LISTEN]\ntcp\n[AIOPS_PIDS]\nPID x\n"):
        json.dumps(observations.analyze("service_map", text, status="partial"))


@pytest.mark.skipif(not HAS_AWK, reason="needs awk")
def test_service_awk_programs_with_fixtures():
    def awk(program, text, **variables):
        args = ["awk"]
        for key, value in variables.items():
            args += ["-v", f"{key}={value}"]
        result = subprocess.run(
            args + [program], input=text, capture_output=True, text=True
        )
        assert result.returncode == 0, result.stderr
        return result.stdout.splitlines()

    ss = MAP_OUTPUT.split("[AIOPS_PIDS]")[0].replace("[AIOPS_LISTEN]\n", "")
    header = "Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n"
    listen = awk(services.LISTEN_AWK, header + ss, n=120, b=20000, w=220)
    assert len(listen) == 8 and listen[0].startswith("udp")
    assert len(awk(services.LISTEN_AWK, header + ss, n=2, b=20000, w=60)) == 2
    pids = awk(services.PIDS_AWK, ss)
    assert pids == ["600", "1235", "1234", "900", "2000", "3000", "3100"]
    ports = awk(services.PORT_AWK, ss, pl="1234,3100")
    assert len(ports) == 3 and "pid=1234," in ports[0] and '"master",3100,' in ports[2]
    for cgroup, expected in (
        ("0::/system.slice/nginx.service\n", "nginx.service -"),
        (
            "12:pids:/system.slice/sshd.service\n1:name=systemd:/system.slice/sshd.service\n",
            "sshd.service -",
        ),
        (
            "0::/system.slice/docker-" + "0123456789abcdef" * 4 + ".scope\n",
            "- 0123456789ab",
        ),
        ("4:memory:/docker/" + "fedcba9876543210" * 4 + "\n", "- fedcba987654"),
        (
            "1:name=systemd:/system.slice/containerd.service/kubepods-pod1.slice:"
            "cri-containerd:" + "1111222233334444" * 4 + "\n",
            "- 111122223333",
        ),
        ("0::/user.slice/user-1000.slice/session-3.scope\n", "- -"),
        ("", "- -"),
    ):
        assert awk(services.CGROUP_AWK, cgroup) == [expected], cgroup
    joined = awk(
        services.JOIN_AWK,
        "P 1234 root 3600 5120\nX 1234 nginx nginx.service -\n"
        "X 2000 java - 0123456789ab\n",
    )
    assert joined == [
        "PID 1234 nginx root 3600 5120 nginx.service -",
        "PID 2000 java - - - - 0123456789ab",
    ]
    history = awk(
        services.HISTORY_AWK,
        "2026-10-29T10:00:00+0800 h systemd[1]: Starting nginx...\n"
        "2026-10-29T10:00:01+0800 h systemd[1]: Started nginx.\n"
        "2026-10-29T13:00:00+0800 h systemd[1]: nginx.service: A process of this unit "
        "has been killed by the OOM killer.\n"
        "2026-10-29T13:00:00+0800 h systemd[1]: nginx.service: Failed with result "
        "'oom-kill'.\n"
        "2026-10-29T13:00:05+0800 h systemd[1]: nginx.service: Scheduled restart job, "
        "restart counter is at 1.\n"
        "2026-10-29T13:30:00+0800 h systemd[1]: nginx.service holdoff time over, "
        "scheduling restart.\n"
        "2026-10-29T13:30:01+0800 h systemd[1]: Unit nginx.service entered failed state.\n"
        "2026-10-29T13:30:02+0800 h systemd[1]: start request repeated too quickly for "
        "nginx.service\n"
        "2026-10-29T13:30:02+0800 h systemd[1]: nginx.service: Consumed 1.2s CPU time.\n",
    )
    assert [line.split()[1] for line in history if line.startswith("H ")] == [
        "other",
        "started",
        "oom",
        "oom",
        "restart_scheduled",
        "restart_scheduled",
        "failed",
        "start_limit",
    ]
    assert history[-5:] == [
        "HCOUNT starts 1",
        "HCOUNT failures 2",
        "HCOUNT restarts 2",
        "HCOUNT oom 2",
        "HCOUNT start_limit 1",
    ]
    text = "".join(f"line {i} CAPABILITY_MISSING:x\n" for i in range(10))
    assert awk(services.HEAD_AWK, text, n=3, b=1000, w=7) == [
        "line 0 ",
        "line 1 ",
        "line 2 ",
    ]
    tail = awk(services.TAIL_AWK, text, n=4, b=1000, w=40)
    assert tail[0] == "line 6 CAPABILITY-MISSING:x" and len(tail) == 4
    assert len(awk(services.TAIL_AWK, text, n=80, b=60, w=40)) == 2


@pytest.mark.skipif(not HAS_SH, reason="needs sh")
def test_service_scripts_run_against_stub_commands(tmp_path):
    show = tmp_path / "show.txt"
    show.write_text(
        HEALTHY.split("[AIOPS_CLOCK]")[0]
        .replace("[AIOPS_SHOW]\n", "")
        .replace("/system.slice/nginx.service", "/system.slice/aiops-test-none.service")
    )
    me = os.getpid()
    stubs = {
        "id": 'case "$1" in -u) echo 0;; -nG) echo root;; esac\n',
        "systemctl": f"""case "$1" in
show) cat {show};;
cat) printf '# /usr/lib/systemd/system/nginx.service\\n[Service]\\nExecStart=/usr/sbin/nginx\\nEnvironment=API_TOKEN=abc\\n';;
esac
""",
        "ps": f"""case "$*" in
*"-o ppid="*) echo " 1234     1 root    86400  2348  0.0     1 nginx";;
*"-o pid= -o user"*) for a; do l=$a; done; IFS=,; for p in $l; do echo " $p root 100 2000"; done;;
esac
""",
        "ss": f"""printf 'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\\n'
printf 'tcp LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=1234,fd=6))\\n'
printf 'tcp LISTEN 0 128 127.0.0.1:{me % 50000 + 10000} 0.0.0.0:* users:(("python",pid={me},fd=3))\\n'
printf 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("init",pid=1,fd=4))\\n'
""",
        "journalctl": """case "$*" in
*_PID=1*) printf '2026-10-29T13:00:05+0800 h systemd[1]: nginx.service: Scheduled restart job, restart counter is at 1.\\n';;
*) printf '2026-10-29T14:05:00+0800 h nginx[1234]: [warn] upstream buffered\\n';;
esac
""",
    }
    for name, body in stubs.items():
        path = tmp_path / name
        path.write_text("#!/bin/sh\n" + body)
        path.chmod(0o755)
    env = {"PATH": f"{tmp_path}:/usr/bin:/bin", "LC_ALL": "C"}

    def run(action, options):
        spec = extensions.spec_for(action)
        options = extensions.validate_options(spec, options)
        result = subprocess.run(
            ["/bin/sh", "-c", spec.script(options)],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr
        report = observations.analyze(action, result.stdout, options=options)
        json.dumps(report, allow_nan=False)
        return result.stdout, report["summary"]

    out, summary = run("service_detail", {"service": "nginx"})
    assert summary["unit"]["id"] == "nginx.service", out
    assert "PROCS_SOURCE MainPID" in out
    assert [p["pid"] for p in summary["processes"]] == [1234]
    assert summary["listening"] == [
        {"proto": "tcp", "address": "0.0.0.0", "port": 80, "pid": 1234}
    ]
    assert summary["unit_file"]["lines"] == [
        "[Service]",
        "ExecStart=/usr/sbin/nginx",
        "Environment=API_TOKEN=[REDACTED]",
    ]
    assert summary["journal"]["entries"] == [
        "2026-10-29T14:05:00+0800 h nginx[1234]: [warn] upstream buffered"
    ]
    assert summary["counts"]["restarts_24h"] == 1
    assert summary["history"][0]["kind"] == "restart_scheduled"
    out, summary = run("service_map", None)
    pids = {row["pid"]: row for row in summary["listeners"]}
    assert set(pids) == {1, 1234, me}, out
    assert pids[me]["user"] == "root" and pids[me]["elapsed_seconds"] == 100
    assert pids[1]["process"] == "init" and summary["process_info_available"]
    assert re.search(rf"(?m)^PID {me} \S+ root 100 2000 \S+ \S+$", out)
