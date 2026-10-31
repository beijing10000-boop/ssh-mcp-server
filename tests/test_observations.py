"""Structured observations must be bounded, conservative and scope safe."""

import json
import os
import subprocess
import sys

import pytest

from sshmcp import diagnostics, jobs, observations, store, triage
from sshmcp.catalog import TITLES
from sshmcp.mcp_tools import mcp
from test_console import auth, mcp_call, ready_host


@pytest.mark.parametrize("action", sorted(set(TITLES) - {"triage"}))
def test_all_actions_parse_unknown_output_conservatively(action):
    data = observations.analyze(
        action,
        "unexpected version output\npassword=[REDACTED]",
        status="partial",
        truncated=True,
    )
    assert "metrics" in data["summary"] and isinstance(data["findings"], list)
    assert any(f["metric"] == "collection_coverage" for f in data["findings"])
    assert all(
        set(f) >= {"level", "metric", "value", "threshold", "hint"}
        for f in data["findings"]
    )
    json.dumps(data, allow_nan=False)


def test_cpu_memory_disk_psi_and_service_rules():
    cases = [
        ("cpu", "CPU_COUNT=2\n5.00 1.00 0.00 1/100 99\n", "load_per_core"),
        (
            "memory",
            "MemTotal: 1000 kB\nMemAvailable: 40 kB\nSwapTotal: 100 kB\nSwapFree: 50 kB\n",
            "memory_available_percent",
        ),
        (
            "disk",
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda 100 99 1 99% /\nFilesystem Inodes IUsed IFree IUse% Mounted on\n/dev/sda 100 95 5 95% /\n",
            "inode:/",
        ),
        (
            "pressure",
            "[io PSI]\nsome avg10=22.50 avg60=10.00 avg300=1.00 total=100\n",
            "psi_io_some_avg10",
        ),
        ("time_sync", "NTP=yes\nNTPSynchronized=no\n", "NTPSynchronized"),
        (
            "failed_services",
            "nginx.service loaded failed failed Nginx\n",
            "failed_service_count",
        ),
        ("oom", "Oct 26 kernel: Killed process 123 (java)\n", "oom_matches"),
    ]
    for action, text, metric in cases:
        data = observations.analyze(action, text)
        assert any(f["metric"] == metric for f in data["findings"]), data
    clean = observations.analyze(
        "memory",
        "MemTotal: 100 kB\nMemAvailable: 80 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
    )
    assert clean["findings"] == []


CPU_OUTPUT = """CPU_COUNT=2
3.34 3.40 3.45 2/327 3592417
cpu  155728400 292744 34479741 8712855818 5153813 13643116 8443476 0 0 0
cpu0 77649037 146615 17150673 4354118911 2593402 7109562 4247095 0 0 0
cpu1 78079363 146129 17329068 4358736907 2560411 6533554 4196381 0 0 0
procs_running 2
procs_blocked 3
procs ---------memory---------- ---swap-- -----io---- -system-- -------cpu-------
 r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st gu
 3  0      0 120000  20000 900000    0    0     5    20  300  500 30  8 60  2  0  0
 2  3      0 119000  20000 900100    0    0     0    44  410  620  1  2 95  2  0  0
"""


def test_cpu_reports_all_load_averages_vmstat_and_load_cpu_divergence():
    data = observations.analyze("cpu", CPU_OUTPUT)
    metrics = {m["metric"]: m for m in data["summary"]["metrics"]}
    assert [metrics[k]["value"] for k in ("load_1m", "load_5m", "load_15m")] == [
        3.34,
        3.4,
        3.45,
    ]
    assert metrics["load_per_core_5m"]["value"] == 1.7
    # Zabbix's default per-CPU warning line, so an active alert is not "info".
    assert metrics["load_per_core"]["threshold"] == 1.5
    assert metrics["load_per_core"]["level"] == "warning"
    # The last vmstat row is the 1 s sample, not the since-boot averages.
    assert metrics["cpu_idle_percent"]["value"] == 95
    assert metrics["vmstat_blocked"]["value"] == 3
    assert metrics["cpu_steal_percent"]["value"] == 0
    assert metrics["procs_blocked"]["level"] == "warning"
    divergence = next(
        f for f in data["findings"] if f["metric"] == "load_cpu_divergence"
    )
    assert divergence["value"] == {"load_per_core": 1.67, "cpu_idle_percent": 95}
    assert "CPU Ready" in divergence["hint"]
    # Gateway/older output without /proc/stat or vmstat still parses.
    old = observations.analyze("cpu", "CPU_COUNT=1\n3.00 2.00 1.00 1/10 99\n")
    assert not any(f["metric"] == "load_cpu_divergence" for f in old["findings"])


PROCESS_OUTPUT = """  PID  PPID COMMAND         %CPU %MEM   RSS     ELAPSED S
3572619 1386621 postgres         8.0 29.3 1096256    10:54:58 S
3573186 1386621 postgres         7.8 29.3 1094960    10:34:41 S
[AIOPS_STATES]
      2 D
      3 R
    320 S
[AIOPS_DSTATE]
811 D io_schedule jbd2/sda1-8
912 D nfs_wait_bit_killable rsync worker
[AIOPS_CPU_DELTA]
AIOPS_DELTA 3572619 45.0 R postgres
AIOPS_DELTA 4100 12.5 S kworker/u8:2-ev
"""


def test_processes_report_states_d_waits_and_one_second_cpu_delta():
    summary = observations.analyze("processes", PROCESS_OUTPUT)["summary"]
    assert [p["pid"] for p in summary["processes"]] == [3572619, 3573186]
    assert summary["state_counts"] == {"D": 2, "R": 3, "S": 320}
    assert summary["uninterruptible"][1] == {
        "pid": 912,
        "wchan": "nfs_wait_bit_killable",
        "name": "rsync worker",
    }
    assert summary["cpu_interval"][0] == {
        "pid": 3572619,
        "cpu_percent_1s": 45.0,
        "state": "R",
        "name": "postgres",
    }
    assert "1 秒" in summary["coverage"]
    # Gateway output (no optional sections) keeps the previous shape.
    plain = observations.analyze("processes", PROCESS_OUTPUT.split("[AIOPS_")[0])
    assert "cpu_interval" not in plain["summary"]
    assert "生命周期平均值" in plain["summary"]["coverage"]


@pytest.mark.skipif(not os.path.exists("/proc/self/stat"), reason="needs Linux /proc")
def test_processes_command_runs_under_sh_and_measures_a_busy_process():
    busy = subprocess.Popen([sys.executable, "-c", "while True: pass"])
    try:
        result = subprocess.run(
            ["/bin/sh", "-c", diagnostics.command_for("processes")],
            capture_output=True,
            text=True,
            timeout=15,
        )
    finally:
        busy.kill()
        busy.wait()
    assert result.returncode == 0, result.stderr
    summary = observations.analyze("processes", result.stdout)["summary"]
    assert summary["state_counts"].get("R", 0) >= 1
    top = {row["pid"]: row["cpu_percent_1s"] for row in summary["cpu_interval"]}
    assert top.get(busy.pid, 0) > 50, result.stdout[-2000:]


def test_catalog_names_the_mcp_tool_for_every_action():
    import asyncio

    from sshmcp.catalog import entries

    registered = {tool.name for tool in asyncio.run(mcp.list_tools())}
    assert all(entry["tool"] in registered for entry in entries())
    by_action = {entry["id"]: entry["tool"] for entry in entries()}
    assert by_action["mount_health"] == "ssh_diagnose_mounts"
    assert by_action["log_errors"] == "ssh_diagnose_system_errors"
    assert by_action["pressure"] == "ssh_diagnose_pressure"


def test_failures_carry_a_stable_error_code():
    from sshmcp.mcp_tools import error_code

    assert (
        error_code(PermissionError("x"), "该 MCP 客户端无权访问此主机或诊断动作")
        == "forbidden"
    )
    assert error_code(ValueError("x"), "主机 ID 必须是正整数") == "invalid_argument"
    failure = diagnostics.SSHDiagnosticError
    assert (
        error_code(failure(), "SSH 诊断执行超时（单项 20 秒 / 组合 60 秒）")
        == "timeout"
    )
    assert error_code(failure(), "主机配置已变更，请重新提交诊断") == "revision_changed"
    assert error_code(failure(), "未核验 SSH 主机公钥") == "host_unverified"
    assert error_code(RuntimeError(), "RuntimeError") == "failed"


def test_counter_snapshots_do_not_invent_rates():
    data = observations.analyze("io", "8 0 sda 120 0 10 10000\n")
    assert not data["findings"] and "不能据此判断速率" in data["summary"]["coverage"]
    assert observations.number("nan") is None and observations.number("inf") is None


def test_summary_schema_and_full_output(client, key_pair, monkeypatch):
    hid = ready_host(client, key_pair)
    monkeypatch.setattr(
        diagnostics,
        "execute",
        lambda *a, **kw: {
            "host_id": hid,
            "action": "memory",
            "status": "success",
            "output": "MemTotal: 100 kB\nMemAvailable: 3 kB\n",
            "stderr": "",
            "truncated": False,
        },
    )
    params = mcp._tool_manager._tools["ssh_diagnose_memory"].parameters
    assert params["properties"]["detail"]["enum"] == ["summary", "full"]
    token = store.token("mcp.token")
    summary = mcp_call(client, token, "ssh_diagnose_memory", {"host_id": hid})[1]
    assert "output" not in summary and summary["findings"]
    full = mcp_call(
        client, token, "ssh_diagnose_memory", {"host_id": hid, "detail": "full"}
    )[1]
    assert "MemTotal" in full["output"]
    assert mcp_call(
        client, token, "ssh_diagnose_memory", {"host_id": hid, "detail": "invalid"}
    )[1]["isError"]
    stored = jobs.detail(summary["job_id"])["result"]
    assert stored["output"] and stored["summary"]


@pytest.mark.parametrize("symptom", triage.SCENARIOS)
def test_triage_scripts_validate_and_preserve_per_step_exit(symptom):
    service = "nginx.service" if symptom == "service_down" else None
    script = diagnostics.command_for("triage", service, symptom=symptom)
    subprocess.run(["/bin/sh", "-n"], input=script, text=True, check=True)
    assert script.count("__SSHMCP_BEGIN_") == len(triage.actions(symptom))
    text = "".join(
        f"__SSHMCP_BEGIN_{a}__\nfixture\n__SSHMCP_END_{a}__:0\n"
        for a in triage.actions(symptom)
    )
    result = triage.parse(text, symptom)
    assert len(result["steps"]) == len(triage.actions(symptom))
    assert all(r["exit_code"] == 0 for r in result["steps"])
    assert all(
        r["status"] == "partial"
        for r in triage.parse("truncated", symptom, True)["steps"]
    )


def test_triage_rejects_shell_and_requires_separate_grant(
    client, key_pair, monkeypatch
):
    for kwargs in (
        {"symptom": "shell"},
        {"symptom": "service_down", "service": "nginx;id"},
        {"symptom": "cpu_high", "service": "nginx"},
    ):
        with pytest.raises(ValueError):
            diagnostics.command_for("triage", **kwargs)
    hid = ready_host(client, key_pair)
    token = client.post(
        "/api/v1/mcp/clients",
        headers=auth(),
        json={"name": "no-triage", "all_hosts": True, "actions": ["health"]},
    ).json()["token"]
    monkeypatch.setattr(
        diagnostics, "execute", lambda *a, **kw: pytest.fail("No unauthorized SSH")
    )
    result = mcp_call(
        client, token, "ssh_triage", {"host_id": hid, "symptom": "cpu_high"}
    )[1]
    assert result["status"] == "failed" and "无权" in result["error"]


def test_failed_triage_audit_has_the_same_parameters_as_success(
    client, key_pair, monkeypatch
):
    hid = ready_host(client, key_pair)
    token = store.token("mcp.token")
    monkeypatch.setattr(
        diagnostics,
        "execute",
        lambda *a, **kw: {"status": "success", "summary": {}, "findings": []},
    )
    args = {"host_id": hid, "symptom": "disk_full", "minutes": 45}
    assert mcp_call(client, token, "ssh_triage", args)[1]["status"] == "success"
    stale = mcp_call(
        client,
        token,
        "ssh_triage",
        {**args, "expected_revision": store.get_host(hid)["revision"] + 1},
    )[1]
    assert stale["error_code"] == "revision_changed"
    invalid = mcp_call(
        client, token, "ssh_triage", {**args, "symptom": "not-a-symptom"}
    )[1]
    assert invalid["error_code"] == "invalid_argument"
    with store.db() as c:
        rows = c.execute(
            "SELECT outcome,detail FROM audit WHERE action='triage' ORDER BY id"
        ).fetchall()
    assert [r["outcome"] for r in rows] == ["success", "failed", "failed"]
    succeeded = rows[0]["detail"].split(";", 1)[1]  # after job=<id>
    failed = rows[1]["detail"].split(";", 2)[2]  # after <exception>;<code>
    assert failed == succeeded == "minutes=45;symptom=disk_full"
    # Values that failed validation are still not written to the audit trail.
    assert "not-a-symptom" not in rows[2]["detail"]


def test_batch_owner_pagination_group_filter_and_resolve(client, key_pair, monkeypatch):
    group = client.post(
        "/api/v1/groups", headers=auth(), json={"name": "Production"}
    ).json()["id"]
    hid = ready_host(client, key_pair, group=group)
    tokens = [
        client.post(
            "/api/v1/mcp/clients",
            headers=auth(),
            json={"name": name, "all_hosts": True, "actions": ["health"]},
        ).json()["token"]
        for name in ("owner", "other")
    ]
    monkeypatch.setattr(jobs.POOL, "submit", lambda *_: None)
    result = mcp_call(
        client, tokens[0], "ssh_submit_diagnostics", {"host_ids": [hid, 999999]}
    )[1]
    batch = mcp_call(
        client,
        tokens[0],
        "ssh_get_diagnostic_batch",
        {"batch_id": result["batch_id"], "page_size": 1},
    )[1]
    assert batch["counts"]["queued"] == 1 and len(batch["skipped"]) == 1
    assert batch["items"][0]["host_id"] == hid and "findings" in batch["items"][0]
    assert mcp_call(
        client, tokens[1], "ssh_get_diagnostic_batch", {"batch_id": result["batch_id"]}
    )[1]["isError"]
    found = mcp_call(
        client, tokens[0], "ssh_resolve_hosts", {"zabbix_hostids": ["101", "999"]}
    )[1]["items"]
    assert found[0]["host_id"] == hid and found[1]["status"] == "failed"
    listed = mcp_call(client, tokens[0], "ssh_list_hosts", {"group_id": group})[1]
    rows = listed if isinstance(listed, list) else listed["result"]
    assert rows[0]["groups"][0]["name"] == "Production"


def test_inventory_parsers_use_named_fields():
    process = observations.analyze(
        "processes",
        "PID PPID COMMAND %CPU %MEM RSS ELAPSED S\n123 1 java 99.0 50.0 1024 01:02 R\n",
    )
    assert process["summary"]["processes"][0]["pid"] == 123
    devices = observations.analyze(
        "block_devices", "NAME TYPE SIZE RO ROTA MOUNTPOINT\nsda disk 2048 0 1 /data\n"
    )
    assert devices["summary"]["devices"][0]["size_bytes"] == 2048
    limits = observations.analyze("resource_limits", "[系统文件句柄]\n99 0 100\n100\n")
    assert limits["findings"][0]["level"] == "critical"
    container = observations.analyze(
        "containers", "abc\tworker\timage:v1\tExited (1) 2 minutes ago\n"
    )
    assert container["findings"][0]["metric"] == "container_state"
