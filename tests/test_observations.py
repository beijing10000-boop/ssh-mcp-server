"""Structured observations must be bounded, conservative and scope safe."""

import json
import subprocess

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
