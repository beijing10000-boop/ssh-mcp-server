"""P0 regressions: real MCP responsiveness, admission, retention and query cost."""

from concurrent.futures import ThreadPoolExecutor
import threading
import time

import pytest

from sshmcp import access, diagnostics, jobs, maintenance, store
from test_console import auth, ready_host, mcp_call


def test_mcp_long_diagnostic_keeps_health_and_context(client, key_pair, monkeypatch):
    hid = ready_host(client, key_pair)
    entered, release = threading.Event(), threading.Event()

    def slow(*args, **kwargs):
        assert access.identity()["id"] == "legacy"
        entered.set()
        assert release.wait(3)
        return {"status": "success", "output": "ok"}

    monkeypatch.setattr(diagnostics, "execute", slow)
    with ThreadPoolExecutor() as pool:
        task = pool.submit(
            mcp_call,
            client,
            store.token("mcp.token"),
            "ssh_diagnose_cpu",
            {"host_id": hid},
        )
        assert entered.wait(2)
        try:
            health = pool.submit(client.get, "/healthz")
            assert health.result(timeout=1).status_code == 200
        finally:
            release.set()
        assert task.result()[1]["status"] == "success"


def test_partial_admission_and_strict_rollback(client, key_pair, monkeypatch):
    hid = ready_host(client, key_pair)
    monkeypatch.setattr(jobs.POOL, "submit", lambda *_: None)
    body = {"host_ids": [hid, 99999], "action": "health"}
    r = client.post("/api/v1/jobs", headers=auth(), json={**body, "strict": True})
    assert r.status_code == 422
    assert client.get("/api/v1/jobs").json()["total"] == 0
    r = client.post("/api/v1/jobs", headers=auth(), json=body).json()
    assert r["total"] == 1 and r["accepted"][0]["host_id"] == hid
    assert r["skipped"][0]["host_id"] == 99999


def test_slots_reserve_interactive_and_serialize_same_host(monkeypatch):
    release = threading.Event()
    entered = []

    def slow(host_id, *a, **k):
        entered.append(host_id)
        assert release.wait(3)
        return {"status": "success"}

    monkeypatch.setattr(diagnostics, "_execute_inner", slow)
    with ThreadPoolExecutor(max_workers=6) as pool:
        tasks = [
            pool.submit(diagnostics.execute, h, "cpu", background=True)
            for h in (1, 2, 3)
        ]
        for _ in range(100):
            if len(entered) == 3:
                break
            time.sleep(0.01)
        waiting = pool.submit(diagnostics.execute, 4, "cpu", background=True)
        interactive = pool.submit(diagnostics.execute, 5, "cpu")
        for _ in range(100):
            if 5 in entered:
                break
            time.sleep(0.01)
        assert 5 in entered and 4 not in entered
        same = pool.submit(diagnostics.execute, 1, "cpu", background=True)
        assert entered.count(1) == 1
        release.set()
        for t in tasks + [waiting, interactive, same]:
            t.result(timeout=3)
    assert entered.count(1) == 2 and diagnostics.slot_usage()["active"] == 0


def test_retention_keeps_active_and_cascades(client, key_pair, monkeypatch):
    hid = ready_host(client, key_pair)
    monkeypatch.setattr(jobs.POOL, "submit", lambda *_: None)
    batch = jobs.create([hid], {"action": "cpu"}, "ou_123456789")
    with store.db() as c:
        c.execute(
            "UPDATE diagnostic_jobs SET created_at='2000-01-01' WHERE id=?",
            (batch["job_ids"][0],),
        )
        c.execute(
            "INSERT INTO audit(actor,action,target,outcome,created_at) VALUES ('a','b','c','ok','2000-01-01')"
        )
        c.execute(
            "INSERT INTO zabbix_sync_runs(id,actor,status,source,options,completed_at) VALUES ('old','a','preview','s','{}','2000-01-01')"
        )
        c.execute(
            "INSERT INTO zabbix_sync_items(run_id,hostid,data) VALUES ('old','1','encrypted')"
        )
    counts = maintenance.cleanup()
    assert counts["audit"] == 1
    with store.db() as c:
        assert c.execute("SELECT COUNT(*) FROM zabbix_sync_items").fetchone()[0] == 0
        assert c.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert jobs.detail(batch["job_ids"][0])["status"] == "queued"
    assert (
        client.put(
            "/api/v1/settings/retention", headers=auth(), json={"audit_days": 0}
        ).status_code
        == 422
    )


def test_host_lists_do_not_open_per_host_connections(client, key_pair, monkeypatch):
    ready_host(client, key_pair)
    monkeypatch.setattr(store, "groups_for", lambda *_: pytest.fail("N+1 query"))
    assert client.get("/api/v1/hosts").status_code == 200
    assert client.get("/api/v1/inventory/hosts").status_code == 200


def test_fernet_reuses_key(client, monkeypatch):
    store._fernet.cache_clear()
    first = store.seal("one")
    monkeypatch.setattr(
        store, "ensure_secret", lambda *_: pytest.fail("master.key reread")
    )
    assert store.unseal(first) == "one"
    assert store.unseal(store.seal("two")) == "two"


def test_all_mcp_tools_registered_as_coroutines():
    from sshmcp.mcp_tools import mcp

    assert all(tool.is_async for tool in mcp._tool_manager._tools.values())


def test_firewall_script_labels_each_service(tmp_path):
    import os
    import subprocess
    from sshmcp.operations import SCRIPTS

    fake = tmp_path / "systemctl"
    fake.write_text("#!/bin/sh\nprintf 'inactive\\n'\nexit 3\n")
    fake.chmod(0o700)
    result = subprocess.run(
        ["/bin/sh", "-c", SCRIPTS["security_status"]],
        capture_output=True,
        text=True,
        env={**os.environ, "PATH": str(tmp_path) + ":/usr/bin:/bin"},
        timeout=5,
    )
    assert all(
        f"{name}: inactive" in result.stdout
        for name in ("firewalld", "nftables", "ufw")
    )
