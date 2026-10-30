"""Authorization boundaries, durable jobs, imports and regression security checks."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import subprocess
import time

import pytest

from sshmcp import diagnostics, jobs, store
from test_core import auth


def ready_host(client, key_pair, address="10.20.0.10", group=None, zabbix="101"):
    cred = client.post(
        "/api/v1/credentials",
        headers=auth(),
        json={"name": address, "private_key": key_pair[0]},
    )
    assert cred.status_code == 201, cred.text
    result = client.post(
        "/api/v1/hosts",
        headers=auth(),
        json={
            "name": "Linux " + address,
            "address": address,
            "host_key": key_pair[1],
            "credential_id": cred.json()["id"],
            "username": "root",
            "zabbix_hostid": zabbix,
            "group_ids": [group] if group else [],
        },
    )
    assert result.status_code == 201, result.text
    return result.json()["id"]


def mcp_call(client, token, name, arguments=None):
    response = client.post(
        "/mcp",
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        },
    )
    if response.status_code != 200:
        return response.status_code, response.json()
    result = response.json()["result"]
    if result.get("isError"):
        return 200, result
    return 200, result.get("structuredContent") or json.loads(
        result["content"][0]["text"]
    )


@pytest.mark.parametrize(
    "source,secret",
    [
        ("password=the-secret", "the-secret"),
        ('{"api_key": "long secret with spaces"}', "long secret"),
        ("Authorization: Bearer secret-token", "secret-token"),
        ("https://alice:private-password@host/path", "private-password"),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nprivate material\n-----END RSA PRIVATE KEY-----",
            "private material",
        ),
    ],
)
def test_output_redaction_covers_actual_secret_patterns(source, secret):
    result = diagnostics.redact_output(source)
    assert secret not in result and "REDACTED" in result


def test_key_validation_and_private_ipv6_scope(key_pair):
    assert store.validate_hostkey(key_pair[1] + " trusted") == key_pair[1]
    for value in (
        "ssh-rsa AAAA",
        "ssh-rsa not-base64",
        "ssh-ed25519 " + key_pair[1].split()[1],
        key_pair[1] + "\nsecond key",
    ):
        with pytest.raises(ValueError):
            store.validate_hostkey(value)
    with pytest.raises(ValueError):
        store.private_ip("fd00::1%eth0")


def test_secret_creation_is_atomic_and_database_is_private(client):
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(
            pool.map(
                lambda _: store.ensure_secret(
                    "atomic-fixture", lambda: b"complete-secret"
                ),
                range(30),
            )
        )
    assert set(values) == {b"complete-secret"}
    for path in (
        store.DATA_DIR,
        store.DATA_DIR / "master.key",
        store.DATA_DIR / "ssh-mcp.sqlite3",
    ):
        assert path.stat().st_mode & 0o077 == 0


def test_invalid_public_key_is_a_validation_error_not_saved(client):
    response = client.post(
        "/api/v1/hosts",
        headers=auth(),
        json={"name": "bad", "address": "10.0.0.1", "host_key": "ssh-rsa AAAA"},
    )
    assert response.status_code == 422
    assert client.get("/api/v1/hosts").json() == []


def test_atomic_import_filter_and_pagination(client):
    group = client.post(
        "/api/v1/groups", headers=auth(), json={"name": "fleet"}
    ).json()["id"]
    values = [
        {
            "name": f"node-{i}",
            "address": f"10.0.{i // 250}.{i % 250 + 1}",
            "username": "root",
            "zabbix_hostid": str(1000 + i),
            "group_ids": [group] if i < 40 else [],
        }
        for i in range(1000)
    ]
    result = client.post("/api/v1/hosts/import", headers=auth(), json={"hosts": values})
    assert result.status_code == 201 and result.json()["count"] == 1000
    assert (
        client.get("/api/v1/inventory/hosts?page=40").json()["items"][0]["name"]
        == "node-24"
    )
    assert len(client.get("/api/v1/inventory/ids").json()["host_ids"]) == 1000
    assert client.get(f"/api/v1/inventory/hosts?group_id={group}").json()["total"] == 40
    assert client.get("/api/v1/inventory/hosts?q=node-999").json()["total"] == 1
    duplicate = client.post(
        "/api/v1/hosts/import",
        headers=auth(),
        json={
            "hosts": [{"name": "would roll back", "address": "10.10.0.1"}, values[0]]
        },
    )
    assert duplicate.status_code in (409, 422)
    assert client.get("/api/v1/inventory/hosts").json()["total"] == 1000


def test_scoped_mcp_token_is_hashed_and_enforced(client, key_pair, monkeypatch):
    group = client.post(
        "/api/v1/groups", headers=auth(), json={"name": "permitted"}
    ).json()["id"]
    allowed = ready_host(client, key_pair, group=group)
    denied = ready_host(client, key_pair, address="10.20.0.11", zabbix="102")
    created = client.post(
        "/api/v1/mcp/clients",
        headers=auth(),
        json={"name": "AI restricted", "group_ids": [group], "actions": ["health"]},
    )
    assert created.status_code == 201 and created.headers["cache-control"] == "no-store"
    token, ident = created.json()["token"], created.json()["id"]
    assert token not in client.get("/api/v1/mcp/clients").text
    with store.db() as c:
        assert (
            c.execute("SELECT token_hash FROM mcp_clients").fetchone()[0]
            == hashlib.sha256(token.encode()).hexdigest()
        )
    calls = []

    def execute(hid, action, **kwargs):
        calls.append(hid)
        return {
            "status": "success",
            "host_id": hid,
            "action": action,
            "output": "fixture",
            "exit_code": 0,
        }

    monkeypatch.setattr(diagnostics, "execute", execute)
    assert (
        mcp_call(client, token, "ssh_diagnose_health", {"host_id": denied})[1]["status"]
        == "failed"
    )
    assert (
        mcp_call(
            client, token, "ssh_diagnose_logs", {"host_id": allowed, "service": "nginx"}
        )[1]["status"]
        == "failed"
    )
    assert calls == []
    assert (
        mcp_call(client, token, "ssh_diagnose_health", {"host_id": allowed})[1][
            "status"
        ]
        == "success"
    )
    assert calls == [allowed]
    assert (
        mcp_call(client, token, "ssh_resolve_host", {"zabbix_hostid": "101"})[1][
            "host_id"
        ]
        == allowed
    )
    assert (
        mcp_call(client, token, "ssh_resolve_host", {"zabbix_hostid": "102"})[1][
            "status"
        ]
        == "failed"
    )
    history = client.get("/api/v1/jobs").json()["items"]
    assert len(history) == 1 and history[0]["actor"] == "mcp:" + ident
    assert (
        client.post(f"/api/v1/mcp/clients/{ident}/revoke", headers=auth()).status_code
        == 200
    )
    assert mcp_call(client, token, "ssh_list_hosts")[0] == 401


def test_token_expiry_and_legacy_disable_do_not_break_web_login(client):
    created = client.post(
        "/api/v1/mcp/clients",
        headers=auth(),
        json={"name": "expire", "all_hosts": True, "actions": ["cpu"]},
    ).json()
    with store.db() as c:
        c.execute("UPDATE mcp_clients SET expires_at=?", (int(time.time()) - 1,))
    assert mcp_call(client, created["token"], "ssh_list_hosts")[0] == 401
    assert (
        client.put(
            "/api/v1/settings/mcp-legacy", headers=auth(), json={"enabled": False}
        ).status_code
        == 200
    )
    assert mcp_call(client, store.token("mcp.token"), "ssh_list_hosts")[0] == 401
    assert client.get("/api/v1/auth/me").status_code == 200
    assert (
        client.post(
            "/api/v1/mcp/clients",
            headers=auth(),
            json={"name": "no scope", "actions": ["cpu"]},
        ).status_code
        == 422
    )


def test_mcp_mapping_refuses_ambiguous_existing_records(client, key_pair):
    first = ready_host(client, key_pair)
    other = ready_host(client, key_pair, address="10.20.0.12", zabbix="103")
    with store.db() as c:
        c.execute("UPDATE hosts SET zabbix_hostid='101' WHERE id=?", (other,))
    result = mcp_call(
        client, store.token("mcp.token"), "ssh_resolve_host", {"zabbix_hostid": "101"}
    )[1]
    assert result["status"] == "failed" and "host_id" not in result
    assert store.get_host(first)["enabled"] == 1


def test_queued_cancel_never_executes_and_retry_snapshots_current_revision(
    client, key_pair, monkeypatch
):
    hid = ready_host(client, key_pair)
    monkeypatch.setattr(jobs.POOL, "submit", lambda *_: None)
    task = client.post(
        "/api/v1/jobs", headers=auth(), json={"host_ids": [hid], "action": "health"}
    ).json()["job_ids"][0]
    calls = []
    monkeypatch.setattr(diagnostics, "execute", lambda *a, **k: calls.append(a))
    assert client.post(f"/api/v1/jobs/{task}/cancel", headers=auth()).status_code == 200
    jobs.work(task)
    assert calls == [] and jobs.detail(task)["status"] == "cancelled"
    with store.db() as c:
        c.execute("UPDATE hosts SET revision=revision+1 WHERE id=?", (hid,))
    new = client.post(f"/api/v1/jobs/{task}/retry", headers=auth()).json()["job_ids"][0]
    assert jobs.detail(new)["host_revision"] == store.get_host(hid)["revision"]


def test_stale_job_and_revoked_web_actor_are_rejected_before_network(
    client, key_pair, monkeypatch
):
    hid = ready_host(client, key_pair)
    monkeypatch.setattr(jobs.POOL, "submit", lambda *_: None)
    task = client.post(
        "/api/v1/jobs", headers=auth(), json={"host_ids": [hid], "action": "health"}
    ).json()["job_ids"][0]
    with store.db() as c:
        c.execute("UPDATE hosts SET revision=revision+1 WHERE id=?", (hid,))
    monkeypatch.setattr(
        diagnostics,
        "client_connect",
        lambda *a, **k: pytest.fail("No connection may start"),
    )
    jobs.work(task)
    assert "配置已变更" in jobs.detail(task)["error"]
    task = client.post(
        "/api/v1/jobs", headers=auth(), json={"host_ids": [hid], "action": "health"}
    ).json()["job_ids"][0]
    store.save_settings({"feishu_admin_open_ids": "ou_somebody_else"})
    jobs.work(task)
    assert "失去管理权限" in jobs.detail(task)["error"]


def test_jobs_result_encrypted_and_restart_marks_pending_failed(
    client, key_pair, monkeypatch
):
    hid = ready_host(client, key_pair)
    monkeypatch.setattr(
        diagnostics,
        "execute",
        lambda *a, **k: {
            "status": "success",
            "output": "private fixture evidence",
            "exit_code": 0,
        },
    )
    result = jobs.run_inline(hid, "health", "ou_123456789", source="web")
    with store.db() as c:
        value = c.execute(
            "SELECT result FROM diagnostic_jobs WHERE id=?", (result["job_id"],)
        ).fetchone()[0]
    assert "private fixture evidence" not in value
    assert (
        jobs.detail(result["job_id"])["result"]["output"] == "private fixture evidence"
    )
    monkeypatch.setattr(jobs.POOL, "submit", lambda *_: None)
    waiting = client.post(
        "/api/v1/jobs", headers=auth(), json={"host_ids": [hid], "action": "cpu"}
    ).json()["job_ids"][0]
    store.init_db()
    assert (
        jobs.detail(waiting)["status"] == "failed"
        and "重启" in jobs.detail(waiting)["error"]
    )


def test_new_endpoints_require_csrf_and_session(client):
    assert client.post("/api/v1/jobs", json={}).status_code == 403
    assert client.post("/api/v1/mcp/clients", json={}).status_code == 403
    client.cookies.clear()
    for path in ("/jobs", "/mcp/clients", "/tools", "/inventory/hosts", "/audit/page"):
        assert client.get("/api/v1" + path).status_code == 401


def test_audit_page_keyword_search(client):
    store.audit("ou_123456789", "group_create", "424242", "success")
    store.audit("mcp:audit-fixture", "cpu", "989898", "failed", "busy")

    def search(**params):
        response = client.get("/api/v1/audit/page", params=params)
        assert response.status_code == 200, response.text
        return response.json()

    for q, action in (
        ("group_create", "group_create"),
        ("audit-fixture", "cpu"),
        ("989898", "cpu"),
    ):
        found = search(q=q)
        assert found["total"] == 1 and [r["action"] for r in found["items"]] == [action]
    assert search(q="group_create", outcome="failed")["total"] == 0
    assert search(q="cpu", outcome="failed")["items"][0]["target"] == "989898"
    missing = search(q="no-such-audit-keyword")
    assert missing["total"] == 0 and missing["items"] == []


def test_malformed_origins_are_rejected_and_non_ascii_fingerprint_is_422(client):
    response = client.get(
        "/mcp",
        headers={
            "Authorization": "Bearer " + store.token("mcp.token"),
            "Origin": "http://[",
        },
    )
    assert response.status_code == 403
    assert client.get("/api/v1/auth/callback?state=中文&code=code").status_code == 403


def test_new_actions_use_fixed_scripts():
    for action in (
        "health",
        "capabilities",
        "memory_processes",
        "failed_services",
        "containers",
        "kernel",
    ):
        assert diagnostics.command_for(action).startswith(diagnostics.PREFIX)
        with pytest.raises(ValueError):
            diagnostics.command_for(action, "nginx; touch /tmp/no")
    containers = diagnostics.command_for("containers")
    assert (
        "timeout -k 1 8" in containers
        and "inspect" not in containers
        and " exec " not in containers
    )


def test_mcp_stale_binding_does_not_execute(client, key_pair, monkeypatch):
    hid = ready_host(client, key_pair)
    rev = store.get_host(hid)["revision"]
    with store.db() as c:
        c.execute("UPDATE hosts SET revision=revision+1 WHERE id=?", (hid,))
    monkeypatch.setattr(
        diagnostics,
        "execute",
        lambda *a, **k: pytest.fail("Stale target must not execute"),
    )
    payload = mcp_call(
        client,
        store.token("mcp.token"),
        "ssh_diagnose_cpu",
        {"host_id": hid, "expected_revision": rev},
    )[1]
    assert payload["status"] == "failed" and "配置已变更" in payload["error"]
    assert client.get("/api/v1/jobs").json()["total"] == 0


def test_fixed_commands_preserve_upstream_failure(tmp_path):
    # Exercise real shell exit semantics with disposable executables; no Docker/systemd access.
    for tool in ("docker", "systemctl"):
        fake = tmp_path / tool
        fake.write_text("#!/bin/sh\nexit 42\n")
        fake.chmod(0o700)
    for action in ("containers", "failed_services"):
        result = subprocess.run(
            ["/bin/sh", "-c", diagnostics.ACTIONS[action]],
            env={**os.environ, "PATH": str(tmp_path) + ":/usr/bin:/bin"},
            capture_output=True,
            timeout=5,
        )
        assert result.returncode == 42


def test_gateway_allows_fixed_root_connection_and_refuses_shell():
    from pathlib import Path

    gateway = str(
        Path(__file__).resolve().parents[1] / "gateway/aiops-diagnostic-gateway"
    )
    for request in (
        "id",
        "aiops-v1 exec 30",
        "aiops-v1 connection 30; id",
        "aiops-v1 service 30 nginx;id",
    ):
        result = subprocess.run(
            ["/bin/sh", gateway],
            env={**os.environ, "SSH_ORIGINAL_COMMAND": request},
            capture_output=True,
            timeout=5,
        )
        assert result.returncode == 64 and b"AIOPS_GATEWAY" not in result.stdout
    result = subprocess.run(
        ["/bin/sh", gateway],
        env={**os.environ, "SSH_ORIGINAL_COMMAND": "aiops-v1 connection 30"},
        capture_output=True,
        timeout=5,
    )
    assert result.returncode == 0 and result.stdout.startswith(
        b"AIOPS_GATEWAY_V1\nAIOPS_SSH_OK\n"
    )


def test_legacy_api_does_not_overwrite_changed_host_or_duplicate_audit(
    client, key_pair, monkeypatch
):
    hid = ready_host(client, key_pair)

    def execute(*args, **kwargs):
        with store.db() as c:
            c.execute(
                "UPDATE hosts SET revision=revision+1,last_status='untested' WHERE id=?",
                (hid,),
            )
        return {
            "status": "success",
            "host_id": hid,
            "action": "connection",
            "exit_code": 0,
        }

    monkeypatch.setattr(diagnostics, "execute", execute)
    response = client.post(f"/api/v1/hosts/{hid}/test", headers=auth())
    assert response.status_code == 200, response.text
    assert store.get_host(hid)["last_status"] == "untested"
    with store.db() as c:
        assert (
            c.execute(
                "SELECT COUNT(*) FROM audit WHERE action='connection'"
            ).fetchone()[0]
            == 1
        )


def test_inline_job_cancelled_before_claim_has_a_typed_result(
    client, key_pair, monkeypatch
):
    hid = ready_host(client, key_pair)
    monkeypatch.setattr(
        jobs, "work", lambda ident: jobs.cancel(ident, actor="ou_123456789")
    )
    result = jobs.run_inline(hid, "health", "ou_123456789", source="web")
    assert (
        result["status"] == "cancelled"
        and result["host_id"] == hid
        and result["job_id"]
    )
