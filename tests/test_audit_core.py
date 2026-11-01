"""2026-11 audit regressions: job finalization, implied-action records, a lost
master.key, collect job scope, error codes, bulk SSH binding and the
recommended client scope."""

import json
import logging
import sqlite3

import pytest
from cryptography.fernet import Fernet

from sshmcp import access, catalog, diagnostics, jobs, store
from sshmcp.mcp_tools import error_code
from test_console import auth, mcp_call, ready_host


def _queued(client, key_pair, monkeypatch, action="cpu"):
    hid = ready_host(client, key_pair)
    monkeypatch.setattr(jobs.POOL, "submit", lambda *_: None)
    return hid, jobs.create([hid], {"action": action}, "ou_123456789")["job_ids"][0]


def _status(ident):
    with store.db() as c:
        return c.execute(
            "SELECT status,error,result FROM diagnostic_jobs WHERE id=?", (ident,)
        ).fetchone()


def _parsed(**extra):
    return {"status": "success", "summary": {}, "findings": [], "output": "ok", **extra}


# SSH-CORE-06: a claimed job always ends in a final state.


def test_undecryptable_request_fails_the_job_instead_of_leaving_it_running(
    client, key_pair, monkeypatch
):
    _, task = _queued(client, key_pair, monkeypatch)
    # Sealed with another master.key, e.g. a database restored with the wrong key.
    with store.db() as c:
        c.execute(
            "UPDATE diagnostic_jobs SET request=? WHERE id=?",
            (Fernet(Fernet.generate_key()).encrypt(b"{}").decode(), task),
        )
    monkeypatch.setattr(
        diagnostics, "execute", lambda *a, **k: pytest.fail("no SSH without request")
    )
    jobs.work(task)
    row = _status(task)
    assert row["status"] == "failed" and row["error"] == "InvalidToken"
    assert json.loads(store.unseal(row["result"]))["error_code"] == "failed"


def test_unsavable_result_ends_the_inline_job_as_failed(client, key_pair, monkeypatch):
    hid = ready_host(client, key_pair)
    monkeypatch.setattr(
        diagnostics, "execute", lambda *a, **k: _parsed(unserializable={1, 2})
    )
    result = jobs.run_inline(hid, "cpu", "ou_123456789", source="web")
    assert result["status"] == "failed" and result["error_code"] == "failed"
    job = jobs.detail(result["job_id"])
    assert job["status"] == "failed" and "保存失败" in job["error"]
    with store.db() as c:
        assert (
            c.execute(
                "SELECT outcome FROM audit WHERE action='cpu' AND target=?", (str(hid),)
            ).fetchone()[0]
            == "failed"
        )


def test_result_write_is_retried_while_the_database_stays_locked(
    client, key_pair, monkeypatch
):
    _, task = _queued(client, key_pair, monkeypatch)
    monkeypatch.setattr(diagnostics, "execute", lambda *a, **k: _parsed())
    original, calls = jobs._save, []

    def locked_once(*args):
        calls.append(args[0])
        if len(calls) == 1:
            raise sqlite3.OperationalError("database is locked")
        return original(*args)

    monkeypatch.setattr(jobs, "_save", locked_once)
    jobs.work(task)
    assert calls == [task, task] and jobs.detail(task)["status"] == "success"


def test_background_job_crash_is_logged(monkeypatch, caplog):
    def crash(ident, background=False):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(jobs, "work", crash)
    with caplog.at_level(logging.ERROR, logger="sshmcp.jobs"):
        jobs._background("f" * 32)
    assert "f" * 32 in caplog.text


# SSH-CORE-07: each implied action is considered once per client.


def test_implied_actions_are_recorded_per_action(client, monkeypatch):
    ident = client.post(
        "/api/v1/mcp/clients",
        headers=auth(),
        json={"name": "platform", "all_hosts": True, "actions": ["containers", "logs"]},
    ).json()["id"]

    def marker():
        with store.db() as c:
            return c.execute(
                "SELECT actions_extended FROM mcp_clients WHERE id=?", (ident,)
            ).fetchone()[0]

    def actions():
        return next(
            c["actions"]
            for c in client.get("/api/v1/mcp/clients").json()["items"]
            if c["id"] == ident
        )

    # The v0.6.0 set keeps the single marker an older release also reads.
    assert marker() == "v0.6.0"
    with store.db() as c:
        c.execute("UPDATE mcp_clients SET actions_extended='' WHERE id=?", (ident,))
    assert access.extend_client_actions() == [
        (ident, ["java", "nginx", "nginx_access", "service_detail", "syslog"])
    ]
    kept = [a for a in actions() if a != "nginx"]
    assert (
        client.put(
            f"/api/v1/mcp/clients/{ident}", headers=auth(), json={"actions": kept}
        ).status_code
        == 200
    )
    # A later release adds an implied action: only that one is considered, and
    # the nginx the administrator removed is not granted again.
    monkeypatch.setitem(access.EXTENDS, "container_stats", ("containers",))
    assert access.extend_client_actions() == [(ident, ["container_stats"])]
    assert actions() == sorted(kept + ["container_stats"])
    assert sorted(json.loads(marker())) == sorted(access.EXTENDS)
    assert access.extend_client_actions() == []
    # A marker this release cannot read never widens the scope.
    with store.db() as c:
        c.execute(
            "UPDATE mcp_clients SET actions_extended='v9.9.9',actions=? WHERE id=?",
            (json.dumps(["containers", "logs"]), ident),
        )
    assert access.extend_client_actions() == []
    assert actions() == ["containers", "logs"]


# SSH-CORE-09: a lost master.key is never silently replaced.


def _seal_setting():
    store.save_settings({"lark_app_secret": "fixture"}, {"lark_app_secret"})


def _seal_credential():
    with store.db() as c:
        c.execute(
            "INSERT INTO credentials(name,secret) VALUES ('fixture',?)",
            (store.seal("private key fixture"),),
        )


@pytest.mark.parametrize(
    "seal", [_seal_setting, _seal_credential], ids=["setting", "credential"]
)
def test_missing_master_key_with_sealed_data_refuses_to_start(
    client, tmp_path, monkeypatch, seal
):
    monkeypatch.setattr(store, "DATA_DIR", tmp_path)
    key = tmp_path / "master.key"
    store.init_db()
    # Nothing sealed yet: a fresh key is still fine.
    key.unlink()
    store.init_db()
    backup = key.read_bytes()
    seal()
    key.unlink()
    with pytest.raises(RuntimeError, match="master.key"):
        store.init_db()
    assert not key.exists()
    # Restoring the key from the backup is the way back.
    key.write_bytes(backup)
    store.init_db()
    with store.db() as c:
        row = c.execute(
            "SELECT value AS sealed FROM settings WHERE encrypted=1 "
            "UNION ALL SELECT secret FROM credentials"
        ).fetchone()
    assert store.unseal(row["sealed"])


# SSH-CORE-12: collect jobs are queried and cancelled per step.


def test_collect_jobs_are_queried_and_cancelled_per_step(client, key_pair, monkeypatch):
    hid = ready_host(client, key_pair)
    created = client.post(
        "/api/v1/mcp/clients",
        headers=auth(),
        json={"name": "steps-only", "all_hosts": True, "actions": ["cpu", "memory"]},
    ).json()
    token, actor = created["token"], "mcp:" + created["id"]
    monkeypatch.setattr(jobs.POOL, "submit", lambda *_: None)

    def submit(steps):
        return jobs.create(
            [hid],
            {"action": "collect", "options": {"actions": steps}},
            actor,
            source="mcp",
        )

    batch = submit(["cpu", "memory"])
    task = batch["job_ids"][0]
    _, job = mcp_call(client, token, "ssh_get_diagnostic_job", {"job_id": task})
    assert job["action"] == "collect" and job["status"] == "queued"
    _, page = mcp_call(
        client, token, "ssh_get_diagnostic_batch", {"batch_id": batch["batch_id"]}
    )
    assert page["total"] == 1 and page["counts"]["queued"] == 1
    _, cancelled = mcp_call(
        client, token, "ssh_cancel_diagnostic_job", {"job_id": task}
    )
    assert cancelled["ok"] is True and jobs.detail(task)["status"] == "cancelled"
    # A step outside the client's scope still refuses the whole job.
    other = submit(["cpu", "disk"])["job_ids"][0]
    _, refused = mcp_call(client, token, "ssh_get_diagnostic_job", {"job_id": other})
    assert refused["error_code"] == "forbidden"


# SSH-CORE-05: classification only; the error text is unchanged.


@pytest.mark.parametrize(
    "message,code",
    [
        ("主机 1: 主机未启用、未核验公钥或未绑定凭据", "not_ready"),
        ("主机 1: 待执行任务已达上限，请等待现有任务完成", "busy"),
        ("主机 1: 资产不是 Linux，不能执行 SSH 诊断", "not_linux"),
        # Unchanged codes around the new entries.
        ("未核验 SSH 主机公钥；请先批量获取并确认 SHA256 指纹", "host_unverified"),
        ("主机 1: 主机配置已变更，请重新解析映射并确认诊断目标", "revision_changed"),
        ("主机 1: 此动作需要标准 SSH 模式；受限网关尚不支持", "unsupported"),
        ("请选择 1–100 台主机", "invalid_argument"),
    ],
)
def test_error_code_mapping(message, code):
    assert error_code(ValueError(message), message) == code


def test_not_ready_host_and_full_queue_codes_over_mcp(client, key_pair, monkeypatch):
    token = store.token("mcp.token")
    monkeypatch.setattr(
        diagnostics, "execute", lambda *a, **k: pytest.fail("must not execute")
    )
    hid = ready_host(client, key_pair)

    def enable(value):
        response = client.post(
            "/api/v1/hosts/bulk-enabled",
            headers=auth(),
            json={"host_ids": [hid], "enabled": value},
        )
        assert response.status_code == 200

    enable(False)
    _, result = mcp_call(client, token, "ssh_diagnose_cpu", {"host_id": hid})
    assert result["error_code"] == "not_ready"
    assert "主机未启用、未核验公钥或未绑定凭据" in result["error"]
    enable(True)
    with store.db() as c:
        c.executemany(
            "INSERT INTO diagnostic_jobs(id,batch_id,host_id,host_name,host_revision,actor,source,action,request) "
            "VALUES (?,'full',?,'fixture',1,'fixture','web','cpu','x')",
            [(f"{i:032x}", hid) for i in range(200)],
        )
    _, result = mcp_call(client, token, "ssh_diagnose_cpu", {"host_id": hid})
    assert result["error_code"] == "busy" and "待执行任务已达上限" in result["error"]


# SSH-FE-01: bulk binding changes only the fields given.


def test_bulk_binding_keeps_unspecified_fields_and_reports_cleared_keys(
    client, key_pair
):
    def credential(name):
        r = client.post(
            "/api/v1/credentials",
            headers=auth(),
            json={"name": name, "private_key": key_pair[0]},
        )
        assert r.status_code == 201, r.text
        return r.json()["id"]

    first, second = credential("bind-a"), credential("bind-b")
    with store.db() as c:
        proxy = c.execute(
            "INSERT INTO proxies(name,address,port,username,host_key,credential_id) "
            "VALUES ('jump','10.30.0.1',22,'root',?,?)",
            (key_pair[1], first),
        ).lastrowid

    def host(address, **values):
        body = {
            "name": "bind " + address,
            "address": address,
            "username": "root",
            "host_key": key_pair[1],
            "credential_id": first,
            **values,
        }
        r = client.post("/api/v1/hosts", headers=auth(), json=body)
        assert r.status_code == 201, r.text
        return r.json()["id"]

    direct = host("10.30.0.11")
    jumped = host("10.30.0.12", port=2222, proxy_id=proxy, username="ops")
    windows = host("10.30.0.13", asset_type="windows", host_key="")

    def bind(**body):
        return client.post("/api/v1/hosts/bulk-access", headers=auth(), json=body)

    def row(ident):
        with store.db() as c:
            return dict(
                c.execute(
                    "SELECT credential_id,username,port,proxy_id,host_key,revision FROM hosts WHERE id=?",
                    (ident,),
                ).fetchone()
            )

    # Only the credential: ports, jump host and users stay, and so do the keys;
    # the non-Linux asset is skipped and listed, as the dialog says.
    r = bind(host_ids=[direct, jumped, windows], credential_id=second)
    assert r.status_code == 200, r.text
    r = r.json()
    assert (r["count"], r["updated"], r["key_cleared"]) == (2, 2, [])
    assert [x["host_id"] for x in r["skipped"]] == [windows]
    assert (row(direct)["port"], row(direct)["proxy_id"], row(direct)["username"]) == (
        22,
        None,
        "root",
    )
    assert (row(jumped)["port"], row(jumped)["proxy_id"], row(jumped)["username"]) == (
        2222,
        proxy,
        "ops",
    )
    assert all(
        row(h)["credential_id"] == second and row(h)["host_key"]
        for h in (direct, jumped)
    )
    # A port change clears the key only where the port really changes.
    before = row(jumped)["revision"]
    r = bind(host_ids=[direct, jumped], port=2222).json()
    assert r["updated"] == 1 and [x["host_id"] for x in r["key_cleared"]] == [direct]
    assert not row(direct)["host_key"] and row(jumped)["host_key"]
    assert row(jumped)["revision"] == before
    # An explicit null proxy means direct: only the jumped host moves.
    r = bind(host_ids=[direct, jumped], proxy_id=None).json()
    assert [x["host_id"] for x in r["key_cleared"]] == [jumped]
    assert row(jumped)["proxy_id"] is None
    # Nothing to change, only non-Linux assets, or an unknown host: refused.
    assert bind(host_ids=[direct]).status_code == 422
    assert bind(host_ids=[windows], credential_id=first).status_code == 422
    assert bind(host_ids=[direct, 999999], credential_id=first).status_code == 422
    assert row(direct)["credential_id"] == second


# Recommended scope served by the API (「按 AI Ops Platform 推荐勾选」).


def test_tools_mark_the_recommended_client_scope(client):
    tools = client.get("/api/v1/tools").json()
    assert all(isinstance(t["recommended"], bool) for t in tools)
    recommended = {t["id"] for t in tools if t["recommended"]}
    assert recommended == catalog.RECOMMENDED <= catalog.TITLES.keys()
    # What the platform's Skills use but the old console list missed.
    assert {
        "mount_health",
        "containers",
        "resource_limits",
        "block_devices",
        "timers",
        "time_sync",
        "container_stats",
        "security_status",
    } <= recommended
    # Costly or intrusive actions stay a manual decision; collect is per step.
    assert not recommended & {
        "jvm",
        "triage",
        "directory",
        "peer_connections",
        "peer_traffic",
        "collect",
    }
    # The MCP catalogue itself is unchanged.
    entries = mcp_call(client, store.token("mcp.token"), "ssh_list_tool_catalog")[1]
    assert entries["result"] and all("recommended" not in e for e in entries["result"])
