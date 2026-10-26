"""Admin workflow regressions, especially preflight must never pin a key."""

from sshmcp import diagnostics, jobs, store
from test_console import auth, ready_host


def test_inventory_group_search_sort_and_detail(client, key_pair, monkeypatch):
    group = client.post(
        "/api/v1/groups", headers=auth(), json={"name": "数据库生产"}
    ).json()["id"]
    first = ready_host(client, key_pair, group=group)
    second = ready_host(client, key_pair, address="10.20.0.11", zabbix="102")
    found = client.get("/api/v1/inventory/hosts?q=数据库").json()
    assert [h["id"] for h in found["items"]] == [first]
    ordered = client.get("/api/v1/inventory/hosts?sort=address&direction=asc").json()[
        "items"
    ]
    assert [h["id"] for h in ordered] == [first, second]
    assert (
        client.get("/api/v1/inventory/hosts?sort=name;drop table hosts").status_code
        == 422
    )
    monkeypatch.setattr(
        diagnostics,
        "execute",
        lambda *a, **k: {"status": "failed", "error": "fixture connection failure"},
    )
    jobs.run_inline(first, "connection", "ou_123456789", source="web")
    detail = client.get(f"/api/v1/hosts/{first}/detail").json()
    assert (
        detail["host"]["last_test_at"]
        and detail["last_test"]["error"] == "fixture connection failure"
    )
    assert detail["recent"][0]["action"] == "connection"
    targets = client.post(
        "/api/v1/inventory/targets", headers=auth(), json={"host_ids": [first, second]}
    ).json()
    assert len(targets) == 2 and all("host_key" not in h for h in targets)


def test_precheck_and_matching_only_save_revalidate_and_audit(client, key_pair):
    first = ready_host(client, key_pair)
    second = ready_host(client, key_pair, address="10.20.0.11", zabbix="102")
    fingerprint = diagnostics.host_fingerprint(key_pair[1])
    with store.db() as c:
        c.execute(
            "INSERT INTO scan_batches(id,status,total) VALUES ('fixture','finished',2)"
        )
        for hid in (first, second):
            c.execute("UPDATE hosts SET host_key='' WHERE id=?", (hid,))
            c.execute(
                "INSERT INTO host_key_candidates(host_id,key,fingerprint,source_signature) VALUES (?,?,?,?)",
                (
                    hid,
                    key_pair[1],
                    fingerprint,
                    store.scan_signature(
                        dict(
                            c.execute(
                                "SELECT * FROM hosts WHERE id=?", (hid,)
                            ).fetchone()
                        )
                    ),
                ),
            )
            c.execute(
                "INSERT INTO scan_results(batch_id,host_id,status,fingerprint,algorithm) VALUES ('fixture',?,'candidate',?,'ssh-rsa')",
                (hid, fingerprint),
            )
    result = client.post(
        "/api/v1/host-keys/precheck",
        headers=auth(),
        json={
            "batch_id": "fixture",
            "manifest": f"{first} {fingerprint}\n{second} SHA256:wrong\n10.99.0.99 {fingerprint}\ninvalid line",
        },
    ).json()
    assert [r["status"] for r in result["items"]] == [
        "matched",
        "mismatch",
        "not_found",
        "invalid",
    ]
    assert not store.get_host(first)["host_key"]
    # Simulate endpoint drift after preview. Confirmation must reject that row.
    with store.db() as c:
        c.execute(
            "UPDATE hosts SET port=2222,revision=revision+1 WHERE id=?", (second,)
        )
    r = client.post(
        "/api/v1/host-keys/confirm-batch",
        headers=auth(),
        json={
            "confirmed": True,
            "matched_only": True,
            "items": [
                {"host_id": h, "independently_verified_sha256": fingerprint}
                for h in (first, second)
            ],
        },
    ).json()
    assert r["count"] == 1 and r["skipped"][0]["host_id"] == second
    assert store.get_host(first)["host_key"] and not store.get_host(second)["host_key"]
    with store.db() as c:
        assert (
            c.execute(
                "SELECT COUNT(*) FROM audit WHERE action='host_key_mismatch' AND outcome='denied'"
            ).fetchone()[0]
            == 2
        )


def test_retry_only_failed_and_task_status(client, key_pair, monkeypatch):
    first = ready_host(client, key_pair)
    second = ready_host(client, key_pair, address="10.20.0.11", zabbix="102")
    monkeypatch.setattr(jobs.POOL, "submit", lambda *_: None)
    batch = jobs.create([first, second], {"action": "health"}, "ou_123456789")
    with store.db() as c:
        c.execute(
            "UPDATE diagnostic_jobs SET status='success',completed_at=CURRENT_TIMESTAMP WHERE id=?",
            (batch["job_ids"][0],),
        )
        c.execute(
            "UPDATE diagnostic_jobs SET status='failed',completed_at=CURRENT_TIMESTAMP WHERE id=?",
            (batch["job_ids"][1],),
        )
    r = client.post(
        f"/api/v1/jobs/batches/{batch['batch_id']}/retry-failed", headers=auth()
    ).json()
    assert r["total"] == 1 and r["accepted"][0]["host_id"] == second
    status = client.get("/api/v1/jobs/status").json()
    assert (
        status["pending"] == 1
        and status["capacity"] == 4
        and status["queue_capacity"] == 200
    )


def test_workflow_assets_are_local_and_csp_safe(client):
    assert client.get("/static/interactions.js").status_code == 200
    assert "script-src 'self'" in client.get("/").headers["content-security-policy"]
    client.cookies.clear()
    assert client.get("/api/v1/jobs/status").status_code == 401
    assert client.post("/api/v1/host-keys/precheck", json={}).status_code == 401
