"""Replacing a lost MCP token, and deleting clients that no longer work."""

import pytest

from sshmcp import jobs, store
from test_console import auth, mcp_call


def make(client, name="log-platform", **more):
    created = client.post(
        "/api/v1/mcp/clients",
        headers=auth(),
        json={
            "name": name,
            "all_hosts": True,
            "actions": ["cpu", "java_apps"],
            "valid_days": 30,
            **more,
        },
    )
    assert created.status_code == 201, created.text
    return created.json()["id"], created.json()["token"]


def listed(client, ident):
    rows = client.get("/api/v1/mcp/clients").json()["items"]
    return next((row for row in rows if row["id"] == ident), None)


def test_a_lost_token_is_replaced_without_a_new_client(client):
    ident, old = make(client)
    assert mcp_call(client, old, "ssh_list_groups")[0] == 200
    before = listed(client, ident)
    assert before["last_used_at"]
    rotated = client.post(f"/api/v1/mcp/clients/{ident}/rotate", headers=auth())
    assert rotated.status_code == 200, rotated.text
    new = rotated.json()["token"]
    assert new.startswith("sshmcp_") and new != old and rotated.json()["id"] == ident
    after = listed(client, ident)
    assert "token" not in after and "token_hash" not in after
    assert (after["name"], after["actions"], after["all_hosts"]) == (
        "log-platform",
        ["cpu", "java_apps"],
        1,
    )
    assert after["prefix"] == new[:14] != before["prefix"]
    # Validity starts over (90 days unless said), and so does "last used".
    assert after["expires_at"] - before["expires_at"] > 50 * 86400
    assert after["last_used_at"] is None and after["enabled"] == 1
    # The old token is dead at once; the new one is the same client, and its
    # first use is recorded without waiting out the old token's minute.
    assert mcp_call(client, old, "ssh_list_groups")[0] == 401
    assert mcp_call(client, new, "ssh_list_groups")[0] == 200
    assert listed(client, ident)["last_used_at"]
    with store.db() as c:
        dumped = str([dict(r) for r in c.execute("SELECT * FROM mcp_clients")])
        audit = c.execute(
            "SELECT target,detail FROM audit WHERE action='mcp_client_rotate'"
        ).fetchone()
    assert new not in dumped and old not in dumped
    assert (audit["target"], audit["detail"]) == (ident, "name=log-platform")
    # Days of one's own choosing; out of range refused.
    short = client.post(
        f"/api/v1/mcp/clients/{ident}/rotate", headers=auth(), json={"valid_days": 7}
    )
    assert short.status_code == 200
    assert listed(client, ident)["expires_at"] < after["expires_at"]
    for bad in ({"valid_days": 0}, {"valid_days": 366}, {"name": "x"}):
        refused = client.post(
            f"/api/v1/mcp/clients/{ident}/rotate", headers=auth(), json=bad
        )
        assert refused.status_code == 422, bad
    # An expired client is renewed by it; a revoked or unknown one gets none.
    with store.db() as c:
        c.execute("UPDATE mcp_clients SET expires_at=1 WHERE id=?", (ident,))
    assert listed(client, ident)["expired"] is True
    renewed = client.post(f"/api/v1/mcp/clients/{ident}/rotate", headers=auth())
    assert mcp_call(client, renewed.json()["token"], "ssh_list_groups")[0] == 200
    assert (
        client.post(f"/api/v1/mcp/clients/{ident}/revoke", headers=auth()).status_code
        == 200
    )
    for target in (ident, "nope"):
        gone = client.post(f"/api/v1/mcp/clients/{target}/rotate", headers=auth())
        assert gone.status_code == 404
    # Like every write of the console: an administrator's session and its CSRF token.
    assert client.post(f"/api/v1/mcp/clients/{ident}/rotate").status_code == 403


def test_a_revoked_or_expired_client_can_be_deleted_and_its_name_reused(client):
    ident, token = make(client)
    # One that still works must be revoked first.
    refused = client.delete(f"/api/v1/mcp/clients/{ident}", headers=auth())
    assert refused.status_code == 409 and "先撤销" in refused.json()["detail"]
    assert mcp_call(client, token, "ssh_list_groups")[0] == 200
    assert (
        client.post(f"/api/v1/mcp/clients/{ident}/revoke", headers=auth()).status_code
        == 200
    )
    # Revoked, it still holds its name ...
    taken = client.post(
        "/api/v1/mcp/clients",
        headers=auth(),
        json={"name": "log-platform", "all_hosts": True, "actions": ["cpu"]},
    )
    assert taken.status_code == 409
    # ... until it is deleted.
    assert client.delete(f"/api/v1/mcp/clients/{ident}").status_code == 403
    assert (
        client.delete(f"/api/v1/mcp/clients/{ident}", headers=auth()).status_code == 200
    )
    assert listed(client, ident) is None
    assert (
        client.delete(f"/api/v1/mcp/clients/{ident}", headers=auth()).status_code == 404
    )
    again, fresh = make(client)
    assert again != ident and mcp_call(client, fresh, "ssh_list_groups")[0] == 200
    assert mcp_call(client, token, "ssh_list_groups")[0] == 401
    with store.db() as c:
        audit = c.execute(
            "SELECT target,detail FROM audit WHERE action='mcp_client_delete'"
        ).fetchone()
    assert (audit["target"], audit["detail"]) == (ident, "name=log-platform")
    # A job the deleted client left in the queue is refused when its turn comes.
    with pytest.raises(PermissionError):
        jobs.authorize(
            {"source": "mcp", "actor": "mcp:" + ident, "action": "cpu", "host_id": 1},
            {"action": "cpu"},
        )
    # An expired one can go without being revoked.
    with store.db() as c:
        c.execute("UPDATE mcp_clients SET expires_at=1 WHERE id=?", (again,))
    assert (
        client.delete(f"/api/v1/mcp/clients/{again}", headers=auth()).status_code == 200
    )
    assert client.get("/api/v1/mcp/clients").json()["items"] == []
