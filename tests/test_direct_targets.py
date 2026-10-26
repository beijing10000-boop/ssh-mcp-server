"""Exact registered-IP lookup for Skill clients, without monitoring queries."""

from sshmcp import store
from test_core import auth
from test_console import ready_host, mcp_call


def test_direct_target_is_scoped_and_never_opens_ssh(client, key_pair, monkeypatch):
    group = client.post(
        "/api/v1/groups", headers=auth(), json={"name": "allowed"}
    ).json()["id"]
    allowed = ready_host(client, key_pair, group=group, zabbix="")
    ready_host(client, key_pair, address="10.20.0.11", zabbix="102")
    token = client.post(
        "/api/v1/mcp/clients",
        headers=auth(),
        json={"name": "skill", "group_ids": [group], "actions": ["cpu"]},
    ).json()["token"]
    monkeypatch.setattr(
        "sshmcp.jobs.run_inline",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("resolve must not SSH")),
    )
    result = mcp_call(client, token, "ssh_resolve_target", {"address": "10.20.0.10"})[1]
    assert result["status"] == "success" and result["host_id"] == allowed
    assert result["address"] == "10.20.0.10" and result["revision"] >= 1
    assert not result["zabbix_hostid"]
    for address in ("10.20.0.11", "10.20.0.99"):
        hidden = mcp_call(client, token, "ssh_resolve_target", {"address": address})[1]
        assert hidden["status"] == "failed" and "host_id" not in hidden
    listed = mcp_call(client, token, "ssh_list_hosts")[1]
    if isinstance(listed, dict):
        listed = listed["result"]
    assert len(listed) == 1 and listed[0]["address"] == "10.20.0.10"
    with store.db() as db:
        db.execute("UPDATE hosts SET enabled=0 WHERE id=?", (allowed,))
    assert (
        mcp_call(client, token, "ssh_resolve_target", {"address": "10.20.0.10"})[1][
            "status"
        ]
        == "failed"
    )


def test_direct_target_rejects_public_ips_domains_and_unreviewed_assets(
    client, key_pair
):
    token = store.token("mcp.token")
    for address in ("8.8.8.8", "localhost", "10.20.0.10;id", "fd00::1%eth0"):
        assert mcp_call(client, token, "ssh_resolve_target", {"address": address})[1][
            "isError"
        ]
    client.post(
        "/api/v1/hosts",
        headers=auth(),
        json={"name": "not reviewed", "address": "10.20.0.12"},
    )
    assert (
        mcp_call(client, token, "ssh_resolve_target", {"address": "10.20.0.12"})[1][
            "status"
        ]
        == "failed"
    )
