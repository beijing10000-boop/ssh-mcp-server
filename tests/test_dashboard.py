"""Overview uses consistent Linux readiness and bounded encrypted history facts."""

import json
import time
from sshmcp import diagnostics, jobs, store
from sshmcp.catalog import entries, TITLES
from test_console import auth, ready_host


def test_dashboard_funnel_diagnostic_rate_findings_and_clients(
    client, key_pair, monkeypatch
):
    first = ready_host(client, key_pair)
    second = ready_host(client, key_pair, address="10.20.0.11", zabbix="102")
    client.post(
        "/api/v1/hosts",
        headers=auth(),
        json={
            "name": "switch",
            "address": "10.20.0.12",
            "username": "root",
            "asset_type": "network",
        },
    )

    def observe(hid, action, **kwargs):
        if action == "connection":
            return {
                "action": action,
                "status": "success",
                "output": "AIOPS_SSH_OK\n0\nLinux",
            }
        return {
            "action": action,
            "status": "success" if hid == first else "partial",
            "output": "MemTotal: 1000 kB\nMemAvailable: 40 kB\nsecret=do-not-return-raw",
            "stderr": "" if hid == first else "fixture missing capability",
        }

    monkeypatch.setattr(diagnostics, "execute", observe)
    jobs.run_inline(first, "connection", "ou_123456789", source="web")
    jobs.run_inline(first, "memory", "ou_123456789", source="web")
    jobs.run_inline(second, "memory", "ou_123456789", source="web")
    token = client.post(
        "/api/v1/mcp/clients",
        headers=auth(),
        json={
            "name": "expires-soon",
            "all_hosts": True,
            "actions": ["memory"],
            "valid_days": 3,
        },
    ).json()
    with store.db() as c:
        c.execute(
            "UPDATE mcp_clients SET last_used_at=CURRENT_TIMESTAMP WHERE id=?",
            (token["id"],),
        )
    data = client.get("/api/v1/overview").json()
    assert data["funnel"] == {
        "registered": 3,
        "eligible": 2,
        "credential_bound": 2,
        "key_verified": 2,
        "tested": 1,
    }
    assert data["ready"] == 2 and data["verified"] == 1
    assert (
        data["diagnostics_24h"]["total"] == 2
        and data["diagnostics_24h"]["success_rate"] == 50
    )
    assert data["recent_findings"][0]["level"] == "critical"
    assert data["mcp"]["active_24h"] == 1 and data["mcp"]["expiring_7d"] == 1
    assert "do-not-return-raw" not in json.dumps(data) and token[
        "token"
    ] not in json.dumps(data)
    assert (
        client.get("/api/v1/inventory/hosts?status=credential_bound").json()["total"]
        == 2
    )


def test_empty_dashboard_and_expired_reminders(client):
    data = client.get("/api/v1/overview").json()
    assert data["hosts"] == 0 and data["diagnostics_24h"]["success_rate"] is None
    token = client.post(
        "/api/v1/mcp/clients",
        headers=auth(),
        json={"name": "expired", "all_hosts": True, "actions": ["health"]},
    ).json()
    with store.db() as c:
        c.execute(
            "UPDATE mcp_clients SET expires_at=? WHERE id=?",
            (int(time.time()) - 1, token["id"]),
        )
    data = client.get("/api/v1/overview").json()
    assert data["mcp"]["expired"] == 1 and data["mcp"]["expiring_7d"] == 0


def test_catalog_explains_questions_parameters_and_duration(client):
    tools = client.get("/api/v1/tools").json()
    assert {tool["id"] for tool in tools} == set(TITLES)
    assert all(
        t["question"] and t["duration_hint"] and isinstance(t["parameters"], list)
        for t in tools
    )
    assert next(t for t in entries() if t["id"] == "triage")["estimated_seconds"] == 60


def test_ui_assets_stay_self_hosted(client):
    assert client.get("/static/presentation.js").status_code == 200
    html = client.get("/")
    assert "script-src 'self'" in html.headers["content-security-policy"]
    assert "https://" not in html.text and "cdn" not in html.text.lower()
    assert (
        'id="breadcrumb-section"' in html.text
        and 'data-action="density-toggle"' in html.text
    )
