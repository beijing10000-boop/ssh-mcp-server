import io
import paramiko
import pytest
from fastapi.testclient import TestClient
from sshmcp import store
from sshmcp.main import app


@pytest.fixture(scope="session")
def client(tmp_path_factory):
    # MCP Streamable HTTP session_manager may run only once per application instance.
    old = store.DATA_DIR
    store.DATA_DIR = tmp_path_factory.mktemp("ssh-mcp")
    try:
        with TestClient(app) as c:
            yield c
    finally:
        store.DATA_DIR = old


@pytest.fixture(autouse=True)
def reset_tables(client):
    from sshmcp.auth import COOKIE, _hash

    client.cookies.clear()
    with store.db() as c:
        for table in (
            "zabbix_sync_items",
            "zabbix_sync_runs",
            "zabbix_memberships",
            "zabbix_groups",
            "diagnostic_jobs",
            "mcp_clients",
            "scan_results",
            "scan_batches",
            "host_key_candidates",
            "host_groups",
            "hosts",
            "proxies",
            "credentials",
            "groups",
            "audit",
            "web_sessions",
            "oauth_states",
            "settings",
        ):
            c.execute("DELETE FROM " + table)
    assert client.get("/api/v1/setup/status").json()["setup_required"] is True
    setup = client.post(
        "/api/v1/setup",
        json={
            "bootstrap_token": store.token("bootstrap.token"),
            "web_protocol": "http",
            "web_public_host": "127.0.0.1:9099",
            "lark_app_id": "cli_1234567890abcdef",
            "lark_app_secret": "dummy-app-secret",
            "feishu_admin_open_ids": "ou_123456789",
        },
    )
    assert setup.status_code == 200, setup.text
    with store.db() as c:
        c.execute(
            "INSERT INTO web_sessions(token_hash,open_id,name,csrf,expires) VALUES (?,?,?,?,?)",
            (
                _hash("test-session"),
                "ou_123456789",
                "已授权管理员",
                "unit-test-csrf",
                9999999999,
            ),
        )
    client.cookies.set(COOKIE, "test-session")


@pytest.fixture(scope="session")
def key_pair():
    key = paramiko.RSAKey.generate(2048)
    stream = io.StringIO()
    key.write_private_key(stream)
    return stream.getvalue(), "ssh-rsa " + key.get_base64()
