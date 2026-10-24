"""纯本地回归测试：不连接真实 SSH 服务器、不需要 Zabbix 或 AI 模型。"""
import io

import paramiko
import pytest
from fastapi.testclient import TestClient

from sshmcp import diagnostics, store
from sshmcp.main import app


@pytest.fixture(scope="module")
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
            "scan_results", "scan_batches", "host_key_candidates", "host_groups",
            "hosts", "proxies", "credentials", "groups", "audit",
            "web_sessions", "oauth_states", "settings"
        ):
            c.execute("DELETE FROM " + table)
    assert client.get("/api/v1/setup/status").json()["setup_required"] is True
    setup = client.post("/api/v1/setup", json={
        "bootstrap_token": store.token("bootstrap.token"),
        "web_protocol": "http", "web_public_host": "127.0.0.1:9099",
        "lark_app_id": "cli_1234567890abcdef",
        "lark_app_secret": "dummy-app-secret",
        "feishu_admin_open_ids": "ou_123456789",
    })
    assert setup.status_code == 200, setup.text
    with store.db() as c:
        c.execute(
            "INSERT INTO web_sessions(token_hash,open_id,name,csrf,expires) VALUES (?,?,?,?,?)",
            (_hash("test-session"), "ou_123456789", "已授权管理员", "unit-test-csrf", 9999999999),
        )
    client.cookies.set(COOKIE, "test-session")


def auth():
    return {"X-CSRF-Token": "unit-test-csrf"}


def make_host(client, key=""):
    response = client.post("/api/v1/hosts", headers=auth(), json={
        "name": "测试主机", "address": "172.20.1.15",
        "username": "root", "host_key": key, "port": 22,
    })
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_auth_is_deny_by_default(client):
    from sshmcp.auth import COOKIE
    assert client.get("/healthz").json()["ok"] is True
    assert client.get("/api/v1/hosts", headers=auth()).status_code == 200
    assert client.get("/api/v1/auth/me").json()["role"] == "super_admin"
    # With a session cookie but no CSRF header, mutations are denied.
    assert client.post("/api/v1/hosts", json={}).status_code == 403
    client.cookies.clear()
    assert client.get("/api/v1/hosts").status_code == 401
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.get("/mcp").status_code == 401
    assert client.post("/mcp", json={}).status_code == 401
    # Neither bootstrap nor the now-deprecated admin token can log into Web.
    assert client.get("/api/v1/hosts", headers={"Authorization": "Bearer " + store.token("bootstrap.token")}).status_code == 401
    assert client.get("/api/v1/hosts", headers={"Authorization": "Bearer " + store.token("mcp.token")}).status_code == 401
    client.cookies.set(COOKIE, "test-session")
    assert client.get("/api/v1/hosts").status_code == 200


def test_target_scope_and_no_arbitrary_shell():
    assert store.private_ip("172.20.1.15") == "172.20.1.15"
    for host in ("8.8.8.8", "localhost", "127.0.0.1", "169.254.1.1", "example.org"):
        with pytest.raises(ValueError):
            store.private_ip(host)
    assert "df -Pk" in diagnostics.command_for("disk")
    assert "loadavg" in diagnostics.command_for("cpu")
    for action in ("execute", "shell", "sudo", "rm -rf", ""):
        with pytest.raises(ValueError):
            diagnostics.command_for(action)
    with pytest.raises(ValueError):
        diagnostics.command_for("logs", "nginx;id")
    with pytest.raises(ValueError):
        diagnostics.command_for("logs", "nginx.service", -1)
    with pytest.raises(ValueError):
        diagnostics.command_for("system", "unexpected")


def test_host_create_and_edit_preserves_pinned_host_key(client):
    key = paramiko.RSAKey.generate(1024)
    public = "ssh-rsa " + key.get_base64()
    host_id = make_host(client, public)
    original = store.get_host(host_id)["host_key"]
    response = client.put("/api/v1/hosts/" + str(host_id), headers=auth(), json={
        "name": "新名称", "address": "172.20.1.15",
        "username": "root", "port": 22, "host_key": "",
    })
    assert response.status_code == 200, response.text
    assert store.get_host(host_id)["host_key"] == original


def test_host_key_never_trusted_without_confirmation(client):
    host_id = make_host(client)
    key = paramiko.RSAKey.generate(1024)
    candidate = "ssh-rsa " + key.get_base64()
    fp = diagnostics.host_fingerprint(candidate)
    with store.db() as c:
        c.execute(
            "INSERT INTO host_key_candidates(host_id,key,fingerprint) VALUES (?,?,?)",
            (host_id, candidate, fp),
        )
    url = "/api/v1/host-keys/confirm"
    assert client.post(url, headers=auth(), json={
        "host_id": host_id, "independently_verified_sha256": fp, "confirmed": False
    }).status_code == 422
    assert client.post(url, headers=auth(), json={
        "host_id": host_id, "independently_verified_sha256": "SHA256:wrong", "confirmed": True
    }).status_code == 422
    assert store.get_host(host_id)["host_key"] == ""
    assert client.post(url, headers=auth(), json={
        "host_id": host_id, "independently_verified_sha256": fp, "confirmed": True
    }).status_code == 200
    assert store.get_host(host_id)["host_key"] == candidate


def test_credentials_encrypted_and_never_echoed(client):
    key = paramiko.RSAKey.generate(1024)
    file = io.StringIO()
    key.write_private_key(file)
    original = file.getvalue()
    response = client.post("/api/v1/credentials", headers=auth(), json={
        "name": "测试诊断密钥", "private_key": original,
    })
    assert response.status_code == 201, response.text
    credential_id = response.json()["id"]
    with store.db() as c:
        row = c.execute("SELECT secret FROM credentials WHERE id=?", (credential_id,)).fetchone()
        assert original not in row["secret"]
    listing = client.get("/api/v1/credentials", headers=auth()).json()
    assert "secret" not in str(listing)
    assert original not in str(listing)


def test_diagnostics_gates_unverified_hosts(client):
    host_id = make_host(client)
    response = client.post("/api/v1/hosts/" + str(host_id) + "/test", headers=auth())
    assert response.status_code == 422
    assert "公钥" in response.json()["detail"]
    with store.db() as c:
        row = c.execute("SELECT action,outcome FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    assert row["outcome"] == "failed"


def test_mcp_streamable_http_handshake_and_tools(client):
    """真正的 MCP JSON-RPC 握手与工具发现；不能只检查 /healthz。"""
    headers = {
        "Authorization": "Bearer " + store.token("mcp.token"),
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    init = client.post("/mcp", headers=headers, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "0.1"},
        },
    })
    assert init.status_code == 200, init.text
    assert "result" in init.json(), init.text
    listing = client.post("/mcp", headers={
        **headers, "MCP-Protocol-Version": "2025-06-18",
    }, json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert listing.status_code == 200, listing.text
    names = {x["name"] for x in listing.json()["result"]["tools"]}
    assert "ssh_test_connection" in names
    assert "ssh_diagnose_disk" in names
    assert "execute_shell" not in names


def test_setup_token_is_single_use_and_app_secret_encrypted(client):
    assert client.get("/api/v1/setup/status").json()["setup_required"] is False
    attempt = client.post("/api/v1/setup", json={
        "bootstrap_token": store.token("bootstrap.token"), "web_protocol": "http",
        "web_public_host": "127.0.0.1:9099", "lark_app_id": "cli_1234567890abcdef",
        "lark_app_secret": "dummy-app-secret", "feishu_admin_open_ids": "ou_wrong",
    })
    assert attempt.status_code == 409
    with store.db() as c:
        row = c.execute("SELECT value,encrypted FROM settings WHERE key='lark_app_secret'").fetchone()
        assert row["encrypted"] == 1
        assert "dummy-app-secret" not in row["value"]
    assert store.setting("lark_app_secret") == "dummy-app-secret"


def test_csrf_and_admin_revoke(client):
    assert client.put("/api/v1/settings/admins", json={"open_ids":"ou_123456789"}).status_code == 403
    assert client.put("/api/v1/settings/admins", headers=auth(), json={"open_ids":"ou_someone_else"}).status_code == 422
    assert client.put("/api/v1/settings/admins", headers=auth(), json={"open_ids":"ou_123456789,ou_someone_else"}).status_code == 200
    assert client.get("/api/v1/settings/feishu").json()["lark_app_secret_configured"] is True
    assert "lark_app_secret" not in client.get("/api/v1/settings/feishu").text
    store.save_settings({"feishu_admin_open_ids":"ou_someone_else"})
    assert client.get("/api/v1/hosts").status_code == 401


def test_feishu_oauth_authorized_and_unauthorized(client, monkeypatch):
    from urllib.parse import parse_qs, urlsplit
    from sshmcp import auth as module
    client.cookies.clear()

    async def rejected_profile(code):
        return {"open_id": "ou_not_registered", "name": "陌生用户"}
    monkeypatch.setattr(module, "exchange_profile", rejected_profile)
    start = client.get("/api/v1/auth/login", follow_redirects=False)
    assert start.status_code == 302
    assert start.headers["location"].startswith("https://open.feishu.cn/")
    params = parse_qs(urlsplit(start.headers["location"]).query)
    assert params["redirect_uri"] == ["http://127.0.0.1:9099/api/v1/auth/callback"]
    state = params["state"][0]
    denied = client.get("/api/v1/auth/callback", params={"code": "fake", "state": state}, follow_redirects=False)
    assert denied.status_code == 403
    # OAuth state may not be reused after denial.
    assert client.get("/api/v1/auth/callback", params={"code": "fake", "state": state}, follow_redirects=False).status_code == 403

    async def accepted_profile(code):
        return {"open_id": "ou_123456789", "name": "系统管理员"}
    monkeypatch.setattr(module, "exchange_profile", accepted_profile)
    start = client.get("/api/v1/auth/login", follow_redirects=False)
    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
    accepted = client.get("/api/v1/auth/callback", params={"code": "fake", "state": state}, follow_redirects=False)
    assert accepted.status_code == 303, accepted.text
    assert client.get("/api/v1/auth/me").json()["name"] == "系统管理员"
    assert client.get("/api/v1/hosts").status_code == 200
