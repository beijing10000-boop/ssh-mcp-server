"""纯本地回归测试：不连接真实 SSH 服务器、不需要 Zabbix 或 AI 模型。"""
import io

import paramiko
import pytest
from fastapi.testclient import TestClient

from sshmcp import diagnostics, store
from sshmcp.main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DATA_DIR", tmp_path)
    with TestClient(app) as c:
        yield c


def auth():
    return {"Authorization": "Bearer " + store.token("admin.token")}


def make_host(client, key=""):
    response = client.post("/api/v1/hosts", headers=auth(), json={
        "name": "测试主机", "address": "172.20.1.15",
        "username": "root", "host_key": key, "port": 22,
    })
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_auth_is_deny_by_default(client):
    assert client.get("/healthz").json()["ok"] is True
    assert client.get("/api/v1/hosts").status_code == 401
    assert client.get("/mcp").status_code == 401
    assert client.post("/mcp", json={}).status_code == 401
    assert client.get("/api/v1/hosts", headers={"Authorization": "Bearer invalid"}).status_code == 401
    assert client.get("/api/v1/hosts", headers=auth()).status_code == 200
    assert store.token("admin.token") != store.token("mcp.token")


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
