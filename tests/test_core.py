"""纯本地回归测试：不连接真实 SSH 服务器、不需要 Zabbix 或 AI 模型。"""

import io

import paramiko
import pytest

from sshmcp import diagnostics, store, insights


def auth():
    return {"X-CSRF-Token": "unit-test-csrf"}


def make_host(client, key=""):
    response = client.post(
        "/api/v1/hosts",
        headers=auth(),
        json={
            "name": "测试主机",
            "address": "172.20.1.15",
            "username": "root",
            "host_key": key,
            "port": 22,
        },
    )
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
    assert (
        client.get(
            "/api/v1/hosts",
            headers={"Authorization": "Bearer " + store.token("bootstrap.token")},
        ).status_code
        == 401
    )
    assert (
        client.get(
            "/api/v1/hosts",
            headers={"Authorization": "Bearer " + store.token("mcp.token")},
        ).status_code
        == 401
    )
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
    response = client.put(
        "/api/v1/hosts/" + str(host_id),
        headers=auth(),
        json={
            "name": "新名称",
            "address": "172.20.1.15",
            "username": "root",
            "port": 22,
            "host_key": "",
        },
    )
    assert response.status_code == 200, response.text
    assert store.get_host(host_id)["host_key"] == original


def test_host_key_never_trusted_without_confirmation(client):
    host_id = make_host(client)
    key = paramiko.RSAKey.generate(1024)
    candidate = "ssh-rsa " + key.get_base64()
    fp = diagnostics.host_fingerprint(candidate)
    with store.db() as c:
        c.execute(
            "INSERT INTO host_key_candidates(host_id,key,fingerprint,source_signature) VALUES (?,?,?,?)",
            (host_id, candidate, fp, store.scan_signature(store.get_host(host_id))),
        )
    url = "/api/v1/host-keys/confirm"
    assert (
        client.post(
            url,
            headers=auth(),
            json={
                "host_id": host_id,
                "independently_verified_sha256": fp,
                "confirmed": False,
            },
        ).status_code
        == 422
    )
    assert (
        client.post(
            url,
            headers=auth(),
            json={
                "host_id": host_id,
                "independently_verified_sha256": "SHA256:wrong",
                "confirmed": True,
            },
        ).status_code
        == 422
    )
    assert store.get_host(host_id)["host_key"] == ""
    assert (
        client.post(
            url,
            headers=auth(),
            json={
                "host_id": host_id,
                "independently_verified_sha256": fp,
                "confirmed": True,
            },
        ).status_code
        == 200
    )
    assert store.get_host(host_id)["host_key"] == candidate


def test_credentials_encrypted_and_never_echoed(client):
    key = paramiko.RSAKey.generate(1024)
    file = io.StringIO()
    key.write_private_key(file)
    original = file.getvalue()
    response = client.post(
        "/api/v1/credentials",
        headers=auth(),
        json={
            "name": "测试诊断密钥",
            "private_key": original,
        },
    )
    assert response.status_code == 201, response.text
    credential_id = response.json()["id"]
    with store.db() as c:
        row = c.execute(
            "SELECT secret FROM credentials WHERE id=?", (credential_id,)
        ).fetchone()
        assert original not in row["secret"]
    listing = client.get("/api/v1/credentials", headers=auth()).json()
    assert "secret" not in str(listing)
    assert original not in str(listing)


def test_credential_rename_to_existing_name_is_409_like_create(client, key_pair):
    def add(name):
        return client.post(
            "/api/v1/credentials",
            headers=auth(),
            json={"name": name, "private_key": key_pair[0]},
        )

    def rotate(ident, name):
        return client.put(
            f"/api/v1/credentials/{ident}",
            headers=auth(),
            json={"name": name, "private_key": key_pair[0]},
        )

    first, second = add("诊断密钥 A"), add("诊断密钥 B")
    assert first.status_code == second.status_code == 201
    duplicate = add("诊断密钥 A")
    assert duplicate.status_code == 409
    renamed = rotate(second.json()["id"], "诊断密钥 A")
    assert renamed.status_code == 409, renamed.text
    assert renamed.json()["detail"] == duplicate.json()["detail"]
    names = {c["name"] for c in client.get("/api/v1/credentials").json()}
    assert names == {"诊断密钥 A", "诊断密钥 B"}
    assert rotate(999999, "诊断密钥 C").status_code == 404
    assert rotate(second.json()["id"], "诊断密钥 C").status_code == 200


def test_diagnostics_gates_unverified_hosts(client):
    host_id = make_host(client)
    response = client.post("/api/v1/hosts/" + str(host_id) + "/test", headers=auth())
    assert response.status_code == 422
    assert "公钥" in response.json()["detail"]
    with store.db() as c:
        row = c.execute(
            "SELECT action,outcome FROM audit ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row["outcome"] == "failed"


def test_mcp_streamable_http_handshake_and_tools(client):
    """真正的 MCP JSON-RPC 握手与工具发现；不能只检查 /healthz。"""
    headers = {
        "Authorization": "Bearer " + store.token("mcp.token"),
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    init = client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "0.1"},
            },
        },
    )
    assert init.status_code == 200, init.text
    assert "result" in init.json(), init.text
    listing = client.post(
        "/mcp",
        headers={
            **headers,
            "MCP-Protocol-Version": "2025-06-18",
        },
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    )
    assert listing.status_code == 200, listing.text
    names = {x["name"] for x in listing.json()["result"]["tools"]}
    assert "ssh_test_connection" in names
    assert "ssh_diagnose_disk" in names
    assert "ssh_diagnose_directory_usage" in names
    assert "ssh_diagnose_peer_connections" in names
    assert "ssh_diagnose_peer_traffic" in names
    assert "execute_shell" not in names


def test_setup_token_is_single_use_and_app_secret_encrypted(client):
    assert client.get("/api/v1/setup/status").json()["setup_required"] is False
    attempt = client.post(
        "/api/v1/setup",
        json={
            "bootstrap_token": store.token("bootstrap.token"),
            "web_protocol": "http",
            "web_public_host": "127.0.0.1:9099",
            "lark_app_id": "cli_1234567890abcdef",
            "lark_app_secret": "dummy-app-secret",
            "feishu_admin_open_ids": "ou_wrong",
        },
    )
    assert attempt.status_code == 409
    with store.db() as c:
        row = c.execute(
            "SELECT value,encrypted FROM settings WHERE key='lark_app_secret'"
        ).fetchone()
        assert row["encrypted"] == 1
        assert "dummy-app-secret" not in row["value"]
    assert store.setting("lark_app_secret") == "dummy-app-secret"


def test_csrf_and_admin_revoke(client):
    assert (
        client.put(
            "/api/v1/settings/admins", json={"open_ids": "ou_123456789"}
        ).status_code
        == 403
    )
    assert (
        client.put(
            "/api/v1/settings/admins",
            headers=auth(),
            json={"open_ids": "ou_someone_else"},
        ).status_code
        == 422
    )
    assert (
        client.put(
            "/api/v1/settings/admins",
            headers=auth(),
            json={"open_ids": "ou_123456789,ou_someone_else"},
        ).status_code
        == 200
    )
    assert (
        client.get("/api/v1/settings/feishu").json()["lark_app_secret_configured"]
        is True
    )
    assert "dummy-app-secret" not in client.get("/api/v1/settings/feishu").text
    store.save_settings({"feishu_admin_open_ids": "ou_someone_else"})
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
    denied = client.get(
        "/api/v1/auth/callback",
        params={"code": "fake", "state": state},
        follow_redirects=False,
    )
    assert denied.status_code == 403
    # OAuth state may not be reused after denial.
    assert (
        client.get(
            "/api/v1/auth/callback",
            params={"code": "fake", "state": state},
            follow_redirects=False,
        ).status_code
        == 403
    )

    async def accepted_profile(code):
        return {"open_id": "ou_123456789", "name": "系统管理员"}

    monkeypatch.setattr(module, "exchange_profile", accepted_profile)
    start = client.get("/api/v1/auth/login", follow_redirects=False)
    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
    accepted = client.get(
        "/api/v1/auth/callback",
        params={"code": "fake", "state": state},
        follow_redirects=False,
    )
    assert accepted.status_code == 303, accepted.text
    assert client.get("/api/v1/auth/me").json()["name"] == "系统管理员"
    assert client.get("/api/v1/hosts").status_code == 200


def test_bulk_trusted_fingerprints_transactionality(client):
    """Wrong SHA256 in any batch row must roll back all trusted keys."""
    first = make_host(client)
    second_response = client.post(
        "/api/v1/hosts",
        headers=auth(),
        json={
            "name": "第二台",
            "address": "172.20.1.16",
            "username": "root",
            "port": 22,
        },
    )
    assert second_response.status_code == 201, second_response.text
    second = second_response.json()["id"]
    keys = [paramiko.RSAKey.generate(1024) for _ in (first, second)]
    manifest = []
    with store.db() as c:
        for host_id, private in zip([first, second], keys):
            pub = "ssh-rsa " + private.get_base64()
            fingerprint = diagnostics.host_fingerprint(pub)
            c.execute(
                "INSERT INTO host_key_candidates(host_id,key,fingerprint,source_signature)"
                " VALUES (?,?,?,?)",
                (
                    host_id,
                    pub,
                    fingerprint,
                    store.scan_signature(store.get_host(host_id)),
                ),
            )
            manifest.append(
                {"host_id": host_id, "independently_verified_sha256": fingerprint}
            )
    url = "/api/v1/host-keys/confirm-batch"
    invalid = [dict(manifest[0]), dict(manifest[1])]
    invalid[1]["independently_verified_sha256"] = "SHA256:WRONG"
    assert (
        client.post(
            url, headers=auth(), json={"items": invalid, "confirmed": True}
        ).status_code
        == 422
    )
    assert store.get_host(first)["host_key"] == ""
    assert store.get_host(second)["host_key"] == ""
    assert (
        client.post(
            url, headers=auth(), json={"items": manifest, "confirmed": True}
        ).status_code
        == 200
    )
    assert store.get_host(first)["host_key"]
    assert store.get_host(second)["host_key"]


def test_host_ip_change_forces_reverification(client):
    trusted = paramiko.RSAKey.generate(1024)
    original = "ssh-rsa " + trusted.get_base64()
    host_id = make_host(client, original)
    response = client.put(
        "/api/v1/hosts/" + str(host_id),
        headers=auth(),
        json={
            "name": "测试改 IP",
            "address": "172.20.1.99",
            "port": 22,
            "username": "root",
            "host_key": "",
        },
    )
    assert response.status_code == 200, response.text
    assert store.get_host(host_id)["host_key"] == ""


def test_stale_scanned_candidate_cannot_be_confirmed(client):
    host_id = make_host(client)
    private = paramiko.RSAKey.generate(1024)
    candidate = "ssh-rsa " + private.get_base64()
    with store.db() as c:
        c.execute(
            "INSERT INTO host_key_candidates(host_id,key,fingerprint,source_signature)"
            " VALUES (?,?,?,?)",
            (
                host_id,
                candidate,
                diagnostics.host_fingerprint(candidate),
                store.scan_signature(store.get_host(host_id)),
            ),
        )
        c.execute("UPDATE hosts SET port=2222 WHERE id=?", (host_id,))
    r = client.post(
        "/api/v1/host-keys/confirm",
        headers=auth(),
        json={
            "host_id": host_id,
            "confirmed": True,
            "independently_verified_sha256": diagnostics.host_fingerprint(candidate),
        },
    )
    assert r.status_code == 409
    assert store.get_host(host_id)["host_key"] == ""


def test_scanner_keeps_candidate_but_not_trust(monkeypatch, client):
    host_id = make_host(client)
    remote = paramiko.RSAKey.generate(1024)

    class FakeSecurity:
        key_types = ("rsa-sha2-512", "ssh-ed25519", "ssh-rsa")

    class FakeTransport:
        def __init__(self, *args):
            self.closed = False

        def get_security_options(self):
            return FakeSecurity()

        def start_client(self, timeout):
            pass

        def get_remote_server_key(self):
            return remote

        def close(self):
            self.closed = True

    monkeypatch.setattr(diagnostics.paramiko, "Transport", FakeTransport)
    from types import SimpleNamespace

    monkeypatch.setattr(
        diagnostics.socket,
        "create_connection",
        lambda *a, **k: SimpleNamespace(close=lambda: None),
    )
    result = diagnostics.scan_host_key(host_id)
    assert result["state"] == "candidate"
    assert result["algorithm"] == "ssh-rsa"
    assert store.get_host(host_id)["host_key"] == ""
    with store.db() as c:
        scanned = c.execute(
            "SELECT fingerprint FROM host_key_candidates WHERE host_id=?", (host_id,)
        ).fetchone()
    assert scanned["fingerprint"] == result["fingerprint"]


def test_bulk_scan_by_filter_and_retry_failed(client, monkeypatch):
    make_host(client)
    r = client.post(
        "/api/v1/hosts",
        headers=auth(),
        json={
            "name": "新办公室",
            "address": "172.20.2.11",
            "username": "root",
            "port": 22,
        },
    )
    assert r.status_code == 201
    from sshmcp import api as module

    # Avoid background-network tests; inspect results of the selection function.
    monkeypatch.setattr(module, "_scan_batch", lambda batch, ids: None)
    response = client.post(
        "/api/v1/host-keys/scan", headers=auth(), json={"query": "172.20.2"}
    )
    assert response.status_code == 202, response.text
    with store.db() as c:
        batch = c.execute(
            "SELECT total FROM scan_batches WHERE id=?", (response.json()["batch_id"],)
        ).fetchone()
    assert batch["total"] == 1
    response = client.post(
        "/api/v1/host-keys/scan", headers=auth(), json={"unverified_only": True}
    )
    assert response.status_code == 202, response.text
    assert response.json()["total"] == 2


def test_safe_directory_roots_and_bounded_commands():
    assert "timeout -k 1 8" in diagnostics.command_for(
        "directory", directory_root="/data/mysql"
    )
    assert "du -B1 -x -d 1" in diagnostics.command_for(
        "directory", directory_root="/var/log"
    )
    for root in ("/root", "/root/.cache", "/root/.ssh"):
        command = diagnostics.command_for("directory", directory_root=root)
        assert "timeout -k 1 8" in command
        assert "du -B1 -x -d 1" in command
        assert command.endswith(" -- " + root)
    assert "ss -H -t -a -n" in diagnostics.command_for("peer_connections")
    assert "sleep 3" in diagnostics.command_for("peer_traffic")
    for invalid in (
        "/etc/shadow",
        "/data/../etc",
        "/data/./mysql",
        "/data;id",
        "/root/../etc",
        "/root/./.ssh",
        "/root;whoami",
        "/root//.ssh",
        "data",
        "/data/" + "x" * 150,
    ):
        with pytest.raises(ValueError):
            diagnostics.command_for("directory", directory_root=invalid)
    for action in ("peer_connections", "peer_traffic"):
        with pytest.raises(ValueError):
            diagnostics.command_for(action, directory_root="/data")
        with pytest.raises(ValueError):
            diagnostics.command_for(action, service="evil")
    with pytest.raises(ValueError):
        diagnostics.command_for("directory", service=";id", directory_root="/data")


def test_parse_biggest_directories_with_bytes():
    parsed = insights.parse_directory(
        "2048\t/data/logs\n4096\t/data/mysql\n8192\t/data\n",
        "/data",
    )
    assert parsed["scanned_root_bytes"] == 8192
    assert [x["directory"] for x in parsed["top_directories"]] == [
        "/data/mysql",
        "/data/logs",
    ]
    assert parsed["top_directories"][0]["bytes"] == 4096


def test_per_ip_connections_sorting():
    parsed = insights.parse_peer_connections(
        "172.20.1.3\t10\t7\n172.20.1.4\t22\t10\n172.20.1.5;rm\t999\t999\n"
    )
    assert parsed["ranking"][0] == {
        "peer_ip": "172.20.1.4",
        "tcp_connections": 22,
        "established_connections": 10,
    }
    assert len(parsed["ranking"]) == 2


def test_tcp_traffic_uses_matched_socket_deltas_only():
    lines = (
        "__SAMPLE_A__\n"
        "10.0.0.5:443\t172.20.1.3:53000\t1000\t2000\n"
        "10.0.0.5:22\t172.20.1.4:53001\t100\t200\n"
        "10.0.0.5:22\t172.20.1.4:53002\t500\t1000\n"
        "__SAMPLE_B__\n"
        "10.0.0.5:443\t172.20.1.3:53000\t4000\t2600\n"
        "10.0.0.5:22\t172.20.1.4:53001\t200\t900\n"
        "10.0.0.5:22\t172.20.1.6:53009\t9999999\t999999\n"
    )
    parsed = insights.parse_tcp_samples(lines, sample_seconds=3)
    assert parsed["supported"]
    assert parsed["matched_sockets"] == 2
    assert parsed["ranking"][0]["peer_ip"] == "172.20.1.3"
    assert parsed["ranking"][0]["total_bytes"] == 3600
    assert parsed["ranking"][0]["avg_bytes_per_second"] == 1200
    assert parsed["ranking"][1]["peer_ip"] == "172.20.1.4"
    assert parsed["ranking"][1]["received_bytes"] == 700
    assert len(parsed["ranking"]) == 2
    assert not insights.parse_tcp_samples("CAPABILITY_MISSING:ss")["supported"]


def test_api_directory_input_and_network_results(client, monkeypatch):
    """API must not make network calls for malformed root and must format structured output."""
    import sshmcp.api as api_module

    seen = []

    def fake_exec(
        host_id, action, service=None, minutes=30, directory_root=None, **kwargs
    ):
        seen.append((host_id, action, directory_root))
        # Exactly the production server-side validation, before any remote shell.
        diagnostics.command_for(
            action, service=service, minutes=minutes, directory_root=directory_root
        )
        return {
            "host_id": host_id,
            "action": action,
            "status": "success",
            "exit_code": 0,
            "output": "",
            "stderr": "",
            "data": insights.parse_directory("100\t/data/a\n200\t/data\n", "/data"),
        }

    monkeypatch.setattr(api_module.diagnostics, "execute", fake_exec)
    hid = make_host(client, "ssh-rsa " + paramiko.RSAKey.generate(1024).get_base64())
    with store.db() as c:
        cid = c.execute(
            "INSERT INTO credentials(name,secret) VALUES (?,?)",
            ("fixture-only", store.seal("fixture-only")),
        ).lastrowid
        c.execute("UPDATE hosts SET credential_id=? WHERE id=?", (cid, hid))
    okay = client.post(
        f"/api/v1/hosts/{hid}/diagnose",
        headers=auth(),
        json={
            "action": "directory",
            "directory_root": "/data",
        },
    )
    assert okay.status_code == 200, okay.text
    assert seen[-1] == (hid, "directory", "/data")
    assert okay.json()["data"]["top_directories"][0]["bytes"] == 100
    invalid = client.post(
        f"/api/v1/hosts/{hid}/diagnose",
        headers=auth(),
        json={
            "action": "directory",
            "directory_root": "/etc/shadow",
        },
    )
    assert invalid.status_code == 422


def test_remote_connection_awk_pipeline_on_fixture():
    """Execute the actual static awk aggregation against representative ss output."""
    import subprocess

    source = diagnostics.PEER_CONNECTIONS_CMD
    script = source[source.index("ss -H -t -a -n | awk") :]
    scripted_input = (
        "printf '%s\\n' "
        "'ESTAB 0 0 10.0.0.10:80 172.20.1.3:55000' "
        "'ESTAB 0 0 10.0.0.10:80 172.20.1.3:55001' "
        "'CLOSE-WAIT 0 0 [::1]:80 [fd00::12]:5555' "
        "'ESTAB 0 0 10.0.0.10:80 172.20.1.4:55002'"
    )
    script = script.replace("ss -H -t -a -n", scripted_input)
    proc = subprocess.run(
        ["/bin/sh", "-c", script], capture_output=True, text=True, timeout=5
    )
    assert proc.returncode == 0, proc.stderr
    parsed = insights.parse_peer_connections(proc.stdout)
    assert parsed["ranking"][0]["peer_ip"] == "172.20.1.3"
    assert parsed["ranking"][0]["tcp_connections"] == 2
    assert any(r["peer_ip"] == "fd00::12" for r in parsed["ranking"])


def test_remote_tcp_sampler_awk_on_fixture_without_ssh():
    """Validate real fixed awk script parses Linux ss -ti counter lines."""
    import subprocess

    source = diagnostics.PEER_TRAFFIC_CMD
    script = source[source.index("capture_peers() {") :]
    fixture = (
        "printf '%s\\n' "
        "'ESTAB 0 0 10.0.0.10:443 172.20.1.3:55000' "
        "'    cubic bytes_sent:1500 bytes_received:900 rto:200'"
    )
    script = script.replace("ss -H -t -n -i state established", fixture).replace(
        "sleep 3", "true"
    )
    proc = subprocess.run(
        ["/bin/sh", "-c", script], capture_output=True, text=True, timeout=5
    )
    assert proc.returncode == 0, proc.stderr
    result = insights.parse_tcp_samples(proc.stdout)
    assert result["supported"]
    assert result["sample_a_sockets"] == 1
    assert result["sample_b_sockets"] == 1
    assert result["matched_sockets"] == 1
    assert result["ranking"][0]["peer_ip"] == "172.20.1.3"


def test_rss_process_names_only_use_safe_jar_or_service_identifiers():
    from sshmcp import observations

    sample = (
        "PID PPID COMMAND %CPU %MEM RSS ELAPSED S\n"
        "31272 1 java 2.2 27.3 2232168 02:00 S\n"
        "6092 1 java 1.1 22.9 1877632 01:00 S\n"
        "24782 1 java 0.4 16.6 1362656 00:15 S\n"
        "[AIOPS_APP_IDENTITY]\n"
        "AIOPS_APP 31272 jar billing-api.jar\n"
        "AIOPS_APP 6092 service order-worker.service\n"
        "AIOPS_APP 24782 jar --password=mysecret.jar\n"
    )
    report = observations.analyze("memory_processes", sample)
    processes = report["summary"]["processes"]
    assert processes[0]["application"] == "billing-api.jar"
    assert processes[0]["identity_source"] == "jar"
    assert processes[1]["application"] == "order-worker.service"
    assert processes[2]["name"] == "java"
    # Report identifiers are hints, not complete argv or proven business ownership.
    assert all("cmdline" not in str(p) for p in processes)


def test_rss_identity_probe_uses_only_bounded_fixed_procfs_reads():
    command = diagnostics.command_for("memory_processes")
    assert "head -n 24" in command
    assert "/proc/$pid/cmdline" in command
    assert "/proc/$pid/cgroup" in command
    assert "AIOPS_APP" in command
    import subprocess

    assert subprocess.run(["sh", "-n", "-c", command], check=False).returncode == 0
    assert "print v" in command  # print only safe basename, never argv
    with pytest.raises(ValueError):
        diagnostics.command_for("memory_processes", service="injected;id")
