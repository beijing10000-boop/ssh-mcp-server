"""Real loopback SSH transport. No production host or local shell is used."""

import io
import json
import socket
import threading
import time

import paramiko
import pytest

from sshmcp import diagnostics, store
from test_console import mcp_call
from test_core import auth


@pytest.fixture
def target(client, monkeypatch):
    original = store.private_ip
    monkeypatch.setattr(
        store,
        "private_ip",
        lambda value: value if value == "127.0.0.1" else original(value),
    )
    host_key, user_key = paramiko.RSAKey.generate(2048), paramiko.RSAKey.generate(2048)
    secret = io.StringIO()
    user_key.write_private_key(secret)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.2)
    stop = threading.Event()
    transports = []

    class Server(paramiko.ServerInterface):
        def __init__(self):
            self.command = None
            self.auth_attempts = 0
            self.executed = threading.Event()
            self.response = b"AIOPS_SSH_OK\n0\nLinux\npassword=wire-fixture-secret\n"

        def check_auth_publickey(self, username, key):
            self.auth_attempts += 1
            return (
                paramiko.AUTH_SUCCESSFUL
                if username == "root" and key == user_key
                else paramiko.AUTH_FAILED
            )

        def get_allowed_auths(self, username):
            return "publickey"

        def check_channel_request(self, kind, chanid):
            return (
                paramiko.OPEN_SUCCEEDED
                if kind == "session"
                else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
            )

        def check_channel_exec_request(self, channel, command):
            self.command = command.decode()
            self.executed.set()
            return True

    server = Server()

    def serve():
        while not stop.is_set():
            try:
                sock, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            transport = paramiko.Transport(sock)
            transports.append(transport)
            try:
                transport.add_server_key(host_key)
                transport.start_server(server=server)
                channel = transport.accept(3)
                if channel and server.executed.wait(3):
                    channel.sendall(server.response)
                    channel.send_exit_status(0)
                    channel.close()
            except (paramiko.SSHException, EOFError, OSError):
                pass
            finally:
                transport.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    credential = client.post(
        "/api/v1/credentials",
        headers=auth(),
        json={"name": "local protocol", "private_key": secret.getvalue()},
    ).json()["id"]
    host = client.post(
        "/api/v1/hosts",
        headers=auth(),
        json={
            "name": "local SSH fixture",
            "address": "127.0.0.1",
            "port": listener.getsockname()[1],
            "username": "root",
            "credential_id": credential,
            "host_key": "ssh-rsa " + host_key.get_base64(),
        },
    ).json()["id"]
    yield host, server
    stop.set()
    listener.close()
    for transport in transports:
        transport.close()
    thread.join(3)


def test_mcp_uses_real_pinned_ssh_and_redacts_before_persistence(client, target):
    host, server = target
    status, result = mcp_call(
        client,
        store.token("mcp.token"),
        "ssh_test_connection",
        {"host_id": host, "detail": "full"},
    )
    assert status == 200 and result["status"] == "success"
    assert "id -u" in server.command and "sudo" not in server.command
    assert result["output"].splitlines()[:2] == ["AIOPS_SSH_OK", "0"]
    assert "wire-fixture-secret" not in result["output"]
    with store.db() as c:
        sealed = c.execute(
            "SELECT result FROM diagnostic_jobs WHERE id=?", (result["job_id"],)
        ).fetchone()[0]
    assert "wire-fixture-secret" not in store.unseal(sealed)
    assert json.loads(store.unseal(sealed))["status"] == "success"


def test_real_changed_key_rejected_before_authentication(target):
    host, server = target
    wrong = paramiko.RSAKey.generate(2048)
    with store.db() as c:
        c.execute(
            "UPDATE hosts SET host_key=? WHERE id=?",
            ("ssh-rsa " + wrong.get_base64(), host),
        )
    with pytest.raises(diagnostics.SSHDiagnosticError, match="公钥"):
        diagnostics.execute(host, "connection")
    assert server.auth_attempts == 0 and server.command is None


def test_real_discovery_does_not_authenticate_or_trust(target):
    host, server = target
    with store.db() as c:
        c.execute("UPDATE hosts SET host_key='',credential_id=NULL WHERE id=?", (host,))
    result = diagnostics.scan_host_key(host)
    assert result["state"] == "candidate" and result["fingerprint"].startswith(
        "SHA256:"
    )
    assert server.auth_attempts == 0 and server.command is None
    assert store.get_host(host)["host_key"] == ""


def test_running_cancellation_closes_real_ssh(target):
    host, server = target
    started = time.monotonic()
    with pytest.raises(diagnostics.SSHDiagnosticError, match="取消"):
        diagnostics.execute(host, "connection", cancelled=server.executed.is_set)
    assert time.monotonic() - started < 4


@pytest.mark.parametrize(
    "tool,fragment,extra",
    [
        ("ssh_diagnose_pressure", "/proc/pressure/", {}),
        ("ssh_diagnose_system_errors", "'-5 min'", {"minutes": 5}),
        ("ssh_diagnose_container_stats", "stats --no-stream", {}),
    ],
)
def test_new_tools_use_pinned_ssh_and_persist_redacted_output(
    client, target, tool, fragment, extra
):
    host, server = target
    status, result = mcp_call(
        client,
        store.token("mcp.token"),
        tool,
        {"host_id": host, "detail": "full", **extra},
    )
    assert status == 200 and result["status"] == "success"
    assert fragment in server.command
    assert "wire-fixture-secret" not in result["output"]
    assert result["captured_at"] and result["job_id"]


def test_triage_uses_one_pinned_ssh_session(client, target):
    from sshmcp.triage import actions

    host, server = target
    samples = {
        "cpu": "CPU_COUNT=1\n3.00 2.00 1.00 1/10 99",
        "processes": "PID COMMAND %CPU\n1 java 95",
        "pressure": "[cpu PSI]\nsome avg10=30.00 avg60=20.00 avg300=10.00 total=1",
    }
    server.response = "".join(
        f"__SSHMCP_BEGIN_{a}__\n{samples[a]}\n__SSHMCP_END_{a}__:0\n"
        for a in actions("cpu_high")
    ).encode()
    result = mcp_call(
        client,
        store.token("mcp.token"),
        "ssh_triage",
        {"host_id": host, "symptom": "cpu_high"},
    )[1]
    assert result["status"] == "success" and len(result["steps"]) == 3
    assert server.auth_attempts == 1 and server.command.count("__SSHMCP_BEGIN_") == 3
    assert any(f["metric"] == "load_per_core" for f in result["findings"])
    assert "output" not in result and all(
        "output" not in step for step in result["steps"]
    )
