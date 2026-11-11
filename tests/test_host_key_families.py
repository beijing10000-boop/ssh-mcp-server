"""A pinned RSA host key on a server that also has an ECDSA (or Ed25519) key and no
longer offers SHA-1 "ssh-rsa" signatures (OpenSSH 8.8+, the RHEL 9 crypto
policy): the handshake stays with the RSA key (rsa-sha2-512/256) instead of
answering with that other key, which looked like a changed key and was
refused (SC-01). Real loopback SSH; no production host is used."""

import io
import socket
import threading

import paramiko
import pytest

from sshmcp import diagnostics, store
from test_core import auth


@pytest.fixture
def modern_server(client, monkeypatch):
    original = store.private_ip
    monkeypatch.setattr(
        store,
        "private_ip",
        lambda value, **kw: value if value == "127.0.0.1" else original(value, **kw),
    )
    rsa, ecdsa = paramiko.RSAKey.generate(2048), paramiko.ECDSAKey.generate()
    user_key = paramiko.RSAKey.generate(2048)
    secret = io.StringIO()
    user_key.write_private_key(secret)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.2)
    stop = threading.Event()
    seen = {"auth": 0}
    executed = threading.Event()

    class Server(paramiko.ServerInterface):
        def check_auth_publickey(self, username, key):
            seen["auth"] += 1
            return paramiko.AUTH_SUCCESSFUL if key == user_key else paramiko.AUTH_FAILED

        def get_allowed_auths(self, username):
            return "publickey"

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED

        def check_channel_exec_request(self, channel, command):
            executed.set()
            return True

    def serve():
        while not stop.is_set():
            try:
                sock, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            # Like OpenSSH 8.8+: RSA keys sign only as rsa-sha2-*.
            transport = paramiko.Transport(
                sock, disabled_algorithms={"keys": ["ssh-rsa"]}
            )
            try:
                transport.add_server_key(rsa)
                transport.add_server_key(ecdsa)
                transport.start_server(server=Server())
                channel = transport.accept(3)
                if channel and executed.wait(3):
                    channel.sendall(b"AIOPS_SSH_OK\n0\nLinux\n")
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
        json={"name": "modern fixture", "private_key": secret.getvalue()},
    ).json()["id"]
    host = client.post(
        "/api/v1/hosts",
        headers=auth(),
        json={
            "name": "modern SSH fixture",
            "address": "127.0.0.1",
            "port": listener.getsockname()[1],
            "username": "root",
            "credential_id": credential,
            "host_key": "ssh-rsa " + rsa.get_base64(),
        },
    ).json()["id"]
    yield host, seen
    stop.set()
    listener.close()
    thread.join(3)


def test_a_pinned_rsa_key_is_used_when_the_server_also_has_ecdsa(modern_server):
    host, seen = modern_server
    result = diagnostics.execute(host, "connection")
    assert result["status"] == "success", result
    assert seen["auth"] == 1


def test_a_wrong_rsa_key_is_still_refused_before_authentication(modern_server):
    host, seen = modern_server
    wrong = paramiko.RSAKey.generate(2048)
    with store.db() as c:
        c.execute(
            "UPDATE hosts SET host_key=? WHERE id=?",
            ("ssh-rsa " + wrong.get_base64(), host),
        )
    with pytest.raises(diagnostics.SSHDiagnosticError, match="公钥"):
        diagnostics.execute(host, "connection")
    assert seen["auth"] == 0


def test_each_pinned_type_keeps_to_its_own_algorithms():
    rsa = diagnostics.pinned_algorithms("ssh-rsa")["keys"]
    assert "ssh-ed25519" in rsa and "rsa-sha2-512" not in rsa and "ssh-rsa" not in rsa
    ed = diagnostics.pinned_algorithms("ssh-ed25519")["keys"]
    assert "ssh-ed25519" not in ed and "rsa-sha2-256" in ed
