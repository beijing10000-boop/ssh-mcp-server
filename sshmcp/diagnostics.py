"""固定只读 SSH 诊断：没有传入任意 Shell 的执行接口。"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import shlex
import socket
import time

import paramiko
from paramiko import SSHException

from . import store

PREFIX = "PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; LC_ALL=C; export LC_ALL=C; "
ACTIONS = {
    "connection": "printf 'AIOPS_SSH_OK\\n'; id -u; uname -s",
    "cpu": "cat /proc/loadavg /proc/stat; command -v vmstat >/dev/null 2>&1 && vmstat 1 2 || true",
    "memory": "cat /proc/meminfo; command -v free >/dev/null 2>&1 && free -k || true",
    "processes": "ps -eo pid,ppid,comm,pcpu,pmem,rss,etime,state --sort=-pcpu | head -n 25",
    "disk": "df -Pk -l; df -Pi -l; head -n 80 /proc/mounts",
    "io": "command -v iostat >/dev/null 2>&1 && iostat -dx 1 2 || cat /proc/diskstats",
    "network": "cat /proc/net/dev /proc/net/snmp; command -v ip >/dev/null 2>&1 && { ip -s link; ip route show; } || cat /proc/net/route",
    "sockets": "command -v ss >/dev/null 2>&1 && { ss -s; ss -lnt | head -n 60; } || head -n 60 /proc/net/tcp",
    "system": "uname -sr; cat /proc/uptime /proc/loadavg; date -u '+%Y-%m-%dT%H:%M:%SZ'",
}
SERVICE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$")


class SSHDiagnosticError(RuntimeError):
    pass


def command_for(action: str, service: str | None = None, minutes: int = 30) -> str:
    if isinstance(minutes, bool) or not isinstance(minutes, int) or not 1 <= minutes <= 120:
        raise ValueError("日志时间窗口必须在 1 到 120 分钟内")
    if action in ACTIONS:
        if service:
            raise ValueError("此诊断动作不接受服务名")
        return PREFIX + ACTIONS[action]
    if action not in {"service", "logs"}:
        raise ValueError("不支持的诊断类型；不允许执行任意 Shell")
    if not service or not SERVICE_RE.fullmatch(service):
        raise ValueError("服务名无效，只允许严格格式的 systemd 服务名称")
    unit = shlex.quote(service)
    if action == "service":
        return PREFIX + (
            "systemctl show --no-pager --property="
            "Id,ActiveState,SubState,Result,MainPID,ExecMainStatus,ActiveEnterTimestamp -- " + unit
        )
    return PREFIX + (
        "journalctl --no-pager -q -u " + unit
        + " --since '-" + str(minutes) + " min' -n 120 -o short-iso"
    )


def host_fingerprint(value: str) -> str:
    normalized = store.validate_hostkey(value)
    raw = base64.b64decode(normalized.split()[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def private_key(credential_id: int):
    blob = store.get_credential(credential_id)
    try:
        data = json.loads(blob)
    except (ValueError, TypeError):
        data = {"private_key": blob, "passphrase": None}
    material = data.get("private_key") or ""
    password = data.get("passphrase") or None
    for klass in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return klass.from_private_key(io.StringIO(material), password=password)
        except (paramiko.SSHException, ValueError, TypeError):
            pass
    raise SSHDiagnosticError("私钥格式或口令无效；支持 Ed25519/RSA/ECDSA")


def client_connect(target: dict, key, *, sock=None):
    expected = store.validate_hostkey(target.get("host_key", ""))
    key_type, encoded = expected.split()
    public_key = paramiko.PKey.from_type_string(key_type, base64.b64decode(encoded))
    client = paramiko.SSHClient()
    address, port = target["address"], int(target.get("port", 22))
    client.get_host_keys().add(
        address if port == 22 else f"[{address}]:{port}",
        key_type,
        public_key,
    )
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            hostname=address, port=port, username=target["username"],
            pkey=key, allow_agent=False, look_for_keys=False,
            timeout=6, banner_timeout=6, auth_timeout=6,
            channel_timeout=6, sock=sock,
        )
        return client
    except Exception:
        client.close()
        raise


def _route(host: dict):
    proxy = store.get_proxy(host.get("proxy_id"))
    jump = None
    tunnel = None
    if proxy:
        jump = client_connect(proxy, private_key(proxy["credential_id"]))
        try:
            tunnel = jump.get_transport().open_channel(
                "direct-tcpip", (host["address"], int(host["port"])),
                ("127.0.0.1", 0), timeout=6,
            )
        except Exception:
            jump.close()
            raise
    return jump, tunnel


def execute(host_id: int, action: str, service: str | None = None, minutes: int = 30) -> dict:
    host = store.get_host(host_id)
    if not host.get("host_key"):
        raise SSHDiagnosticError("未核验 SSH 主机公钥；请先批量获取并确认 SHA256 指纹")
    command = command_for(action, service, minutes)
    if host.get("mode") == "gateway":
        if not host.get("gateway_approved"):
            raise SSHDiagnosticError("受限网关模式尚未经管理员批准")
        command = "aiops-v1 " + action + " " + str(minutes) + (" " + service if service else "")
    began = time.monotonic()
    jump = client = chan = None
    try:
        jump, tunnel = _route(host)
        client = client_connect(host, private_key(host["credential_id"]), sock=tunnel)
        chan = client.get_transport().open_session(timeout=6)
        chan.settimeout(6)
        chan.exec_command(command)
        stdout, stderr = bytearray(), bytearray()
        deadline = time.monotonic() + 20
        truncated = False
        while True:
            if time.monotonic() > deadline:
                raise SSHDiagnosticError("SSH 诊断执行超时（20秒）")
            for ready, recv, dest, limit in (
                (chan.recv_ready, chan.recv, stdout, 32768),
                (chan.recv_stderr_ready, chan.recv_stderr, stderr, 2048),
            ):
                if ready():
                    room = max(1, limit - len(dest) + 1)
                    dest.extend(recv(min(4096, room)))
                    if len(dest) > limit:
                        truncated = True
            if truncated:
                break
            if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                break
            time.sleep(0.03)
        code = None if truncated else chan.recv_exit_status()
        output = stdout[:32768].decode("utf-8", "replace")
        error = stderr[:2048].decode("utf-8", "replace")
        if host.get("mode") == "gateway" and not output.startswith("AIOPS_GATEWAY_V1\n"):
            raise SSHDiagnosticError("目标未返回受限网关标识，请核验 authorized_keys 强制命令")
        return {
            "host_id": host_id, "host": host["name"], "action": action,
            "status": "partial" if truncated or code not in (0, None) or error else "success",
            "exit_code": code, "output": output, "stderr": error,
            "truncated": truncated, "duration_ms": int((time.monotonic() - began) * 1000),
        }
    except paramiko.BadHostKeyException:
        raise SSHDiagnosticError("SSH 主机公钥与已登记公钥不一致，已拒绝连接") from None
    except paramiko.AuthenticationException:
        raise SSHDiagnosticError("SSH 身份认证失败：检查账户、私钥与 authorized_keys") from None
    except (socket.timeout, TimeoutError):
        raise SSHDiagnosticError("SSH 连接或协议握手超时") from None
    except (OSError, EOFError, SSHException) as exc:
        # Remove endpoint details and potentially sensitive upstream error content.
        name = type(exc).__name__
        raise SSHDiagnosticError("SSH 网络或协议错误：" + name) from None
    finally:
        if chan is not None:
            chan.close()
        if client is not None:
            client.close()
        if jump is not None:
            jump.close()


def scan_host_key(host_id: int) -> dict:
    """只做服务器 SSH 握手，不认证，不执行诊断命令。结果为候选，绝不自动授权。"""
    host = store.get_host(host_id)
    jump = transport = None
    try:
        jump, tunnel = _route(host) if host.get("proxy_id") else (None, None)
        if tunnel is not None:
            transport = paramiko.Transport(tunnel)
        else:
            transport = paramiko.Transport((host["address"], int(host["port"])))
        transport.banner_timeout = 6
        transport.start_client(timeout=6)
        key = transport.get_remote_server_key()
        candidate = store.validate_hostkey(key.get_name() + " " + key.get_base64())
        result = {"host_id": host_id, "name": host["name"], "fingerprint": host_fingerprint(candidate)}
        with store.db() as c:
            c.execute(
                "INSERT INTO host_key_candidates(host_id,key,fingerprint,collected_at) "
                "VALUES (?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(host_id) DO UPDATE SET "
                "key=excluded.key,fingerprint=excluded.fingerprint,collected_at=CURRENT_TIMESTAMP",
                (host_id, candidate, result["fingerprint"]),
            )
        return {**result, "state": "candidate", "previous_fingerprint": host_fingerprint(host["host_key"]) if host.get("host_key") else None}
    except (OSError, SSHException, ValueError) as exc:
        return {"host_id": host_id, "name": host["name"], "state": "failed", "error": type(exc).__name__}
    finally:
        if transport is not None:
            transport.close()
        if jump is not None:
            jump.close()
