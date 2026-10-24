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
import threading

import paramiko
from paramiko import SSHException

from . import store, insights

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

# Static scripts only: no user-provided IP, shell, or filesystem path enters awk.
PEER_CONNECTIONS_CMD = r"""
if ! command -v ss >/dev/null 2>&1; then
  printf 'CAPABILITY_MISSING:ss\n'
  exit 69
fi
ss -H -t -a -n | awk '
  NF >= 5 {
    peer=$5
    if (substr(peer,1,1)=="[") {
      sub(/^\[/,"",peer); sub(/\]:[^:]*$/,"",peer)
    } else {
      sub(/:[^:]*$/,"",peer)
    }
    if (peer=="*" || peer=="0.0.0.0" || peer=="::" || peer=="") next
    count[peer]++
    if ($1=="ESTAB") established[peer]++
  }
  END { for (peer in count) print peer "\t" count[peer] "\t" (established[peer]+0) }
' | sort -k2,2nr | head -n 50
"""
PEER_TRAFFIC_CMD = r"""
if ! command -v ss >/dev/null 2>&1; then
  printf 'CAPABILITY_MISSING:ss\n'
  exit 69
fi
capture_peers() {
  ss -H -t -n -i state established | awk '
    function emit() {
      if (local!="" && peer!="" && sent!="" && received!="")
        print local "\t" peer "\t" sent "\t" received
    }
    $1=="ESTAB" {
      emit()
      local=$4; peer=$5; sent=""; received=""
      next
    }
    {
      for (i=1;i<=NF;i++) {
        if ($i ~ /^bytes_sent:[0-9]+$/) { split($i, item, ":"); sent=item[2] }
        if ($i ~ /^bytes_received:[0-9]+$/) { split($i, item, ":"); received=item[2] }
      }
    }
    END { emit() }
  '
}
printf '__SAMPLE_A__\n'
capture_peers
sleep 3
printf '__SAMPLE_B__\n'
capture_peers
"""
INSIGHT_ACTIONS = {"directory", "peer_connections", "peer_traffic"}

SERVICE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$")
REDACTION = re.compile(r"(?i)\\b(password|passwd|token|secret|api[_-]?key|authorization)\\b(\\s*[:=]\\s*)([^\\s,;]+)")


def redact_output(text: str) -> str:
    """Minimize accidental secret exfiltration in tool outputs."""
    return REDACTION.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]", text)


class SSHDiagnosticError(RuntimeError):
    pass


# One application process runs at most four SSH actions concurrently and never
# executes two diagnostics on the same registered host at the same time.
_GLOBAL_SSH_LIMIT = threading.BoundedSemaphore(4)
_ACTIVE_HOSTS = set()
_ACTIVE_LOCK = threading.Lock()


def command_for(action: str, service: str | None = None, minutes: int = 30, directory_root: str | None = None) -> str:
    if isinstance(minutes, bool) or not isinstance(minutes, int) or not 1 <= minutes <= 120:
        raise ValueError("日志时间窗口必须在 1 到 120 分钟内")
    if action == "directory":
        if service or directory_root not in insights.DIRECTORY_ROOTS:
            raise ValueError("请选择允许扫描的固定根目录；不接受任意文件路径")
        # timeout + nice: avoid unbounded disk scans; no files are written.
        return PREFIX + (
            "if ! command -v timeout >/dev/null 2>&1; then "
            "printf 'CAPABILITY_MISSING:timeout\\n'; exit 69; fi; "
            "timeout -k 1 8 nice -n 19 du -B1 -x -d 1 -- "
            + shlex.quote(directory_root)
        )
    if directory_root is not None:
        raise ValueError("该诊断动作不接受目录参数")
    if action == "peer_connections":
        if service: raise ValueError("连接排行不接受服务名")
        return PREFIX + PEER_CONNECTIONS_CMD
    if action == "peer_traffic":
        if service: raise ValueError("IP 流量采样不接受服务名")
        return PREFIX + PEER_TRAFFIC_CMD
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


def execute(host_id: int, action: str, service: str | None = None, minutes: int = 30, directory_root: str | None = None) -> dict:
    if not _GLOBAL_SSH_LIMIT.acquire(blocking=False):
        raise SSHDiagnosticError("SSH 诊断并发已达上限（4），请稍后重试")
    with _ACTIVE_LOCK:
        if host_id in _ACTIVE_HOSTS:
            _GLOBAL_SSH_LIMIT.release()
            raise SSHDiagnosticError("该主机已有一项诊断正在执行，请稍后重试")
        _ACTIVE_HOSTS.add(host_id)
    try:
        return _execute_inner(host_id, action, service, minutes, directory_root)
    finally:
        with _ACTIVE_LOCK:
            _ACTIVE_HOSTS.discard(host_id)
        _GLOBAL_SSH_LIMIT.release()


def _execute_inner(host_id: int, action: str, service: str | None = None, minutes: int = 30, directory_root: str | None = None) -> dict:
    host = store.get_host(host_id)
    if not host.get("host_key"):
        raise SSHDiagnosticError("未核验 SSH 主机公钥；请先批量获取并确认 SHA256 指纹")
    command = command_for(action, service, minutes, directory_root)
    if host.get("mode") == "gateway":
        if action in INSIGHT_ACTIONS:
            raise SSHDiagnosticError("当前 B 模式强制命令网关尚未支持此诊断动作；请使用已批准的 A 模式主机")
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
        output_limit = 262144 if action == "peer_traffic" else 32768
        deadline = time.monotonic() + 20
        truncated = False
        while True:
            if time.monotonic() > deadline:
                raise SSHDiagnosticError("SSH 诊断执行超时（20秒）")
            for ready, recv, dest, limit in (
                (chan.recv_ready, chan.recv, stdout, output_limit),
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
        output = redact_output(stdout[:output_limit].decode("utf-8", "replace"))
        error = redact_output(stderr[:2048].decode("utf-8", "replace"))
        if host.get("mode") == "gateway" and not output.startswith("AIOPS_GATEWAY_V1\n"):
            raise SSHDiagnosticError("目标未返回受限网关标识，请核验 authorized_keys 强制命令")
        result = {
            "host_id": host_id, "host": host["name"], "action": action,
            "status": "partial" if truncated or code != 0 or error else "success",
            "exit_code": code, "output": output, "stderr": error,
            "truncated": truncated, "duration_ms": int((time.monotonic() - began) * 1000),
        }
        if action in INSIGHT_ACTIONS:
            if action == "directory":
                data = insights.parse_directory(output, directory_root)
            elif action == "peer_connections":
                data = insights.parse_peer_connections(output)
            else:
                data = insights.parse_tcp_samples(output)
                if not data["supported"] or data["matched_sockets"] == 0:
                    result["status"] = "partial"
                    data["notes"].append("没有可比较的 TCP 连接字节计数；请确认目标支持 ss -ti，且采样期间存在持续的 TCP 会话。")
            if truncated or code != 0:
                data["notes"].append("命令执行失败、超时或输出超限：当前排行不完整，不可据此判定全局 Top IP / Top 目录。")
            result["data"] = data
            result["output"] = ""  # Avoid leaking raw socket/directory inventory to LLM.
        return result
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
    """Batch-safe candidate discovery. A handshake is not a trust decision."""
    host = store.get_host(host_id)
    signature = store.scan_signature(host)
    jump = transport = None
    try:
        jump, tunnel = _route(host) if host.get("proxy_id") else (None, None)
        transport = (
            paramiko.Transport(tunnel)
            if tunnel is not None
            else paramiko.Transport((host["address"], int(host["port"])))
        )
        transport.banner_timeout = 6
        # Prefer an existing pinned key algorithm to avoid false key-change alarms
        # when a server offers multiple host-key algorithms.
        if host.get("host_key"):
            known_type = store.validate_hostkey(host["host_key"]).split()[0]
            preferred = {
                "ssh-ed25519": "ssh-ed25519",
                "ecdsa-sha2-nistp256": "ecdsa-sha2-nistp256",
                "ssh-rsa": "rsa-sha2-512",
            }.get(known_type)
            if preferred:
                options = transport.get_security_options()
                options.key_types = tuple(
                    [preferred] + [alg for alg in options.key_types if alg != preferred]
                )
        transport.start_client(timeout=6)
        remote = transport.get_remote_server_key()
        candidate = store.validate_hostkey(remote.get_name() + " " + remote.get_base64())
        fingerprint = host_fingerprint(candidate)
        previous = host_fingerprint(host["host_key"]) if host.get("host_key") else None
        result = {
            "host_id": host_id, "name": host["name"],
            "fingerprint": fingerprint,
            "algorithm": candidate.split()[0],
            "previous_fingerprint": previous,
        }
        with store.db() as c:
            c.execute("BEGIN IMMEDIATE")
            current = c.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()
            if not current or not current["enabled"] or store.scan_signature(dict(current)) != signature:
                return {**result, "state": "stale", "error": "主机地址、端口或跳板已变化，请重新获取"}
            if current["host_key"] == candidate:
                c.execute("DELETE FROM host_key_candidates WHERE host_id=?", (host_id,))
                return {**result, "state": "unchanged"}
            c.execute(
                "INSERT INTO host_key_candidates(host_id,key,fingerprint,source_signature,collected_at) "
                "VALUES (?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(host_id) DO UPDATE SET "
                "key=excluded.key,fingerprint=excluded.fingerprint,"
                "source_signature=excluded.source_signature,collected_at=CURRENT_TIMESTAMP",
                (host_id, candidate, fingerprint, signature),
            )
        return {**result, "state": "changed" if previous else "candidate"}
    except (OSError, SSHException, ValueError) as exc:
        return {"host_id": host_id, "name": host["name"], "state": "failed",
                "error": type(exc).__name__}
    finally:
        if transport is not None:
            transport.close()
        if jump is not None:
            jump.close()
