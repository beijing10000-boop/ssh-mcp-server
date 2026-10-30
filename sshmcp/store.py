"""持久化 SQLite + 加密凭据 + 双令牌，禁止将敏感信息写入日志。"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import tempfile
from contextlib import contextmanager
from functools import lru_cache

from cryptography.fernet import Fernet
import paramiko

DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
IDENTITY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")
HOSTKEY = re.compile(
    r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]+(?: .*)?$"
)


def ensure_secret(filename: str, creator) -> bytes:
    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    DATA_DIR.chmod(0o700)
    p = DATA_DIR / filename
    if not p.exists():
        descriptor, temporary = tempfile.mkstemp(dir=DATA_DIR, prefix=".secret-")
        try:
            with os.fdopen(descriptor, "wb") as fh:
                fh.write(creator())
                fh.flush()
                os.fsync(fh.fileno())
            try:
                os.link(temporary, p)
            except FileExistsError:
                pass
        finally:
            os.unlink(temporary)
    p.chmod(0o600)
    return p.read_bytes().strip()


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    ensure_secret("master.key", Fernet.generate_key)
    _fernet.cache_clear()
    # Bootstrap credential is one-time only; not accepted by normal Web login.
    ensure_secret("bootstrap.token", lambda: secrets.token_urlsafe(48).encode())
    ensure_secret("mcp.token", lambda: secrets.token_urlsafe(36).encode())
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS settings(
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL,
          encrypted INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS oauth_states(
          state_hash TEXT PRIMARY KEY,
          expires INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS web_sessions(
          token_hash TEXT PRIMARY KEY,
          open_id TEXT NOT NULL,
          name TEXT NOT NULL,
          csrf TEXT NOT NULL,
          expires INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS credentials(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          secret TEXT NOT NULL,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS proxies(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE,
          address TEXT NOT NULL,
          port INTEGER NOT NULL DEFAULT 22,
          username TEXT NOT NULL,
          host_key TEXT NOT NULL,
          credential_id INTEGER NOT NULL REFERENCES credentials(id)
        );
        CREATE TABLE IF NOT EXISTS hosts(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          address TEXT NOT NULL UNIQUE,
          port INTEGER NOT NULL DEFAULT 22,
          username TEXT NOT NULL,
          host_key TEXT NOT NULL DEFAULT '',
          credential_id INTEGER REFERENCES credentials(id),
          proxy_id INTEGER REFERENCES proxies(id),
          zabbix_hostid TEXT,
          enabled INTEGER NOT NULL DEFAULT 1,
          mode TEXT NOT NULL DEFAULT 'standard',
          gateway_approved INTEGER NOT NULL DEFAULT 0,
          last_status TEXT NOT NULL DEFAULT 'untested',
          updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS groups(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS host_groups(
          host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
          group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
          PRIMARY KEY(host_id,group_id)
        );
        CREATE TABLE IF NOT EXISTS audit(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          actor TEXT NOT NULL,
          action TEXT NOT NULL,
          target TEXT NOT NULL,
          outcome TEXT NOT NULL,
          detail TEXT NOT NULL DEFAULT '',
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS host_key_candidates(
          host_id INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
          key TEXT NOT NULL,
          fingerprint TEXT NOT NULL,
          source_signature TEXT NOT NULL DEFAULT '',
          collected_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS scan_batches(
          id TEXT PRIMARY KEY,
          status TEXT NOT NULL,
          total INTEGER NOT NULL,
          completed INTEGER NOT NULL DEFAULT 0,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS scan_results(
          batch_id TEXT NOT NULL REFERENCES scan_batches(id),
          host_id INTEGER NOT NULL,
          status TEXT NOT NULL,
          fingerprint TEXT,
          algorithm TEXT,
          previous_fingerprint TEXT,
          error TEXT,
          PRIMARY KEY(batch_id,host_id)
        );
        """)
        # revision/asset_type are not in CREATE TABLE above: new databases get them here too.
        _add_columns(
            c,
            "hosts",
            {
                "mode": "TEXT NOT NULL DEFAULT 'standard'",
                "gateway_approved": "INTEGER NOT NULL DEFAULT 0",
                "revision": "INTEGER NOT NULL DEFAULT 1",
                "asset_type": "TEXT NOT NULL DEFAULT 'linux'",
            },
        )
        c.executescript("""
        CREATE TABLE IF NOT EXISTS zabbix_groups(
          zabbix_groupid TEXT PRIMARY KEY,
          group_id INTEGER NOT NULL UNIQUE REFERENCES groups(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS zabbix_memberships(
          host_id INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
          group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
          PRIMARY KEY(host_id,group_id)
        );
        CREATE TABLE IF NOT EXISTS zabbix_sync_runs(
          id TEXT PRIMARY KEY, actor TEXT NOT NULL, status TEXT NOT NULL,
          source TEXT NOT NULL, options TEXT NOT NULL,
          total INTEGER NOT NULL DEFAULT 0, completed INTEGER NOT NULL DEFAULT 0,
          error TEXT NOT NULL DEFAULT '', created_at TEXT DEFAULT CURRENT_TIMESTAMP,
          completed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS zabbix_sync_items(
          run_id TEXT NOT NULL REFERENCES zabbix_sync_runs(id) ON DELETE CASCADE,
          hostid TEXT NOT NULL, data TEXT NOT NULL, outcome TEXT NOT NULL DEFAULT 'pending',
          host_id INTEGER REFERENCES hosts(id),
          PRIMARY KEY(run_id,hostid)
        );
        """)
        c.execute(
            "UPDATE zabbix_sync_runs SET status='failed',error='服务重启，资产发现中断；请重新拉取',"
            "completed_at=CURRENT_TIMESTAMP WHERE status IN ('queued','running')"
        )
        c.executescript("""
        CREATE TABLE IF NOT EXISTS mcp_clients(
          id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE,
          prefix TEXT NOT NULL, group_ids TEXT NOT NULL, actions TEXT NOT NULL,
          all_hosts INTEGER NOT NULL DEFAULT 0,
          expires_at INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          created_at TEXT DEFAULT CURRENT_TIMESTAMP, last_used_at TEXT
        );
        CREATE TABLE IF NOT EXISTS diagnostic_jobs(
          id TEXT PRIMARY KEY, batch_id TEXT NOT NULL, host_id INTEGER NOT NULL,
          host_name TEXT NOT NULL, host_revision INTEGER NOT NULL,
          actor TEXT NOT NULL, source TEXT NOT NULL, action TEXT NOT NULL,
          request TEXT NOT NULL, result TEXT, status TEXT NOT NULL DEFAULT 'queued',
          cancel_requested INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT '',
          created_at TEXT DEFAULT CURRENT_TIMESTAMP, started_at TEXT, completed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS diagnostic_batches(
          id TEXT PRIMARY KEY, actor TEXT NOT NULL, source TEXT NOT NULL,
          skipped TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS ix_jobs_host_action_completed ON diagnostic_jobs(host_id,action,completed_at);
        CREATE INDEX IF NOT EXISTS ix_jobs_batch ON diagnostic_jobs(batch_id);
        CREATE INDEX IF NOT EXISTS ix_batches_created ON diagnostic_batches(created_at);
        CREATE INDEX IF NOT EXISTS ix_jobs_created ON diagnostic_jobs(created_at DESC,id);
        CREATE INDEX IF NOT EXISTS ix_jobs_host ON diagnostic_jobs(host_id,status);
        CREATE INDEX IF NOT EXISTS ix_hosts_zabbix ON hosts(zabbix_hostid);
        CREATE INDEX IF NOT EXISTS ix_audit_created ON audit(created_at DESC,id);
        """)
        c.execute(
            "UPDATE diagnostic_jobs SET status='failed',error='服务重启，任务中断；请重新提交',"
            "completed_at=CURRENT_TIMESTAMP WHERE status IN ('queued','running')"
        )
        _add_columns(
            c, "host_key_candidates", {"source_signature": "TEXT NOT NULL DEFAULT ''"}
        )
        _add_columns(
            c, "scan_results", {"algorithm": "TEXT", "previous_fingerprint": "TEXT"}
        )
        # Release whose implied actions were applied (access.extend_client_actions).
        _add_columns(c, "mcp_clients", {"actions_extended": "TEXT NOT NULL DEFAULT ''"})
        c.execute("UPDATE scan_batches SET status='interrupted' WHERE status='running'")
        c.execute(
            "UPDATE scan_results SET status='interrupted',error='任务执行中断，可仅重试失败主机' "
            "WHERE status='queued' AND batch_id IN "
            "(SELECT id FROM scan_batches WHERE status='interrupted')"
        )


def _add_columns(c, table: str, columns: dict[str, str]):
    """Idempotent upgrade of databases created by older releases (in order)."""
    present = {r["name"] for r in c.execute(f"PRAGMA table_info({table})")}
    for name, definition in columns.items():
        if name not in present:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


@contextmanager
def db():
    c = sqlite3.connect(str(DATA_DIR / "ssh-mcp.sqlite3"), timeout=10)
    (DATA_DIR / "ssh-mcp.sqlite3").chmod(0o600)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA foreign_keys=ON")
    c.execute("PRAGMA busy_timeout=10000")
    try:
        yield c
        c.commit()
    except BaseException:
        c.rollback()
        raise
    finally:
        c.close()


def token(name: str) -> str:
    return (DATA_DIR / name).read_text().strip()


@lru_cache(maxsize=8)
def _fernet(directory: Path) -> Fernet:
    # `directory` is only the cache key: one cached key per resolved DATA_DIR.
    return Fernet(ensure_secret("master.key", Fernet.generate_key))


def seal(plaintext: str) -> str:
    return _fernet(DATA_DIR.resolve()).encrypt(plaintext.encode()).decode()


def unseal(ciphertext: str) -> str:
    return _fernet(DATA_DIR.resolve()).decrypt(ciphertext.encode()).decode()


def private_ip(value: str) -> str:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValueError("只允许登记内网 IP 地址，不接受域名") from None
    allowed = (
        any(
            addr in ipaddress.ip_network(n)
            for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
        )
        if addr.version == 4
        else addr in ipaddress.ip_network("fc00::/7")
    )
    if (
        not allowed
        or getattr(addr, "scope_id", None)
        or addr.is_multicast
        or addr.is_loopback
        or addr.is_unspecified
    ):
        raise ValueError("目标必须是允许的内网地址")
    return str(addr)


def username(value: str) -> str:
    if not IDENTITY.fullmatch(value):
        raise ValueError("SSH 用户名格式无效")
    return value


def validate_hostkey(value: str, *, optional: bool = False) -> str:
    if len(value) > 4096 or "\n" in value.strip():
        raise ValueError("主机公钥长度或格式无效")
    value = " ".join(value.strip().split())
    if not value and optional:
        return ""
    if not HOSTKEY.fullmatch(value):
        raise ValueError("主机公钥格式错误；需要 ssh-ed25519/ssh-rsa/ECDSA 公钥")
    kind, encoded = value.split()[:2]
    try:
        raw = base64.b64decode(encoded, validate=True)
        if paramiko.PKey.from_type_string(kind, raw).asbytes() != raw:
            raise ValueError()
    except Exception:
        raise ValueError("SSH 公钥内容与算法不匹配或已损坏") from None
    return " ".join(value.split()[:2])


def audit(actor: str, action: str, target: str, outcome: str, detail: str = ""):
    # Detail may contain only developer-selected diagnostic codes, never credentials.
    with db() as c:
        c.execute(
            "INSERT INTO audit(actor,action,target,outcome,detail) VALUES (?,?,?,?,?)",
            (actor[:50], action[:60], str(target)[:120], outcome[:30], detail[:240]),
        )


def get_host(host_id: int) -> dict:
    with db() as c:
        item = c.execute("SELECT * FROM hosts WHERE id=?", (host_id,)).fetchone()
    if not item or not item["enabled"]:
        raise ValueError("目标主机未登记或已被禁用")
    if item["asset_type"] != "linux":
        raise ValueError("该资产尚不支持 Linux SSH 诊断")
    return dict(item)


def get_credential(credential_id: int | None) -> str:
    if not credential_id:
        raise ValueError("目标未绑定 SSH 凭据")
    with db() as c:
        row = c.execute(
            "SELECT secret FROM credentials WHERE id=?", (credential_id,)
        ).fetchone()
    if not row:
        raise ValueError("SSH 凭据不存在")
    return unseal(row["secret"])


def get_proxy(proxy_id: int | None) -> dict | None:
    if proxy_id is None:
        return None
    with db() as c:
        row = c.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    if not row:
        raise ValueError("SSH 跳板不存在")
    return dict(row)


def groups_for(host_id: int) -> list[int]:
    with db() as c:
        return [
            r[0]
            for r in c.execute(
                "SELECT group_id FROM host_groups WHERE host_id=?", (host_id,)
            )
        ]


def setting(key: str) -> str:
    """Return a non-sensitive setting or decrypt encrypted application secret."""
    with db() as c:
        row = c.execute(
            "SELECT value,encrypted FROM settings WHERE key=?", (key,)
        ).fetchone()
    if not row:
        return ""
    return unseal(row["value"]) if row["encrypted"] else row["value"]


def save_settings(values: dict[str, str], encrypted: set[str] | None = None):
    encrypted = encrypted or set()
    with db() as c:
        for key, value in values.items():
            c.execute(
                "INSERT INTO settings(key,value,encrypted) VALUES (?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value,encrypted=excluded.encrypted",
                (
                    key,
                    seal(value) if key in encrypted else value,
                    int(key in encrypted),
                ),
            )


def scan_signature(host: dict) -> str:
    """Stable snapshot of SSH endpoint identity; no secret/key stored in snapshot."""
    material = json.dumps(
        {
            "id": host["id"],
            "address": host["address"],
            "port": host["port"],
            "proxy_id": host.get("proxy_id"),
            "enabled": host.get("enabled"),
            "host_key": host.get("host_key", ""),
            "revision": host.get("revision", 1),
        },
        ensure_ascii=False,
        sort_keys=True,
    )
    return hashlib.sha256(material.encode()).hexdigest()
