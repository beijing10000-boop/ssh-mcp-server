"""持久化 SQLite + 加密凭据 + 双令牌，禁止将敏感信息写入日志。"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
from contextlib import contextmanager

from cryptography.fernet import Fernet

DATA_DIR = Path(os.environ.get("DATA_DIR", "/app/data"))
IDENTITY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")
HOSTKEY = re.compile(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/=]+(?: .*)?$")
GROUP = re.compile(r"^.{1,80}$", re.S)


def ensure_secret(filename: str, creator) -> bytes:
    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    p = DATA_DIR / filename
    try:
        with p.open("xb") as fh:
            os.chmod(p, 0o600)
            fh.write(creator())
    except FileExistsError:
        pass
    return p.read_bytes().strip()


def init_db():
    DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    ensure_secret("master.key", Fernet.generate_key)
    ensure_secret("admin.token", lambda: secrets.token_urlsafe(36).encode())
    ensure_secret("mcp.token", lambda: secrets.token_urlsafe(36).encode())
    with db() as c:
        c.executescript("""
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
          collected_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """)


@contextmanager
def db():
    c = sqlite3.connect(str(DATA_DIR / "ssh-mcp.sqlite3"), timeout=10)
    c.row_factory = sqlite3.Row
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


def seal(plaintext: str) -> str:
    return Fernet(ensure_secret("master.key", Fernet.generate_key)).encrypt(plaintext.encode()).decode()


def unseal(ciphertext: str) -> str:
    return Fernet(ensure_secret("master.key", Fernet.generate_key)).decrypt(ciphertext.encode()).decode()


def private_ip(value: str) -> str:
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValueError("只允许登记内网 IP 地址，不接受域名") from None
    allowed = (
        any(addr in ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
        if addr.version == 4 else addr in ipaddress.ip_network("fc00::/7")
    )
    if not allowed or addr.is_multicast or addr.is_loopback or addr.is_unspecified:
        raise ValueError("目标必须是允许的内网地址")
    return str(addr)


def username(value: str) -> str:
    if not IDENTITY.fullmatch(value):
        raise ValueError("SSH 用户名格式无效")
    return value


def validate_hostkey(value: str, *, optional: bool = False) -> str:
    value = " ".join(value.strip().split())
    if not value and optional:
        return ""
    if not HOSTKEY.fullmatch(value):
        raise ValueError("主机公钥格式错误；需要 ssh-ed25519/ssh-rsa/ECDSA 公钥")
    return " ".join(value.split()[:2])


def safe_row(row) -> dict | None:
    return dict(row) if row else None


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
    return dict(item)


def get_credential(credential_id: int | None) -> str:
    if not credential_id:
        raise ValueError("目标未绑定 SSH 凭据")
    with db() as c:
        row = c.execute("SELECT secret FROM credentials WHERE id=?", (credential_id,)).fetchone()
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
        return [r[0] for r in c.execute("SELECT group_id FROM host_groups WHERE host_id=?", (host_id,))]
