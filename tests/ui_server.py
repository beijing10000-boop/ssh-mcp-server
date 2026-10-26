"""Explicitly isolated browser fixture; this file is not copied into the image."""

import io
import json
import os
import secrets
import tempfile
import time

if os.getenv("SSHMCP_UI_TEST") != "1":
    raise RuntimeError("SSHMCP_UI_TEST=1 is required")
os.environ["DATA_DIR"] = tempfile.mkdtemp(prefix="sshmcp-ui-")

import paramiko
from fastapi.responses import RedirectResponse
from sshmcp import diagnostics, jobs, store
from sshmcp.auth import COOKIE, _hash
from sshmcp.main import app

store.init_db()
store.save_settings(
    {
        "web_protocol": "http",
        "web_public_host": "127.0.0.1:9099",
        "lark_app_id": "cli_ui_fixture",
        "lark_app_secret": "isolated-ui-app-secret",
        "feishu_admin_open_ids": "ou_ui_fixture",
    },
    encrypted={"lark_app_secret"},
)
if os.getenv("SSHMCP_ZABBIX_FIXTURE"):
    store.save_settings(
        {
            "zabbix_mcp_config": json.dumps(
                {
                    "url": os.environ["SSHMCP_ZABBIX_FIXTURE"],
                    "token": "isolated-upstream-token",
                    "server": "",
                    "transport": "http",
                    "verify_tls": True,
                    "batch_size": 20,
                    "interval_ms": 200,
                }
            )
        },
        encrypted={"zabbix_mcp_config"},
    )
key = paramiko.RSAKey.generate(2048)
stream = io.StringIO()
key.write_private_key(stream)
public = "ssh-rsa " + key.get_base64()
with store.db() as c:
    c.execute(
        "INSERT INTO credentials(id,name,secret) VALUES (1,?,?)",
        ("隔离测试凭据", store.seal(json.dumps({"private_key": stream.getvalue()}))),
    )
    c.executemany(
        "INSERT INTO groups(id,name) VALUES (?,?)",
        [(1, "生产应用"), (2, "开发测试"), (3, "基础服务")],
    )
    for i in range(1, 32):
        c.execute(
            "INSERT INTO hosts(id,name,address,username,host_key,credential_id,zabbix_hostid) VALUES (?,?,?,?,?,?,?)",
            (
                i,
                f"测试资产 · linux-{i:02d}",
                f"10.20.0.{i}",
                "root",
                public if i < 31 else "",
                1,
                str(10000 + i),
            ),
        )
        c.execute("INSERT INTO host_groups VALUES (?,?)", (i, (i - 1) % 3 + 1))


def fixture_execute(
    host_id,
    action,
    service=None,
    minutes=30,
    directory_root=None,
    cancelled=lambda: False,
    **kwargs,
):
    for _ in range(300 if action == "io" else 6):
        if cancelled():
            raise diagnostics.SSHDiagnosticError("任务已取消")
        time.sleep(0.05)
    return {
        "host_id": host_id,
        "action": action,
        "status": "success",
        "exit_code": 0,
        "duration_ms": 300,
        "truncated": False,
        "stderr": "",
        "output": "隔离界面测试结果，不代表生产观测。\n[采集范围]\n负载、内存、文件系统与进程快照\nAIOPS_SSH_OK\n0\nLinux",
    }


diagnostics.execute = fixture_execute
for hid in (1, 2, 3):
    jobs.run_inline(hid, "health", "ou_ui_fixture", source="web")


@app.get("/__ui_login")
def login():
    raw = secrets.token_urlsafe(32)
    with store.db() as c:
        c.execute(
            "INSERT INTO web_sessions VALUES (?,?,?,?,?)",
            (
                _hash(raw),
                "ou_ui_fixture",
                "隔离界面测试",
                secrets.token_urlsafe(24),
                int(time.time()) + 3600,
            ),
        )
    response = RedirectResponse("/")
    response.set_cookie(COOKIE, raw, httponly=True, samesite="lax")
    return response


# Main mounts '/' last; insert the fixture login route ahead of that mount.
app.router.routes.insert(0, app.router.routes.pop())
