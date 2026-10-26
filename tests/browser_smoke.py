"""Desktop workflows against a disposable local service; never a user browser."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from examples.ai_platform_adapter import connect

OUT = ROOT / "docs/screenshots"
OUT.mkdir(exist_ok=True)
for image in OUT.glob("*.png"):
    image.unlink()
(ROOT / "docs/UI-TEST-RESULTS.json").unlink(missing_ok=True)
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
base = f"http://127.0.0.1:{port}"
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    zabbix_port = sock.getsockname()[1]
zabbix_log = Path("/tmp/sshmcp-zabbix-fixture.log").open("w")
zabbix_server = subprocess.Popen(
    [
        sys.executable,
        "-m",
        "uvicorn",
        "tests.zabbix_fixture:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(zabbix_port),
    ],
    cwd=ROOT,
    env={**os.environ, "SSHMCP_UI_TEST": "1"},
    stdout=zabbix_log,
    stderr=zabbix_log,
)
log = Path("/tmp/sshmcp-browser-test.log").open("w")
server = subprocess.Popen(
    [
        sys.executable,
        "-m",
        "uvicorn",
        "tests.ui_server:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
    ],
    cwd=ROOT,
    env={
        **os.environ,
        "SSHMCP_UI_TEST": "1",
        "SSHMCP_ZABBIX_FIXTURE": f"http://127.0.0.1:{zabbix_port}/mcp",
    },
    stdout=log,
    stderr=log,
)
checks = []
try:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(100):
        try:
            opener.open(base + "/healthz", timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    else:
        raise RuntimeError("Fixture did not start")
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
        )
        page = browser.new_page(
            viewport={"width": 1440, "height": 1080}, device_scale_factor=1
        )
        errors, failed = [], []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("response", lambda r: failed.append(r.url) if r.status >= 500 else None)
        page.on("dialog", lambda d: d.accept())
        page.goto(base + "/__ui_login")
        page.locator(".welcome").wait_for()

        def navigate(name):
            page.locator(f'nav [data-page="{name}"]').click()
            page.locator(f'nav [data-page="{name}"].active').wait_for()
            page.locator("#content .loading-panel").wait_for(state="hidden")
            assert not page.locator('#content [role="alert"]').count(), page.locator(
                "#content"
            ).inner_text()

        for width in (1280, 1440, 1920):
            page.set_viewport_size({"width": width, "height": 1080})
            for name in (
                "overview",
                "hosts",
                "groups",
                "zabbix",
                "credentials",
                "proxies",
                "keys",
                "diagnostics",
                "history",
                "clients",
                "audit",
                "feishu",
            ):
                navigate(name)
                assert page.evaluate(
                    "document.documentElement.scrollWidth <= innerWidth"
                ), (width, name)
                checks.append({"width": width, "page": name, "ok": True})
        page.set_viewport_size({"width": 1440, "height": 1080})
        navigate("hosts")
        page.locator('[data-action="page-next"]').click()
        page.locator(".pagination").get_by_text(
            "共 31 条 · 第 2 / 2 页", exact=True
        ).wait_for()
        assert page.locator('[data-action="page-next"]').is_disabled()
        page.locator('[data-action="page-prev"]').click()
        page.locator(".pagination").get_by_text(
            "共 31 条 · 第 1 / 2 页", exact=True
        ).wait_for()
        page.locator("#host-group").select_option(label="开发测试")
        page.locator("#host-search-form button[type=submit]").click()
        page.locator(".pagination").get_by_text(
            "共 10 条 · 第 1 / 1 页", exact=True
        ).wait_for()
        page.locator('[data-action="select-filtered"]').click()
        page.locator("#selected-count").get_by_text(
            "已选 10 台", exact=False
        ).wait_for()
        checks.append(
            {
                "workflow": "server pagination, group filter and all matching selection",
                "ok": True,
            }
        )
        page.locator('[data-action="clear-selected"]').click()
        page.locator('[data-action="new-host"]').click()
        page.get_by_label("资产名称", exact=True).fill("浏览器验证资产")
        page.get_by_label("内网 IP 地址", exact=True).fill("8.8.8.8")
        page.locator("#editor-form button[type=submit]").click()
        page.locator("#editor-feedback").get_by_text(
            "目标必须是允许的内网地址"
        ).wait_for()
        page.get_by_label("内网 IP 地址", exact=True).fill("10.20.1.99")
        page.locator("#editor-form button[type=submit]").click()
        page.locator("#editor").wait_for(state="hidden")
        checks.append(
            {"workflow": "asset validation appears in modal and root saves", "ok": True}
        )
        navigate("proxies")
        page.locator('[data-action="new-proxy"]').click()
        assert page.locator("#editor select[name=credential_id] option").count() == 1
        page.locator("#editor-close").click()
        checks.append({"workflow": "direct jump page loads credentials", "ok": True})
        navigate("diagnostics")
        page.get_by_label("诊断类型", exact=True).select_option("memory_processes")
        assert page.locator("#diagnostic-form [name=service]").is_hidden()
        page.locator("#diagnostic-form button[type=submit]").click()
        page.get_by_role("heading", name="采集结果", exact=True).wait_for()
        page.get_by_text(
            "隔离界面测试结果，不代表生产观测。", exact=False
        ).first.wait_for()
        job_url = page.url
        page.reload()
        page.get_by_role("heading", name="采集结果", exact=True).wait_for()
        assert page.url == job_url
        checks.append(
            {"workflow": "background diagnosis, saved report and reload", "ok": True}
        )
        page.screenshot(path=str(OUT / "job-1440.png"), full_page=True)
        navigate("diagnostics")
        page.get_by_label("诊断类型", exact=True).select_option("io")
        page.locator("#diagnostic-form button[type=submit]").click()
        page.locator('[data-action="cancel-job"]').click()
        page.get_by_text("已取消", exact=True).wait_for()
        checks.append({"workflow": "running diagnosis cancellation", "ok": True})
        navigate("clients")
        page.locator('[data-action="new-client"]').click()
        page.get_by_label("客户端名称", exact=True).fill("浏览器验证客户端")
        page.locator("#editor input[name=all_hosts]").check()
        page.locator("#editor-form button[type=submit]").click()
        page.get_by_role("heading", name="保存客户端令牌", exact=True).wait_for()
        token = page.get_by_label("MCP 接入令牌", exact=True).input_value()
        assert token.startswith("sshmcp_")
        page.locator("#editor-close").click()
        assert token not in page.locator("#content").inner_text()
        assert page.locator("#editor-fields textarea").count() == 0

        async def verify_mcp_adapter():
            async with connect(base + "/mcp", token, allow_http=True) as remote:
                binding = await remote.resolve("10001")
                result = await remote.diagnose(binding, "health")
                assert result["status"] == "success" and result["job_id"]
                stale = await remote.diagnose(
                    replace(binding, revision=binding.revision + 1), "health"
                )
                assert stale["status"] == "failed" and "配置已变更" in stale["error"]

        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(lambda: asyncio.run(verify_mcp_adapter())).result(timeout=30)
        checks.append(
            {
                "workflow": "real MCP SDK initialize, exact host mapping, diagnostic and stale revision rejection",
                "ok": True,
            }
        )
        row = page.locator("tr").filter(has_text="浏览器验证客户端")
        row.locator('[data-action="revoke-client"]').click()
        row.get_by_text("已撤销", exact=True).wait_for()
        assert (
            page.request.post(
                base + "/mcp", headers={"Authorization": "Bearer " + token}, data={}
            ).status
            == 401
        )
        checks.append(
            {
                "workflow": "scoped client token shown once and revocation enforced",
                "ok": True,
            }
        )
        navigate("zabbix")
        page.locator(".connection-settings summary").click()
        page.locator('[data-action="zabbix-test"]').click()
        page.locator("#zabbix-feedback").get_by_text(
            "MCP 握手、主机组读取和主机计数均已通过", exact=False
        ).wait_for(timeout=15000)
        assert page.locator(".zabbix-group-check:checked").count() == 1
        before_count = len(page.request.get(base + "/api/v1/hosts").json())
        page.locator("#zabbix-discover-form button[type=submit]").click()
        page.locator(".sync-progress .status.preview").wait_for(timeout=30000)
        assert len(page.request.get(base + "/api/v1/hosts").json()) == before_count
        page.locator("#zabbix-register-form [name=credential_id]").select_option("1")
        page.locator("#zabbix-register-form [name=register_all]").click()
        page.locator("#zabbix-register-result").get_by_text(
            "本次登记 28 台", exact=False
        ).wait_for(timeout=15000)
        after = page.request.get(base + "/api/v1/hosts").json()
        imported = [
            h
            for h in after
            if h["zabbix_hostid"] and h["zabbix_hostid"].startswith("200")
        ]
        assert len(imported) == 28 and all(
            not h["has_host_key"] and h["port"] == 22 and h["credential_id"] == 1
            for h in imported
        )
        checks.append(
            {
                "workflow": "real MCP handshake, initMAX notice, adaptive batches, preview, Linux registration and unverified keys",
                "ok": True,
            }
        )
        page.locator('[data-action="page-next"][data-id="zabbix"]').click()
        page.locator(".pagination").get_by_text("第 2 / 2 页", exact=False).wait_for()
        checks.append({"workflow": "Zabbix preview pagination", "ok": True})
        page.screenshot(path=str(OUT / "zabbix-1440.png"), full_page=True)
        navigate("diagnostics")
        page.locator('[data-action="tool-category"][data-id="服务与日志"]').click()
        page.locator('[data-action="choose-tool"][data-id="oom"]').click()
        assert page.locator("#diagnostic-form [name=action]").input_value() == "oom"
        assert page.locator("#diagnostic-form [name=minutes]").is_visible()
        assert page.locator("#diagnostic-form [name=service]").is_hidden()
        checks.append(
            {"workflow": "diagnostic category and parameter guidance", "ok": True}
        )
        page.locator('[data-action="tool-category"][data-id="全部"]').click()
        for name in ("overview", "hosts", "diagnostics", "clients"):
            navigate(name)
            page.evaluate("document.fonts.ready")
            page.screenshot(path=str(OUT / (name + "-1440.png")), full_page=True)
        page.locator("#theme-toggle").click()
        assert page.locator("html").get_attribute("data-theme") == "dark"
        page.mouse.move(0, 0)
        # Let the CSS color transition finish before capturing the theme.
        page.wait_for_timeout(200)
        page.screenshot(path=str(OUT / "clients-dark-1440.png"), full_page=True)
        checks.append({"workflow": "theme toggle", "ok": True})
        assert errors == [], errors
        assert failed == [], failed
        browser.close()
    result = {
        "fixture": "isolated local database and simulated diagnostic output",
        "checks": checks,
        "javascript_errors": errors,
        "http_5xx": failed,
    }
    (ROOT / "docs/UI-TEST-RESULTS.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    )
    print(
        json.dumps(
            {"passed": len(checks), "javascript_errors": errors, "http_5xx": failed}
        )
    )
finally:
    zabbix_server.terminate()
    zabbix_server.wait(timeout=10)
    zabbix_log.close()
    server.terminate()
    server.wait(timeout=10)
    log.close()
