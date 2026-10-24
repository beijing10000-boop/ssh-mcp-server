"""Second MCP connection for AI Ops Platform; no SSH credentials or arbitrary tools.

Use from the platform's server, keeping this connection separate from Zabbix MCP.
The caller owns the overall task deadline, evidence storage and action budget.
"""

from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
import asyncio
import json
import re
from urllib.parse import urlsplit

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

TOOLS = {
    "connection": "ssh_test_connection",
    "directory": "ssh_diagnose_directory_usage",
    **{
        action: "ssh_diagnose_" + action
        for action in (
            "health",
            "capabilities",
            "cpu",
            "memory",
            "processes",
            "memory_processes",
            "disk",
            "io",
            "network",
            "sockets",
            "peer_connections",
            "peer_traffic",
            "system",
            "service",
            "failed_services",
            "logs",
            "kernel",
            "containers",
        )
    },
}
SERVICE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$")


class IntegrationError(RuntimeError):
    """Safe to surface in an evidence-gap record; never embeds a bearer token."""


@dataclass(frozen=True)
class HostBinding:
    zabbix_hostid: str
    host_id: int
    revision: int


class SSHMCPAdapter:
    def __init__(self, session: ClientSession, timeout: float = 90):
        self.session = session
        self.timeout = timeout

    async def _call(self, name, arguments):
        try:
            async with asyncio.timeout(self.timeout):
                result = await self.session.call_tool(name, arguments)
        except Exception as exc:
            raise IntegrationError(
                "SSH MCP 调用未完成：" + type(exc).__name__
            ) from None
        if result.isError:
            raise IntegrationError("SSH MCP 拒绝工具调用")
        payload = result.structuredContent
        if payload is None:
            texts = [item.text for item in result.content if item.type == "text"]
            if len(texts) != 1 or len(texts[0]) > 1_000_000:
                raise IntegrationError("SSH MCP 返回格式或长度无效")
            try:
                payload = json.loads(texts[0])
            except ValueError:
                raise IntegrationError("SSH MCP 返回非 JSON 内容") from None
        if not isinstance(payload, dict) or len(json.dumps(payload)) > 1_000_000:
            raise IntegrationError("SSH MCP 返回格式或长度无效")
        return payload

    async def resolve(self, zabbix_hostid: str) -> HostBinding:
        if not isinstance(zabbix_hostid, str) or not re.fullmatch(
            r"[0-9]{1,32}", zabbix_hostid
        ):
            raise IntegrationError("必须使用任务绑定的数字 Zabbix Host ID")
        data = await self._call("ssh_resolve_host", {"zabbix_hostid": zabbix_hostid})
        if (
            data.get("status") != "success"
            or data.get("zabbix_hostid") != zabbix_hostid
            or type(data.get("host_id")) is not int
            or data["host_id"] < 1
            or type(data.get("revision")) is not int
            or data["revision"] < 1
        ):
            raise IntegrationError("SSH 主机映射缺失、重复、未就绪或不在授权范围内")
        return HostBinding(zabbix_hostid, data["host_id"], data["revision"])

    async def diagnose(
        self,
        binding: HostBinding,
        action: str,
        *,
        service: str | None = None,
        minutes: int = 30,
        directory_root: str | None = None,
    ) -> dict:
        if action not in TOOLS:
            raise IntegrationError("不支持的 SSH 诊断动作")
        if type(minutes) is not int or not 1 <= minutes <= 120:
            raise IntegrationError("时间范围必须为 1–120 分钟")
        args = {"host_id": binding.host_id, "expected_revision": binding.revision}
        if action in {"service", "logs"}:
            if not isinstance(service, str) or not SERVICE.fullmatch(service):
                raise IntegrationError("需要管理员授权的合法服务名")
            args["service"] = service
        elif service is not None:
            raise IntegrationError("该动作不接受服务参数")
        if action in {"logs", "kernel"}:
            args["minutes"] = minutes
        if action == "directory":
            if (
                not isinstance(directory_root, str)
                or not 1 <= len(directory_root) <= 200
            ):
                raise IntegrationError("需要管理员授权的目录路径")
            args["root"] = directory_root
        elif directory_root is not None:
            raise IntegrationError("该动作不接受目录参数")
        data = await self._call(TOOLS[action], args)
        if (
            data.get("host_id") != binding.host_id
            or data.get("action") != action
            or data.get("status") not in {"success", "partial", "failed", "cancelled"}
        ):
            raise IntegrationError("SSH MCP 返回的主机、动作或状态不匹配")
        return {
            **data,
            "provider": "ssh_mcp",
            "zabbix_hostid": binding.zabbix_hostid,
            "host_revision": binding.revision,
        }


@asynccontextmanager
async def connect(
    url: str, token: str, *, allow_http: bool = False, timeout: float = 90
):
    """URL/token are administrator configuration, never model/tool arguments.

    HTTP must be explicitly enabled for isolated testing. No redirects, automatic
    retries, environment proxy, or fallback to local SSH. TLS verification stays on.
    """
    try:
        parsed = urlsplit(url)
        valid = (
            parsed.scheme in ({"https", "http"} if allow_http else {"https"})
            and parsed.hostname
            and not parsed.username
            and not parsed.password
            and parsed.path.rstrip("/") == "/mcp"
            and not parsed.query
            and not parsed.fragment
            and not any(c.isspace() for c in url)
            and (parsed.port is None or 1 <= parsed.port <= 65535)
        )
    except ValueError:
        valid = False
    if not valid or not token or not token.isascii() or any(c.isspace() for c in token):
        raise IntegrationError("SSH MCP 地址或令牌配置无效")
    if not 1 <= timeout <= 120:
        raise IntegrationError("调用超时必须为 1–120 秒")

    def client_factory(headers=None, timeout=None, auth=None):
        return httpx.AsyncClient(
            headers=headers,
            timeout=timeout,
            auth=auth,
            follow_redirects=False,
            trust_env=False,
        )

    async with streamablehttp_client(
        url,
        headers={"Authorization": "Bearer " + token},
        timeout=timeout,
        sse_read_timeout=timeout,
        httpx_client_factory=client_factory,
    ) as (read, write, _):
        async with ClientSession(
            read, write, read_timeout_seconds=timedelta(seconds=timeout)
        ) as session:
            async with asyncio.timeout(min(timeout, 15)):
                await session.initialize()
            yield SSHMCPAdapter(session, timeout)
