import asyncio
from types import SimpleNamespace

import pytest

from examples.ai_platform_adapter import HostBinding, IntegrationError, SSHMCPAdapter


class Session:
    def __init__(self, result, error=False):
        self.result, self.error, self.calls = result, error, []

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return SimpleNamespace(
            isError=self.error, structuredContent=self.result, content=[]
        )


def test_adapter_binds_exact_asset_revision_and_preserves_partial():
    session = Session(
        {"status": "success", "zabbix_hostid": "101", "host_id": 7, "revision": 4}
    )
    adapter = SSHMCPAdapter(session)
    binding = asyncio.run(adapter.resolve("101"))
    session.result = {
        "status": "partial",
        "host_id": 7,
        "action": "kernel",
        "job_id": "job",
    }
    result = asyncio.run(adapter.diagnose(binding, "kernel", minutes=15))
    assert session.calls[-1] == (
        "ssh_diagnose_kernel",
        {"host_id": 7, "expected_revision": 4, "minutes": 15},
    )
    assert result["status"] == "partial" and result["provider"] == "ssh_mcp"


def test_adapter_rejects_mismatched_or_failed_resolution():
    for payload in (
        {"status": "failed"},
        {"status": "success", "zabbix_hostid": "102", "host_id": 7, "revision": 4},
    ):
        with pytest.raises(IntegrationError):
            asyncio.run(SSHMCPAdapter(Session(payload)).resolve("101"))


def test_adapter_fails_closed_without_arbitrary_tools_or_shell():
    session = Session({})
    adapter, binding = SSHMCPAdapter(session), HostBinding("101", 7, 4)
    for action, args in (
        ("exec", {}),
        ("logs", {"service": "nginx; id"}),
        ("cpu", {"directory_root": "/data"}),
    ):
        with pytest.raises(IntegrationError):
            asyncio.run(adapter.diagnose(binding, action, **args))
    assert session.calls == []
    session.error = True
    with pytest.raises(IntegrationError):
        asyncio.run(adapter.diagnose(binding, "cpu"))
