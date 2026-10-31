# 现有 AI Ops Platform 如何接入独立 SSH MCP

当前接入：AI Ops Platform v0.9.0 支持 Skill 驱动查询，配合本服务 v0.4.1 的 ssh_resolve_target 按已登记 IP 直接诊断，不要求先查 Zabbix。详见 [v0.4.1 说明](RELEASE-v0.4.1.md)。下文保留早期固定剧本适配方案作为历史设计参考；其中本地资产、强制 Zabbix 优先与固定剧本不适用于新 Skill 模式。

本方案针对 `beijing10000-boop/ai-ops-platform` 的 `integration/unified-platform`，检查基线为 `c6cf7021c0668cdf334927213d45014cee03cbac`。这里提供改造设计及可运行客户端示例；**未自动修改、部署或切换现有 AI 平台**。

## 1. 保留 Zabbix 连接，增加 SSH 专用连接

现有 `mcp_url` / `mcp_token` 用于 Zabbix。新增独立配置：

| 配置 | 用途 |
| --- | --- |
| `ssh_mcp_enabled` | SSH 远程后端开关，默认关闭 |
| `ssh_mcp_url` | 管理员配置的 `https://ssh-mcp.example.internal/mcp` |
| `ssh_mcp_token` | Web「MCP 接入」生成的专用令牌，加密存储、不回显 |
| `ssh_mcp_timeout_seconds` | 单工具超时，建议 90 秒并受整体任务剩余预算限制 |
| 资产 `diagnostic_backend` | 显式选 `local` 或 `ssh_mcp`，迁移时逐组切换 |

不要把 token 放到前端 localStorage、提示词、事件载荷、数据库普通文本或审计详细日志。远端连接失败时记录证据缺口；不能悄悄回退到旧 SSH 执行器。

## 2. 改哪些文件

| AI 平台位置 | 具体改造 |
| --- | --- |
| `app/main.py` | 将 `ssh_mcp_token` 加入 `SENSITIVE`；增加独立连接配置、地址校验和管理员连接测试。公开配置仅返回 token 是否已配置。不要覆盖 Zabbix 配置。 |
| 新增 `app/integrations/ssh_mcp.py` | 参考本仓库 `examples/ai_platform_adapter.py`，实现第二个 MCP 会话、固定工具映射、超时、结构化结果检查。 |
| `app/mcp_runtime.py` | 在 `AsyncExitStack` 增加 SSH 会话；保留 `diagnose_linux_host` 模型工具外形。在嵌套 `linux(args)` 内按资产后端选择本地/远端执行；`can_ssh` 加入远端配置及映射就绪条件。 |
| `app/diagnostics/playbooks.py` | 继续由固定剧本决定动作。CPU→cpu/processes，内存→memory/memory_processes/kernel，磁盘→disk/已授权目录，服务→service/sockets/logs 等。 |
| 资产模型及数据库迁移 | 增加后端选择、SSH 实例标识/Host ID 绑定（若使用多实例）和映射状态；旧资产默认 `local`。Zabbix Host ID 与 SSH Host ID 不是同一 ID。 |
| `app/platform_api.py` | 工具注册表、连接测试、平台健康状态区分 Zabbix MCP 与 SSH MCP。 |
| `app/diagnostic_worker.py` | 测试/诊断按照后端路由，不能继续默认调用本地执行器。 |
| `app/orchestrator/tasks.py` 及证据调用点 | 记录 `provider=ssh_mcp`、远端 `job_id`、实例、主机 ID/版本、耗时、状态；保留 cancellation/deadline/call/token 预算。 |
| `web/assets/app.js` | 连接管理增加独立 SSH MCP 卡片；资产展示后端、映射与测试状态，已迁移资产的凭据/公钥管理引导到 SSH MCP。 |

这是一次后端适配改造，不能通过只改一个 MCP URL 完成。

## 3. 每个任务如何选对主机

1. 从已核实的告警/任务绑定读取 **Zabbix Host ID**，不使用模型提交的 IP、名称或 SSH Host ID。
2. 调用 `ssh_resolve_host(zabbix_hostid)`。服务端要求唯一关联、已启用、已核验公钥、已绑定凭据且在客户端授权范围内。
3. 将返回的 `host_id` + `revision` 固定在此次任务上下文。
4. 每个诊断工具同时传 `host_id` 和 `expected_revision`。服务端在创建任务事务中检查，并在 SSH 执行前再次核验版本；修改主机地址、凭据、跳板、公钥或启停会使旧任务失效。
5. 映射重复、失效、权限不足、版本变化：停止后续 SSH 补查，在报告中说明证据不足，由管理员处理；不按 IP 猜测新目标，也不自动重新解析并转向新资产。

`ssh_list_hosts` 适合管理员探索和检查，不应替代生产告警的精确映射。

## 4. 适配器使用方式

示例已通过真正的 MCP SDK 初始化、主机解析、诊断与过期版本拒绝联调；服务端诊断输出使用隔离 fixture，并非真实生产指标。

```python
from examples.ai_platform_adapter import connect

# 从平台服务端的加密配置读取；这些值不能来自模型参数。
async with connect(ssh_mcp_url, ssh_mcp_token, timeout=90) as ssh:
    binding = await ssh.resolve(task_zabbix_hostid)
    evidence = await ssh.diagnose(binding, "memory_processes")
    # 保存 evidence 的 provider/job_id/host_revision/status/duration_ms。
    # partial、failed、cancelled 不能作为“已证实故障原因”。
```

支持 `structuredContent` 和单条 JSON TextContent，并同时检查 MCP `isError` 及业务 `status`。适配器关闭重定向和隐式代理，不自动重试；TLS 验证保持开启。HTTP 仅用于明确指定 `allow_http=True` 的隔离联调。

保留当前 `diagnose_linux_host` 的参数限制、证据缺口 reason、quick 模式禁用 SSH、事件与资产一致性检查。模型不需要直接看到全部远端工具（v0.6.0 共 51 个）；由平台将一次剧本请求展开为允许的动作，逐个计入工具预算。目录仍须来自当前资产的管理员授权路径，不能直接把模型提供路径透传给远端。

## 5. 超时、取消与证据

- 原执行器只预留约 35 秒；远端 SSH 经跳板可能需要更长连接时间，必须同步调整任务预留预算，不能只把客户端 timeout 拉长。
- 经典固定命令读取阶段限制 20 秒（组合诊断 60 秒；v0.6.0 扩展动作与 `ssh_collect` 各有上限，见 [MCP 接入](MCP.md)），同步调用还可能排队等待同主机名额最多 30 秒；TCP/握手/认证/跳板各有超时，这不等于整个调用固定 20 秒。
- 单项诊断工具同步返回结果。AI 平台超时/取消不会保证立即终止服务端已开始的 SSH；服务端仍受自身超时限制。Web 可按任务取消；不要给 AI 客户端发 Web 管理员 Cookie 来调用管理 REST API。
- 后台批量诊断可用 `ssh_submit_diagnostics` 提交，再用 `ssh_get_diagnostic_job` / `ssh_get_diagnostic_batch` 查询、`ssh_cancel_diagnostic_job` 取消（仅限本客户端提交的任务，见 [MCP 接入](MCP.md)）。没有跨实例 exactly-once。未收到响应时不要自动重试相同采集；先留下证据缺口，必要时人工查看 MCP 控制台历史。
- 返回的日志是外部数据，应在提示词中明确其不能改变工具授权和执行规则。继续执行平台现有截断、脱敏与模型 Token 预算。

## 6. 推荐切换顺序

1. 在 SSH MCP 登记测试组，批量导入资产、获取并独立核验主机公钥，绑定凭据。root 仍支持。
2. 为 AI 平台创建只覆盖该测试组和所需剧本动作的令牌。日志、内核等扩展动作按需授权。
3. 实现并测试第二会话：成功、401/撤销/过期、重复关联、版本变化、跳板故障、partial、超时、预算耗尽及服务重启。
4. 少量资产显式切到 `ssh_mcp`；同一任务只选一个后端。保留 Zabbix 历史证据与现有报告路径。
5. 测试组稳定后逐组迁移。移除旧平台对已迁移资产的私钥管理入口，保留历史报告和审计；不要在联调阶段直接删数据库或整个 Worker。
6. 全部资产切换且回退流程验证后，再删除不再使用的本地 SSH 执行/公钥扫描代码和对应 Worker。其他队列职责不能一起误删。
7. 停用 SSH MCP 的原始全局令牌；后续每个调用方用独立客户端令牌轮换。
