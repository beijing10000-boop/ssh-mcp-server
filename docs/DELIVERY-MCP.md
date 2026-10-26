# 第 2 批：MCP / AI 能力

- 新增 observations.py：32 类动作均有有界解析入口，输出 summary 和 findings；CPU/核数、可用内存、Swap、磁盘/inode、PSI、NTP、失败服务、OOM 等含明确阈值与核查提示。进程、块设备、接口、容器等返回命名结构；未适配的工具版本只返回有界表格和口径说明，不臆造速率或健康判断。
- 新增 triage.py；diagnostics.py 支持 6 个固定组合，同一严格校验的 SSH 连接和通道顺序运行，逐动作退出码/完整性，独立 triage 动作授权，最大 60 秒、128 KiB。已有 32 类单项工具保持名称。
- mcp_tools.py 默认 detail=summary，显式 full 才返回可用的脱敏原文；任务和分页批次结果也支持。新增 ssh_triage、ssh_get_diagnostic_batch、ssh_resolve_hosts，ssh_list_hosts 可按组筛选并返回获准的组名；总工具数 42。
- jobs.py/store.py 新增 diagnostic_batches，保存加密的跳过原因，提供分页聚合、计数、所有者隔离和当前范围检查；维护任务同步清理过期批次。Web 补组合场景参数，避免新动作在表单不可用。

## 验证与迁移

125 pytest、57 浏览器检查通过；ruff、Python 编译、Node 和 diff 检查通过。新增 test_observations.py 覆盖所有动作的未知/不完整输出、阈值、命名字段、detail schema/原文裁剪、组合固定命令/注入拒绝/独立授权、批次所有者/分页/组名/批量解析；test_ssh_protocol.py 用真实本地 SSH 协议验证组合仅认证一次与摘要裁剪。原文断言的旧测试显式传 full。

迁移：init_db 使用 CREATE TABLE IF NOT EXISTS 和索引创建补充 diagnostic_batches，不改现有列；旧批次由 diagnostic_jobs 聚合兼容。历史 JSON 扩展字段，无需解密重写旧结果。保留旧主机版本、执行前二次授权、公钥严格校验与加密格式。

兼容性：MCP 默认省略 output/stderr，旧消费者如依赖原文需传 detail=full；现有具名令牌不会新增 triage 权限。CLI/AI adapter 仍可按原工具名调用，结果保留状态与 job_id。不曾在真实生产主机、所有发行版/命令版本、真实 Zabbix 与千台负载上验证；浏览器为隔离数据，容器由 CI 验证。
