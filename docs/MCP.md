# MCP 工具及接入方法

## 接入地址

- 传输：**Streamable HTTP**（MCP 标准协议）
- 地址：`http://可信内网IP:9099/mcp`
- Header：`Authorization: Bearer <Web「系统配置 → MCP 接入」签发的客户端令牌>`
- Web 使用飞书 Cookie 会话，不能用于 MCP；初始化 Token 也不能用于 MCP。

在 Web「系统配置 → MCP 接入」创建客户端，选择允许的主机组（或明确授权全部主机）、诊断动作和 1–365 天有效期。原始令牌只显示一次，关闭弹窗后不能再次读取；数据库仅存哈希。撤销/到期从下一次请求起生效，不承诺终止已经执行中的 SSH。

兼容的 `/app/data/mcp.token` 拥有全部主机和动作权限，可在 MCP 接入页面停用。不同团队应使用不同客户端令牌。当前为内部服务 Bearer 认证，不提供完整 OAuth 2.1 动态客户端授权流程。

示例客户端配置（结构依据客户端支持情况调整）：

```json
{
  "mcpServers": {
    "linux-ssh-diagnostics": {
      "type": "streamable-http",
      "url": "http://可信内网IP:9099/mcp",
      "headers": {"Authorization": "Bearer 请通过安全配置渠道注入MCP令牌"}
    }
  }
}
```

## 工具目录

| MCP 工具 | 说明 |
| --- | --- |
| ssh_list_hosts | 只列出已登记、已启用、已审核公钥的主机 |
| ssh_resolve_target | 按已登记内网 IP 精确解析授权 Linux 主机，返回 SSH host_id、address、revision；不依赖 Zabbix |
| ssh_resolve_host | 按 Zabbix Host ID 精确定位唯一授权主机，返回主机 ID 与版本 |
| ssh_test_connection | 验证 SSH 身份、认证和固定命令 |
| ssh_diagnose_health | 负载、内存、Swap、文件系统、inode 与高 CPU 进程综合快照 |
| ssh_diagnose_capabilities | 登录 UID、诊断命令是否可用，不自动安装工具 |
| ssh_diagnose_cpu | CPU 负载/内核计数 |
| ssh_diagnose_memory | 内存与 Swap |
| ssh_diagnose_disk | 磁盘容量、inode 与挂载 |
| ssh_diagnose_processes | 进程概况 |
| ssh_diagnose_memory_processes | 按 RSS 排序的进程概况，不读取环境变量或完整命令行 |
| ssh_diagnose_io | I/O 数据 |
| ssh_diagnose_network | 网卡与路由 |
| ssh_diagnose_sockets | 监听与 TCP 汇总 |
| ssh_diagnose_system | 运行时长/内核 |
| ssh_diagnose_service | 指定合法 systemd 服务状态 |
| ssh_diagnose_failed_services | 最多 60 项失败 systemd 服务，不重启 |
| ssh_diagnose_containers | 限时读取最多 60 项 Docker/Podman 容器状态，不 inspect/exec |
| ssh_diagnose_kernel | 最近 1–120 分钟、最多 100 行内核告警 |
| ssh_diagnose_logs | 指定合法 systemd 服务最近有限时间范围日志 |
| ssh_diagnose_directory_usage | 白名单目录下一级空间排行，8 秒限时，支持逐层深入 |
| ssh_diagnose_peer_connections | 当前远端 IP TCP 连接数 Top 50 |
| ssh_diagnose_peer_traffic | 约 3 秒同一 TCP socket 的发送、接收字节增量 Top 30 |
| ssh_diagnose_pressure | CPU/内存/I/O PSI 压力 |
| ssh_diagnose_resource_limits | 文件句柄、PID 与当前 SSH shell 限制 |
| ssh_diagnose_mounts | 挂载类型与只读文件系统 |
| ssh_diagnose_block_devices | 块设备结构 |
| ssh_diagnose_time_sync | 时间与 NTP/chrony 状态 |
| ssh_diagnose_tcp_states | TCP 状态分布 |
| ssh_diagnose_service_inventory | 系统服务清单 |
| ssh_diagnose_timers | systemd timer 上次和下次运行 |
| ssh_diagnose_system_errors | 有限时间内的系统告警日志 |
| ssh_diagnose_oom | 有限内核日志中的 OOM 线索 |
| ssh_diagnose_container_stats | Docker/Podman 当前资源数据 |
| ssh_diagnose_security_status | 安全组件状态 |
| ssh_list_tool_catalog | 当前客户端授权的诊断目录与参数要求 |
| ssh_list_groups | 当前客户端获授权的主机组 |
| ssh_submit_diagnostics | 每批 1–100 台授权主机，后台执行固定只读诊断 |
| ssh_get_diagnostic_job | 查询自己提交且仍有权访问的任务 |
| ssh_cancel_diagnostic_job | 取消自己提交且仍有权访问的任务 |

共 42 个工具（32 类单项诊断、组合诊断、资产/目录查询及后台任务管理）。`ssh_list_hosts` 支持 query、group_id、offset、limit（最多 1000），返回当前授权范围内的所属主机组名称，只返回当前客户端可访问且已就绪的资产。所有执行操作**仅接受登记的数字 host_id**，单项诊断支持可选的 `expected_revision`：建议 AI 平台始终传入解析时取得的版本，拒绝过期映射。即使模型请求任意 IP 或 shell 命令，服务端也没有对应工具。

结果包含 `status=success|partial|failed|cancelled`；已创建的执行任务包含 `job_id`，可供管理员在 Web 查看。工具层面的 MCP `isError` 和结果里的 `status` 都需要检查。缺命令、读取权限不足、非零退出或输出截断不能解释为诊断成功。单项诊断同步返回；批量任务通过 ssh_submit_diagnostics 后台提交，再查询状态。客户端断连不保证立即取消远端任务。

## 接入 AI Ops Platform

当前整合平台使用内置的 `diagnose_linux_host` 工具和执行器，**不能仅更改 MCP URL 就自动将其切换至本服务**。

详细逐文件说明和可运行适配器见 [AI 平台改造方案](AI-PLATFORM-INTEGRATION.md)。需要在整合平台单独实现：
1. 将本 SSH MCP 作为第二个 MCP 会话加载，与 Zabbix MCP 分开认证；
2. 工具发现与白名单按 `ssh_*` 限制；
3. 使用本平台 Host ID 的精确映射，不要把 Zabbix Host ID 或 IP 直接当作 SSH Host ID；
4. 证据、工具超时、Token 预算、审计和断连错误独立记录；
5. 联调确认无误后禁用旧执行器，避免重复 SSH 任务。

切换前，本 MCP 可以独立使用 MCP Inspector 等受信客户端做测试。


新增诊断数据的覆盖条件请参阅 [目录与 IP 流量分析](INSIGHTS.md)。不要把一次 TCP 采样误写成全协议或历史 IP 流量统计。


v0.3 的 12 类新增诊断需要标准 SSH 模式；受限网关尚不支持。后台任务在执行前重新核对客户端授权。详情见 [v0.3 更新说明](RELEASE-v0.3.md)。


## 结构化结果与组合诊断

诊断工具、任务与批次结果查询支持 `detail=summary|full`，默认 summary：返回 `summary`、`findings` 与执行元数据，省略 stdout/stderr。`full` 才附带可用的脱敏原文；已有目录/连接排行工具保留原来的原文裁剪。历史仍加密保存完整的可用结果，Web 管理员可查看。findings 字段为 level（critical/warning/info）、metric、value、threshold、hint，组合诊断另有 source_action。规则是经验阈值，未触发不代表健康；缺失工具、截断、日志窗口和累计计数均有说明。

`ssh_triage(host_id, symptom, service?, minutes=30, expected_revision?, detail="summary")` 需要单独的 `triage` 授权，现有具名客户端不会自动获得。场景固定为 cpu_high、mem_high、disk_full、io_slow、service_down、network；service_down 必须给合法服务名。每个场景在同一已核验的 SSH 连接和通道中顺序执行预设动作，逐项保留退出码与完整性，最长 60 秒，输出上限 128 KiB；受限网关暂不支持。

`ssh_get_diagnostic_batch(batch_id, page=1, page_size=25, detail="summary")` 一次返回 counts、completed、skipped 和逐主机状态/findings，仅限本客户端提交、且所有目标仍获当前授权的批次。每页最多 100 项，旧版批次可按已有任务聚合。`ssh_resolve_hosts(zabbix_hostids)` 最多 100 个 Host ID，逐项返回精确映射或原因；不接受 IP/名称猜测映射。
