# MCP 工具及接入方法

## 接入地址

- 传输：**Streamable HTTP**（MCP 标准协议）
- 地址：`http://可信内网IP:9099/mcp`
- Header：`Authorization: Bearer <从 /app/data/mcp.token 获取的独立 MCP 令牌>`
- Web 登录使用的 admin.token **不能用于** MCP。

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
| ssh_test_connection | 验证 SSH 身份、认证和固定命令 |
| ssh_diagnose_cpu | CPU 负载/内核计数 |
| ssh_diagnose_memory | 内存与 Swap |
| ssh_diagnose_disk | 磁盘容量、inode 与挂载 |
| ssh_diagnose_processes | 进程概况 |
| ssh_diagnose_io | I/O 数据 |
| ssh_diagnose_network | 网卡与路由 |
| ssh_diagnose_sockets | 监听与 TCP 汇总 |
| ssh_diagnose_system | 运行时长/内核 |
| ssh_diagnose_service | 指定合法 systemd 服务状态 |
| ssh_diagnose_logs | 指定合法 systemd 服务最近有限时间范围日志 |
| ssh_diagnose_directory_usage | 白名单目录下一级空间排行，8 秒限时，支持逐层深入 |
| ssh_diagnose_peer_connections | 当前远端 IP TCP 连接数 Top 50 |
| ssh_diagnose_peer_traffic | 约 3 秒同一 TCP socket 的发送、接收字节增量 Top 30 |

所有主机操作**仅接受登记的数字 host_id**。即使模型请求任意 IP 或 shell 命令，服务端也没有对应工具，SSH 执行器更会拒绝无效动作。

## 接入 AI Ops Platform

当前整合平台使用内置的 `diagnose_linux_host` 工具和执行器，**不能仅更改 MCP URL 就自动将其切换至本服务**。

需要在整合平台单独实现：
1. 将本 SSH MCP 作为第二个 MCP 会话加载，与 Zabbix MCP 分开认证；
2. 工具发现与白名单按 `ssh_*` 限制；
3. 使用本平台 Host ID 的精确映射，不要把 Zabbix Host ID 或 IP 直接当作 SSH Host ID；
4. 证据、工具超时、Token 预算、审计和断连错误独立记录；
5. 联调确认无误后禁用旧执行器，避免重复 SSH 任务。

切换前，本 MCP 可以独立使用 MCP Inspector 等受信客户端做测试。


新增诊断数据的覆盖条件请参阅 [目录与 IP 流量分析](INSIGHTS.md)。不要把一次 TCP 采样误写成全协议或历史 IP 流量统计。
