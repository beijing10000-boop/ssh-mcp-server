# SSH MCP Server · Linux 智能诊断 MCP 服务器

> 独立部署、中文优先、免 Agent 的 Linux SSH 诊断服务。默认 Web/MCP 端口 **9099**。

**当前版本：v0.1.0（联调候选版，尚未经实际生产主机验证）**

## 项目定位

本项目独立于 Zabbix MCP 和 AI Ops Platform 运行，拥有自己的主机资产、SSH 凭据、连接测试、密钥核验、诊断执行、审计记录和 Streamable HTTP MCP 服务。AI 客户端只需要连接 MCP 服务，不需要获得 SSH 私钥。

- **Web 管理**：`http://127.0.0.1:9099/`
- **MCP 地址**：`http://127.0.0.1:9099/mcp`
- **健康检查**：`GET /healthz`

## 安全设计

- 首次初始化 Token 用于绑定飞书应用和指定管理员 Open ID；完成后 Web 只能通过飞书 OAuth 登录，MCP 独立使用 Bearer Token。
- Web/API 使用飞书管理员会话、HttpOnly Cookie 与 CSRF 校验；MCP 使用独立 Bearer Token。
- SSH **只允许已登记的内网 IP**、已登记 SSH 凭据、经管理员确认的主机公钥。
- 严格 SSH 主机公钥校验，批量获取只能产生候选结果，不自动信任。
- 固定只读诊断动作，无执行任意 Shell 的 MCP 工具，不支持文件上传、下载或自动修复。
- SSH 私钥加密保存，审计日志记录任务与错误分类，不记录私钥。
- `root` 可以使用标准诊断模式，但 **root 本身并非只读账户**。固定命令不能保证操作系统层面绝对只读。
- 默认只绑定回环地址。公网使用须额外配置 HTTPS、访问控制、可信代理和来源 IP 限制；不要直接暴露 HTTP。
- 当前没有自动导入旧平台数据库/凭据。迁移时不复制旧平台的加密密钥或明文私钥文件；使用 Web 重新登记。

## 快速启动（Docker Compose）

```bash
git clone https://github.com/beijing10000-boop/ssh-mcp-server.git
cd ssh-mcp-server
docker compose up -d --build
docker compose ps
docker compose logs --tail=50 ssh-mcp
```

一次性初始化 Token、MCP 接入令牌分别查看：

```bash
docker compose exec ssh-mcp cat /app/data/bootstrap.token
docker compose exec ssh-mcp cat /app/data/mcp.token
```

不要将这两段令牌发到聊天窗口、工单、公开日志或 GitHub。

需开放给可信内网时，在项目目录创建 `.env`，并设置 `WEB_BIND_IP=内网绑定IP`；建议同时通过防火墙限制允许访问的源地址。

请阅读 [安装部署](docs/INSTALLATION.md)、[MCP 接入](docs/MCP.md)、[安全说明](docs/SECURITY.md)。

## 核心能力

| 能力 | 说明 |
| --- | --- |
| 中文 Web | 主机、主机组、凭据、跳板、主机密钥核验、执行与审计 |
| 主机公钥获取 | 支持批量探测 + SHA256 指纹审核确认，绝不自动信任 |
| SSH 诊断 | 连接、CPU、内存、磁盘、进程、I/O、网络、系统、服务与日志 |
| MCP 工具 | 列表与定向受控诊断，不允许模型传入任意目标 IP 或 Shell |
| 访问控制 | Web 飞书 OAuth + CSRF、独立 MCP Bearer、服务端主机白名单 |
| 部署 | 单容器 + SQLite，独立端口 9099，日志轮转 |

## 与现有 AI Ops Platform 关系

现阶段 **保持原有 AI Ops Platform 不变**，两个 SSH 诊断执行器不会自动共享资产或凭据。请先用测试机验证 MCP 工具再切换主平台调用。后续移除旧平台 SSH 执行模块时应采用渐进式迁移，避免影响告警处理。

## 免责声明

v0.1.0 是开发与联调版本；未声明通过真实 Rocky Linux、Zabbix 或 SSH 生产环境验收。请先在隔离测试环境验证身份认证、命令白名单、公钥变更与 SSH 授权。