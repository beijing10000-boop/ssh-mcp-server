# Rocky Linux 9/10 全新部署（中文）

> 独立服务，不需要 Zabbix、AI Ops Platform 或旧数据库。部署在新主机/测试网段，先联调再迁移生产。

## 前置条件

Rocky Linux 9/10、Docker Engine + Docker Compose plugin、能访问目标服务器 TCP/22 的网络路径。**目标 Linux 只需要 SSH 服务与基本系统命令**；模式 A 不需要 Python/Agent/MCP 安装在每一台目标主机上。

## 一、克隆与启动

```bash
mkdir -p /data
cd /data
git clone https://github.com/beijing10000-boop/ssh-mcp-server.git
cd ssh-mcp-server
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:9099/healthz
```

本机访问 `http://127.0.0.1:9099/`。

## 二、读取初始访问令牌

首次启动自动在**持久数据卷**中创建两个独立随机令牌和加密主密钥：

```bash
docker compose exec ssh-mcp cat /app/data/admin.token
docker compose exec ssh-mcp cat /app/data/mcp.token
```

第一个用于 Web 登录，第二个用于其他 MCP 客户端的 `Authorization: Bearer <token>`。**不要复制到公开聊天、环境变量、日志或仓库中**。

## 三、内网客户端访问

若需要从内网电脑打开管理界面，可在仓库目录创建 `.env`：

```dotenv
WEB_BIND_IP=你的服务器可信内网IP
```

然后运行 `docker compose up -d`。只绑定指定网卡并用防火墙/ACL 限制来源。HTTP 只允许隔离内网联调；生产应放到具备 HTTPS、认证和访问控制的反向代理后。

## 四、Web 配置顺序

1. 登录 Web，创建「SSH 凭据」，粘贴 SSH 私钥（仅加密存储，不回显）。
2. 创建主机组（可选）。
3. 「主机资产 → 新增主机」，填内网 IP、端口、账号（可以是 root 或普通账号）、凭据和可选 Zabbix Host ID。
4. 勾选主机，「批量获取选中主机公钥」，后台并行 SSH 握手。
5. 根据目标服务器可信控制台 `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256` 等命令核对相应算法的 SHA256 指纹。不要只凭扫描结果自动信任。
6. 在「主机公钥核验」人工输入核验到的完整指纹并确认。
7. 点击主机「测试」，检查 `AIOPS_SSH_OK`；然后在「只读诊断」尝试 CPU、内存、磁盘等固定剧本。

日志：

```bash
docker compose logs --tail=200 ssh-mcp
docker compose logs -f ssh-mcp
```

## 五、备份与升级

数据卷中 `ssh-mcp.sqlite3` + `master.key` + `admin.token` + `mcp.token` 必须成套备份；加密主密钥一旦丢失无法解密数据库中的 SSH 私钥。

升级前先暂停新的 SSH 任务并备份，`git pull --ff-only && docker compose up -d --build`。**不可执行 `docker compose down -v`**，否则会删除持久数据卷。

## 六、权限模式

模式 A：以登记账号进行固定命令的免 Agent 诊断，root 允许，但 root 不是 OS 级只读。

模式 B：管理员先通过可信途径部署 [受限网关脚本](../gateway/aiops-diagnostic-gateway)，按 [安全手册](SECURITY.md) 设置 OpenSSH 强制命令与来源限制；MCP 只发送固定协议 `aiops-v1` 请求。

## 七、部署边界

此版本没有对旧 AI Ops Platform 进行自动迁移或删除。请在测试目标通过诊断、核验、审计和 MCP 工具验证后，再安排旧执行器切换。新项目与现有 Zabbix MCP 服务完全独立。
