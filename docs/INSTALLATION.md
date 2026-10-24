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
docker compose exec ssh-mcp cat /app/data/bootstrap.token
docker compose exec ssh-mcp cat /app/data/mcp.token
```

第一个仅用于首次在 /setup 填写飞书 App ID、App Secret、Web 地址和管理员 Open ID，之后 Web 使用飞书登录；第二个用于其他 MCP 客户端的 `Authorization: Bearer <token>`。**不要复制到公开聊天、环境变量、日志或仓库中**。

## 三、内网客户端访问

若需要从内网电脑打开管理界面，可在仓库目录创建 `.env`：

```dotenv
WEB_BIND_IP=你的服务器可信内网IP
```

然后运行 `docker compose up -d`。只绑定指定网卡并用防火墙/ACL 限制来源。HTTP 只允许隔离内网联调；生产应放到具备 HTTPS、认证和访问控制的反向代理后。

## 四、Web 配置顺序

1. 首次访问 /setup，填写一次性 Token、飞书应用 App ID、App Secret、管理员 Open ID、Web 外部地址，并在飞书开放平台登记对应 /api/v1/auth/callback 回调地址；保存后使用飞书登录。
2. 登录 Web，创建「SSH 凭据」，粘贴 SSH 私钥（仅加密存储，不回显）。
3. 创建主机组（可选；建议用组管理 MCP 授权）。
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

v0.1 → v0.2 的完整步骤及运行边界见 [升级与验证](RELEASE-v0.2.md)。

数据卷中 `ssh-mcp.sqlite3` + `master.key` + `bootstrap.token` + `mcp.token` 必须成套备份；加密主密钥一旦丢失无法解密数据库中的 SSH 私钥。

升级前先暂停新的 SSH 任务并备份，`git pull --ff-only && docker compose up -d --build`。**不可执行 `docker compose down -v`**，否则会删除持久数据卷。

## 六、权限模式

模式 A：以登记账号进行固定命令的免 Agent 诊断，root 允许，但 root 不是 OS 级只读。

模式 B：管理员先通过可信途径部署 [受限网关脚本](../gateway/aiops-diagnostic-gateway)，按 [安全手册](SECURITY.md) 设置 OpenSSH 强制命令与来源限制；MCP 只发送固定协议 `aiops-v1` 请求。

## 七、部署边界

此版本没有对旧 AI Ops Platform 进行自动迁移或删除。请在测试目标通过诊断、核验、审计和 MCP 工具验证后，再安排旧执行器切换。新项目与现有 Zabbix MCP 服务完全独立。

## 八、批量主机公钥：实际可用的推荐流程

新版本 Web「主机公钥核验」支持一次扫描未核验主机、4 台并发、持久化进度、仅重试失败、按算法显示新旧指纹，以及批量导入可信指纹后一并确认。主机 IP/端口/跳板变更会自动清除旧身份绑定；过期扫描结果不可确认。

**不需要逐台登录服务器复制主机公钥。** 如果你已经使用 Ansible，通过事先独立核实的 SSH 主机身份访问 Linux，可以在 Ansible 控制机运行：

```bash
cd /data/ssh-mcp-server
ANSIBLE_HOST_KEY_CHECKING=True ansible-playbook \
  -i /etc/ansible/hosts scripts/trusted-host-fingerprints.yml \
  --limit linux --forks 10
```

请将上面的 `/etc/ansible/hosts` 和 `--limit linux` 替换成你实际的 Inventory 和主机组。如果 SSH 未设置经过可信核验的 `known_hosts`，该来源**不能**被视为独立可信来源；不要为求通过而设置 `host_key_checking=False`。

该 Playbook 使用 `raw`，**目标端无需 Python/Agent**；输出位于执行目录的 `trusted-host-fingerprints.txt`，格式例如：

```text
172.20.200.93 ssh-ed25519 SHA256:示例指纹
172.20.200.93 ssh-rsa SHA256:示例指纹
172.20.200.94 ssh-ed25519 SHA256:示例指纹
```

接下来，在新 SSH MCP Web「主机公钥核验」：

1. 点击「扫描所有未核验主机」，读取候选主机公钥和指纹；
2. 将独立可信来源生成的 `trusted-host-fingerprints.txt` **文本内容**粘贴到「批量导入可信指纹」；
3. 平台按主机 IP 与主机密钥算法匹配，仅确认指纹完全相同的候选，其他算法或其他主机的行会跳过；
4. 任一主机指纹不一致，整批取消并保持原公钥不变；
5. 通过后到「主机资产」点击「测试」，再进行诊断。

只扫描网络握手、公钥未经独立验证时不允许直接视为可信。已经正确绑定且公钥相同的主机标为「与已有可信公钥一致」，不会重复要求确认。

**不要把可信资产清单上传到公共 GitHub 仓库。**


## 九、目录空间及 IP 连接排行

Web「只读诊断」新增「目录空间排行」「远端 IP 连接数排行」「远端 IP 流量采样」，并以中文表格展示 Top 排名与限制说明。无需在每台目标 Linux 安装 Agent；其中 IP 排名需要目标主机具备 `ss`，目录扫描需要 `du` 与 `timeout`。目录空间排行支持 `/root` 及其子目录（需要目标 SSH 账号具备读取权限），仍限制为单层、限时的只读空间统计。

说明与限制参见 [目录与 IP 流量分析](INSIGHTS.md)。三项新功能暂仅支持 A 标准免 Agent 模式，B 强制命令网关会明确提示尚未支持。

## 十、v0.2 任务与客户端授权

「主机资产」可分页搜索、按主机组筛选、跨页选择，并通过 JSON 一次原子导入最多 1000 台。选中最多 100 台可在「诊断工作台」提交相同动作；任务后台执行，在「诊断历史」查看、取消、重试和刷新恢复详情。

在「MCP 接入」为每个 AI 调用方创建独立令牌，指定主机组、诊断动作及有效期。只在创建时复制一次令牌到调用方的加密配置。接通后再停用旧的全局令牌。

本服务只支持单进程部署，不要设置多个 Uvicorn workers。当前任务与审计没有自动清理策略，应监控持久卷容量，并按团队留存策略定期备份归档；不要直接删除运行中的任务数据。
