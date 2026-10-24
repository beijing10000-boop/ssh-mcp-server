# v0.2 升级、验证与已知边界

## 更新内容

- 新增综合快照、命令能力、RSS 进程、失败 systemd 服务、容器状态、内核告警，共 20 类诊断，MCP 共 22 个工具。
- 后台批量诊断、取消、重试、加密请求/结果与持久化任务历史；主机配置版本用于拒绝过期目标。
- 独立客户端令牌按主机组/动作/有效期授权，可单独撤销；原始全局令牌可停用。
- Web 深浅主题、资产分页/筛选/跨页选择、批量 JSON 导入、批量启停、分组维护、跳板编辑、审计分页。
- 修复脱敏、无效公钥校验、公钥扫描 TCP 连接超时、原子密钥文件创建、OAuth state 一次性消费、弹窗校验反馈与直接访问跳板页面凭据为空等问题。
- 提供 AI 平台适配器示例与逐文件改造方案。当前 AI 平台不会自动切换。

## 从 v0.1 升级

1. 停止提交新任务，等待已有任务完成。记录当前镜像/提交，以便回退。
2. 停止服务并将数据卷备份到仅管理员可读的位置。数据库、master.key、bootstrap.token、mcp.token 必须成套保留；包含新增的客户端授权和任务历史。

```bash
docker compose stop ssh-mcp
umask 077
backup_dir="./backup/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup_dir"
docker compose cp ssh-mcp:/app/data/. "$backup_dir/"
```

3. 检查备份成功后，获取已审核代码并重建。以下适用于更新已经合并到所用分支之后：

```bash
git pull --ff-only
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:9099/healthz
```

4. 启动自动增加 `hosts.revision`、客户端授权/任务表和索引，不删除原资产、私钥或公钥。旧版本已有的重复 Zabbix Host ID 不会被静默修改：管理员须修正，重复映射会拒绝诊断。
5. 登录确认资产/公钥/跳板、root 连接测试、历史和 MCP 工具。创建专用客户端令牌，完成调用方切换后停用原始全局令牌。
6. B 强制命令模式的目标机须由管理员审核并更新网关脚本后才能使用新增动作；本次更新没有自动向目标服务器写入文件。目录/IP 三类扩展诊断仍仅支持 A 模式。

不要执行 `docker compose down -v`。如果需要回退，应停服并恢复成套备份与原镜像；不可用旧 master.key 混合新数据库。重启时 queued/running 任务会被明确标记为中断失败，不会自动重放。

## 可复现验证

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
ruff check --select F401,F811,F821,F841 sshmcp tests examples
ruff format --check sshmcp tests examples
python -m pytest -q
node --check web/app.js
/bin/sh -n gateway/aiops-diagnostic-gateway
python -m playwright install --with-deps chromium
# Linux 截图环境需要中文字体，例如 fonts-noto-cjk。
python tests/browser_smoke.py
docker build -t ssh-mcp-server:ci .
python tests/container_smoke.py
```

测试覆盖范围：

- Python 单元/接口：输入与 CSRF 校验、公钥真实格式、1000 台导入/回滚、分页、范围授权、令牌撤销/到期、映射歧义、版本变更、任务取消/重试/重启和加密结果。
- 真实协议：本机 Paramiko 服务握手、root 认证、固定公钥、变更公钥拒绝（认证前）、扫描不认证/不自动信任、取消断开通道。目标响应为隔离 fixture，没有连接生产主机。
- 浏览器：1280/1440/1920 三种宽度、11 个页面；分页筛选、输入错误、root 资产登记、任务持久化/取消、令牌一次展示/撤销及主题。另含真实 MCP SDK 初始化、解析与版本约束调用。
- 容器：非 root UID、健康端点、未授权访问拒绝、文件权限、卷内配置及令牌身份在重启后保留。

GitHub Actions 执行 Python 3.11/3.12、桌面浏览器和容器三个类别。浏览器摘要在 [UI-TEST-RESULTS.json](UI-TEST-RESULTS.json)，截图来自测试资产，不代表生产观测。

## 尚未承诺的能力

没有多副本/分布式队列、完整租户 RBAC、MCP OAuth 2.1 授权服务器、自动修复/任意 Shell、自动结果留存清理或面向 MCP 的异步任务取消协议。飞书真实租户回调、实际 Rocky Linux/跳板/生产 ACL 需部署方联调。命令存在不代表账号有读取权限；容器检查仅状态，TCP 采样也不是完整网络流量监控。
