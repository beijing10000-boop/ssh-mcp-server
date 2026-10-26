# 第 1 批：可靠性修复

- 文件：`mcp_tools.py` 的全部注册工具使用可等待包装和 `asyncio.to_thread`；`diagnostics.py` 用条件变量管理 4 个 SSH 名额（后台最多 3），同主机串行、交互等待 2 秒、后台等待 180 秒，等待后再次校验提交者权限与主机 revision。等待可取消。
- `jobs.py` / Web / MCP 返回 `accepted`、`skipped`（逐台原因）；`total`、`job_ids` 保留。默认允许部分接收；传 `strict=true` 恢复事务内全有或全无。无可接收目标时返回空清单，不创建远程操作。
- `app.js` 的后台轮询协调现有 DOM，仅变更有差异节点，保留输入、焦点、展开状态与滚动；页面切换才显示加载状态。
- `operations.py` 防火墙状态逐行标明服务名。`api.py` / `console_api.py` 批量取得组成员，去除逐主机数据库连接。
- `store.py` 开启 WAL，按数据目录缓存 Fernet（初始化时失效）；`maintenance.py` 和系统配置新增保留天数，每小时删除过期的已结束诊断、审计、扫描与资产预览，级联清理预览项；有删除时每天最多一次 VACUUM，锁繁忙时延后。

## 验证与兼容性

新增 `tests/test_reliability.py`：真实 MCP 请求执行长诊断期间健康端点响应与 ContextVar 传递；预留名额、同主机串行；部分接收/严格回滚；保留策略/活动任务/级联/WAL；清单无 N+1；Fernet 不重复读文件。浏览器补轮询保留焦点及保留策略表单保存。

本地结果：80 项 pytest、57 项浏览器检查通过；ruff 指定规则与格式、Python 编译、Node 语法、git diff --check 通过。

数据库无需新增列；继续由 `init_db` 兼容旧库，WAL 自动启用，策略保存于现有 settings。备份运行中数据库时应使用 SQLite backup API，或停服务后一起复制整个数据目录（含 WAL/SHM 与 master.key）。默认保留：审计 180 天、诊断与扫描 30 天、Zabbix 预览 7 天。

API 行为变化：批量默认部分接收，依赖旧式整体拒绝的客户端应传 strict=true；原有返回字段保留。工具名、令牌、公钥信任流程与加密格式不变。未验证真实生产 SSH/Zabbix、千台实测与本机容器运行；SSH 协议测试使用本地真实 SSH 服务，浏览器使用隔离数据。
