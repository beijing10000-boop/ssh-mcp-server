# v0.4 · 诊断可靠性、AI 证据与运维控制台

本次按修复、MCP 能力、交互、UI 拆分；各批文件和验证清单见 DELIVERY-P0.md、DELIVERY-MCP.md、DELIVERY-INTERACTIONS.md、DELIVERY-UI.md。

## 行为变化

- MCP 工具可等待并在线程执行，保留 ContextVar 授权身份。SSH 总计 4 名额，后台最多 3，给同步调用预留 1 个；同主机串行等待，交互 2 秒、后台 180 秒，等待后重查权限和 revision。
- 批量诊断默认允许部分接收，返回 accepted/skipped（逐台原因）；保留 total/job_ids。依赖旧原子行为的调用方传 strict=true。
- 42 个 MCP 工具：32 类单项、独立 triage 授权的 6 个固定场景，以及批次查询/批量 Host ID 解析等。具名客户端不会自动获得 triage 动作。
- 诊断与结果查询默认 detail=summary，提供结构化 summary/findings。依赖 output/stderr 的旧调用方传 detail=full；已有排行工具保持原来的原文隐私裁剪。
- 指纹先逐行预检，再由管理员确认独立可信来源并保存匹配项；不匹配记审计。默认严格公钥 API 不变，matched_only=true 才跳过不匹配项，提交时再次核验目标签名；SSH 握手绝不建立信任。
- Web 增加显式目标清单、准备详情/引导、批次进度和失败项重试、筛选 URL、全局任务指示器。总览提供真实接入漏斗、队列、24 小时成功率和 MCP 活跃/到期提醒；结果页严重线索置顶、阈值条、原文折叠/复制/下载。导航四组、本地 SVG、紧凑表格、固定表头与操作栏、390/768px 布局。

## 自动迁移和保留策略

保持单进程 + SQLite。init_db 自动创建 diagnostic_batches 表和查询索引，旧表不删改；旧批次从 diagnostic_jobs 兼容聚合，原有列的兼容迁移仍沿用 ALTER TABLE。新增摘要在原有加密结果 JSON 内，凭据、主机、公钥、令牌无需重新录入。

SQLite 自动开启 WAL；Fernet 按数据目录缓存。系统配置 → 数据保留，默认审计 180 天、诊断/扫描 30 天、Zabbix 预览 7 天，每小时清理已结束历史，运行中的工作、资产和信任记录不删除。有删除时每日最多一次 VACUUM。修改保留天数会影响下一次清理。

## 升级

合并依赖 PR 后，在已有项目目录升级；升级前停止服务并备份整个数据目录（数据库、可能的 WAL/SHM、master.key、令牌一起保留），或使用 SQLite backup API。运行中只复制 .sqlite3 主文件可能遗漏 WAL 内的数据。

```bash
cd /data/ssh-mcp-server
git switch main
git pull --ff-only origin main
docker compose up -d --build
docker compose ps
```

不要执行 docker compose down -v。检查 /healthz 返回 0.4.0；浏览器 Ctrl+F5。先在小组验证凭据、公钥、连接测试和 MCP 授权；现有具名客户端如需组合诊断，重新签发包含 triage 的范围。

## 验证范围与可选扩展

真实生产 SSH、Zabbix、千台压力和真实飞书移动端仍需环境联调。本地测试使用真实回环 SSH 协议、真实 MCP SDK 和隔离 Zabbix/浏览器夹具；截图中的资产与告警均为模拟，不是生产观测。

第 5 批为可选扩展，本次未启用 Zabbix 双通道指纹自动比对、跳板扫描、定时巡检/飞书通知、客户端续期/轮换、归档和 CSV 导出。双通道核验需要先确认 Zabbix 独立采集监控项及 MCP item 查询权限，不能从 SSH 候选指纹反推可信结果。
