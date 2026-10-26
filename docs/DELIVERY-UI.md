# 第 4 批：运维 UI

文件：dashboard.py / api.py 提供接入漏斗、队列、24 小时成功率、失败原因、具名 MCP 活跃与到期提醒、去重的最近 findings；catalog.py 提供每项问题说明、参数和耗时。presentation.js / app.js / app.css / index.html 实现四组 SVG 导航、面包屑、场景模板、严重线索置顶、阈值条、原文折叠/复制/下载、紧凑表格、固定表头与批量栏，以及手机历史卡片和任务详情。main.py 提供本地静态脚本，版本更新为 0.4.0。

验证：134 pytest、67 浏览器检查通过，无 JavaScript 异常或 HTTP 5xx；ruff、编译、JS 语法和 diff 检查通过。新增 test_dashboard.py 验证漏斗口径、成功率分母、findings、客户端提醒与本地资源；browser_smoke.py 增加场景模板、漏斗跳转、SVG 导航、原文折叠、HTTP 复制回退、下载、390/768px 历史与详情、移动导航及紧凑模式。已复核截图，保存在 docs/screenshots。

数据库：本批不新增列或表；统计从已有记录聚合，结果仍加密存储。保持 CSP self、无 CDN、单进程 SQLite。成功率表示完整采集成功率，不表示主机健康率。

兼容性：管理接口保留已有 overview 字段并扩展新字段；旧导航与令牌继续兼容。完整发布、保留策略、MCP 默认摘要和批量部分接收的迁移说明见 RELEASE-v0.4.md。

未验证：生产 SSH/Zabbix、千台负载、真实飞书移动端；手机验证使用 Chromium 仿真。容器运行由 GitHub CI 验证。本机未部署生产服务。可选第 5 批未实施，独立监控项和 MCP item 权限尚未确认。
