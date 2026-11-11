# v0.10.3 · 服务深度诊断在旧版 systemd 上不再误报“部分完成”

> 发布于 2026-11-11，基线为 v0.10.2（`41f18d7`）。

不新增 MCP 工具，工具参数与返回结构不变，无数据库结构变化。

## 变更

- **`ssh_diagnose_service_detail` 的单元属性读取**：较老的 systemd（EL7 一类、cgroup v1 主机）对 `systemctl show -p …` 里不认识的属性名会照常输出其余属性，但退出码为 1。此前脚本只要退出码非 0 就记 `SHOW_FAILED` 并以 1 退出，结果总是 `partial`——即使 `LoadState`、`ActiveState`、`SubState` 都已取到。现在只有输出里没有 `LoadState=` 时才算读取失败（`SHOW_FAILED`，结果 `partial`，单元状态未知）；有属性而退出码非 0 时只记一行 `SHOW_RC <退出码>`，不影响结果状态。
- 影响：AI 运维平台对 agent 不可用、服务未运行类告警调用该工具时，这些主机上的分析不再因此被标为“部分完成”。

## 升级

1. 备份数据卷中的 `ssh-mcp.sqlite3`、`master.key`、`admin.token`、`mcp.token`。
2. 拉取新代码后 `docker compose up -d --build --wait`，`/healthz` 返回 0.10.3。

客户端授权与令牌不变，不需要重新授权。

## 回滚

检出 v0.10.2（`41f18d7`）后重建；无数据库变化。
