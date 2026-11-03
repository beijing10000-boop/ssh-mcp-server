# v0.10.1 · 审计修复：Nginx master 信任（P0）、RSA 主机公钥、TCP 状态与清单截断

> 发布于 2026-11-03，基线为 v0.10.0（`71f9f3a`）。

本版修复 2026-11 第三轮代码审计中 SSH MCP 的 P0 与 P1 问题（括号内为审计编号）。不新增 MCP 工具（仍为 51 个），工具参数不变，无数据库结构变化；MCP 结果只增加字段。

## 修复

- **只采用 root 或诊断账号运行的 Nginx master（SE-01，P0，安全）**：此前取进程列表中第一条 `nginx: master process …`，而任何本地账号都能这样命名进程。诊断账号为 root 时，伪造的 `-c` 配置会让诊断执行 `nginx -T -c <他人的配置>`（`load_module` 以 root 加载任意 .so），找不到 nginx 时还会执行伪造的二进制。现在用 `ps -e -o pid= -o uid= -o args=` 只接受 uid 为 0 或等于诊断账号的 master；其他账号的同名进程不再决定二进制与 `-c`/`-p`，`ssh_diagnose_nginx` 报 warning 级 `nginx_master_untrusted`，`summary.master_untrusted=true`。
- **RSA 主机公钥在 OpenSSH 8.8+ 上误报“不一致”（SC-01）**：固定的主机公钥为 RSA、目标同时有 Ed25519/ECDSA 主机密钥且不再提供 SHA-1 `ssh-rsa` 签名（OpenSSH 8.8+、RHEL/Rocky 9 默认加密策略）时，握手拿到另一把密钥，被报为 `host_unverified`。现在握手只协商固定公钥所属的算法（RSA：rsa-sha2-512、rsa-sha2-256、ssh-rsa）。
- **tcp_states 包含 FIN-WAIT-1 / FIN-WAIT-2（SC-02）**：此前正则不接受数字，这两种状态被丢掉。
- **service_inventory 说明截断（SC-03）**：先列全部非 inactive 的单元（失败单元不会被截掉），再列最多 50 个 inactive 的；新增 `summary.units_total` 与 `units_truncated`，被截短时 `coverage` 写明 `active_counts` 只统计列出的单元。此前只取前 100 行且不标注。
- **访问日志统计未完成时为“未知”（SE-04）**：`ssh_diagnose_nginx_access` 在写出统计段之前结束（超时或输出截断）时，`summary.totals_missing=true`、`totals.requests` 为 null，报 warning 级 `access_totals_missing`；不再报 `requests_total=0` 与“可能确实没有流量”的 `no_requests`。

## 升级

1. 备份数据卷中的 `ssh-mcp.sqlite3`、`master.key`、`admin.token`、`mcp.token`。
2. 拉取新代码后 `docker compose up -d --build --wait`，`/healthz` 返回 0.10.1。
3. 核对：对一台 Rocky 9 与一台 CentOS 7 主机执行连接测试、`ssh_diagnose_nginx`、`ssh_diagnose_tcp_states`、`ssh_diagnose_service_inventory`；此前报“主机公钥不一致”的 RSA 主机重新测试连接。

客户端授权与令牌不变，不需要重新授权。

## 回滚

检出 v0.10.0（`71f9f3a`）后重建；无数据库变化，备份只在需要时恢复。
