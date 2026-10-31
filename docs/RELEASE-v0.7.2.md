# v0.7.2 · CentOS/RHEL 7 等旧版 procps 上的 ps 列修复

无数据库变化，MCP 工具名、参数与返回字段不变。

## 修复

- **`ssh_diagnose_java` 在 CentOS/RHEL 7 上 RSS、CPU、内存占比与运行时长全部为空**：procps-ng 3.3.11 及更早版本（CentOS/RHEL 7、Ubuntu 16.04 等）在 ps 命令行只含 POSIX 选项时按 Unix98 规则解析 `-o`：`ps -o user=,etimes=,rss=,… -p PID` 中第一个 `=` 之后的整串都成了 `user` 列的表头，只输出这一列。于是每个 Java 进程的 `rss_KiB`、`cpu_percent`、`mem_percent`、`elapsed_seconds` 都是 null，依赖它们的“RSS 远超堆上限”“最近启动”两类提示也不会出现（线程数、句柄、cwd、堆与 GC 参数不受影响）。这与 `etimes` 是否可用无关：procps-ng 3.3.10 支持 `etimes`。现在每个 `-o` 只写一列（`ps -o user= -o etimes= …`），procps 3.2.8 到 4.x 的解析结果一致。
- 同一写法还影响以下采集，已一并改写：
  - `ssh_diagnose_service_detail` 的进程表与 `ssh_diagnose_service_map` 的属主、运行时长、RSS 为空；
  - `ssh_diagnose_nginx` 在这些系统上看不到 Nginx 进程：进程列表为空、worker 数为 0，systemd 显示 active 时提示“进程不可见”，不由 systemd 管理的 Nginx 则被误报为严重级别的“无 nginx master 进程”；
  - `ssh_diagnose_processes`（以及包含它的 `ssh_collect`、组合诊断）的 D 状态进程列表始终为空。
- CentOS/RHEL 8 及以上、Ubuntu 18.04 及以上（procps-ng ≥ 3.3.12）不受影响。

## 测试

- 新增静态检查：遍历全部固定脚本与受限网关脚本，带 `=` 表头的 `-o` 只能有一列。
- CI 新增 `old-procps` 任务：在 CentOS 7（procps-ng 3.3.10）容器中先验证旧写法确实只返回一列，再执行所有脚本里的每一条 ps 调用并核对列数，最后对一个名为 java 的进程运行完整的 Java 盘点脚本，确认上述四个字段有值。

## 升级

先备份数据目录（至少 `ssh-mcp.sqlite3` 与密钥文件），然后在原部署目录执行：

```bash
cd /data/ssh-mcp-server
git fetch origin
git switch main
git pull --ff-only origin main
docker compose up -d --build --wait --wait-timeout 180
curl -fsS http://127.0.0.1:9099/healthz
```

`/healthz` 应返回 `0.7.2`（`.env` 的 `WEB_BIND_IP` 设成服务器地址时，curl 改用该地址）。回滚：切回 v0.7.1（`55d078e`）后按同样命令重建。
