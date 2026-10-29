# v0.5.0 · CPU 与进程信号、授权目录工具名、稳定错误码

本版本只增强已有工具的返回内容，不新增诊断动作、MCP 权限或数据库结构。原客户端令牌、主机组、动作范围与资产无需改动。

## CPU（ssh_diagnose_cpu）

原命令本来就采集 `/proc/loadavg`、`/proc/stat` 和 `vmstat 1 2`，但只解析了 1 分钟负载。现在摘要里还会给出：
- 5 分钟、15 分钟负载，以及 5 分钟的每核负载；
- vmstat 最后一行（最近 1 秒的采样，不是开机以来的平均值）：运行队列、阻塞队列，以及 us / sy / id / wa / st；
- `procs_running` 和 `procs_blocked`。

每核负载的告警线从 2 调整为 1.5，与 Zabbix “Linux by Zabbix agent” 模板的默认值 `{$LOAD_AVG_PER_CPU.MAX.WARN}` 一致，避免 Zabbix 已经告警、工具却报 `info`。

每核负载达到 1.5、同时 CPU 空闲率不低于 50% 时，会给出 `load_cpu_divergence` 线索：负载更可能来自 D 状态（不可中断等待）任务或宿主机 CPU 争抢，而不是计算繁忙。线索里会提醒：VMware 等虚拟机通常不上报 steal，需要到虚拟化平台查看 CPU Ready。

## 进程（ssh_diagnose_processes）

A 模式主机除原有排行外，还会采集以下内容，执行时间约多 1 秒，全程只读，不写任何文件：
- 进程状态计数（`state_counts`），D 状态数量达到 1 时给出线索；
- 最多 10 个 D 状态进程及其 wchan（`uninterruptible`），用于判断在等待磁盘、网络存储还是内核锁；
- 最近 1 秒的 CPU 增量（`cpu_interval`，前 15 个）：通过两次读取 `/proc/*/stat` 的 utime + stime 计算，说明的是“当前”谁在用 CPU。原 `cpu_percent` 仍是进程生命周期平均值。

B 模式（强制命令网关）主机仍返回原格式，解析结果与之前一致；如需同样的信号，需另行更新目标机上的网关脚本，本版本未改动网关。

## 授权目录与错误码

- `ssh_list_tool_catalog` 的每一项新增 `tool` 字段，即该动作对应的 MCP 工具名（例如 `mount_health` → `ssh_diagnose_mounts`）。AI Ops Platform 可以据此只向模型展示当前令牌有权执行的工具，避免“目录里看得到、调用时被拒绝”。
- 诊断失败的结果新增稳定的 `error_code`：`forbidden`、`unavailable`、`mapping_unresolved`、`timeout`、`revision_changed`、`host_unverified`、`unsupported`、`invalid_argument`、`cancelled`、`failed`。原 `error` 中文说明保持不变。

## 升级

先按 v0.4 发布说明备份完整数据目录与密钥，然后在原部署目录执行：

```bash
cd /data/ssh-mcp-server
git fetch origin
git switch main
git pull --ff-only origin main
docker compose up -d --build --wait --wait-timeout 180
curl -fsS http://127.0.0.1:9099/healthz
```

`/healthz` 应返回 `0.5.0`。旧客户端不受影响：新增字段都是附加的，原有字段的含义不变（每核负载的告警线除外）。
