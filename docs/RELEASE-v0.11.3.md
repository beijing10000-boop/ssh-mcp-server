# v0.11.3 · 名字里带 dubbo 的别的包不再被当成 Dubbo 的版本

> 基线为 v0.11.2（`5b3f253`）。

不新增 MCP 工具，工具参数与返回字段不变，无数据库结构变化。修的是 `ssh_diagnose_java_apps`（动作 `java_apps`）里 `dubbo_version` 的取值。

## 修复

- **`dubbo_version` 只认 Dubbo 自己的发布号**。v0.11.2 只要求文件名是 `dubbo-` 后面以数字开头，于是“给某个 Dubbo 版本用的别的包”也被读成了 Dubbo 的版本：
  - `dubbo-2.7.x-plugin-1.0.0.jar` 被读成 Dubbo `2.7.x-plugin-1.0.0`（这是一个插件，`1.0.0` 是插件自己的版本）；
  - 探针目录里的 `dubbo-2.7.x-conflict-patch-8.9.0.jar`、`dubbo-3.x-conflict-patch-8.9.0.jar` 被 JVM 打开着，应用就被说成带了 Dubbo `2.7.x-conflict-patch-8.9.0`，哪怕它根本没有用 Dubbo；
  - 这类名字排在前面时，应用真正的 `dubbo-2.7.20.jar` 落到了 `dubbo_versions` 的第二位，`dubbo_version` 给出的是插件的名字。
- 现在的规则：`dubbo-`（或核心模块 `dubbo-common-` 等）后面是**两段以上用点分开的数字**（`2.7.23`、`2.7.4.1`），可以再带一个以字母开头的后缀（`-SNAPSHOT`、`.RELEASE`、`-beta.1`）。下面两种是别的包，它们的名字不说明任何事（既不算有 Dubbo，也不算没有）：
  - 数字的位置上是字母占位：`2.7.x`、`3.x`；
  - 后缀里还有另一个版本号：`dubbo-2.7-plugin-1.0.0.jar`。
- 目标机上的脚本（awk）与服务端的解析用同一条规则；脚本不再输出这类文件名，它们也不占每个进程最多 8 个名字的名额。

## 对已有结果的影响

- 之前显示为 `2.7.x-plugin-…`、`2.7.x-conflict-patch-…`、`3.x-conflict-patch-…` 的应用，升级后的下一次采集会给出它真正的 Dubbo 版本；应用里没有 Dubbo 本身的，变成 `absent`（应用 JAR 的目录区完整读过）或 `unknown`。
- 同一个应用里并存的只是 Dubbo 和这类插件时，不再有 `dubbo_versions` 与 `dubbo_versions_mixed` 提示。
- 只有一段数字的名字（`dubbo-2.jar`）、数字后直接跟数字后缀的名字（`dubbo-2.7.23-1.jar`）不再算版本。
- 已经保存的任务结果不会改写；调用方保存过的清单（例如日志平台的应用看板）要重新采集一次才会更新。

## 验证

- 新增用例：33 个文件名逐个核对服务端的判断；同一批名字经脚本里的两个 awk 程序，在测试机上找得到的每一种 awk（`awk`、`gawk`、`mawk`、`busybox awk`）下结果与服务端一致；CentOS 7 镜像里的 gawk 4.0.2 另跑一遍；真实进程持有的 JAR 里“插件排在 Dubbo 前面”与“只有插件”两种情形。
- 脚本仍然只读，输出不含其他依赖的名字。

## 升级

1. 备份数据卷中的 `ssh-mcp.sqlite3`、`master.key`、`admin.token`、`mcp.token`。
2. 拉取新代码后 `docker compose up -d --build --wait`，`/healthz` 返回 0.11.3。
3. 保存了清单的调用方重新采集一次。

客户端的授权不变，控制台脚本没有改动。

## 回滚

检出 v0.11.2（`5b3f253`）后重建；无数据库变化。回滚后上面这类文件名又会被读成版本。
