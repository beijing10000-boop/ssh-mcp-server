"use strict";
const iconPaths = {
  overview:
    '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  hosts:
    '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M12 6.5h5M12 17.5h5"/>',
  zabbix: '<path d="M12 3v12m-4-4 4 4 4-4M4 16v5h16v-5"/>',
  groups:
    '<rect x="8" y="3" width="8" height="6" rx="1"/><rect x="2" y="16" width="8" height="5" rx="1"/><rect x="14" y="16" width="8" height="5" rx="1"/><path d="M12 9v4M6 16v-3h12v3"/>',
  credentials:
    '<circle cx="8" cy="8" r="5"/><path d="m12 12 9 9m-3-3 3-3m-6 0 3-3"/>',
  proxies: '<path d="M3 7h18m-4-4 4 4-4 4M21 17H3m4-4-4 4 4 4"/>',
  keys: '<path d="m12 3 8 4v5c0 5-8 9-8 9s-8-4-8-9V7l8-4Z"/><path d="m8 12 3 3 5-6"/>',
  diagnostics: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  history: '<path d="M3 10a9 9 0 1 1 1 8M3 3v7h7m2-3v6l4 2"/>',
  audit: '<path d="M8 3H5v18h14V3h-3M9 2h6v4H9zM8 11h8M8 15h8"/>',
  settings:
    '<path d="M4 6h16M4 12h16M4 18h16"/><circle cx="8" cy="6" r="2" fill="currentColor"/><circle cx="16" cy="12" r="2" fill="currentColor"/><circle cx="10" cy="18" r="2" fill="currentColor"/>',
  terminal: '<path d="m5 7 5 5-5 5m8 0h6"/>',
  moon: '<path d="M20 14A8 8 0 0 1 10 4a8 8 0 1 0 10 10Z"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
};
function icon(name) {
  return (
    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    (iconPaths[name] || iconPaths.diagnostics) +
    "</svg>"
  );
}
function initPresentation() {
  for (const el of document.querySelectorAll("[data-icon]"))
    el.innerHTML = icon(el.dataset.icon);
  document.documentElement.dataset.density =
    localStorage.getItem("ssh-density") || "comfortable";
  updateDensity();
}
function updateDensity() {
  const button = $("#density-toggle");
  if (button)
    button.setAttribute(
      "aria-pressed",
      document.documentElement.dataset.density === "compact",
    );
}
function breadcrumb() {
  const section = [
    "hosts",
    "zabbix",
    "groups",
    "credentials",
    "proxies",
    "keys",
  ].includes(state.page)
    ? "资产接入"
    : ["diagnostics", "history", "job"].includes(state.page)
      ? "诊断"
      : ["audit", "settings"].includes(state.page)
        ? "治理"
        : "概览";
  $("#breadcrumb-section").textContent = section;
}
const valueText = (v) =>
  typeof v === "object" ? JSON.stringify(v) : String(v ?? "—");
const numberText = (n) =>
  new Intl.NumberFormat("zh-CN", { maximumFractionDigits: 2 }).format(n);
function findingValue(f, threshold = false) {
  const value = threshold ? f.threshold : f.value;
  if (typeof value !== "number") return valueText(value);
  if (f.metric.endsWith("_KiB")) return formatSize(value * 1024);
  const percent =
    f.metric.endsWith("_percent") ||
    f.metric.startsWith("disk:") ||
    f.metric.startsWith("inode:") ||
    f.metric.startsWith("psi_") ||
    f.metric.startsWith("io_util:");
  return numberText(value) + (percent ? "%" : "");
}
function metricLabel(key) {
  const names = {
    load_1m: "1 分钟负载",
    cpu_cores: "CPU 核数",
    load_per_core: "每核负载",
    memory_available_percent: "可用内存",
    swap_used_KiB: "Swap 已用",
    MemTotal_KiB: "内存总量",
    MemAvailable_KiB: "可用内存容量",
    SwapTotal_KiB: "Swap 总量",
    SwapFree_KiB: "Swap 可用",
    failed_service_count: "失败服务数",
    oom_matches: "OOM 日志命中",
    NTPSynchronized: "NTP 同步",
    collection_coverage: "采集完整性",
    triage_coverage: "组合采集完整性",
    observed_log_lines: "本次日志行数",
    warning_log_lines: "告警日志行数",
    service_active_state: "服务运行状态",
    container_state: "容器状态",
    file_handles_used_percent: "系统句柄使用率",
  };
  if (names[key]) return names[key];
  if (key.startsWith("disk:")) return "磁盘 " + key.slice(5);
  if (key.startsWith("inode:")) return "inode " + key.slice(6);
  if (key.startsWith("psi_"))
    return key
      .replace("psi_cpu", "CPU 压力")
      .replace("psi_memory", "内存压力")
      .replace("psi_io", "I/O 压力")
      .replace("_some_avg10", "（部分任务，10 秒）")
      .replace("_full_avg10", "（全部任务，10 秒）");
  return key;
}
function findingsView(findings = []) {
  const order = { critical: 0, warning: 1, info: 2 };
  const items = [...findings].sort(
    (a, b) => (order[a.level] ?? 3) - (order[b.level] ?? 3),
  );
  if (!items.length)
    return '<p class="empty-state">未触发已实现的规则。请结合采集完整性、历史监控与业务表现判断。</p>';
  return (
    '<div class="findings-list">' +
    items
      .map(
        (f) =>
          '<article class="finding ' +
          (Object.hasOwn(order, f.level) ? f.level : "info") +
          '"><div class="finding-title"><span class="severity">' +
          esc(
            { critical: "严重", warning: "关注", info: "说明" }[f.level] ||
              "说明",
          ) +
          "</span><strong>" +
          esc(metricLabel(f.metric)) +
          '</strong><span class="finding-value">' +
          esc(findingValue(f)) +
          "</span></div><p>" +
          esc(f.hint) +
          "</p><small>规则阈值：" +
          esc(
            (typeof f.threshold === "number"
              ? f.metric === "memory_available_percent"
                ? "≤ "
                : "≥ "
              : "") + findingValue(f, true),
          ) +
          (f.source_action
            ? " · 证据：" + esc(actionName(f.source_action))
            : "") +
          "</small></article>",
      )
      .join("") +
    "</div>"
  );
}
function metricsView(result) {
  const metrics = result.summary?.metrics || [];
  const visible = metrics
    .filter((m) => m.unit === "%" || m.metric === "load_per_core")
    .slice(0, 30);
  let html = visible.length
    ? '<div class="metric-grid">' +
      visible
        .map((m) => {
          const max = m.metric === "load_per_core" ? Math.max(4, m.value) : 100;
          const level = ["critical", "warning", "info"].includes(m.level)
            ? m.level
            : "info";
          return (
            '<div class="metric-card ' +
            level +
            '"><div><strong>' +
            esc(metricLabel(m.metric)) +
            "</strong><b>" +
            esc(numberText(m.value)) +
            (m.unit === "%" ? "%" : "") +
            '</b></div><progress value="' +
            Math.max(0, Math.min(max, Number(m.value) || 0)) +
            '" max="' +
            max +
            '" aria-label="' +
            esc(metricLabel(m.metric)) +
            '"></progress><small>' +
            (m.threshold !== null && m.threshold !== undefined
              ? "规则阈值 " +
                (m.metric === "memory_available_percent" ? "≤ " : "≥ ") +
                esc(m.threshold) +
                (m.unit || "")
              : "当前采样") +
            "</small></div>"
          );
        })
        .join("") +
      "</div>"
    : "";
  if (metrics.length)
    html +=
      '<details class="result-details"><summary>全部结构化指标（' +
      metrics.length +
      "）</summary>" +
      table(
        ["指标", "值", "单位"],
        metrics
          .map(
            (m) =>
              "<tr><td>" +
              esc(metricLabel(m.metric)) +
              "</td><td>" +
              esc(numberText(m.value)) +
              "</td><td>" +
              esc(m.unit || "—") +
              "</td></tr>",
          )
          .join(""),
      ) +
      "</details>";
  return html;
}
function diagnosticReport(result, job) {
  const notes =
    '<p class="help">' +
    esc(result.summary?.assessment || "当前采集结果") +
    " · " +
    esc(result.summary?.coverage || result.evidence || "有界只读快照") +
    "</p>";
  const meta =
    '<dl class="execution-meta">' +
    [
      [
        "采集耗时",
        result.duration_ms !== undefined ? result.duration_ms + " ms" : "—",
      ],
      ["退出码", result.exit_code ?? "未完整返回"],
      ["来源", job.source === "mcp" ? "MCP 客户端" : "Web 控制台"],
      ["执行者", job.actor],
      ["输出截断", result.truncated ? "是，结果不完整" : "否"],
      ["采集时间", date(result.captured_at || job.completed_at)],
    ]
      .map(([k, v]) => "<div><dt>" + k + "</dt><dd>" + esc(v) + "</dd></div>")
      .join("") +
    "</dl>";
  const steps = (result.steps || [])
    .map(
      (step) =>
        '<details class="result-details"><summary>' +
        esc(actionName(step.action)) +
        " · " +
        esc(statuses[step.status] || step.status) +
        "</summary>" +
        metricsView(step) +
        findingsView(step.findings) +
        "</details>",
    )
    .join("");
  return (
    '<section class="diagnostic-report"><h3>诊断线索</h3>' +
    findingsView(result.findings) +
    notes +
    metricsView(result) +
    (result.data ? summarizeDiagnostic(result) : "") +
    steps +
    meta +
    '<details id="raw-evidence" class="result-details"><summary>原始输出（已脱敏，点击展开）</summary><div class="actions">' +
    btn("copy-raw", "复制原始输出") +
    btn("download-result", "下载诊断记录") +
    '</div><pre id="raw-output" class="code-result">' +
    esc(
      [result.output, result.stderr].filter(Boolean).join("\n") ||
        "没有可用原文，可能未采集完成或已按工具隐私规则裁剪。",
    ) +
    '</pre></details><details class="result-details"><summary>完整结构化结果</summary><pre class="code-result">' +
    esc(JSON.stringify(result, null, 2)) +
    "</pre></details></section>"
  );
}
function scenarioTemplates() {
  return (
    '<section class="scenario-section"><div class="section-head"><div><h2>从故障场景开始</h2><p class="muted">先选场景，再确认目标清单。每个场景只运行固定诊断。</p></div></div><div class="scenario-grid">' +
    [
      ["cpu_high", "CPU 高", "CPU、进程与 PSI"],
      ["mem_high", "内存高", "内存、RSS、PSI 与 OOM"],
      ["disk_full", "磁盘满", "容量、inode 与挂载"],
      ["io_slow", "I/O 慢", "I/O、PSI 与设备"],
      ["service_down", "服务异常", "服务状态与日志"],
      ["network", "网络异常", "接口、端口与 TCP"],
    ]
      .map(
        ([id, name, description]) =>
          '<button type="button" class="scenario-card" data-action="scenario-template" data-id="' +
          id +
          '">' +
          icon(id === "disk_full" ? "hosts" : "diagnostics") +
          "<strong>" +
          name +
          "</strong><small>" +
          description +
          "</small></button>",
      )
      .join("") +
    "</div></section>"
  );
}
async function dashboard() {
  const [data, recent] = await Promise.all([
    api("/overview"),
    api("/jobs?page_size=5"),
  ]);
  state.dashboard = data;
  const f = data.funnel,
    q = data.queue,
    d = data.diagnostics_24h,
    m = data.mcp;
  const empty = !data.hosts
    ? '<section class="welcome"><div><h2>接入第一台 Linux 主机</h2><p>从资产来源开始，绑定凭据、独立核验指纹，再测试 SSH。</p><div class="actions">' +
      btn("open-zabbix", "从 Zabbix 同步", "", "primary") +
      btn("open-hosts", "登记主机") +
      "</div></div></section>"
    : "";
  const funnel =
    '<div class="funnel-grid">' +
    [
      ["all", "登记资产", f.registered, "主机与设备总数"],
      ["credential_bound", "绑定凭据", f.credential_bound, "已启用 Linux"],
      ["ready", "核验公钥", f.key_verified, "凭据与已核验公钥齐全"],
      ["verified", "测试通过", f.tested, "当前配置 SSH 测试成功"],
    ]
      .map(
        ([id, label, count, note], i) =>
          '<button type="button" class="funnel-step" data-action="funnel-filter" data-id="' +
          id +
          '"><span class="step-label">' +
          (i + 1) +
          " / " +
          label +
          "</span><strong>" +
          count +
          "</strong><small>" +
          note +
          "</small></button>",
      )
      .join("") +
    '</div><p class="help">SSH 配置完成：' +
    f.key_verified +
    " 台；SSH 验证通过：" +
    f.tested +
    " / " +
    f.eligible +
    " 台已启用 Linux。配置齐全与连接测试通过分别统计。</p>";
  const queue =
    '<div class="queue-numbers"><div><strong>' +
    q.active +
    "<small>/4</small></strong><span>SSH 名额占用</span></div><div><strong>" +
    q.pending +
    '<small>/200</small></strong><span>待执行与运行任务</span></div></div><progress aria-label="任务容量" value="' +
    q.pending +
    '" max="200"></progress><p class="help">运行 ' +
    q.running +
    " · 排队 " +
    q.queued +
    " · 后台最多占用 3 个 SSH 名额</p>";
  const reasons = d.failure_reasons.length
    ? '<ul class="reason-list">' +
      d.failure_reasons
        .map(
          (r) =>
            "<li><span>" +
            esc(r.reason) +
            "</span><strong>" +
            r.count +
            "</strong></li>",
        )
        .join("") +
      "</ul>"
    : '<p class="muted">最近 24 小时没有记录失败或部分完成的诊断。</p>';
  const clientAlerts = m.items
    .filter((c) => c.enabled && c.expires_at <= Date.now() / 1000 + 7 * 86400)
    .slice(0, 5);
  const clients =
    '<div class="client-summary"><span>近 24 小时活跃 <b>' +
    m.active_24h +
    "</b></span><span>7 天内到期 <b>" +
    m.expiring_7d +
    "</b></span><span>已过期 <b>" +
    m.expired +
    "</b></span></div>" +
    table(
      ["客户端", "最近接入", "有效期"],
      (clientAlerts.length
        ? clientAlerts
        : m.items.filter((c) => c.enabled).slice(0, 5)
      )
        .map(
          (c) =>
            "<tr><td>" +
            esc(c.name) +
            "</td><td>" +
            date(c.last_used_at) +
            "</td><td>" +
            date(new Date(c.expires_at * 1000).toISOString()) +
            "</td></tr>",
        )
        .join(""),
    );
  const findings = data.recent_findings.length
    ? data.recent_findings
        .map(
          (item) =>
            '<div class="recent-finding"><div><strong>' +
            esc(item.host_name) +
            "</strong><small>" +
            esc(actionName(item.action)) +
            " · " +
            date(item.captured_at) +
            "</small></div>" +
            findingsView([item]) +
            btn("job-detail", "查看证据", item.job_id) +
            "</div>",
        )
        .join("")
    : '<p class="empty-state">暂无线索。完成诊断后，这里显示规则结果与证据入口。</p>';
  return (
    '<div id="overview-dashboard">' +
    empty +
    panel("资产接入漏斗", funnel, btn("open-hosts", "管理资产")) +
    '<div class="dashboard-grid">' +
    panel("诊断队列", queue, btn("open-history", "查看任务")) +
    panel(
      "24 小时诊断成功率",
      '<div class="success-rate">' +
        (d.success_rate === null ? "—" : d.success_rate + "%") +
        '</div><p class="muted">完整 ' +
        (d.counts.success || 0) +
        " · 部分 " +
        (d.counts.partial || 0) +
        " · 失败 " +
        (d.counts.failed || 0) +
        '</p><p class="help">' +
        esc(d.definition) +
        "</p>" +
        reasons,
    ) +
    panel(
      "MCP 客户端（具名）",
      clients +
        '<p class="help">活跃按最近接入时间统计，原始兼容令牌不计入。</p>',
      btn("open-settings/clients", "管理授权"),
    ) +
    panel(
      "最近 findings",
      '<p class="help">' + esc(data.findings_scope) + "</p>" + findings,
    ) +
    "</div>" +
    panel("最近诊断", jobTable(recent.items), btn("open-history", "全部历史")) +
    "</div>"
  );
}
function copyText(text) {
  if (navigator.clipboard) return navigator.clipboard.writeText(text);
  const input = document.createElement("textarea");
  input.className = "clipboard-buffer";
  input.value = text;
  document.body.append(input);
  input.select();
  const ok = document.execCommand("copy");
  input.remove();
  if (!ok) throw Error("复制失败，请展开原文后选择文本复制");
  return Promise.resolve();
}
document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-action]");
  if (!b || b.disabled) return;
  const a = b.dataset.action,
    id = b.dataset.id;
  if (
    ![
      "toggle-nav",
      "density-toggle",
      "funnel-filter",
      "scenario-template",
      "copy-raw",
      "download-result",
    ].includes(a)
  )
    return;
  e.preventDefault();
  e.stopImmediatePropagation();
  try {
    if (a === "toggle-nav") {
      document.body.classList.toggle("nav-open");
      $("#menu-toggle").setAttribute(
        "aria-expanded",
        document.body.classList.contains("nav-open"),
      );
    }
    if (a === "density-toggle") {
      const density =
        document.documentElement.dataset.density === "compact"
          ? "comfortable"
          : "compact";
      document.documentElement.dataset.density = density;
      localStorage.setItem("ssh-density", density);
      updateDensity();
    }
    if (a === "funnel-filter") go("hosts?status=" + id);
    if (a === "scenario-template") {
      state.toolCategory = "全部";
      state.diagnosticAction = "triage";
      state.scenario = id;
      await render();
      const form = $("#diagnostic-form");
      form.elements.symptom.value = id;
      updateDiagnosticInputs();
      form.scrollIntoView({ behavior: "smooth", block: "start" });
      $("#target-search").focus({ preventScroll: true });
    }
    if (a === "copy-raw") {
      await copyText($("#raw-output").textContent);
      notice("原始输出已复制");
    }
    if (a === "download-result") {
      const blob = new Blob([JSON.stringify(state.currentJob, null, 2)], {
          type: "application/json",
        }),
        url = URL.createObjectURL(blob),
        link = document.createElement("a");
      link.href = url;
      link.download = "ssh-diagnostic-" + state.currentJob.id + ".json";
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  } catch (ex) {
    notice(ex.message, true);
  }
});
