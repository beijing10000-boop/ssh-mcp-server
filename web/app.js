"use strict";
const $ = (q) => document.querySelector(q);
const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (x) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        x
      ],
  );
let csrfToken = "";
let currentUser = null;
const state = {
  page: "overview",
  hosts: [],
  groups: [],
  credentials: [],
  proxies: [],
  batchId: null,
  editor: null,
  selected: new Set(),
  selectedHosts: new Map(),
  targets: new Map(),
  targetCandidates: [],
  targetQuery: "",
  hostSort: "id",
  hostDirection: "desc",
  hostQuery: "",
  hostGroup: "",
  hostStatus: "all",
  hostPage: 1,
  historyPage: 1,
  historyStatus: "all",
  auditPage: 1,
  auditQuery: "",
  auditStatus: "all",
  manifest: "",
  tools: [],
  zabbixGroups: [],
  zabbixSelected: new Set(),
  zabbixPage: 1,
  zabbixGroupIds: new Set(),
  toolCategory: "全部",
  settingsTab: "zabbix",
};
const titles = {
  overview: "运维总览",
  hosts: "主机资产",
  zabbix: "Zabbix 资产同步",
  groups: "主机组",
  credentials: "SSH 凭据管理",
  proxies: "SSH 跳板管理",
  keys: "主机公钥核验",
  diagnostics: "诊断工作台",
  history: "诊断历史",
  job: "诊断详情",
  audit: "操作审计",
  settings: "系统配置",
};
let timer = null;
let generation = 0;
let fieldId = 0;
const statuses = {
  success: "已完成",
  partial: "部分完成",
  failed: "失败",
  queued: "排队中",
  running: "执行中",
  cancelled: "已取消",
  untested: "尚未测试",
  interrupted: "已中断",
  finished: "已完成",
  preview: "等待登记",
  registered: "已登记",
  missing_credential: "待绑定凭据",
  unverified: "待核验公钥",
  verified: "SSH 验证通过",
  unsupported: "仅登记资产",
  disabled: "已停用",
};
const date = (s) =>
  s
    ? new Date(
        String(s).includes("T") ? s : String(s).replace(" ", "T") + "Z",
      ).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false })
    : "—";
// Unix seconds (MCP client expiry) shown like every other timestamp.
const epochDate = (seconds) => date(new Date(seconds * 1000).toISOString());
const badge = (s) =>
  `<span class="status ${esc(s)}">${esc(statuses[s] || s)}</span>`;
// A status chip whose text is not one of the state labels above.
const chip = (text, tone = "") => `<span class="status ${tone}">${esc(text)}</span>`;
const actionName = (action) => toolById(action)?.name || action;
const sourceName = (source) => (source === "mcp" ? "MCP 客户端" : "Web 控制台");
function go(page) {
  if (location.hash === "#" + page) render();
  else location.hash = page;
}
function pagination(name, data) {
  const pages = Math.max(1, Math.ceil(data.total / data.page_size));
  state[name + "Pages"] = pages;
  return (
    `<div class="pagination"><span class="muted">共 ${data.total} 条 · 第 ${data.page} / ${pages} 页</span><div class="actions">` +
    `<button class="btn small" data-action="page-prev" data-id="${name}" ${data.page <= 1 ? "disabled" : ""}>上一页</button>` +
    `<button class="btn small" data-action="page-next" data-id="${name}" ${data.page >= pages ? "disabled" : ""}>下一页</button></div></div>`
  );
}
function hostQuery() {
  return new URLSearchParams({
    q: state.hostQuery,
    status: state.hostStatus,
    sort: state.hostSort,
    direction: state.hostDirection,
    ...(state.hostGroup ? { group_id: state.hostGroup } : {}),
  });
}

async function api(path, method = "GET", body) {
  const result = await fetch("/api/v1" + path, {
    method,
    credentials: "same-origin",
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(method !== "GET" && csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const payload = await result.json().catch(() => ({}));
  if (result.status === 401) {
    csrfToken = "";
    currentUser = null;
    $("#app").hidden = true;
    $("#login").hidden = false;
    throw Object.assign(new Error("身份验证失效，请重新登录"), { status: 401 });
  }
  if (!result.ok) {
    const info = payload.detail;
    throw new Error(
      typeof info === "string"
        ? info
        : Array.isArray(info)
          ? info.map((e) => e.msg).join("; ")
          : "请求失败（HTTP " + result.status + "）",
    );
  }
  return payload;
}
function notice(text, failure = false) {
  if (failure && $("#editor").open) {
    const e = $("#editor-feedback");
    e.textContent = text;
    e.hidden = false;
    return;
  }
  const box = $("#notice");
  box.hidden = !text;
  box.textContent = text || "";
  box.classList.toggle("error", failure);
  // A floating notice: errors stay longer, a click dismisses it early.
  clearTimeout(state.noticeTimer);
  if (text) state.noticeTimer = setTimeout(() => notice(""), failure ? 12000 : 6000);
}
const btn = (name, text, id = "", kind = "") =>
  `<button type="button" class="btn small ${kind}" data-action="${esc(name)}" data-id="${esc(id)}">${esc(text)}</button>`;
function panel(title, body, tools = "") {
  return `<section class="panel"><div class="section-head"><h2>${esc(title)}</h2><div class="actions">${tools}</div></div>${body}</section>`;
}
function table(head, body, kind = "") {
  return (
    `<div class="table-wrap${kind ? " " + kind : ""}"><table><thead><tr>` +
    head.map((x) => `<th>${x}</th>`).join("") +
    "</tr></thead><tbody>" +
    (body || `<tr><td colspan="${head.length}" class="empty">暂无记录</td></tr>`) +
    "</tbody></table></div>"
  );
}
// One labelled form control; `opts` ([value, label] pairs) renders a select.
const field = (
  name,
  title,
  value = "",
  type = "text",
  opts = null,
  wide = false,
  help = "",
) => {
  const ident = "field-" + ++fieldId;
  const input = opts
    ? `<select id="${ident}" name="${name}">` +
      opts
        .map(
          ([v, t]) =>
            `<option value="${esc(v)}" ${String(value) === String(v) ? "selected" : ""}>${esc(t)}</option>`,
        )
        .join("") +
      "</select>"
    : type === "textarea"
      ? `<textarea id="${ident}" name="${name}" autocomplete="off">${esc(value)}</textarea>`
      : type === "checkbox"
        ? `<label class="check"><input id="${ident}" type="checkbox" name="${name}" ${value ? "checked" : ""}/> 启用</label>`
        : `<input id="${ident}" type="${type}" name="${name}" value="${esc(value)}" autocomplete="off"/>`;
  return (
    `<div class="${wide ? "wide" : ""}"><label for="${ident}">${esc(title)}</label>${input}` +
    (help ? `<div class="help">${esc(help)}</div>` : "") +
    "</div>"
  );
};
function openModal(title, fields, submit) {
  state.editor = submit;
  $("#editor-heading").textContent = title;
  $("#editor-fields").innerHTML = fields;
  $("#editor-feedback").textContent = "";
  $("#editor-feedback").hidden = true;
  $('#editor-form button[type="submit"]').hidden = !submit;
  $("#editor").showModal();
  $('#editor-form button[type="submit"]').textContent = "保存";
}
function clearEditor() {
  state.editor = null;
  $("#editor-fields").replaceChildren();
  $("#editor-feedback").textContent = "";
}
function closeModal() {
  $("#editor").close();
  clearEditor();
}
function getForm(form, name) {
  return form.elements.namedItem(name)?.value ?? "";
}
function checkbox(form, name) {
  return !!form.elements.namedItem(name)?.checked;
}
function numberOrNull(value) {
  return value ? Number(value) : null;
}
function currentHost(id) {
  return state.hosts.find((h) => String(h.id) === String(id));
}

// The trusted-console command that prints the fingerprint for a host key
// algorithm (all ECDSA curves share ssh_host_ecdsa_key).
function hostKeyCommand(algorithm) {
  const file = /^(ssh-rsa|rsa-sha2-)/.test(algorithm || "")
    ? "rsa"
    : /^ecdsa-sha2-/.test(algorithm || "")
      ? "ecdsa"
      : algorithm === "ssh-ed25519"
        ? "ed25519"
        : "*";
  return `ssh-keygen -lf /etc/ssh/ssh_host_${file}_key.pub -E sha256`;
}
async function pageHosts() {
  const [data, groups, credentials, proxies] = await Promise.all([
    api("/inventory/hosts?" + hostQuery() + "&page=" + state.hostPage),
    api("/groups"),
    api("/credentials"),
    api("/proxies"),
  ]);
  if (state.hostPage > 1 && !data.items.length) {
    state.hostPage--;
    return pageHosts();
  }
  const hosts = data.items;
  for (const h of hosts) state.selectedHosts.set(h.id, h);
  state.hosts = hosts;
  state.groups = groups;
  state.credentials = credentials;
  state.proxies = proxies;
  const rows = hosts
    .map((h) => {
      const groupNames =
        h.group_ids
          .map((id) => groups.find((g) => g.id === id)?.name)
          .filter(Boolean)
          .join(" · ") || "未分组";
      const actions =
        btn("edit-host", "编辑", h.id) +
        (h.enabled && h.has_host_key && h.credential_id
          ? btn("test", "测试", h.id) + btn("diagnose-host", "诊断", h.id)
          : "");
      return (
        `<tr><td><input class="row-check host-selected" type="checkbox" data-id="${h.id}" aria-label="选中${esc(h.name)}" ${state.selected.has(h.id) ? "checked" : ""}/></td>` +
        `<td><button type="button" class="text-button cell-title" data-action="host-detail" data-id="${h.id}">${esc(h.name)}</button><small>资产 ID ${h.id} · Zabbix Host ID ${esc(h.zabbix_hostid || "未关联")}</small></td>` +
        `<td class="mono">${esc(h.address)}:${h.port}<small>${esc(h.username)}${h.proxy_id ? " · 跳板 " + esc(proxies.find((p) => p.id === h.proxy_id)?.name || h.proxy_id) : " · 直连"}</small></td>` +
        `<td>${esc(h.mode === "gateway" ? "B · 受限强制命令网关" : "A · 标准免 Agent")}</td>` +
        `<td><button type="button" class="readiness-button" data-action="prepare-host" data-id="${h.id}">${badge(h.readiness || "untested")}</button><small>${esc(groupNames)}</small></td>` +
        `<td class="date">${date(h.last_test_at)}<small>诊断 ${date(h.last_diagnostic_at)}</small></td>` +
        `<td><div class="actions">${actions}</div></td></tr>`
      );
    })
    .join("");
  const groupOptions = groups
    .map(
      (g) =>
        `<option value="${g.id}" ${String(g.id) === state.hostGroup ? "selected" : ""}>${esc(g.name)}</option>`,
    )
    .join("");
  return panel(
    "主机与设备资产",
    `<form id="host-search-form" class="toolbar"><input id="host-filter" aria-label="搜索主机" value="${esc(state.hostQuery)}" placeholder="主机名称、IP 或 Zabbix Host ID"/>` +
      `<select id="host-group" aria-label="筛选主机组"><option value="">全部主机组</option>${groupOptions}</select>` +
      '<select id="host-status" aria-label="筛选主机状态">' +
      [
        ["all", "全部状态"],
        ["ready", "已配置 SSH"],
        ["credential_bound", "已绑定凭据的 Linux"],
        ["verified", "SSH 验证通过"],
        ["missing_credential", "待绑定凭据"],
        ["untested", "待测试"],
        ["unsupported", "仅登记资产"],
        ["unverified", "待核验公钥"],
        ["failed", "测试失败"],
        ["disabled", "已停用"],
      ]
        .map(
          ([v, t]) =>
            `<option value="${v}" ${state.hostStatus === v ? "selected" : ""}>${t}</option>`,
        )
        .join("") +
      '</select><button class="btn" type="submit">搜索</button></form>' +
      `<div class="selection-bar"><span id="selected-count">已选 ${state.selected.size} 台</span>` +
      btn("select-filtered", "全选筛选结果") +
      btn("clear-selected", "清空") +
      btn("bind-selected", "绑定 SSH") +
      btn("scan-selected", "获取公钥") +
      btn("test-selected", "测试 SSH") +
      btn("diagnose-selected", "批量诊断") +
      btn("enable-selected", "启用") +
      btn("disable-selected", "停用", "", "danger") +
      "</div>" +
      table(
        [
          '<input type="checkbox" id="select-page" aria-label="选择本页主机">',
          btn("sort-host", "主机 / 关联", "name"),
          btn("sort-host", "SSH 路由", "address"),
          "权限模式",
          "准备状态",
          btn("sort-host", "上次测试 / 诊断", "last_test_at") +
            btn("sort-host", "按诊断时间", "last_diagnostic_at"),
          "操作",
        ],
        rows,
      ) +
      pagination("host", data),
    btn("open-zabbix", "从 Zabbix 同步") +
      btn("import-hosts", "表格导入") +
      btn("new-host", "登记主机", "", "primary"),
  );
}
async function pageGroups() {
  state.groups = await api("/groups");
  return panel(
    "主机组",
    '<p class="intro">主机可以属于多个组。MCP 客户端按组授权，分组调整会影响它能访问的资产。</p>' +
      table(
        ["ID", "主机组名称", "操作"],
        state.groups
          .map(
            (x) =>
              `<tr><td>${x.id}</td><td>${esc(x.name)}</td><td>${btn("edit-group", "编辑", x.id)}${btn("delete-group", "删除", x.id, "danger")}</td></tr>`,
          )
          .join(""),
      ),
    btn("new-group", "新增主机组", "", "primary"),
  );
}
async function pageCredentials() {
  state.credentials = await api("/credentials");
  return panel(
    "加密 SSH 凭据",
    '<p class="intro">只保存加密私钥，不会把已保存的私钥回显到 Web。请为诊断服务单独生成密钥对，勿复用个人管理密钥。</p>' +
      table(
        ["ID", "凭据名称", "创建时间", "操作"],
        state.credentials
          .map(
            (x) =>
              `<tr><td>${x.id}</td><td>${esc(x.name)}</td><td>${date(x.created_at)}</td><td>${btn("rotate-credential", "轮换", x.id)}</td></tr>`,
          )
          .join(""),
      ),
    btn("new-credential", "新增凭据", "", "primary"),
  );
}
async function pageProxies() {
  [state.proxies, state.credentials] = await Promise.all([
    api("/proxies"),
    api("/credentials"),
  ]);
  return panel(
    "SSH 跳板管理",
    '<p class="intro">仅允许登记内网跳板；跳板主机公钥必须事先通过可信渠道核验。</p>' +
      table(
        ["ID", "跳板名称", "SSH 地址", "登录账号", "凭据", "操作"],
        state.proxies
          .map(
            (p) =>
              `<tr><td>${p.id}</td><td>${esc(p.name)}</td><td>${esc(p.address)}:${esc(p.port)}</td><td>${esc(p.username)}</td>` +
              `<td>${esc(state.credentials.find((c) => c.id === p.credential_id)?.name || p.credential_id)}</td><td>${btn("edit-proxy", "编辑", p.id)}</td></tr>`,
          )
          .join(""),
      ),
    btn("new-proxy", "新增跳板", "", "primary"),
  );
}
async function pageKeys() {
  const batches = await api("/host-keys/batches");
  if (!state.batchId && batches.length) state.batchId = batches[0].id;
  let intro =
    '<p class="intro">① 选择目标并批量扫描 SSH 握手公钥 → ② 按服务器实际密钥算法取得可信指纹 → ③ 独立核对后确认保存 → ④ 返回主机资产进行连接测试。扫描本身不会自动信任服务器。</p>';
  let records = "",
    detail = null;
  if (state.batchId) {
    detail = await api(
      "/host-keys/batches/" + encodeURIComponent(state.batchId),
    );
    const batch = detail.batch;
    intro +=
      `<div class="progress-heading">${badge(batch.status)}<strong>${batch.completed} / ${batch.total} 台</strong></div>` +
      `<progress value="${batch.completed}" max="${batch.total}" aria-label="公钥获取进度"></progress>`;
    state.keyDetail = detail;
    records = detail.items
      .map((r) => {
        const statusName =
          {
            candidate: "待人工确认",
            changed: "主机公钥发生变化",
            unchanged: "与已有可信公钥一致",
            confirmed: "已核验保存",
            failed: "获取失败",
            stale: "主机配置已变化",
            interrupted: "任务中断",
          }[r.status] || r.status;
        const changed =
          r.previous_fingerprint &&
          r.fingerprint &&
          r.previous_fingerprint !== r.fingerprint;
        const command = hostKeyCommand(r.algorithm);
        const previous = r.previous_fingerprint
          ? `<small>原可信指纹：${esc(r.previous_fingerprint)}</small>`
          : "";
        const hint = r.fingerprint
          ? `<small>在目标可信控制台执行：<code>${esc(command)}</code></small>`
          : "";
        return (
          `<tr><td><strong>${esc(r.name || "")}</strong><small>资产 ${r.host_id} · ${esc(r.address || "")}</small></td>` +
          `<td class="mono">${esc(r.fingerprint || "—")}<small>算法 ${esc(r.algorithm || "—")}</small></td>` +
          `<td><span class="${changed ? "state-bad" : ""}">${esc(statusName)}</span>${previous}</td>` +
          `<td>${esc(r.error || "—")}${hint}</td>` +
          `<td>${r.status === "candidate" || r.status === "changed" ? btn("confirm-key", "核验并保存", r.host_id) : "—"}</td></tr>`
        );
      })
      .join("");
  }
  const batchlist = batches
    .map(
      (x) =>
        `<option value="${esc(x.id)}" ${state.batchId === x.id ? "selected" : ""}>${date(x.created_at)} · ${esc(statuses[x.status] || x.status)} · ${x.completed}/${x.total}</option>`,
    )
    .join("");
  const scanButtons =
    btn("scan-all-unverified", "扫描所有未核验主机", "", "primary") +
    (detail &&
    ["finished", "interrupted"].includes(detail.batch.status) &&
    detail.items.some((r) =>
      ["failed", "stale", "interrupted"].includes(r.status),
    )
      ? btn("retry-failed", "仅重试本批失败主机")
      : "");
  const results = panel(
    "批量扫描与进度",
    intro +
      '<div class="toolbar"><select id="batch-select">' +
      (batchlist || "<option>没有扫描记录</option>") +
      "</select>" +
      btn("refresh", "刷新") +
      "</div>" +
      table(
        ["主机", "候选 SHA256 指纹", "核验状态", "详情与核验命令", "操作"],
        records,
      ),
    scanButtons,
  );
  const matching = detail
    ? detail.items.filter(
        (r) => r.status === "candidate" || r.status === "changed",
      )
    : [];
  const trust = panel(
    "批量导入可信指纹",
    '<p class="muted">批量核验无需逐台点击弹窗。请先通过服务器控制台、Ansible 可信通道或已有可信资产台账取得真实 SHA256 指纹，再按「主机 ID/IP + [可选算法] + SHA256 指纹」逐行粘贴；支持从已开启 SSH 主机身份校验的 Ansible 清单导入。<strong>不能直接复制本页面扫描到的指纹作为可信来源。</strong> 先逐行预检，确认后只保存匹配项；不匹配会记录安全审计。</p>' +
      `<p class="muted">当前批次待确认：${matching.length} 台</p>` +
      `<textarea id="trusted-fingerprints" aria-label="独立可信指纹清单" rows="7" placeholder="1 SHA256:独立可信渠道获取的指纹&#10;192.0.2.10 ssh-ed25519 SHA256:独立可信渠道获取的指纹">${esc(state.manifest)}</textarea>` +
      `<div class="modal-actions">${btn("confirm-batch-from-manifest", "核对并保存可信指纹", "", "primary")}</div>`,
  );
  return results + trust;
}
async function pageDiagnostics() {
  const [tools, groups] = await Promise.all([api("/tools"), api("/groups")]);
  state.tools = tools;
  state.groups = groups;
  const picker = await targetPicker();
  const visible = tools.filter(
    (t) => state.toolCategory === "全部" || t.category === state.toolCategory,
  );
  const categories = ["全部", ...new Set(tools.map((t) => t.category))]
    .map(
      (c) =>
        `<button class="category-chip ${state.toolCategory === c ? "active" : ""}" data-action="tool-category" data-id="${esc(c)}">${esc(c)}</button>`,
    )
    .join("");
  const form =
    '<form id="diagnostic-form"><div class="fields">' +
    picker +
    field(
      "action",
      "诊断类型",
      state.diagnosticAction || "health",
      "text",
      visible.map((t) => [t.id, t.name]),
    ) +
    field(
      "symptom",
      "故障场景",
      state.scenario || "cpu_high",
      "text",
      faultScenarios,
    ) +
    field("service", "systemd 服务名称", "nginx.service") +
    field("minutes", "时间范围（分钟）", 30, "number") +
    field(
      "directory_root",
      "扫描目录",
      "/data",
      "text",
      null,
      true,
      "支持 /root、/root/.cache、/data、/var 等目录，每次最多扫描 8 秒；仅统计单层，不修改或清理文件。",
    ) +
    '<div id="diagnostic-options" class="wide" hidden></div>' +
    '</div><div class="notice diagnostic-help">快照反映采集时刻的状态。日志、目录与流量数据需有相应读取权限；缺失能力会显示为部分完成。</div>' +
    (!state.targets.size
      ? '<p class="inline-error">请选择上方搜索结果中的主机，明确目标后提交。</p>'
      : "") +
    `<div class="modal-actions"><span class="muted">固定动作 · 无任意命令输入</span><button class="btn primary" type="submit" ${!state.targets.size ? "disabled" : ""}>提交诊断</button></div></form>`;
  const capabilities = visible
    .map(
      (t) =>
        `<button class="capability" data-action="choose-tool" data-id="${esc(t.id)}"><span class="capability-icon">${icon(t.sensitive ? "keys" : "diagnostics")}</span>` +
        `<div><strong>${esc(t.name)}</strong> ${riskBadge(t.risk)}<p>${esc(t.question)}</p>` +
        `<small>参数：${esc(paramNames(t))}</small><small>${esc(t.duration_hint)}</small>` +
        `<small>${t.standard_only ? "标准 SSH 模式 · " : ""}${t.sensitive ? "按授权范围采集" : "固定只读采集"}</small>` +
        (Array.isArray(t.notes) ? t.notes : [])
          .map((note) => `<small>${esc(note)}</small>`)
          .join("") +
        "</div></button>",
    )
    .join("");
  return (
    `<div class="page-intro"><p>选择目标与诊断方式。任务在后台执行，离开页面后仍可在历史中查看。</p>${btn("open-history", "查看诊断历史")}</div>` +
    scenarioTemplates() +
    `<div class="tool-categories" aria-label="按诊断场景筛选">${categories}</div>` +
    panel("创建诊断任务", form) +
    `<div class="capability-grid">${capabilities}</div>`
  );
}
function jobTable(items) {
  const labels = [
    "主机 / 任务",
    "诊断类型",
    "来源",
    "状态",
    "提交时间",
    "操作",
  ];
  const rows = items
    .map((j) => {
      const cells = [
        `<strong>${esc(j.host_name)}</strong><small class="mono">${esc(j.id.slice(0, 10))}</small>`,
        esc(actionName(j.action)),
        esc(sourceName(j.source)),
        badge(j.status),
        date(j.created_at),
        btn("job-detail", "查看", j.id),
      ];
      return (
        `<tr data-key="${esc(j.id)}">` +
        cells
          .map((html, i) => `<td data-label="${labels[i]}">${html}</td>`)
          .join("") +
        "</tr>"
      );
    })
    .join("");
  return table(labels, rows, "job-history");
}

async function pageHistory() {
  const query = new URLSearchParams({
    page: state.historyPage,
    status: state.historyStatus,
    ...(state.batchFilter ? { batch_id: state.batchFilter } : {}),
  });
  const [data, progress] = await Promise.all([
    api("/jobs?" + query),
    batchProgress(),
  ]);
  if (state.historyPage > 1 && !data.items.length) {
    state.historyPage--;
    return pageHistory();
  }
  state.pollHistory = data.items.some((j) =>
    ["queued", "running"].includes(j.status),
  );
  return panel(
    state.batchFilter ? "本批诊断任务" : "诊断历史",
    '<div class="toolbar"><select id="history-status" aria-label="筛选任务状态">' +
      ["all", "queued", "running", "success", "partial", "failed", "cancelled"]
        .map(
          (x) =>
            `<option value="${x}" ${state.historyStatus === x ? "selected" : ""}>${esc(x === "all" ? "全部状态" : statuses[x])}</option>`,
        )
        .join("") +
      "</select>" +
      (state.batchFilter ? btn("all-history", "显示全部历史") : "") +
      '<span class="muted">结果加密保存 · 重启中断可追溯</span></div>' +
      progress +
      jobTable(data.items) +
      pagination("history", data),
    btn("open-diagnostics", "新建诊断", "", "primary"),
  );
}
async function pageJob() {
  const job = await api("/jobs/" + encodeURIComponent(state.jobId));
  state.currentJob = job;
  const active = ["queued", "running"].includes(job.status);
  const actions =
    btn("open-history", "返回历史") +
    (active
      ? btn("cancel-job", "取消任务", job.id, "danger")
      : btn("retry-job", "重新诊断", job.id));
  const meta =
    `<div class="job-meta"><div><small>目标主机</small><strong>${esc(job.host_name)}</strong></div>` +
    `<div><small>诊断动作</small><strong>${esc(actionName(job.action))}</strong></div>` +
    `<div><small>提交时间</small><strong>${date(job.created_at)}</strong></div>` +
    `<div><small>状态</small>${badge(job.status)}</div></div>`;
  const result = job.result;
  // v0.6: non-fatal stderr (e.g. df gvfs noise) is kept as result.warnings
  // and no longer makes a result partial; do not show it as an error box.
  const benign =
    job.status === "success" &&
    Array.isArray(result?.warnings) &&
    result.warnings.length > 0 &&
    !result.error;
  return (
    `<div class="page-intro"><span class="muted mono">任务 ${esc(job.id)}</span><div class="actions">${actions}</div></div>` +
    panel("诊断记录", meta) +
    panel(
      "采集结果",
      active
        ? `<div class="pending-result"><span class="spinner"></span><strong>${job.status === "queued" ? "等待执行" : "正在采集"}</strong><p>可以离开此页面，结果将在诊断历史中保留。</p></div>`
        : (job.error && !benign
            ? `<p class="inline-error">${esc(job.error)}</p>`
            : "") +
            (result
              ? (result.note
                  ? `<p class="notice">${esc(result.note)}</p>`
                  : "") + diagnosticReport(result, job)
              : '<p class="muted">没有完成采集，尚无结果。</p>'),
    )
  );
}
async function pageClients() {
  const [data, groups, tools] = await Promise.all([
    api("/mcp/clients"),
    api("/groups"),
    api("/tools"),
  ]);
  state.clients = data.items;
  state.groups = groups;
  state.tools = tools;
  state.legacyEnabled = data.legacy_enabled;
  const rows = data.items
    .map((c) => {
      const scope = c.all_hosts
        ? "全部已登记主机"
        : c.group_ids
            .map((id) => groups.find((g) => g.id === id)?.name || "已删除分组")
            .join("、");
      const actions = c.enabled
        ? '<div class="actions">' +
          (c.expired ? "" : btn("edit-client", "编辑权限", c.id)) +
          btn("revoke-client", "撤销", c.id, "danger") +
          "</div>"
        : "—";
      return (
        `<tr><td><strong>${esc(c.name)}</strong><small class="mono">${esc(c.prefix)}…</small></td>` +
        `<td>${esc(scope)}<small>${c.actions.length} 项诊断权限${esc(costlyActions(c.actions))}</small></td>` +
        `<td>${epochDate(c.expires_at)}<small>最近使用 ${date(c.last_used_at)}</small></td>` +
        `<td>${!c.enabled ? chip("已撤销", "disabled") : c.expired ? chip("已过期", "warning") : chip("有效", "success")}</td><td>${actions}</td></tr>`
      );
    })
    .join("");
  const endpoint = {
    url: location.origin + "/mcp",
    headers: { Authorization: "Bearer <客户端令牌>" },
  };
  return (
    '<div class="page-intro"><p>为每个 AI 平台或集成系统签发独立令牌，限定主机组、工具与有效期。编辑权限不更换令牌，从下一次 MCP 请求起生效。</p></div>' +
    panel(
      "MCP 客户端",
      table(["客户端", "授权范围", "有效期 / 最近使用", "状态", "操作"], rows),
      btn("new-client", "新增客户端", "", "primary"),
    ) +
    '<div class="grid2">' +
    panel(
      "接入配置",
      '<p class="muted">协议为 Streamable HTTP。令牌放在 AI 平台的服务器端加密配置中。</p>' +
        codeBlock(JSON.stringify(endpoint, null, 2)) +
        '<p class="help">Zabbix Host ID 通过 ssh_resolve_host 精确映射，不按 IP 或主机名猜测。</p>' +
        '<p class="help">v0.6.0 起服务启动时，已获 logs 授权的客户端自动获得 nginx、nginx_access、syslog、java、service_detail（syslog 也随 log_errors 扩展），已获 sockets 或 service 的获得 service_map，并写入审计 mcp_client_actions_extended；jvm 只能手动授权。ssh_collect 按步骤授权，无需单独勾选。</p>',
    ) +
    panel(
      "原始兼容令牌",
      `<p>当前状态：${data.legacy_enabled ? chip("已启用", "success") : chip("已停用", "disabled")}</p>` +
        '<p class="muted">原始 mcp.token 拥有全部主机权限。迁移到独立客户端后可在此停用；不会影响飞书登录。</p>' +
        btn(
          "toggle-legacy",
          data.legacy_enabled ? "停用原始令牌" : "启用原始令牌",
          "",
          "danger",
        ),
    ) +
    "</div>"
  );
}

// Recommended scope for the AI Ops Platform pre-collection: no JVM attach,
// no triage, directory scan or per-peer sampling.
const recommendedClientActions = [
  "connection",
  "health",
  "capabilities",
  "cpu",
  "memory",
  "disk",
  "network",
  "system",
  "processes",
  "memory_processes",
  "pressure",
  "io",
  "sockets",
  "tcp_states",
  "service",
  "logs",
  "log_errors",
  "oom",
  "kernel",
  "failed_services",
  "service_inventory",
  "syslog",
  "nginx",
  "nginx_access",
  "java",
  "service_detail",
  "service_map",
];
function costlyActions(actions) {
  const names = state.tools
    .filter((t) => actions.includes(t.id) && ["medium", "high"].includes(t.risk))
    .map((t) => t.name);
  return names.length ? " · 含中/高开销：" + names.join("、") : "";
}
function clientActionLabel(t) {
  return (
    t.name +
    (t.sensitive ? " · 扩展采集" : "") +
    (t.risk === "high" ? " · 高开销" : t.risk === "medium" ? " · 中开销" : "") +
    (t.id === "collect" ? " · 按步骤授权" : "")
  );
}
function clientScopeFields(actions = [], client = null) {
  const groups = client?.group_ids || [];
  return (
    `<div class="wide"><label class="check"><input type="checkbox" name="all_hosts" ${client?.all_hosts ? "checked" : ""}>授权全部已登记主机（包含未来新增主机）</label></div>` +
    '<fieldset class="wide option-grid"><legend>或选择授权主机组</legend>' +
    state.groups
      .map(
        (g) =>
          `<label class="check"><input type="checkbox" name="client_group" value="${g.id}" ${groups.includes(g.id) ? "checked" : ""}>${esc(g.name)}</label>`,
      )
      .join("") +
    "</fieldset>" +
    `<div class="wide actions">${btn("recommend-client-actions", "按 AI Ops Platform 推荐勾选")}` +
    '<span id="client-action-hint" class="help">推荐范围覆盖预采集所需的只读动作，不含 jvm、triage、directory、peer_*；ssh_collect 按步骤授权。</span></div>' +
    '<fieldset class="wide option-grid"><legend>允许的诊断动作</legend>' +
    state.tools
      .map(
        (t) =>
          `<label class="check"><input type="checkbox" name="client_action" value="${esc(t.id)}" ${actions.includes(t.id) ? "checked" : ""}>${esc(clientActionLabel(t))}</label>`,
      )
      .join("") +
    "</fieldset>"
  );
}
function clientScopeBody(form) {
  const body = {
    all_hosts: checkbox(form, "all_hosts"),
    group_ids: [...form.querySelectorAll("[name=client_group]:checked")].map(
      (x) => Number(x.value),
    ),
    actions: [...form.querySelectorAll("[name=client_action]:checked")].map(
      (x) => x.value,
    ),
  };
  if (!body.actions.length) throw Error("请至少选择一个诊断动作");
  if (!body.all_hosts && !body.group_ids.length)
    throw Error("请选择授权主机组，或明确勾选全部主机");
  return body;
}

function formatSize(n) {
  if (!Number.isFinite(Number(n))) return "—";
  let v = Number(n),
    unit = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (v >= 1024 && i < unit.length - 1) {
    v /= 1024;
    i++;
  }
  return (v >= 10 || i === 0 ? v.toFixed(0) : v.toFixed(1)) + " " + unit[i];
}
// Ranking tables for the actions that return structured `data` (only called
// when `result.data` is present).
function summarizeDiagnostic(result) {
  const d = result.data;
  const label = result.status === "success" ? "完成" : "部分结果或采集能力不足";
  let title = `<p class="muted">${esc(label)} · ${esc(d.metric || d.ranking_scope || "目录占用")} · ${esc(result.duration_ms)} ms</p>`;
  let rows = [],
    header = [];
  if (result.action === "directory") {
    title += `<p class="muted">扫描根目录：<strong>${esc(d.root)}</strong>；根目录占用：${formatSize(d.scanned_root_bytes)}</p>`;
    header = ["排名", "目录", "已占用空间"];
    rows = d.top_directories.map(
      (v, i) =>
        `<tr><td>${i + 1}</td><td class="mono">${esc(v.directory)}</td><td>${formatSize(v.bytes)}</td></tr>`,
    );
  } else if (result.action === "peer_connections") {
    header = ["排名", "远端 IP", "TCP 连接总数", "其中已建立"];
    rows = d.ranking.map(
      (v, i) =>
        `<tr><td>${i + 1}</td><td class="mono">${esc(v.peer_ip)}</td><td><strong>${esc(v.tcp_connections)}</strong></td><td>${esc(v.established_connections)}</td></tr>`,
    );
  } else if (result.action === "peer_traffic") {
    title += `<p class="muted">${esc(d.sample_seconds)} 秒 TCP 采样 · 两次都存在的 socket：${esc(d.matched_sockets)}（采样 A ${esc(d.sample_a_sockets)} / B ${esc(d.sample_b_sockets)}）</p>`;
    header = ["排名", "远端 IP", "发送增量", "接收增量", "总计", "平均每秒"];
    rows = d.ranking.map(
      (v, i) =>
        `<tr><td>${i + 1}</td><td class="mono">${esc(v.peer_ip)}</td><td>${formatSize(v.sent_bytes)}</td><td>${formatSize(v.received_bytes)}</td>` +
        `<td><strong>${formatSize(v.total_bytes)}</strong></td><td>${formatSize(v.avg_bytes_per_second)}/s</td></tr>`,
    );
  }
  const caveats = (d.notes || [])
    .map((v) => `<p class="help">· ${esc(v)}</p>`)
    .join("");
  return (
    title +
    table(header, rows.join("")) +
    (rows.length
      ? ""
      : '<p class="inline-error">本次未获得可用于排行的数据。请查看下方详细结果与能力说明。</p>') +
    caveats
  );
}
// Cost level of a catalog action (`risk`); the diagnostic report shares it.
const riskNames = { low: "低开销", medium: "中开销", high: "高开销" };
function riskBadge(risk) {
  if (!Object.hasOwn(riskNames, risk)) return "";
  const tone = { low: "", medium: "partial", high: "failed" }[risk];
  return `<span class="status ${tone}">${riskNames[risk]}</span>`;
}
function toolById(id) {
  return state.tools.find((t) => t.id === id);
}
function paramNames(tool) {
  if (!Array.isArray(tool.params))
    return tool.parameters?.join("、") || "无需额外参数";
  return (
    tool.params
      .map((p) => p.name + (p.required ? "（必填）" : ""))
      .join("、") || "无需额外参数"
  );
}
// Browsers compile the `pattern` attribute with the `v` flag where supported;
// a server pattern that is not valid there is only shown as help text.
const patternFlag = (() => {
  try {
    new RegExp("", "v");
    return "v";
  } catch {
    return "u";
  }
})();
function compilePattern(source, flag = "u") {
  if (typeof source !== "string" || !source) return null;
  try {
    return new RegExp("^(?:" + source + ")$", flag);
  } catch {
    return null;
  }
}
function choiceLabel(value) {
  const name = actionName(value);
  return name === value ? String(value) : `${name}（${value}）`;
}
function optionHelp(p) {
  const parts = [p.description];
  if (Number.isFinite(p.minimum) || Number.isFinite(p.maximum))
    parts.push(
      `范围 ${Number.isFinite(p.minimum) ? p.minimum : "…"}–${Number.isFinite(p.maximum) ? p.maximum : "…"}`,
    );
  if (p.default !== undefined && p.default !== null)
    parts.push(
      `默认 ${Array.isArray(p.default) ? p.default.join("、") : p.default}`,
    );
  if (p.pattern) parts.push("格式 " + p.pattern);
  if (p.type === "integer" && /Unix/.test(p.description || ""))
    parts.push("当前 Unix 秒约 " + Math.floor(Date.now() / 1000));
  return parts.filter(Boolean).join(" · ");
}
// Extension actions take every parameter through the validated `options`
// object; one input per structured catalog `params` entry.
function optionField(p) {
  const ident = "field-" + ++fieldId,
    title = p.name + (p.required ? "（必填）" : "（可选）"),
    choices = Array.isArray(p.choices) ? p.choices.map(String) : [],
    help = optionHelp(p),
    hasDefault = p.default !== undefined && p.default !== null,
    attrs = ` id="${ident}" name="opt-${esc(p.name)}" data-option="${esc(p.name)}"${p.required ? " required" : ""}`;
  if (p.type === "array" && choices.length) {
    const defaults = Array.isArray(p.default) ? p.default.map(String) : [];
    // ssh_collect lists diagnostic action ids: show their console names too.
    const actions = choices.every((c) => toolById(c));
    return (
      `<fieldset class="wide option-grid" data-option="${esc(p.name)}"><legend>${esc(title)}</legend>` +
      choices
        .map(
          (c) =>
            `<label class="check"><input type="checkbox" value="${esc(c)}" ${defaults.includes(c) ? "checked" : ""}/>${esc(actions ? choiceLabel(c) : c)}</label>`,
        )
        .join("") +
      `<p class="help wide">${esc(help + (p.required ? "" : " · 不勾选则使用服务端默认值"))}</p></fieldset>`
    );
  }
  let input;
  if (p.type === "integer")
    input =
      `<input type="number" step="1"${attrs}` +
      (Number.isFinite(p.minimum) ? ` min="${p.minimum}"` : "") +
      (Number.isFinite(p.maximum) ? ` max="${p.maximum}"` : "") +
      ` value="${esc(hasDefault ? p.default : "")}" autocomplete="off"/>`;
  else if (choices.length)
    input =
      `<select${attrs}>` +
      (hasDefault && choices.includes(String(p.default))
        ? ""
        : `<option value="">${p.required ? "请选择" : "不限（使用服务端默认值）"}</option>`) +
      choices
        .map(
          (c) =>
            `<option value="${esc(c)}" ${hasDefault && String(p.default) === c ? "selected" : ""}>${esc(c)}</option>`,
        )
        .join("") +
      "</select>";
  else {
    const pattern =
      p.type !== "array" && compilePattern(p.pattern, patternFlag)
        ? p.pattern
        : "";
    const value = hasDefault
      ? Array.isArray(p.default)
        ? p.default.join(",")
        : p.default
      : "";
    const placeholder =
      p.type === "array" ? "多个值用英文逗号分隔" : p.required ? "" : "留空不传";
    input =
      `<input type="text"${attrs}` +
      (pattern ? ` pattern="${esc(pattern)}"` : "") +
      ` value="${esc(value)}" placeholder="${placeholder}" autocomplete="off"/>`;
  }
  return (
    `<div><label for="${ident}">${esc(title)}</label>${input}` +
    (help ? `<div class="help">${esc(help)}</div>` : "") +
    "</div>"
  );
}
function optionFields(tool) {
  const params = Array.isArray(tool.params) ? tool.params : [];
  return (
    '<div class="fields">' +
    (params.length
      ? params.map(optionField).join("")
      : '<p class="help wide">此动作无需额外参数。</p>') +
    `<p class="help wide">${riskBadge(tool.risk)} 扩展诊断参数随任务以 options 提交，由服务端注册表校验；可选参数留空即不传，使用服务端默认值。</p>` +
    (Array.isArray(tool.notes) ? tool.notes : [])
      .map((note) => `<p class="help wide">${esc(note)}</p>`)
      .join("") +
    "</div>"
  );
}
// Read the dynamic inputs back into a typed options object: empty values are
// omitted, integers become numbers, arrays collect the checked choices.
function collectOptions(form, tool) {
  const options = {};
  for (const p of Array.isArray(tool.params) ? tool.params : []) {
    if (p.type === "array") {
      const group = [...form.querySelectorAll("fieldset[data-option]")].find(
        (x) => x.dataset.option === p.name,
      );
      const values = group
        ? [...group.querySelectorAll("input[type=checkbox]:checked")].map(
            (x) => x.value,
          )
        : String(getForm(form, "opt-" + p.name))
            .split(",")
            .map((x) => x.trim())
            .filter(Boolean);
      if (values.length) options[p.name] = values;
      else if (p.required) throw Error("请至少选择一项：" + p.name);
      continue;
    }
    const raw = String(getForm(form, "opt-" + p.name)).trim();
    if (!raw) {
      if (p.required) throw Error("请填写必需参数：" + p.name);
      continue;
    }
    if (p.type === "integer") {
      const value = Number(raw);
      if (!Number.isInteger(value))
        throw Error("参数 " + p.name + " 必须是整数");
      if (Number.isFinite(p.minimum) && value < p.minimum)
        throw Error("参数 " + p.name + " 不能小于 " + p.minimum);
      if (Number.isFinite(p.maximum) && value > p.maximum)
        throw Error("参数 " + p.name + " 不能大于 " + p.maximum);
      options[p.name] = value;
      continue;
    }
    if (Array.isArray(p.choices) && p.choices.length) {
      if (!p.choices.map(String).includes(raw))
        throw Error("参数 " + p.name + " 只能是 " + p.choices.join("、"));
    } else {
      const pattern = compilePattern(p.pattern);
      if (pattern && !pattern.test(raw))
        throw Error("参数 " + p.name + " 格式不符合要求：" + p.pattern);
    }
    options[p.name] = raw;
  }
  return options;
}
function updateDiagnosticInputs() {
  const form = $("#diagnostic-form");
  if (!form) return;
  const action = getForm(form, "action");
  const tool = toolById(action);
  const extension = !!tool?.extension;
  for (const [name, visible] of [
    ["symptom", action === "triage"],
    [
      "service",
      !extension &&
        (!!tool?.service_required ||
          (action === "triage" && getForm(form, "symptom") === "service_down")),
    ],
    ["minutes", !extension && (!!tool?.window_required || action === "triage")],
    ["directory_root", action === "directory"],
  ]) {
    const item = form.elements.namedItem(name);
    if (item) item.closest("div").hidden = !visible;
  }
  const box = $("#diagnostic-options");
  if (!box) return;
  if (!extension) {
    box.hidden = true;
    box.replaceChildren();
    delete box.dataset.action;
    return;
  }
  // Rebuild only when the action changes so typed values survive re-checks.
  if (box.dataset.action !== action) {
    box.innerHTML = optionFields(tool);
    box.dataset.action = action;
  }
  box.hidden = false;
}
async function pageAudit() {
  const query = new URLSearchParams({
    q: state.auditQuery,
    outcome: state.auditStatus,
    page: state.auditPage,
  });
  const data = await api("/audit/page?" + query);
  const outcomes = ["all", "success", "partial", "failed", "denied", "cancelled"]
    .map(
      (s) =>
        `<option value="${s}" ${state.auditStatus === s ? "selected" : ""}>${esc(s === "all" ? "全部结果" : statuses[s] || s)}</option>`,
    )
    .join("");
  return panel(
    "操作审计",
    `<form id="audit-search-form" class="toolbar"><input id="audit-search" aria-label="搜索审计记录" value="${esc(state.auditQuery)}" placeholder="动作、操作者或主机 ID">` +
      `<select id="audit-status" aria-label="筛选审计结果">${outcomes}</select><button class="btn" type="submit">搜索</button></form>` +
      table(
        ["时间", "操作者", "动作", "目标", "结果", "说明"],
        data.items
          .map(
            (r) =>
              `<tr><td class="date">${date(r.created_at)}</td><td class="mono">${esc(r.actor)}</td><td>${esc(actionName(r.action))}</td>` +
              `<td>${esc(r.target)}</td><td>${badge(r.outcome)}</td><td class="mono">${esc(r.detail)}</td></tr>`,
          )
          .join(""),
      ) +
      pagination("audit", data),
  );
}

async function pageFeishu() {
  const r = await api("/settings/feishu");
  const origin = r.web_protocol + "://" + r.web_public_host;
  const readonly = (label, value, wide = false) =>
    `<div${wide ? ' class="wide"' : ""}><label>${label}</label><div class="code-result">${esc(value)}</div></div>`;
  return panel(
    "飞书登录与授权管理",
    '<p class="intro">SSH MCP 控制台仅允许指定的飞书 Open ID 登录。首次初始化 Token 不再具备日常登录权限。</p>' +
      '<div class="fields">' +
      readonly("飞书应用 App ID", r.lark_app_id) +
      readonly("Web 外部访问地址", origin) +
      readonly("飞书回调地址", origin + "/api/v1/auth/callback", true) +
      `<div class="wide"><label>App Secret</label><div class="pill">${r.lark_app_secret_configured ? "已加密配置（不回显）" : "未配置"}</div></div>` +
      '</div><hr class="rule"/>' +
      '<form id="feishu-admins-form"><div class="fields">' +
      field(
        "open_ids",
        "指定管理员 Open ID（英文逗号分隔）",
        r.feishu_admin_open_ids,
        "textarea",
        null,
        true,
        "必须保留当前登录管理员；更改名单后，已移除的账号会立即失去访问权限。",
      ) +
      '</div><div class="modal-actions"><button type="submit" class="btn primary">保存管理员名单</button></div></form>',
  );
}
async function pageRetention() {
  const r = await api("/settings/retention");
  return panel(
    "历史数据保留",
    '<p class="help">每小时清理到期记录；有删除时每天最多执行一次 VACUUM。运行中的任务、凭据和已核验公钥保留。修改天数会影响下一次清理。</p><form id="retention-form"><div class="fields">' +
      [
        ["audit_days", "审计记录（天，最少 7）"],
        ["diagnostic_days", "诊断结果（天）"],
        ["scan_days", "公钥扫描历史（天）"],
        ["zabbix_days", "资产发现预览（天）"],
      ]
        .map(([k, v]) => field(k, v, r[k], "number"))
        .join("") +
      `</div><p class="muted">最近清理：${date(r.last_cleanup)} · 最近压缩：${date(r.last_vacuum)}</p>` +
      '<div class="modal-actions"><button class="btn primary" type="submit">保存保留策略</button></div></form>',
  );
}

const settingsTabs = [
  ["zabbix", "Zabbix MCP"],
  ["clients", "MCP 接入"],
  ["feishu", "飞书配置"],
  ["retention", "数据保留"],
];
async function pageSettings() {
  const tab = state.settingsTab;
  const tabs =
    '<nav class="segmented" aria-label="系统配置分类">' +
    settingsTabs
      .map(
        ([id, title]) =>
          `<button type="button" class="${tab === id ? "active" : ""}" data-action="settings-tab" data-id="${id}" aria-pressed="${tab === id}">${title}</button>`,
      )
      .join("") +
    "</nav>";
  const content =
    tab === "clients"
      ? await pageClients()
      : tab === "feishu"
        ? await pageFeishu()
        : tab === "retention"
          ? await pageRetention()
          : zabbixConnectionPanel((await api("/zabbix/config")).config);
  return (
    '<div class="page-intro"><p>集中管理 Zabbix MCP 连接、SSH MCP 接入授权与飞书登录配置。</p></div>' +
    tabs +
    content
  );
}

// Reconcile unchanged nodes so polling does not replace forms, focus or scroll.
function patchNode(old, next) {
  if (old.nodeType !== next.nodeType || old.nodeName !== next.nodeName) {
    old.replaceWith(next);
    return;
  }
  if (old.isEqualNode(next)) return;
  if (old.nodeType === Node.TEXT_NODE) {
    old.nodeValue = next.nodeValue;
    return;
  }
  if (old.nodeType !== Node.ELEMENT_NODE) return;
  if (
    old.matches("input,textarea,select") ||
    (old.contains(document.activeElement) && old.matches("form"))
  )
    return;
  if (old.tagName === "DETAILS") next.open = old.open;
  if (old.id === "content") next.id = "content";
  for (const a of [...old.attributes])
    if (!next.hasAttribute(a.name)) old.removeAttribute(a.name);
  for (const a of [...next.attributes])
    if (old.getAttribute(a.name) !== a.value) old.setAttribute(a.name, a.value);
  if (
    next.children.length &&
    [...next.children].every((el) => el.dataset.key)
  ) {
    const keys = new Set([...next.children].map((el) => el.dataset.key));
    const focused = document.activeElement;
    for (const [i, item] of [...next.children].entries()) {
      const existing = [...old.children].find(
        (el) => el.dataset.key === item.dataset.key,
      );
      const current = existing || item;
      if (existing) patchNode(existing, item);
      if (old.children[i] !== current)
        old.insertBefore(current, old.children[i] || null);
    }
    for (const el of [...old.children])
      if (!keys.has(el.dataset.key)) el.remove();
    if (focused?.isConnected && document.activeElement !== focused)
      focused.focus({ preventScroll: true });
    return;
  }
  const left = [...old.childNodes],
    right = [...next.childNodes];
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    if (!left[i]) old.append(right[i]);
    else if (!right[i]) left[i].remove();
    else patchNode(left[i], right[i]);
  }
}
async function render(poll = false) {
  // Also an event listener: only an explicit `true` is a background poll.
  poll = poll === true;
  clearTimeout(timer);
  const version = ++generation;
  const [page, id] = location.hash.slice(1).split("?")[0].split("/");
  // Bookmarks from before the settings tabs existed.
  if (["clients", "feishu"].includes(page)) {
    location.replace("#settings/" + page);
    return;
  }
  state.page = page || "overview";
  if (state.loadedHash !== location.hash) {
    readFilters();
    state.loadedHash = location.hash;
  }
  if (state.page === "settings")
    state.settingsTab = settingsTabs.some(([tab]) => tab === id)
      ? id
      : state.settingsTab;
  if (state.page === "job") state.jobId = id || "";
  if (state.page === "zabbix" && id && state.zabbixRun !== id) {
    state.zabbixRun = id;
    state.zabbixPage = 1;
    state.zabbixSelected.clear();
  }
  if (state.page === "history") state.batchFilter = id || "";
  if (state.page === "keys" && id && state.batchId !== id) {
    state.batchId = id;
    state.manifest = "";
  }
  $("#page-title").textContent = titles[state.page] || "运维总览";
  breadcrumb();
  for (const el of document.querySelectorAll(".nav-link"))
    el.classList.toggle(
      "active",
      el.dataset.page === state.page ||
        (state.page === "job" && el.dataset.page === "history"),
    );
  if (!poll && state.renderedRoute !== location.hash)
    $("#content").innerHTML =
      '<div class="loading-panel" role="status"><span class="spinner"></span>正在加载…</div>';
  try {
    const pages = {
      overview: dashboard,
      hosts: pageHosts,
      zabbix: pageZabbix,
      groups: pageGroups,
      credentials: pageCredentials,
      proxies: pageProxies,
      keys: pageKeys,
      diagnostics: pageDiagnostics,
      history: pageHistory,
      job: pageJob,
      audit: pageAudit,
      settings: pageSettings,
    };
    const html = await (pages[state.page] || dashboard)();
    if (version !== generation) return;
    const content = $("#content"),
      scroll = document.scrollingElement.scrollTop;
    if (poll) {
      const next = content.cloneNode(false);
      next.innerHTML = html;
      patchNode(content, next);
      document.scrollingElement.scrollTop = scroll;
    } else content.innerHTML = html;
    state.renderedRoute = location.hash;
    if (state.page === "diagnostics") {
      const field = document.querySelector("#diagnostic-form [name=action]");
      if (
        state.diagnosticAction &&
        [...field.options].some((x) => x.value === state.diagnosticAction)
      )
        field.value = state.diagnosticAction;
      updateDiagnosticInputs();
    }
    const discoverButton = document.querySelector(
      "#zabbix-discover-form button[type=submit]",
    );
    if (discoverButton) discoverButton.disabled = !!state.zabbixPolling;
    updateSelection();
    const pending =
      (state.page === "job" &&
        ["queued", "running"].includes(state.currentJob?.status)) ||
      (state.page === "history" && state.pollHistory) ||
      (state.page === "keys" && state.keyDetail?.batch.status === "running") ||
      (state.page === "zabbix" && state.zabbixPolling);
    if (pending) timer = setTimeout(() => render(true), 3000);
  } catch (e) {
    if (version === generation)
      $("#content").innerHTML =
        `<div class="inline-error" role="alert">${esc(e.message)}</div>`;
  }
}
function updateSelection() {
  const count = $("#selected-count");
  if (count) count.textContent = `已选 ${state.selected.size} 台（跨页保留）`;
  const boxes = [...document.querySelectorAll(".host-selected")];
  boxes.forEach((b) => (b.checked = state.selected.has(Number(b.dataset.id))));
  const ready = [...state.selected].filter((id) =>
    canExecute(state.selectedHosts.get(id) || {}),
  ).length;
  for (const [name, label] of [
    ["test-selected", "测试 SSH"],
    ["diagnose-selected", "批量诊断"],
  ]) {
    const button = document.querySelector(`[data-action="${name}"]`);
    if (button)
      button.textContent = `${label}（${ready}/${state.selected.size} 可执行）`;
  }
  const page = $("#select-page");
  if (page) {
    const count = boxes.filter((b) => b.checked).length;
    page.checked = !!boxes.length && count === boxes.length;
    page.indeterminate = count > 0 && count < boxes.length;
    page.disabled = !boxes.length;
  }
}

async function login() {
  try {
    currentUser = await api("/auth/me");
    csrfToken = currentUser.csrf || "";
    state.tools = await api("/tools");
    $("#whoami").textContent = currentUser.name;
    $("#avatar").textContent = String(currentUser.name || "?").slice(0, 1);
    fetch("/healthz")
      .then((r) => r.json())
      .then((h) => ($("#version").textContent = "v" + h.version))
      .catch(() => ($("#version").textContent = "版本未知"));
    $("#login").hidden = true;
    $("#app").hidden = false;
    await render();
    clearTimeout(state.taskTimer);
    taskIndicator();
  } catch (e) {
    $("#app").hidden = true;
    $("#login").hidden = false;
    const message = $("#login-error");
    // Not being signed in yet is the normal state of this screen, not an error.
    message.textContent = e.status === 401 ? "" : e.message;
    try {
      const r = await fetch("/api/v1/setup/status");
      if (r.ok && (await r.json()).setup_required) {
        message.textContent = "系统尚未初始化，请先进入初始化向导。";
        message.className = "notice";
      }
    } catch {}
    message.hidden = !message.textContent;
  }
}
$("#logout").addEventListener("click", async () => {
  try {
    await api("/auth/logout", "POST");
    location.reload();
  } catch (e) {
    notice(e.message, true);
  }
});
$("#reload").addEventListener("click", render);
$("#nav").addEventListener("click", (e) => {
  const b = e.target.closest("[data-page]");
  if (b) {
    notice("");
    go(b.dataset.page);
  }
});
$("#notice").addEventListener("click", () => notice(""));
$("#editor-close").addEventListener("click", closeModal);
$("#editor-cancel").addEventListener("click", closeModal);
$("#editor").addEventListener("cancel", () => clearEditor());
$("#editor-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!state.editor) return;
  const save = $("#editor-form").querySelector("button[type=submit]");
  save.disabled = true;
  const error = $("#editor-feedback");
  error.hidden = true;
  error.textContent = "";
  try {
    const result = await state.editor(e.target);
    closeModal();
    notice(result?.notice || "保存成功");
    await render();
    if (result?.token) {
      openModal(
        "保存客户端令牌",
        '<div class="wide"><p class="notice">仅显示这一次。关闭后不能再次读取，可撤销后重新签发。</p>' +
          field(
            "new_token",
            "MCP 接入令牌",
            result.token,
            "textarea",
            null,
            true,
          ) +
          "</div>" +
          btn("copy-token", "复制令牌"),
        null,
      );
      $("#editor-fields textarea").readOnly = true;
    }
  } catch (ex) {
    error.textContent = ex.message;
    error.hidden = false;
    error.scrollIntoView({ block: "nearest" });
  } finally {
    save.disabled = false;
  }
});
function hostFields(h = {}) {
  const selected = h.group_ids || [];
  const gs = state.groups
    .map(
      (g) =>
        `<label class="check"><input type="checkbox" class="group-check" value="${g.id}" ${selected.includes(g.id) ? "checked" : ""}/> ${esc(g.name)}</label>`,
    )
    .join("");
  return (
    field("name", "资产名称", h.name || "") +
    field("asset_type", "资产类型", h.asset_type || "linux", "text", [
      ["linux", "Linux 服务器"],
      ["windows", "Windows 服务器（仅登记）"],
      ["network", "网络设备（仅登记）"],
      ["other", "其他（仅登记）"],
    ]) +
    field("address", "内网 IP 地址", h.address || "") +
    field("port", "SSH 端口", h.port || 22, "number") +
    field("username", "SSH 用户名", h.username || "root") +
    field("zabbix_hostid", "Zabbix Host ID（可选）", h.zabbix_hostid || "") +
    field("credential_id", "SSH 凭据", h.credential_id || "", "text", [
      ["", "未绑定"],
      ...state.credentials.map((c) => [c.id, c.name]),
    ]) +
    field("proxy_id", "跳板（可选）", h.proxy_id || "", "text", [
      ["", "直连"],
      ...state.proxies.map((p) => [p.id, p.name]),
    ]) +
    field("mode", "诊断模式", h.mode || "standard", "text", [
      ["standard", "A · 标准免 Agent"],
      ["gateway", "B · 受限强制命令网关"],
    ]) +
    field(
      "host_key",
      "已核验 SSH 主机公钥",
      "",
      "textarea",
      null,
      true,
      h.id
        ? "留空表示保留当前已核验主机公钥；也可以使用批量公钥核验流程。"
        : "建议先留空，保存后批量获取候选指纹并在可信渠道核实。",
    ) +
    '<div class="wide">' +
    field(
      "enabled",
      "启用资产",
      h.enabled === undefined ? true : Boolean(h.enabled),
      "checkbox",
    ) +
    "</div>" +
    `<div class="wide"><label class="check"><input type="checkbox" name="gateway_approved" ${h.gateway_approved ? "checked" : ""}/> 已核实受限强制命令网关（仅 B 模式）</label></div>` +
    '<div class="wide"><label>所属主机组</label>' +
    (gs || '<div class="muted">暂无主机组</div>') +
    "</div>"
  );
}
function hostBody(form) {
  return {
    name: getForm(form, "name"),
    asset_type: getForm(form, "asset_type"),
    address: getForm(form, "address"),
    port: Number(getForm(form, "port")),
    username: getForm(form, "username"),
    zabbix_hostid: getForm(form, "zabbix_hostid") || null,
    credential_id: numberOrNull(getForm(form, "credential_id")),
    proxy_id: numberOrNull(getForm(form, "proxy_id")),
    mode: getForm(form, "mode"),
    gateway_approved: checkbox(form, "gateway_approved"),
    host_key: getForm(form, "host_key"),
    enabled: checkbox(form, "enabled"),
    group_ids: [...form.querySelectorAll(".group-check:checked")].map((x) =>
      Number(x.value),
    ),
  };
}
function keyEditor() {
  return (
    field("name", "凭据名称", "诊断专用 SSH 密钥") +
    field("passphrase", "私钥口令（可选）", "", "password") +
    field(
      "key_source",
      "私钥提供方式",
      "file",
      "text",
      [
        ["file", "上传密钥文件"],
        ["paste", "粘贴私钥内容"],
      ],
      true,
    ) +
    '<div class="wide credential-upload"><label for="ssh-private-key-file">SSH 私钥文件</label>' +
    '<input id="ssh-private-key-file" name="key_file" type="file" required aria-describedby="key-file-status">' +
    '<p id="key-file-status" class="help" role="status">支持 OpenSSH / PEM 私钥，包括无后缀文件、.pem、.key；最大 16 KB。加密私钥需填写口令。</p></div>' +
    field(
      "private_key",
      "完整 SSH 私钥（不回显）",
      "",
      "textarea",
      null,
      true,
      "私钥使用应用持久化的 Fernet 主密钥加密后存储。",
    )
  );
}

function updateCredentialInputs() {
  const form = $("#editor-form");
  const source = form.elements.namedItem("key_source");
  if (!source) return;
  const fromFile = source.value === "file";
  for (const [name, visible] of [
    ["key_file", fromFile],
    ["private_key", !fromFile],
  ]) {
    const item = form.elements.namedItem(name);
    item.closest("div").hidden = !visible;
    item.disabled = !visible;
    item.required = visible;
  }
}

async function credentialBody(form, existingName) {
  const name = existingName || getForm(form, "name");
  const passphrase = getForm(form, "passphrase");
  let material = getForm(form, "private_key");
  if (getForm(form, "key_source") === "file") {
    const file = form.elements.namedItem("key_file").files?.[0];
    if (!file) throw Error("请选择 SSH 私钥文件");
    if (!file.size || file.size > 16000)
      throw Error("密钥文件不能为空，大小不能超过 16 KB（16000 字节）");
    if (/\.pub$/i.test(file.name))
      throw Error("请选择私钥文件，.pub 是公钥文件，不能用于 SSH 登录");
    material = await file.text();
  }
  material = material
    .replace(/^\uFEFF/, "")
    .replace(/\r\n/g, "\n")
    .trim();
  if (/^PuTTY-User-Key-File-/i.test(material))
    throw Error("暂不支持 PuTTY .ppk，请先导出为 OpenSSH 私钥");
  if (
    material.length < 64 ||
    material.length > 16000 ||
    !/^-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/.test(material)
  )
    throw Error("私钥格式无效，请选择 OpenSSH 或 PEM 格式的 SSH 私钥");
  return { name, passphrase, private_key: material };
}

function clearCredentialFeedback() {
  if (!$("#editor-form [name=key_source]")) return;
  $("#editor-feedback").hidden = true;
  $("#editor-feedback").textContent = "";
}
$("#editor-fields").addEventListener("input", clearCredentialFeedback);
$("#editor-fields").addEventListener("change", (e) => {
  clearCredentialFeedback();
  if (e.target.name === "key_source") updateCredentialInputs();
  if (e.target.name === "key_file") {
    const file = e.target.files?.[0];
    $("#key-file-status").textContent = file
      ? `已选择：${file.name} · ${formatSize(file.size)}。保存时校验私钥与口令。`
      : "请选择 OpenSSH / PEM 私钥文件，最大 16 KB。";
  }
});
$("#content").addEventListener("input", (e) => {
  if (e.target.id === "trusted-fingerprints") state.manifest = e.target.value;
});

$("#content").addEventListener("change", (e) => {
  if (e.target.classList.contains("zabbix-group-check")) {
    if (e.target.checked) state.zabbixGroupIds.add(e.target.value);
    else state.zabbixGroupIds.delete(e.target.value);
  }
  if (e.target.classList.contains("zabbix-host-check")) {
    if (e.target.checked) state.zabbixSelected.add(e.target.value);
    else state.zabbixSelected.delete(e.target.value);
    zabbixSelectedCount();
  }
  if (e.target.name === "action") state.diagnosticAction = e.target.value;
  if (["action", "symptom"].includes(e.target.name)) updateDiagnosticInputs();
  if (e.target.classList.contains("host-selected")) {
    const id = Number(e.target.dataset.id);
    if (e.target.checked) state.selected.add(id);
    else state.selected.delete(id);
  }
  if (e.target.id === "batch-select") {
    state.batchId = e.target.value;
    state.manifest = "";
    go("keys/" + state.batchId);
  }
  if (e.target.id === "select-page") {
    state.hosts.forEach((h) =>
      e.target.checked ? state.selected.add(h.id) : state.selected.delete(h.id),
    );
  }
  if (e.target.id === "history-status") {
    state.historyStatus = e.target.value;
    state.historyPage = 1;
    writeFilters();
    render();
  }
  updateSelection();
});
$("#content").addEventListener("submit", async (e) => {
  if (e.target.id.startsWith("zabbix-")) {
    e.preventDefault();
    e.target.dataset.submitter = e.submitter?.name || "";
    await submitZabbixForm(e.target);
    return;
  }
  if (e.target.id === "feishu-admins-form") {
    e.preventDefault();
    const button = e.target.querySelector("button[type=submit]");
    button.disabled = true;
    try {
      await api("/settings/admins", "PUT", {
        open_ids: e.target.elements.open_ids.value,
      });
      notice("管理员名单已保存，权限立即生效。");
    } catch (ex) {
      notice(ex.message, true);
    } finally {
      button.disabled = false;
    }
    return;
  }
  if (e.target.id === "host-search-form") {
    e.preventDefault();
    state.hostQuery = $("#host-filter").value.trim();
    state.hostGroup = $("#host-group").value;
    state.hostStatus = $("#host-status").value;
    state.hostPage = 1;
    state.selected.clear();
    writeFilters();
    render();
    return;
  }
  if (e.target.id === "audit-search-form") {
    e.preventDefault();
    state.auditQuery = $("#audit-search").value.trim();
    state.auditStatus = $("#audit-status").value;
    state.auditPage = 1;
    writeFilters();
    render();
    return;
  }
  if (e.target.id === "retention-form") {
    e.preventDefault();
    try {
      await api(
        "/settings/retention",
        "PUT",
        Object.fromEntries(
          [...new FormData(e.target).entries()].map(([k, v]) => [k, Number(v)]),
        ),
      );
      notice("保留策略已保存");
    } catch (ex) {
      notice(ex.message, true);
    }
    return;
  }
  if (e.target.id !== "diagnostic-form") return;
  e.preventDefault();
  const form = e.target,
    button = form.querySelector("button[type=submit]"),
    version = generation;
  button.disabled = true;
  try {
    const action = getForm(form, "action");
    const host_ids = [...state.targets.keys()];
    const tool = toolById(action);
    let body;
    if (tool?.extension) {
      // Extension actions take every parameter through `options`; the
      // classic service/minutes/directory fields stay out of the request.
      const options = collectOptions(form, tool);
      body = {
        host_ids,
        action,
        ...(Object.keys(options).length ? { options } : {}),
      };
    } else
      body = {
        host_ids,
        action,
        service:
          ["logs", "service"].includes(action) ||
          (action === "triage" && getForm(form, "symptom") === "service_down")
            ? getForm(form, "service")
            : null,
        minutes: Number(getForm(form, "minutes")),
        ...(action === "triage" ? { symptom: getForm(form, "symptom") } : {}),
        directory_root:
          action === "directory" ? getForm(form, "directory_root").trim() : null,
      };
    const result = await api("/jobs", "POST", body);
    notice(
      `已接受 ${result.total} 项；跳过 ${result.skipped.length} 项。` +
        result.skipped.map((x) => `主机 ${x.host_id}: ${x.reason}`).join("；"),
      !result.total,
    );
    if (!result.total) return;
    if (version === generation) {
      state.historyPage = 1;
      state.historyStatus = "all";
      go(
        result.total === 1
          ? "job/" + result.job_ids[0]
          : "history/" + result.batch_id,
      );
    }
  } catch (ex) {
    notice(ex.message, true);
  } finally {
    button.disabled = false;
  }
});
document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-action]");
  if (!b || b.disabled) return;
  const action = b.dataset.action,
    id = b.dataset.id;
  b.disabled = true;
  try {
    if (action === "settings-tab") {
      go("settings/" + id);
      return;
    }
    if (action.startsWith("zabbix-")) {
      await zabbixAction(action, id);
      return;
    }
    if (action === "tool-category") {
      state.toolCategory = id;
      if (
        id !== "全部" &&
        !state.tools.some(
          (t) => t.id === state.diagnosticAction && t.category === id,
        )
      )
        state.diagnosticAction = state.tools.find((t) => t.category === id)?.id;
      await render();
      return;
    }
    if (action === "choose-tool") {
      const form = $("#diagnostic-form");
      state.diagnosticAction = id;
      form.elements.action.value = id;
      updateDiagnosticInputs();
      form.scrollIntoView({ behavior: "smooth", block: "center" });
      return;
    }
    if (action === "refresh") {
      render();
      return;
    }
    if (action.startsWith("open-")) {
      go(action.slice(5));
      return;
    }
    if (action === "page-prev" || action === "page-next") {
      const key = id + "Page";
      state[key] = Math.max(
        1,
        Math.min(
          state[id + "Pages"],
          state[key] + (action === "page-next" ? 1 : -1),
        ),
      );
      writeFilters();
      await render();
      return;
    }
    if (action === "job-detail") {
      $("#host-drawer").close();
      go("job/" + id);
      return;
    }
    if (action === "all-history") {
      state.historyPage = 1;
      go("history");
      return;
    }
    if (action === "cancel-job") {
      await api("/jobs/" + id + "/cancel", "POST");
      notice("已请求取消，连接结束后保留已有结果。");
      await render();
      return;
    }
    if (action === "retry-job") {
      const r = await api("/jobs/" + id + "/retry", "POST");
      go("job/" + r.job_ids[0]);
      return;
    }
    if (action === "clear-selected") {
      state.selected.clear();
      updateSelection();
      return;
    }
    if (action === "enable-selected" || action === "disable-selected") {
      if (!state.selected.size) throw Error("请先选择主机");
      const enabled = action === "enable-selected";
      if (
        !(await askConfirmation(
          `确认${enabled ? "启用" : "停用"}所选 ${state.selected.size} 台主机？` +
            (enabled ? "" : "停用会立即阻止新的诊断。"),
        ))
      )
        return;
      await api("/hosts/bulk-enabled", "POST", {
        host_ids: [...state.selected],
        enabled,
      });
      state.selected.clear();
      await render();
      return;
    }
    if (action === "diagnose-selected") {
      if (!state.selected.size || state.selected.size > 100)
        throw Error("批量诊断请选择 1–100 台主机");
      await setTargets([...state.selected]);
      return;
    }
    if (action === "bind-selected") {
      if (!state.selected.size) throw Error("请先选择需要绑定的 Linux 主机");
      if (!state.credentials.length) throw Error("请先在 SSH 凭据页面添加私钥");
      openModal(
        "批量绑定 SSH 访问",
        field(
          "credential_id",
          "SSH 凭据",
          state.credentials[0]?.id,
          "text",
          state.credentials.map((c) => [c.id, c.name]),
        ) +
          field("username", "SSH 用户名", "root") +
          field("port", "SSH 端口", 22, "number") +
          field("proxy_id", "跳板", "", "text", [
            ["", "直连"],
            ...state.proxies.map((p) => [p.id, p.name]),
          ]) +
          '<p class="notice wide">应用到所选全部 Linux 主机。端口或跳板发生变化时，需要重新核验公钥；凭据变更后需要重新测试 SSH。</p>',
        (form) =>
          api("/hosts/bulk-access", "POST", {
            host_ids: [...state.selected],
            credential_id: Number(getForm(form, "credential_id")),
            username: getForm(form, "username"),
            port: Number(getForm(form, "port")),
            proxy_id: numberOrNull(getForm(form, "proxy_id")),
          }),
      );
      return;
    }
    if (action === "test-selected") {
      if (!state.selected.size || state.selected.size > 100)
        throw Error("请选择 1–100 台已绑定凭据并核验公钥的主机");
      const r = await api("/jobs", "POST", {
        host_ids: [...state.selected],
        action: "connection",
      });
      notice(
        `接受 ${r.total} 台；跳过 ${r.skipped.length} 台。` +
          r.skipped.map((x) => `${x.host_id}: ${x.reason}`).join("；"),
        !r.total,
      );
      if (r.total)
        go(r.total === 1 ? "job/" + r.job_ids[0] : "history/" + r.batch_id);
      return;
    }
    if (action === "import-hosts") {
      openModal(
        "从表格登记主机",
        field(
          "rows",
          "粘贴 Excel 表格内容",
          "",
          "textarea",
          null,
          true,
          "每行：主机名称、内网 IP、Zabbix Host ID（可留空）。从 Excel 复制三列并粘贴，使用制表符分隔；最多 1000 行。",
        ) +
          field("username", "SSH 用户名", "root") +
          field("credential_id", "统一 SSH 凭据", "", "text", [
            ["", "稍后绑定"],
            ...state.credentials.map((c) => [c.id, c.name]),
          ]),
        (form) => {
          const rows = getForm(form, "rows")
            .trim()
            .split(/\r?\n/)
            .filter(Boolean);
          if (!rows.length || rows.length > 1000)
            throw Error("请粘贴 1–1000 行资产");
          const hosts = rows.map((line, index) => {
            const cells = line.split("\t").map((x) => x.trim());
            if (cells.length < 2 || cells.length > 3)
              throw Error(`第 ${index + 1} 行应为 2–3 列，使用 Excel 制表符分隔`);
            return {
              name: cells[0],
              address: cells[1],
              zabbix_hostid: cells[2] || null,
              username: getForm(form, "username"),
              credential_id: numberOrNull(getForm(form, "credential_id")),
            };
          });
          return api("/hosts/import", "POST", { hosts });
        },
      );
      return;
    }
    if (action === "new-client") {
      const basic = [
        "connection",
        "health",
        "capabilities",
        "cpu",
        "memory",
        "disk",
        "network",
        "system",
      ];
      openModal(
        "创建 MCP 客户端",
        field("name", "客户端名称", "AI Ops Platform") +
          field("valid_days", "有效期（天）", 90, "number") +
          clientScopeFields(basic),
        (form) =>
          api("/mcp/clients", "POST", {
            name: getForm(form, "name"),
            valid_days: Number(getForm(form, "valid_days")),
            ...clientScopeBody(form),
          }),
      );
      return;
    }
    if (action === "edit-client") {
      const c = state.clients?.find((x) => x.id === id);
      if (!c) throw Error("客户端不存在，请刷新后重试");
      const known = new Set(state.tools.map((t) => t.id));
      const dropped = c.actions.filter((a) => !known.has(a));
      openModal(
        "编辑 MCP 客户端权限",
        field(
          "name",
          "客户端名称",
          c.name,
          "text",
          null,
          true,
          `令牌（${c.prefix}…）保持不变；保存后从下一次 MCP 请求起按新范围授权，执行中的 SSH 不受影响。`,
        ) +
          (dropped.length
            ? `<p class="notice wide">以下动作已不在当前诊断目录中，保存后将移除：${esc(dropped.join("、"))}</p>`
            : "") +
          clientScopeFields(c.actions, c),
        async (form) => {
          await api(
            "/mcp/clients/" + encodeURIComponent(c.id),
            "PUT",
            clientScopeBody(form),
          );
          return { notice: `已更新「${c.name}」的授权范围，令牌不变。` };
        },
      );
      $("#editor-fields [name=name]").readOnly = true;
      return;
    }
    if (action === "recommend-client-actions") {
      const boxes = [
        ...document.querySelectorAll("#editor-fields [name=client_action]"),
      ];
      for (const box of boxes)
        box.checked = recommendedClientActions.includes(box.value);
      const hint = $("#client-action-hint");
      if (hint)
        hint.textContent = `已按推荐勾选 ${boxes.filter((box) => box.checked).length} 项（不含 jvm、triage、directory、peer_*），可继续手动调整。`;
      return;
    }
    if (action === "copy-token") {
      // copyText falls back to execCommand on plain-HTTP intranet access.
      await copyText($("#editor-fields [name=new_token]").value);
      b.textContent = "已复制";
      return;
    }
    if (action === "revoke-client") {
      const c = state.clients.find((x) => String(x.id) === id);
      if (!c) throw Error("该客户端已不存在，请刷新页面后再操作。");
      if (
        !(await askConfirmation(
          `撤销「${c.name}」的令牌？该客户端将无法继续访问 MCP，其他客户端不受影响。`,
        ))
      )
        return;
      await api("/mcp/clients/" + id + "/revoke", "POST");
      await render();
      return;
    }
    if (action === "toggle-legacy") {
      if (
        !(await askConfirmation(
          state.legacyEnabled
            ? "停用原始 mcp.token？请先确认 AI 平台已改用新的客户端令牌。"
            : "启用原始令牌会授予全部主机和工具权限，确认启用？",
        ))
      )
        return;
      await api("/settings/mcp-legacy", "PUT", {
        enabled: !state.legacyEnabled,
      });
      await render();
      return;
    }
    if (action === "new-host" || action === "edit-host") {
      const h =
        action === "edit-host"
          ? currentHost(id) || (await api("/hosts/" + id + "/detail")).host
          : {};
      $("#host-drawer").close();
      openModal(
        h.id ? "编辑主机资产" : "登记 Linux 主机",
        hostFields(h),
        (form) =>
          api(
            "/hosts" + (h.id ? "/" + h.id : ""),
            h.id ? "PUT" : "POST",
            hostBody(form),
          ),
      );
    } else if (action === "new-group" || action === "edit-group") {
      const g = state.groups.find((x) => String(x.id) === id);
      openModal(
        g ? "编辑主机组" : "创建主机组",
        field("name", "主机组名称", g?.name || ""),
        (form) =>
          api("/groups" + (g ? "/" + g.id : ""), g ? "PUT" : "POST", {
            name: getForm(form, "name"),
          }),
      );
    } else if (action === "delete-group") {
      if (
        !(await askConfirmation(
          "删除此分组？主机保留，仅通过该分组授权的 MCP 客户端将失去相应主机访问权限。",
        ))
      )
        return;
      await api("/groups/" + id, "DELETE");
      await render();
    } else if (action === "new-credential" || action === "rotate-credential") {
      const prev = state.credentials.find((x) => String(x.id) === id);
      openModal(
        prev ? "轮换 SSH 私钥" : "新增 SSH 凭据",
        keyEditor(),
        async (form) =>
          api(
            "/credentials" + (prev ? "/" + prev.id : ""),
            prev ? "PUT" : "POST",
            await credentialBody(form, prev?.name),
          ),
      );
      if (prev) $("#editor-fields input[name=name]").value = prev.name;
      updateCredentialInputs();
    } else if (action === "new-proxy" || action === "edit-proxy") {
      const proxy = state.proxies.find((p) => String(p.id) === id) || {};
      openModal(
        proxy.id ? "编辑 SSH 跳板" : "新增 SSH 跳板",
        field("name", "跳板名称", proxy.name || "") +
          field("address", "内网 IP 地址", proxy.address || "") +
          field("port", "SSH 端口", proxy.port || 22, "number") +
          field("username", "SSH 用户名", proxy.username || "root") +
          field(
            "credential_id",
            "SSH 凭据",
            proxy.credential_id || "",
            "text",
            state.credentials.map((c) => [c.id, c.name]),
          ) +
          field(
            "host_key",
            "已核验跳板公钥",
            proxy.host_key || "",
            "textarea",
            null,
            true,
          ),
        (form) =>
          api(
            "/proxies" + (proxy.id ? "/" + proxy.id : ""),
            proxy.id ? "PUT" : "POST",
            {
              name: getForm(form, "name"),
              address: getForm(form, "address"),
              port: Number(getForm(form, "port")),
              username: getForm(form, "username"),
              credential_id: Number(getForm(form, "credential_id")),
              host_key: getForm(form, "host_key"),
            },
          ),
      );
    } else if (action === "test") {
      await startJob(Number(id), "connection");
    } else if (action === "diagnose-host") {
      $("#host-drawer").close();
      await setTargets([Number(id)]);
    } else if (action === "select-filtered") {
      const r = await api("/inventory/ids?" + hostQuery());
      state.selected = new Set(r.host_ids);
      if (r.host_ids.length) {
        const items = await api("/inventory/targets", "POST", {
          host_ids: r.host_ids,
        });
        for (const h of items) state.selectedHosts.set(h.id, h);
      }
      updateSelection();
    } else if (
      action === "scan-selected" ||
      action === "scan-all-unverified" ||
      action === "retry-failed"
    ) {
      let body;
      if (action === "scan-selected") {
        const ids = [...state.selected];
        if (!ids.length) throw new Error("请先勾选至少一台主机");
        body = { host_ids: ids };
      } else if (action === "retry-failed") {
        if (!state.batchId) throw new Error("没有可重试的批次");
        body = { retry_failed_batch: state.batchId };
      } else {
        body = { unverified_only: true };
      }
      const result = await api("/host-keys/scan", "POST", body);
      state.selected.clear();
      state.batchId = result.batch_id;
      state.manifest = "";
      notice(`已提交 ${result.total} 台主机。请在可信渠道独立核对，再确认公钥。`);
      go("keys/" + result.batch_id);
    } else if (action === "confirm-batch-from-manifest") {
      await precheckManifest();
    } else if (action === "confirm-key") {
      const current = await api(
        "/host-keys/batches/" + encodeURIComponent(state.batchId),
      );
      const entry = current.items.find((x) => String(x.host_id) === id);
      openModal(
        "人工核验主机公钥",
        `<div class="wide"><p>主机：<strong>${esc(entry?.name)}</strong></p><p>候选指纹：<strong class="mono">${esc(entry?.fingerprint)}</strong>（${esc(entry?.algorithm || "算法未知")}）</p>` +
          `<p class="muted">请在目标服务器可信控制台执行 <code>${esc(hostKeyCommand(entry?.algorithm))}</code>，确认指纹后手工填入。</p></div>` +
          field(
            "fingerprint",
            "通过可信渠道独立核验的 SHA256 指纹",
            "",
            "text",
            null,
            true,
          ) +
          '<div class="wide"><label class="check"><input type="checkbox" name="confirmed"/> 我已在可信渠道独立核验，确认本次公钥属于目标服务器</label></div>',
        (form) =>
          api("/host-keys/confirm", "POST", {
            host_id: Number(id),
            independently_verified_sha256: getForm(form, "fingerprint"),
            confirmed: checkbox(form, "confirmed"),
          }),
      );
    }
  } catch (ex) {
    notice(ex.message, true);
  } finally {
    b.disabled = false;
  }
});
window.addEventListener("hashchange", render);
initPresentation();
login();
