"use strict";

function askConfirmation(message) {
  const dialog = document.querySelector("#action-confirm");
  document.querySelector("#action-confirm-message").textContent = message;
  dialog.returnValue = "";
  dialog.showModal();
  return new Promise((resolve) =>
    dialog.addEventListener(
      "close",
      () => resolve(dialog.returnValue === "confirm"),
      { once: true },
    ),
  );
}
function readFilters() {
  const q = new URLSearchParams(location.hash.split("?")[1] || "");
  const n = (k) => Math.max(1, Number(q.get(k)) || 1);
  if (state.page === "hosts") {
    state.hostQuery = q.get("q") || "";
    state.hostGroup = q.get("group") || "";
    state.hostStatus = q.get("status") || "all";
    state.hostPage = n("page");
    state.hostSort = q.get("sort") || "id";
    state.hostDirection = q.get("direction") || "desc";
  }
  if (state.page === "history") {
    state.historyPage = n("page");
    state.historyStatus = q.get("status") || "all";
  }
  if (state.page === "audit") {
    state.auditPage = n("page");
    state.auditQuery = q.get("q") || "";
    state.auditStatus = q.get("status") || "all";
  }
}
function writeFilters() {
  let data;
  if (state.page === "hosts")
    data = {
      q: state.hostQuery,
      group: state.hostGroup,
      status: state.hostStatus,
      page: state.hostPage,
      sort: state.hostSort,
      direction: state.hostDirection,
    };
  if (state.page === "history")
    data = { page: state.historyPage, status: state.historyStatus };
  if (state.page === "audit")
    data = {
      page: state.auditPage,
      q: state.auditQuery,
      status: state.auditStatus,
    };
  if (data) {
    history.replaceState(
      null,
      "",
      location.hash.split("?")[0] + "?" + new URLSearchParams(data),
    );
    state.loadedHash = location.hash;
  }
}
const canExecute = (h) =>
  h.asset_type === "linux" && h.enabled && h.has_host_key && !!h.credential_id;
async function setTargets(ids) {
  const items = await api("/inventory/targets", "POST", { host_ids: ids });
  state.targets = new Map(items.map((h) => [h.id, h]));
  go("diagnostics");
}
function selectedTargets() {
  return [...state.targets.values()]
    .map(
      (h) =>
        "<li><div><strong>" +
        esc(h.name) +
        "</strong><small>" +
        esc(h.address) +
        " · Host ID " +
        esc(h.zabbix_hostid || "未关联") +
        " · " +
        esc(
          (h.group_ids || [])
            .map((id) => state.groups.find((g) => g.id === id)?.name)
            .filter(Boolean)
            .join(" / "),
        ) +
        "</small>" +
        (!canExecute(h) ? badge(h.readiness) : "") +
        "</div>" +
        btn("remove-target", "移除", h.id) +
        "</li>",
    )
    .join("");
}
function targetOptions(items) {
  return (
    items
      .map(
        (h) =>
          '<label class="target-option"><input type="checkbox" class="target-check" data-id="' +
          h.id +
          '" aria-label="选择诊断目标 ' +
          esc(h.address) +
          '" ' +
          (state.targets.has(h.id) ? "checked" : "") +
          "><span><strong>" +
          esc(h.name) +
          "</strong><small>" +
          esc(h.address) +
          " · Host ID " +
          esc(h.zabbix_hostid || "未关联") +
          "</small></span></label>",
      )
      .join("") || '<p class="muted">没有匹配且已准备好 SSH 的主机。</p>'
  );
}
function updateTargets() {
  const list = $("#diagnostic-targets");
  if (!list) return;
  list.innerHTML = selectedTargets();
  $("#target-count").textContent =
    "明确目标 " + state.targets.size + " 台（最多 100 台）";
  for (const el of document.querySelectorAll(".target-check"))
    el.checked = state.targets.has(Number(el.dataset.id));
  $("#diagnostic-form button[type=submit]").disabled = !state.targets.size;
}
let targetGeneration = 0,
  targetTimer;
async function searchTargets() {
  const version = ++targetGeneration,
    q = $("#target-search")?.value || "";
  state.targetQuery = q;
  const data = await api(
    "/inventory/hosts?" +
      new URLSearchParams({ q, status: "ready", page_size: 20 }),
  );
  if (version !== targetGeneration || !$("#target-options")) return;
  state.targetCandidates = data.items;
  $("#target-options").innerHTML = targetOptions(data.items);
  $("#target-search-count").textContent =
    "找到 " +
    data.total +
    " 台，显示前 20 台；可继续输入名称、IP、Host ID 或组名缩小范围。";
}
async function targetPicker() {
  const data = await api(
    "/inventory/hosts?" +
      new URLSearchParams({
        q: state.targetQuery,
        status: "ready",
        page_size: 20,
      }),
  );
  state.targetCandidates = data.items;
  return (
    '<div class="wide target-picker"><label for="target-search">搜索并选择诊断目标</label><input id="target-search" autocomplete="off" value="' +
    esc(state.targetQuery) +
    '" placeholder="名称 / IP / Host ID / 主机组"><p id="target-search-count" class="help">找到 ' +
    data.total +
    ' 台，显示前 20 台；每批最多 100 台。</p><div id="target-options" class="target-options">' +
    targetOptions(data.items) +
    '</div><h3 id="target-count">明确目标 ' +
    state.targets.size +
    ' 台（最多 100 台）</h3><ul id="diagnostic-targets" class="target-list">' +
    selectedTargets() +
    "</ul></div>"
  );
}
async function showHost(id) {
  const data = await api("/hosts/" + id + "/detail"),
    h = data.host;
  state.drawerHost = h;
  const tests = data.last_test;
  $("#host-drawer-content").innerHTML =
    '<div class="section-head"><div><h2>' +
    esc(h.name) +
    '</h2><p class="mono">' +
    esc(h.address) +
    ":" +
    h.port +
    " · Host ID " +
    esc(h.zabbix_hostid || "未关联") +
    "</p></div>" +
    btn("close-drawer", "关闭") +
    '</div><h3>准备情况</h3><ul class="readiness-list">' +
    [
      [
        !!h.credential_id,
        "SSH 凭据",
        h.credential_id ? "已绑定" : "等待绑定凭据",
      ],
      [
        h.has_host_key,
        "主机身份",
        h.has_host_key ? h.host_fingerprint : "等待扫描并独立核验指纹",
      ],
      [
        h.last_status === "success",
        "连接测试",
        tests
          ? statuses[tests.status] + " · " + date(tests.completed_at)
          : "尚未测试",
      ],
    ]
      .map(
        ([ok, label, text]) =>
          '<li><span class="' +
          (ok ? "check-good" : "check-pending") +
          '">' +
          (ok ? "已完成" : "待处理") +
          "</span><div><strong>" +
          label +
          "</strong><small>" +
          esc(text) +
          "</small></div></li>",
      )
      .join("") +
    "</ul>" +
    (tests?.error
      ? '<p class="inline-error">最近测试失败：' + esc(tests.error) + "</p>"
      : "") +
    '<div class="actions">' +
    btn("prepare-host", "准备下一步", h.id, "primary") +
    btn("edit-host", "编辑资产", h.id) +
    btn("diagnose-host", "诊断", h.id) +
    '</div><h3>常用诊断</h3><div class="actions">' +
    ["health", "cpu", "memory", "disk"]
      .map(
        (a) =>
          '<button type="button" class="btn small" data-action="quick-diagnose" data-id="' +
          h.id +
          '" data-tool="' +
          a +
          '" ' +
          (!canExecute(h) ? "disabled" : "") +
          ">" +
          esc(actionName(a)) +
          "</button>",
      )
      .join("") +
    "</div><h3>最近诊断</h3>" +
    table(
      ["动作", "状态", "时间", "详情"],
      data.recent
        .map(
          (j) =>
            "<tr><td>" +
            esc(actionName(j.action)) +
            "</td><td>" +
            badge(j.status) +
            "</td><td>" +
            date(j.created_at) +
            "</td><td>" +
            btn("job-detail", "查看", j.id) +
            "</td></tr>",
        )
        .join(""),
    );
  $("#host-drawer").showModal();
}
async function prepareHost(id) {
  const { host: h } = await api("/hosts/" + id + "/detail");
  if ($("#host-drawer").open) $("#host-drawer").close();
  if (h.asset_type !== "linux") {
    notice("当前仅提供 Linux SSH 诊断，其他设备保留资产登记。");
    go("hosts?status=unsupported");
    return;
  }
  if (!h.enabled) {
    [state.credentials, state.proxies, state.groups] = await Promise.all([
      api("/credentials"),
      api("/proxies"),
      api("/groups"),
    ]);
    openModal("编辑并启用资产 · " + h.name, hostFields(h), (form) =>
      api("/hosts/" + h.id, "PUT", hostBody(form)),
    );
    return;
  }
  if (!h.credential_id) {
    state.credentials = await api("/credentials");
    if (!state.credentials.length) {
      notice("先添加 SSH 凭据，再从资产详情绑定。");
      go("credentials");
      return;
    }
    openModal(
      "绑定 SSH 访问 · " + h.name,
      field(
        "credential_id",
        "SSH 凭据",
        state.credentials[0].id,
        "text",
        state.credentials.map((c) => [c.id, c.name]),
      ) +
        field("username", "SSH 用户名", h.username) +
        field("port", "SSH 端口", h.port, "number"),
      (form) =>
        api("/hosts/bulk-access", "POST", {
          host_ids: [h.id],
          credential_id: Number(getForm(form, "credential_id")),
          username: getForm(form, "username"),
          port: Number(getForm(form, "port")),
          proxy_id: h.proxy_id,
        }),
    );
  } else if (!h.has_host_key) {
    const batch = await api("/host-keys/scan", "POST", { host_ids: [h.id] });
    state.batchId = batch.batch_id;
    notice("扫描只收集候选公钥；请通过独立可信渠道核验后再确认。");
    go("keys/" + batch.batch_id);
  } else if (h.last_status === "success") {
    await setTargets([h.id]);
  } else {
    const r = await api("/jobs", "POST", {
      host_ids: [h.id],
      action: "connection",
    });
    if (r.total) go("job/" + r.job_ids[0]);
    else notice(r.skipped.map((x) => x.reason).join("；"), true);
  }
}
async function batchProgress() {
  if (!state.batchFilter) return "";
  const data = await api("/jobs/batches/" + state.batchFilter);
  state.batchProgress = data;
  return (
    '<section class="batch-progress"><h3>批次进度 ' +
    data.completed +
    " / " +
    data.total +
    '</h3><progress aria-label="批次进度" value="' +
    data.completed +
    '" max="' +
    Math.max(1, data.total) +
    '"></progress><div class="actions">' +
    Object.entries(data.counts)
      .map(
        ([k, v]) =>
          "<span>" + esc(statuses[k]) + ": <strong>" + v + "</strong></span>",
      )
      .join("") +
    btn(
      "retry-failed-jobs",
      "只重试失败项（" + data.counts.failed + "）",
      data.batch_id,
    ) +
    "</div>" +
    (data.skipped.length
      ? "<details><summary>提交时跳过 " +
        data.skipped.length +
        " 台（查看原因）</summary>" +
        table(
          ["资产 ID", "原因"],
          data.skipped
            .map(
              (h) =>
                "<tr><td>" +
                h.host_id +
                "</td><td>" +
                esc(h.reason) +
                "</td></tr>",
            )
            .join(""),
        ) +
        "</details>"
      : "") +
    "</section>"
  );
}
async function taskIndicator() {
  if (!currentUser) return;
  try {
    const s = await api("/jobs/status");
    $("#task-indicator").textContent =
      "运行 " +
      s.running +
      " · SSH " +
      s.active +
      "/4 · 待执行 " +
      s.pending +
      "/200";
  } catch {}
  state.taskTimer = setTimeout(taskIndicator, 5000);
}
async function precheckManifest() {
  const manifest = $("#trusted-fingerprints")?.value.trim();
  if (!manifest) throw Error("请粘贴通过独立可信渠道取得的主机指纹清单");
  const data = await api("/host-keys/precheck", "POST", {
    batch_id: state.batchId,
    manifest,
  });
  const matched = data.items.filter((r) => r.status === "matched");
  const fields =
    '<div class="wide"><p>预检 ' +
    data.total +
    " 行，匹配 " +
    data.matched +
    " 行。只会保存匹配项；不匹配已记安全审计。保存时再次校验目标和候选指纹。</p>" +
    table(
      ["行", "目标", "预检", "原因"],
      data.items
        .map(
          (r) =>
            "<tr><td>" +
            r.line +
            "</td><td>" +
            esc(r.target || "—") +
            "</td><td>" +
            esc(
              {
                matched: "匹配",
                mismatch: "不匹配",
                not_found: "找不到",
                invalid: "格式错误",
                algorithm_mismatch: "算法不匹配",
                duplicate: "重复",
              }[r.status],
            ) +
            "</td><td>" +
            esc(r.reason) +
            "</td></tr>",
        )
        .join(""),
    ) +
    '<label class="check"><input type="checkbox" name="independent_confirmed" required>我确认这些指纹来自独立可信渠道，并已核对本次影响范围：' +
    data.matched +
    " 台主机。</label></div>";
  openModal(
    "可信指纹预检",
    fields,
    matched.length
      ? async (form) => {
          if (!checkbox(form, "independent_confirmed"))
            throw Error("请确认独立可信来源");
          const r = await api("/host-keys/confirm-batch", "POST", {
            items: matched.map(
              ({ host_id, independently_verified_sha256 }) => ({
                host_id,
                independently_verified_sha256,
              }),
            ),
            confirmed: true,
            matched_only: true,
          });
          state.manifest = "";
          notice(
            "已保存 " +
              r.count +
              " 台；跳过 " +
              r.skipped.length +
              " 台。" +
              (r.skipped.length
                ? "目标在预检后发生变化，请重新扫描并核验。"
                : ""),
          );
          return {
            ...r,
            notice:
              "已保存 " + r.count + " 台；跳过 " + r.skipped.length + " 台。",
          };
        }
      : null,
  );
}

document.addEventListener("input", (e) => {
  if (e.target.id === "target-search") {
    clearTimeout(targetTimer);
    targetTimer = setTimeout(
      () => searchTargets().catch((ex) => notice(ex.message, true)),
      220,
    );
  }
});
document.addEventListener("change", (e) => {
  if (!e.target.matches(".target-check")) return;
  const id = Number(e.target.dataset.id),
    h = state.targetCandidates.find((x) => x.id === id);
  if (e.target.checked) {
    if (state.targets.size >= 100) {
      e.target.checked = false;
      notice("每批最多 100 台", true);
      return;
    }
    if (h) state.targets.set(id, h);
  } else state.targets.delete(id);
  updateTargets();
});
document.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-action]");
  if (!b || b.disabled) return;
  const a = b.dataset.action,
    id = b.dataset.id;
  if (
    ![
      "remove-target",
      "host-detail",
      "prepare-host",
      "close-drawer",
      "quick-diagnose",
      "sort-host",
      "retry-failed-jobs",
    ].includes(a)
  )
    return;
  e.preventDefault();
  e.stopImmediatePropagation();
  try {
    if (a === "remove-target") {
      state.targets.delete(Number(id));
      updateTargets();
    }
    if (a === "host-detail") await showHost(id);
    if (a === "close-drawer") $("#host-drawer").close();
    if (a === "prepare-host") await prepareHost(id);
    if (a === "sort-host") {
      state.hostDirection =
        state.hostSort === id && state.hostDirection === "asc" ? "desc" : "asc";
      state.hostSort = id;
      state.hostPage = 1;
      writeFilters();
      await render();
    }
    if (a === "quick-diagnose") {
      $("#host-drawer").close();
      const r = await api("/jobs", "POST", {
        host_ids: [Number(id)],
        action: b.dataset.tool,
      });
      if (r.total) go("job/" + r.job_ids[0]);
      else notice(r.skipped.map((x) => x.reason).join("；"), true);
    }
    if (a === "retry-failed-jobs") {
      const r = await api("/jobs/batches/" + id + "/retry-failed", "POST");
      notice(
        "只重试失败项：接受 " +
          r.total +
          " 台；跳过 " +
          r.skipped.length +
          " 台。",
      );
      if (r.total) go("history/" + r.batch_id);
    }
  } catch (ex) {
    notice(ex.message, true);
  }
});
