"use strict";
const form = document.querySelector("#setup-form");
const status = document.querySelector("#setup-feedback");
function show(message, tone = "") {
  status.className = "notice " + tone;
  status.hidden = false;
  status.textContent = message;
}
(async () => {
  try {
    const r = await fetch("/api/v1/setup/status", {
      credentials: "same-origin",
    });
    const data = await r.json();
    if (!data.setup_required) {
      form.hidden = true;
      show(
        "系统已完成初始化，不能再次使用一次性凭据。请返回登录页使用飞书登录。",
      );
    }
  } catch {
    show("无法读取初始化状态，请确认服务健康。", "error");
  }
})();
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const submit = document.querySelector("#setup-submit");
  submit.disabled = true;
  status.hidden = true;
  const values = Object.fromEntries(new FormData(form).entries());
  try {
    const response = await fetch("/api/v1/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(values),
    });
    const result = await response.json();
    if (!response.ok)
      throw new Error(
        typeof result.detail === "string" ? result.detail : "保存失败",
      );
    form.reset();
    form.hidden = true;
    show(
      "初始化成功！请在飞书开发者后台配置 /api/v1/auth/callback 回调地址，然后返回登录页使用飞书账号登录。",
      "success",
    );
    const link = document.createElement("a");
    link.href = "/api/v1/auth/login";
    link.className = "btn primary";
    link.textContent = "使用飞书账号登录";
    status.after(link);
  } catch (ex) {
    show(ex.message, "error");
    submit.disabled = false;
  }
});
