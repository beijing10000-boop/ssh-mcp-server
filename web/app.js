"use strict";
const $ = (q) => document.querySelector(q);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (x) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[x]));
let adminToken = sessionStorage.getItem("sshmcp_admin") || "";
const state = {page:"overview",hosts:[],groups:[],credentials:[],proxies:[],batchId:null,editor:null,selected:new Set()};
const titles = {overview:"运维总览",hosts:"主机资产",groups:"主机组",credentials:"SSH 凭据管理",proxies:"SSH 跳板管理",keys:"主机公钥核验",diagnostics:"Linux 只读诊断",audit:"操作审计"};
let timer = null;

async function api(path, method="GET", body) {
  const result = await fetch("/api/v1" + path, {
    method, headers: {"Authorization":"Bearer " + adminToken, ...(body ? {"Content-Type":"application/json"} : {})},
    body: body ? JSON.stringify(body) : undefined,
  });
  const payload = await result.json().catch(() => ({}));
  if (result.status === 401) {
    sessionStorage.removeItem("sshmcp_admin");
    adminToken = "";
    $("#app").hidden = true;
    $("#login").hidden = false;
    throw new Error("身份验证失效，请重新登录");
  }
  if (!result.ok) {
    const info = payload.detail;
    throw new Error(typeof info === "string" ? info : Array.isArray(info) ? info.map(e => e.msg).join("; ") : "请求失败（HTTP " + result.status + "）");
  }
  return payload;
}
function notice(text, failure=false) {
  const box = $("#notice");
  box.hidden = !text;
  box.textContent = text || "";
  box.style.color = failure ? "var(--danger)" : "";
}
const btn = (name, text, id="", kind="") => '<button class="btn small ' + kind + '" data-action="' + esc(name) + '" data-id="' + esc(id) + '">' + esc(text) + '</button>';
function panel(title, body, tools="") {return '<section class="panel"><div class="section-head"><h2>'+esc(title)+'</h2><div class="actions">'+tools+'</div></div>'+body+'</section>';}
function table(head, body) {
  return '<div class="table-wrap"><table><thead><tr>'+head.map(x=>'<th>'+x+'</th>').join("")+'</tr></thead><tbody>'+
    (body || '<tr><td colspan="'+head.length+'" class="empty">暂无记录</td></tr>')+'</tbody></table></div>';
}
const field = (name,title,value="",type="text",opts=null,wide=false,help="") => {
 let input = opts ? '<select name="'+name+'">'+opts.map(([v,t])=>'<option value="'+esc(v)+'" '+(String(value)===String(v)?"selected":"")+'>'+esc(t)+'</option>').join("")+'</select>' :
   type==="textarea" ? '<textarea name="'+name+'" autocomplete="off">'+esc(value)+'</textarea>':
   type==="checkbox" ? '<label class="check"><input type="checkbox" name="'+name+'" '+(value?"checked":"")+'/> 启用</label>' :
   '<input type="'+type+'" name="'+name+'" value="'+esc(value)+'" autocomplete="off"/>';
 return '<div class="'+(wide?"wide":"")+'"><label>'+esc(title)+'</label>'+input+(help?'<div class="help">'+esc(help)+'</div>':"")+'</div>';
};
function openModal(title, fields, submit) {
  state.editor = submit;
  $("#editor-heading").textContent = title;
  $("#editor-fields").innerHTML = fields;
  $("#editor-feedback").textContent = "";
  $("#editor-feedback").hidden = true;
  $("#editor").showModal();
}
function closeModal() {$("#editor").close();state.editor=null;}
function getForm(form, name) {return form.elements.namedItem(name)?.value ?? "";}
function checkbox(form, name) {return !!form.elements.namedItem(name)?.checked;}
function numberOrNull(value) {return value ? Number(value) : null;}
function currentHost(id) {return state.hosts.find(h=>String(h.id)===String(id));}

async function pageOverview(){
 const o=await api("/overview");
 let cards = [["主机资产总数",o.hosts],["已核验 SSH 主机",o.ready],["本地主机组",o.groups],["失败操作记录",o.failed_actions]];
 let grid='<div class="stat-grid">'+cards.map(([name,value])=>'<div class="panel stat"><div class="label">'+esc(name)+'</div><div class="number">'+esc(value)+'</div></div>').join("")+'</div>';
 return '<p class="intro">统一管理 Linux 主机的只读 SSH 诊断能力。此服务独立运行，不依赖 Zabbix、飞书或 AI Ops Platform。</p>'+
 grid+panel("服务状态",'<div class="grid2"><div><strong>MCP Streamable HTTP</strong><p class="muted">路径 /mcp · Bearer 令牌鉴权</p><span class="state-ok">● 已加载</span></div><div><strong>安全执行边界</strong><p class="muted">固定只读命令 · 主机白名单 · 公钥指纹核验 · 私钥加密</p><span class="state-ok">● 已启用</span></div></div>')+
 panel("接入提醒",'<p class="muted">请先在「SSH 凭据管理」中登记密钥，在「主机资产」登记内网 IP。使用「主机公钥核验」获取候选指纹，经过独立核实后确认保存，最后执行连接测试。</p><p class="muted">生产环境应通过 HTTPS 和网络 ACL 访问，不要把 9099 的 HTTP 管理接口直接暴露在公网。</p>');
}
async function pageHosts(){
 const [hosts,groups,credentials,proxies] = await Promise.all([api("/hosts"),api("/groups"),api("/credentials"),api("/proxies")]);
 state.hosts=hosts;state.groups=groups;state.credentials=credentials;state.proxies=proxies;
 const rows=hosts.map(h=>'<tr><td><input class="row-check host-selected" type="checkbox" data-id="'+h.id+'" aria-label="选中'+esc(h.name)+'" '+(state.selected.has(h.id)?"checked":"")+'/></td>'+
 '<td><strong>'+esc(h.name)+'</strong><small>资产 ID '+h.id+' · Zabbix Host ID '+esc(h.zabbix_hostid||"未关联")+'</small></td>'+
 '<td class="mono">'+esc(h.address)+':'+h.port+'<small>'+esc(h.username)+(h.proxy_id?" · 跳板 "+h.proxy_id:" · 直连")+'</small></td>'+
 '<td>'+esc(h.mode==="gateway"?"B · 受限网关":"A · 免 Agent")+'</td>'+
 '<td><span class="'+(h.has_host_key?"state-ok":"state-bad")+'">'+(h.has_host_key?"已核验公钥":"待核验")+'</span><small>'+esc(h.last_status)+'</small></td>'+
 '<td><div class="actions">'+btn("test","测试",h.id)+btn("edit-host","编辑",h.id)+btn("diagnose-host","诊断",h.id)+btn("disable-host","停用",h.id,"danger")+'</div></td></tr>').join("");
 return panel("Linux 主机资产",
   '<p class="intro">SSH 从本服务发起；主机必须是经过登记的内网 IP。管理员可以使用 root，但系统层面的 root 不等于只读账号。</p>'+
   '<div class="toolbar"><input id="host-filter" placeholder="按主机名称 / IP / Host ID 筛选"/>'+btn("scan-selected","批量获取选中主机公钥")+'</div>'+
   table(["选择","主机 / 关联","SSH 路由","权限模式","公钥 / 验证","操作"],rows),
   btn("new-host","新增主机","","primary"));
}
async function pageGroups(){
 state.groups=await api("/groups");
 return panel("主机组",table(["ID","主机组名称"],state.groups.map(x=>'<tr><td>'+x.id+'</td><td>'+esc(x.name)+'</td></tr>').join("")),btn("new-group","新增主机组","","primary"));
}
async function pageCredentials(){
 state.credentials=await api("/credentials");
 return panel("加密 SSH 凭据",'<p class="intro">只保存加密私钥，不会把已保存的私钥回显到 Web。请为诊断服务单独生成密钥对，勿复用个人管理密钥。</p>'+
 table(["ID","凭据名称","创建时间","操作"],state.credentials.map(x=>'<tr><td>'+x.id+'</td><td>'+esc(x.name)+'</td><td>'+esc(x.created_at)+'</td><td>'+btn("rotate-credential","轮换",x.id)+'</td></tr>').join("")),btn("new-credential","新增凭据","","primary"));
}
async function pageProxies(){
 state.proxies=await api("/proxies");
 return panel("SSH 跳板管理",'<p class="intro">仅允许登记内网跳板；跳板主机公钥必须事先通过可信渠道核验。</p>'+
 table(["ID","跳板名称","SSH 地址","登录账号","凭据"],state.proxies.map(p=>'<tr><td>'+p.id+'</td><td>'+esc(p.name)+'</td><td>'+esc(p.address)+':'+esc(p.port)+'</td><td>'+esc(p.username)+'</td><td>'+p.credential_id+'</td></tr>').join("")),btn("new-proxy","新增跳板","","primary"));
}
async function pageKeys(){
 const batches=await api("/host-keys/batches");
 if(!state.batchId && batches.length)state.batchId=batches[0].id;
 let body='<p class="intro">获取主机公钥只执行 SSH 握手，不使用目标 SSH 私钥登录。返回的指纹仅为候选值，不会自动信任。</p>';
 let records="";
 if(state.batchId) {
   const info=await api("/host-keys/batches/"+encodeURIComponent(state.batchId));
   body+='<p class="muted">当前批次 '+esc(info.batch.id)+' · '+esc(info.batch.status)+' · 进度 '+info.batch.completed+'/'+info.batch.total+'</p>';
   records=info.items.map(r=>'<tr><td>'+r.host_id+'<small>'+esc(r.name||"")+'</small></td><td class="mono">'+esc(r.fingerprint||"—")+'</td><td>'+esc(r.status)+'</td><td>'+esc(r.error||"—")+'</td><td>'+(r.status==="candidate"?btn("confirm-key","人工核验并保存",r.host_id):"—")+'</td></tr>').join("");
 }
 const batchlist=batches.map(x=>'<option value="'+esc(x.id)+'" '+(state.batchId===x.id?"selected":"")+'>'+esc(x.created_at)+' · '+esc(x.status)+' · '+x.completed+'/'+x.total+'</option>').join("");
 return panel("批量获取与确认",body+'<div class="toolbar"><select id="batch-select">'+batchlist+'</select>'+btn("refresh","刷新批次")+'</div>'+
 table(["资产","待核验 SHA256 指纹","状态","错误","人工确认"],records)) ;
}
async function pageDiagnostics(){
 state.hosts=await api("/hosts");
 const hosts=state.hosts.filter(h=>h.enabled).map(h=>[h.id,h.name+' · '+h.address]);
 const action=[["connection","连接测试"],["cpu","CPU 负载"],["memory","内存使用"],["disk","文件系统"],["processes","进程"],["io","磁盘 I/O"],["network","网络接口"],["sockets","TCP 监听"],["system","系统信息"],["service","服务状态"],["logs","服务日志"]];
 return panel("Linux 固定只读诊断",
  '<p class="intro">所有操作仅作用于已登记的内网资产。诊断失败会直接展示明确的中文错误信息。</p>'+
  '<form id="diagnostic-form"><div class="fields">'+field("host_id","目标主机",hosts[0]?.[0]??"", "text",hosts)+
    field("action","诊断类型","cpu","text",action)+field("service","systemd 服务名称","")+
    field("minutes","日志查询窗口（分钟）",30,"number")+
  '</div><div class="modal-actions"><button class="btn primary" type="submit">执行诊断 →</button></div></form><hr class="rule"/><h3>执行结果</h3><pre id="diagnostic-result" class="code-result">尚未执行</pre>');
}
async function pageAudit(){
 const rows=await api("/audit");
 return panel("只读与管理操作审计",table(["时间","操作者","动作","目标","结果","说明"],rows.map(r=>
  '<tr><td>'+esc(r.created_at)+'</td><td>'+esc(r.actor)+'</td><td>'+esc(r.action)+'</td><td>'+esc(r.target)+'</td><td>'+esc(r.outcome)+'</td><td>'+esc(r.detail)+'</td></tr>').join("")));
}
async function render(){
 clearTimeout(timer);
 $("#page-title").textContent=titles[state.page]||"SSH MCP";
 for(const el of document.querySelectorAll(".nav-link"))el.classList.toggle("active",el.dataset.page===state.page);
 $("#content").innerHTML='<div class="panel muted">正在加载…</div>';
 try {
   let html = await ({overview:pageOverview,hosts:pageHosts,groups:pageGroups,credentials:pageCredentials,proxies:pageProxies,keys:pageKeys,diagnostics:pageDiagnostics,audit:pageAudit}[state.page]||pageOverview)();
   $("#content").innerHTML=html;
   if(state.page==="keys"&&state.batchId){
     const batches=await api("/host-keys/batches");
     if(batches.some(b=>b.id===state.batchId && b.status==="running"))timer=setTimeout(render,2500);
   }
 } catch(e) {$("#content").textContent="加载失败："+e.message;}
}
async function login(){
 if(!adminToken)return;
 try{
   await api("/auth/check");
   $("#login").hidden=true;$("#app").hidden=false;await render();
 }catch(e){$("#login-error").hidden=false;$("#login-error").textContent=e.message;}
}
$("#login-form").addEventListener("submit", async (e)=>{
 e.preventDefault();adminToken=$("#admin-token").value.trim();
 sessionStorage.setItem("sshmcp_admin",adminToken);await login();
});
$("#logout").addEventListener("click",()=>{adminToken="";sessionStorage.removeItem("sshmcp_admin");$("#app").hidden=true;$("#login").hidden=false;$("#admin-token").value="";});
$("#reload").addEventListener("click",render);
$("#nav").addEventListener("click",e=>{const b=e.target.closest("[data-page]");if(b){state.page=b.dataset.page;notice("");render();}});
$("#editor-close").addEventListener("click",closeModal);
$("#editor-cancel").addEventListener("click",closeModal);
$("#editor-form").addEventListener("submit",async(e)=>{
 e.preventDefault();if(!state.editor)return;
 const save=$("#editor-form").querySelector("button[type=submit]");save.disabled=true;
 const error=$("#editor-feedback");error.hidden=true;error.textContent="";
 try{await state.editor(e.target);closeModal();notice("保存成功");render();}
 catch(ex){error.textContent=ex.message;error.hidden=false;error.scrollIntoView({block:"nearest"});}
 finally{save.disabled=false;}
});
function hostFields(h={}){
 const selected=h.group_ids||[];
 const gs=state.groups.map(g=>'<label class="check"><input type="checkbox" class="group-check" value="'+g.id+'" '+(selected.includes(g.id)?"checked":"")+'/> '+esc(g.name)+'</label>').join("");
 return field("name","资产名称",h.name||"")+field("address","内网 IP 地址",h.address||"")+
 field("port","SSH 端口",h.port||22,"number")+field("username","SSH 用户名",h.username||"root")+
 field("zabbix_hostid","Zabbix Host ID（可选）",h.zabbix_hostid||"")+
 field("credential_id","SSH 凭据",h.credential_id||"","text",[["","未绑定"],...state.credentials.map(c=>[c.id,c.name])])+
 field("proxy_id","跳板（可选）",h.proxy_id||"","text",[["","直连"],...state.proxies.map(p=>[p.id,p.name])])+
 field("mode","诊断模式",h.mode||"standard","text",[["standard","A · 标准免 Agent"],["gateway","B · 受限强制命令网关"]])+
 field("host_key","已核验 SSH 主机公钥", "", "textarea",null,true, h.id ? "留空表示保留当前已核验主机公钥；也可以使用批量公钥核验流程。" : "建议先留空，保存后批量获取候选指纹并在可信渠道核实。")+
 '<div class="wide">'+field("enabled","启用资产",h.enabled!==false,"checkbox")+'</div>'+
 '<div class="wide"><label class="check"><input type="checkbox" name="gateway_approved" '+(h.gateway_approved?"checked":"")+'/> 已核实受限强制命令网关（仅 B 模式）</label></div>'+
 '<div class="wide"><label>所属主机组</label>'+ (gs||'<div class="muted">暂无主机组</div>')+'</div>';
}
function hostBody(form){
 return {
   name:getForm(form,"name"),address:getForm(form,"address"),
   port:Number(getForm(form,"port")),username:getForm(form,"username"),
   zabbix_hostid:getForm(form,"zabbix_hostid")||null,
   credential_id:numberOrNull(getForm(form,"credential_id")),
   proxy_id:numberOrNull(getForm(form,"proxy_id")),
   mode:getForm(form,"mode"), gateway_approved:checkbox(form,"gateway_approved"),
   host_key:getForm(form,"host_key"),enabled:checkbox(form,"enabled"),
   group_ids:[...form.querySelectorAll(".group-check:checked")].map(x=>Number(x.value))
 };
}
function keyEditor(){
 return field("name","凭据名称","诊断专用 SSH 密钥")+
 field("passphrase","私钥口令（可选）","","password")+
 field("private_key","完整 SSH 私钥（不回显）","","textarea",null,true,"私钥使用应用持久化的 Fernet 主密钥加密后存储。");
}
$("#content").addEventListener("change",(e)=>{
 if(e.target.classList.contains("host-selected")){
  const id=Number(e.target.dataset.id);if(e.target.checked)state.selected.add(id);else state.selected.delete(id);
 }
 if(e.target.id==="batch-select"){state.batchId=e.target.value;render();}
});
$("#content").addEventListener("submit",async(e)=>{
 if(e.target.id!=="diagnostic-form")return;
 e.preventDefault();
 const form=e.target, display=$("#diagnostic-result");
 display.textContent="正在执行只读诊断…";
 try{
  const host_id=Number(getForm(form,"host_id"));
  const action=getForm(form,"action");
  const body={action,service:["logs","service"].includes(action)?getForm(form,"service"):null,minutes:Number(getForm(form,"minutes"))};
  const out=await api("/hosts/"+host_id+"/diagnose","POST",body);
  display.textContent=JSON.stringify(out,null,2);
 }catch(ex){display.textContent="诊断失败："+ex.message;}
});
$("#content").addEventListener("click",async (e)=>{
 const b=e.target.closest("[data-action]");if(!b)return;
 const action=b.dataset.action, id=b.dataset.id;
 b.disabled=true;
 try{
  if(action==="refresh"){render();return;}
  if(action==="new-host"||action==="edit-host"){
   const h=action==="edit-host"?currentHost(id):{};
   openModal(h.id?"编辑主机资产":"登记 Linux 主机",hostFields(h),form=>
    api("/hosts"+(h.id?"/"+h.id:""),h.id?"PUT":"POST",hostBody(form)));
  }
  else if(action==="new-group"){
   openModal("创建主机组",field("name","主机组名称",""),form=>api("/groups","POST",{name:getForm(form,"name")}));
  }else if(action==="new-credential"||action==="rotate-credential"){
   const prev=state.credentials.find(x=>String(x.id)===id);
   openModal(prev?"轮换 SSH 私钥":"新增 SSH 凭据",keyEditor(),form=>
    api("/credentials"+(prev?"/"+prev.id:""),prev?"PUT":"POST",{
      name:prev?.name||getForm(form,"name"),passphrase:getForm(form,"passphrase"),private_key:getForm(form,"private_key")
    }));
   if(prev)$("#editor-fields input[name=name]").value=prev.name;
  }else if(action==="new-proxy"){
   openModal("新增 SSH 跳板",
    field("name","跳板名称","")+field("address","内网 IP 地址","")+
    field("port","SSH 端口",22,"number")+field("username","SSH 用户名","root")+
    field("credential_id","SSH 凭据","","text",state.credentials.map(c=>[c.id,c.name]))+
    field("host_key","已核验跳板公钥","","textarea",null,true),
    form=>api("/proxies","POST",{
      name:getForm(form,"name"),address:getForm(form,"address"),
      port:Number(getForm(form,"port")),username:getForm(form,"username"),
      credential_id:Number(getForm(form,"credential_id")),host_key:getForm(form,"host_key")
    }));
  }else if(action==="test"){
   notice("正在测试 SSH 登录…");
   const value=await api("/hosts/"+id+"/test","POST");
   notice("连接测试："+value.status+" · "+(value.output||"").slice(0,200));
   await render();
  }else if(action==="disable-host"){
   if(!confirm("确定停用资产 "+id+"？停用后 MCP 将无法诊断这台主机。"))return;
   await api("/hosts/"+id+"/disable","POST");notice("主机已停用");render();
  }else if(action==="diagnose-host"){
   state.page="diagnostics";await render();
   const selector=$("#diagnostic-form [name=host_id]");if(selector)selector.value=id;
  }else if(action==="scan-selected"){
   const ids=[...state.selected];
   if(!ids.length)throw new Error("请先勾选至少一台主机");
   const result=await api("/host-keys/scan","POST",{host_ids:ids});
   state.selected.clear();state.batchId=result.batch_id;state.page="keys";notice("已提交 "+result.total+" 台主机的公钥握手任务，请在可信渠道逐台核对指纹");render();
  }else if(action==="confirm-key"){
   const h=await api("/hosts");
   const asset=h.find(x=>String(x.id)===id);
   const current=await api("/host-keys/batches/"+encodeURIComponent(state.batchId));
   const entry=current.items.find(x=>String(x.host_id)===id);
   openModal("人工核验主机公钥",'<div class="wide"><p>主机：<strong>'+esc(asset?.name)+'</strong></p><p>候选指纹：<strong class="mono">'+esc(entry?.fingerprint)+'</strong></p><p class="muted">请在目标服务器可信控制台执行 ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256（根据实际协商的公钥算法选择文件），确认指纹后手工填入。</p></div>'+
    field("fingerprint","通过可信渠道独立核验的 SHA256 指纹","","text",null,true)+
    '<div class="wide"><label class="check"><input type="checkbox" name="confirmed"/> 我已在可信渠道独立核验，确认本次公钥属于目标服务器</label></div>',
    form=>api("/host-keys/confirm","POST",{
      host_id:Number(id),independently_verified_sha256:getForm(form,"fingerprint"),confirmed:checkbox(form,"confirmed")
    }));
  }
 }catch(ex){notice(ex.message,true);}
 finally{b.disabled=false;}
});
login();
