// 哨兵前端逻辑：标签切换、上传、调用 /api/analyze、渲染报告
const $ = (s) => document.querySelector(s);
const threadId = "web-" + Math.random().toString(36).slice(2, 8);
let currentTab = "log";
let uploadId = null;

// ---------- 初始化 ----------
async function init() {
  bindTabs();
  bindUpload();
  await loadHealth();
  await loadSamples();
  $("#analyzeBtn").onclick = runAnalyze;
  $("#sendBtn").onclick = sendChat;
  $("#msgInput").addEventListener("keydown", (e) => { if (e.key === "Enter") sendChat(); });
  addBot("你好，我是网络安全流量分析智能体「哨兵」🛡️\n请在左侧粘贴流量日志、上传日志文件，或指定一个端口，我会自动完成攻击检测、IP 溯源并生成安全分析报告。");
}

async function loadHealth() {
  try {
    const r = await fetch("/api/health").then((x) => x.json());
    const el = $("#status");
    el.textContent = r.llm;
    el.className = "status " + (r.llm_available ? "ok" : "warn");
  } catch { $("#status").textContent = "后端未连接"; }
}

async function loadSamples() {
  try {
    const r = await fetch("/api/samples").then((x) => x.json());
    const box = $("#sampleBtns");
    box.innerHTML = "";
    r.samples.forEach((s) => {
      const b = document.createElement("span");
      b.className = "chip"; b.textContent = s.name;
      b.onclick = async () => {
        const d = await fetch("/api/samples/" + encodeURIComponent(s.id)).then((x) => x.json());
        $("#logInput").value = d.content;
        switchTab("log");
      };
      box.appendChild(b);
    });
  } catch {}
}

// ---------- 标签 ----------
function bindTabs() {
  document.querySelectorAll(".tab").forEach((t) => {
    t.onclick = () => switchTab(t.dataset.tab);
  });
}
function switchTab(name) {
  currentTab = name;
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".tab-pane").forEach((p) => p.classList.toggle("active", p.id === "pane-" + name));
}

// ---------- 上传 ----------
function bindUpload() {
  const dz = $("#dropzone"), fi = $("#fileInput");
  dz.onclick = () => fi.click();
  fi.onchange = () => fi.files[0] && doUpload(fi.files[0]);
  ["dragover", "dragenter"].forEach((e) => dz.addEventListener(e, (ev) => { ev.preventDefault(); dz.classList.add("drag"); }));
  ["dragleave", "drop"].forEach((e) => dz.addEventListener(e, () => dz.classList.remove("drag")));
  dz.addEventListener("drop", (ev) => { ev.preventDefault(); ev.dataTransfer.files[0] && doUpload(ev.dataTransfer.files[0]); });
}
async function doUpload(file) {
  const fd = new FormData(); fd.append("file", file);
  $("#uploadInfo").textContent = "上传中…";
  try {
    const r = await fetch("/api/upload", { method: "POST", body: fd });
    const d = await r.json();
    if (!r.ok) { $("#uploadInfo").style.color = "var(--crit)"; $("#uploadInfo").textContent = "❌ " + (d.detail || "上传失败"); uploadId = null; return; }
    uploadId = d.upload_id;
    $("#uploadInfo").style.color = "var(--accent2)";
    $("#uploadInfo").textContent = `✅ 已上传 ${d.filename}（${d.lines} 行）`;
  } catch (e) { $("#uploadInfo").textContent = "❌ 上传出错"; }
}

// ---------- 分析 ----------
async function runAnalyze() {
  const extra = $("#msgInput").value.trim();
  let payload = { thread_id: threadId, message: extra || null };

  if (currentTab === "log") {
    const content = $("#logInput").value.trim();
    if (!content) return addBot("请先粘贴流量日志，或点击示例。");
    payload.mode = "log"; payload.log_content = content;
    addUser(extra || "请分析这批流量日志。");
  } else if (currentTab === "upload") {
    if (!uploadId) return addBot("请先上传一个结构化文本日志文件。");
    payload.mode = "log"; payload.upload_id = uploadId;
    addUser(extra || "请分析已上传的日志文件。");
  } else {
    const port = parseInt($("#portInput").value);
    if (!port) return addBot("请填写要监测的端口号。");
    payload.mode = "port"; payload.port = port;
    payload.target_host = $("#hostInput").value.trim() || null;
    payload.duration = parseInt($("#durInput").value) || 15;
    addUser(extra || `请监测端口 ${port} 并分析是否存在攻击。`);
  }
  $("#msgInput").value = "";
  await callAnalyze(payload);
}

async function sendChat() {
  const text = $("#msgInput").value.trim();
  if (!text) return;
  addUser(text);
  $("#msgInput").value = "";
  await callAnalyze({ thread_id: threadId, mode: "chat", message: text });
}

async function callAnalyze(payload) {
  const btn = $("#analyzeBtn"); btn.disabled = true;
  const loader = addBot('<span class="loading">哨兵正在分析</span>', true);
  try {
    const r = await fetch("/api/analyze", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const d = await r.json();
    loader.remove();
    if (!r.ok) return addBot("❌ " + (d.detail || "分析失败"));
    renderResult(d);
  } catch (e) {
    loader.remove(); addBot("❌ 请求出错：" + e.message);
  } finally { btn.disabled = false; }
}

// ---------- 渲染 ----------
function renderResult(d) {
  const notesHtml = (d.notes && d.notes.length)
    ? `<div class="notes">${d.notes.map((n) => `<div>${esc(n)}</div>`).join("")}</div>` : "";
  addBot(esc(d.reply || "分析完成。") + "", false, notesHtml);
  if (d.report) renderReport(d.report);
}

function renderReport(rep) {
  const sevClass = { "严重": "critical", "高危": "high", "中危": "medium", "低危": "low", "无明显风险": "info" }[rep.risk_level] || "info";
  const tr = rep.time_range || {};
  const findingsRows = (rep.findings || []).map((f) => `
    <tr>
      <td>${esc(f.type)}</td>
      <td><span class="sev ${sevMap(f.severity)}">${sevText(f.severity)}</span></td>
      <td>${f.count}</td>
      <td>${(f.src_ips || []).map((ip) => `<code>${esc(ip)}</code>`).join("<br>")}</td>
      <td>${f.mitre ? `<code>${esc(f.mitre)}</code>` : "-"}</td>
    </tr>`).join("");

  const originsRows = (rep.attacker_origins || []).map((o) => `
    <tr>
      <td><code>${esc(o.ip)}</code></td>
      <td>${esc(o.is_private ? "内网/保留地址" : [o.country, o.province, o.city].filter(Boolean).join(" · ") || "未知")}</td>
      <td>${esc(o.isp || "-")}</td>
      <td>${esc(o.source || "-")}</td>
    </tr>`).join("");

  const recs = (rep.recommendations || []).map((r) => `<li>${esc(r)}</li>`).join("");
  const st = rep.stats || {};

  const html = `
  <div class="report" id="${rep.report_id}">
    <div class="report-head">
      <h3>🛡️ 安全分析报告<span class="badge ${sevClass}">${esc(rep.risk_level)}</span></h3>
      <div class="report-meta">报告编号 ${esc(rep.report_id)} · 生成于 ${esc(rep.generated_at)}
        · 研判引擎：${rep.llm_powered ? "DeepSeek 大模型" : "内置规则（离线）"}
        · 时间范围：${esc(tr.start || "—")} ~ ${esc(tr.end || "—")}</div>
    </div>
    <div class="report-body">
      <div class="verdict">研判结论：${esc(rep.verdict)}</div>
      <div class="summary">${esc(rep.summary)}</div>

      <div class="stat-grid">
        <div class="stat"><b>${st.total_events ?? 0}</b><span>流量事件</span></div>
        <div class="stat"><b>${st.unique_src_ips ?? 0}</b><span>来源 IP</span></div>
        <div class="stat"><b>${st.finding_count ?? 0}</b><span>攻击类型</span></div>
        <div class="stat"><b>${rep.attack_detected ? "是" : "否"}</b><span>是否攻击</span></div>
      </div>

      ${rep.findings && rep.findings.length ? `
      <h4>攻击发现明细</h4>
      <table><thead><tr><th>攻击类型</th><th>等级</th><th>次数</th><th>来源 IP</th><th>ATT&CK</th></tr></thead>
      <tbody>${findingsRows}</tbody></table>` : ""}

      ${rep.attacker_origins && rep.attacker_origins.length ? `
      <h4>攻击者 IP 溯源</h4>
      <table><thead><tr><th>IP</th><th>归属地（省份级）</th><th>运营商</th><th>来源</th></tr></thead>
      <tbody>${originsRows}</tbody></table>` : ""}

      ${recs ? `<h4>处置与加固建议</h4><ul class="recs">${recs}</ul>` : ""}

      <div class="report-actions">
        <button onclick='downloadReport(${JSON.stringify(rep.report_id)})'>⬇ 下载报告(JSON)</button>
      </div>
    </div>
  </div>`;
  const wrap = document.createElement("div");
  wrap.innerHTML = html;
  window.__reports = window.__reports || {};
  window.__reports[rep.report_id] = rep;
  $("#chat").appendChild(wrap.firstElementChild);
  scrollChat();
}

function downloadReport(id) {
  const rep = (window.__reports || {})[id];
  if (!rep) return;
  const blob = new Blob([JSON.stringify(rep, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = id + ".json"; a.click();
}

// ---------- 工具 ----------
function sevMap(s) { return ({ critical: "critical", high: "high", medium: "medium", low: "low" })[s] || "low"; }
function sevText(s) { return ({ critical: "严重", high: "高危", medium: "中危", low: "低危", info: "提示" })[s] || s; }
function esc(s) { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c])); }
function addUser(t) { const d = document.createElement("div"); d.className = "msg user"; d.textContent = t; $("#chat").appendChild(d); scrollChat(); }
function addBot(html, isLoader, notesHtml) {
  const d = document.createElement("div"); d.className = "msg bot";
  d.innerHTML = html + (notesHtml || "");
  $("#chat").appendChild(d); scrollChat();
  return d;
}
function scrollChat() { const c = $("#chat"); c.scrollTop = c.scrollHeight; }

init();
