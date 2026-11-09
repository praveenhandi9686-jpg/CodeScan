const $ = s => document.querySelector(s);
const el = (t, props = {}, ...kids) => { const e = document.createElement(t); Object.assign(e, props); kids.forEach(k => e.append(k)); return e; }; // textContent only: XSS-safe
const api = async (path, method = "GET", body) => {
  const t0 = performance.now(); const r = await fetch("/api" + path, { method, credentials: "same-origin", headers: { "Content-Type": "application/json", "X-Requested-With": "fetch" }, body: body ? JSON.stringify(body) : undefined });
  const d = await r.json().catch(() => ({ success: false, error: "Unexpected server response." }));
  if (debugOn()) console.debug(`[CodeScan] ${method} /api${path} -> ${r.status} (${Math.round(performance.now() - t0)} ms)`, d);
  if (!r.ok) throw new Error(d.error || "Request failed."); return d;
};
const toast = m => { const t = $("#toast"); t.textContent = m; t.classList.add("show"); setTimeout(() => t.classList.remove("show"), 3000); };
let mode = "login";
const LANGS = { python: "Python", javascript: "JavaScript", typescript: "TypeScript", html: "HTML", css: "CSS", java: "Java", c: "C", cpp: "C++", csharp: "C#", go: "Go", php: "PHP", ruby: "Ruby", rust: "Rust", kotlin: "Kotlin", swift: "Swift", sql: "SQL", bash: "Bash" };
["#lang"].forEach(s => Object.entries(LANGS).forEach(([k, v]) => $(s).append(new Option(v, k))));

document.documentElement.dataset.theme = localStorage.getItem("theme") || "dark";
$("#theme").onclick = () => { const t = document.documentElement.dataset.theme === "dark" ? "light" : "dark"; document.documentElement.dataset.theme = t; localStorage.setItem("theme", t); };
function view(v) { closeMenu(); ["auth", "dash", "new", "hist", "set", "prof"].forEach(x => $("#" + x).hidden = x !== v); document.body.classList.toggle("auth-mode", v === "auth"); document.querySelectorAll("nav [data-v]").forEach(b => b.classList.toggle("active", b.dataset.v === v)); window.scrollTo(0, 0); if (v === "hist") loadHistory(); if (v === "dash") loadDash(); if (v === "set") loadSettings(); if (v === "prof") loadProfile(); }
function setUser(u) { $("#nav").hidden = !u; if (u) { $("#who").textContent = u.username; $("#who").dataset.i = u.username.slice(0, 2).toUpperCase(); $("#lang").value = u.default_language || "python"; view("new"); paintDebug(); } else view("auth"); }
document.querySelectorAll("[data-v]").forEach(b => b.onclick = () => { if (!$("#nav").hidden) view(b.dataset.v); });
$("#showpw").onchange = e => ["#password", "#confirm"].forEach(i => $(i).type = e.target.checked ? "text" : "password");
const T = { login: ["Login", "Welcome back — sign in to start reviewing.", "Login"], register: ["Create Account", "Create your free account to get started.", "Create account"] };
const setMode = m => { mode = m;
  document.querySelectorAll("#authform [data-m]").forEach(e => e.hidden = !e.dataset.m.split(" ").includes(m));
  [$("#authtitle").textContent, $("#authsub").textContent, $("#submit").textContent] = T[m];
  $("#email").type = m === "login" ? "text" : "email";
  $("#idl").firstChild.textContent = m === "login" ? "Email or username" : "Email";
  document.querySelectorAll("#authform input:not([type=checkbox])").forEach(i => i.required = !i.closest("[data-m]").hidden);
  $("#password").autocomplete = m === "register" ? "new-password" : "current-password"; $("#autherr").textContent = ""; };
document.querySelectorAll("#authform [data-go]").forEach(b => b.onclick = () => setMode(b.dataset.go));
$("#authform").onsubmit = async e => { e.preventDefault(); const err = $("#autherr"), btn = e.submitter, v = id => $("#" + id).value.trim(); err.textContent = ""; btn.disabled = true;
  try {
    if (mode === "register") { showLoader("Creating your account…", "Just a moment"); await api("/auth/register", "POST", { username: v("username"), email: v("email"), password: $("#password").value, confirm_password: $("#confirm").value }); await hideLoader(900); const id = v("email"); $("#authform").reset(); setMode("login"); $("#email").value = id; toast("Account created. Please log in."); }
    else { showLoader("Signing you in…", "Checking your credentials"); const d = await api("/auth/login", "POST", { identifier: v("email"), password: $("#password").value });
      $("#ltitle").textContent = `Welcome back, ${d.user.username}!`; $("#lsub").textContent = "Opening your workspace…"; await hideLoader(1500); $("#authform").reset(); setUser(d.user); }
  } catch (x) { await hideLoader(0); err.textContent = x.message; } finally { btn.disabled = false; } };
$("#logout").onclick = async () => { await api("/auth/logout", "POST"); setUser(null); };
const upd = () => { const v = $("#code").value; $("#counts").textContent = `${v ? v.split("\n").length : 0} lines · ${v.length} chars`; };
$("#code").oninput = upd; $("#clear").onclick = () => { $("#code").value = ""; $("#result").replaceChildren(); $("#dbgout").replaceChildren(); upd(); };

$("#run").onclick = async () => {
  const code = $("#code").value; if (!code.trim()) return toast("Please enter source code before starting the review.");
  const btn = $("#run"); btn.disabled = true; $("#status").textContent = ""; showLoader("Analyzing your code…", "Syntax, security and quality checks");
  try { const d = await api("/reviews", "POST", { language: $("#lang").value, code }); await hideLoader(900); render(d.review); showDebug(d.debug); $("#result").scrollIntoView({ behavior: "smooth" }); $("#status").textContent = d.review.ai_status; }
  catch (x) { await hideLoader(0); $("#status").textContent = ""; toast(x.message); } finally { btn.disabled = false; }
};
function render(r, filter = "All") {
  const out = $("#result"); out.replaceChildren();
  const sc = [["Overall", r.overall_score], ["Security", r.security_score], ["Quality", r.quality_score], ["Maintainability", r.maintainability_score], ["Reliability", r.reliability_score]];
  out.append(el("div", { className: "card" }, el("h2", { textContent: `Code Review Result — Issues: ${r.issue_count}` }), el("p", { textContent: r.summary }),
    el("div", { className: "scores" }, ...sc.map(([n, v]) => el("div", {}, el("b", { textContent: v }), n))),
    el("button", { textContent: "Download PDF", onclick: () => location.href = `/api/reviews/${r.id}/report?format=pdf` })));
  out.append(...getExtras(r));
  const f = el("div", { className: "filters" });
  ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW", "Security", "Bug", "Quality", "Performance"].forEach(n => f.append(el("button", { textContent: n, className: n === filter ? "on" : "", onclick: () => render(r, n) })));
  out.append(f);
  const list = r.findings.filter(x => filter === "All" || x.severity === filter || x.category === filter);
  if (!list.length) out.append(el("p", { textContent: "No findings match this filter." }));
  list.forEach(x => {
    const c = el("div", { className: "card" }, el("span", { className: "badge", textContent: x.severity, style: `background:var(--${x.severity})` }), ` ${x.title} `,
      el("small", { textContent: `${x.category} · line ${x.line_number} · ${x.status} · ${Math.round(x.confidence * 100)}% confidence · ${x.source}` }),
      el("pre", { textContent: x.code }), el("p", {}, el("b", { textContent: "Why: " }), x.explanation, el("br"), el("b", { textContent: "Impact: " }), x.impact, el("br"), el("b", { textContent: "Recommendation: " }), x.recommendation));
    if (x.suggested_fix) c.append(el("details", {}, el("summary", { textContent: "Suggested Fix (review before applying)" }),
      el("p", { textContent: "Original" }), el("pre", { textContent: x.code }), el("p", { textContent: "Suggested Version" }), el("pre", { textContent: x.suggested_fix })));
    out.append(c);
  });
}
async function loadHistory() {
  const box = $("#histlist"); box.replaceChildren();
  try { const d = await api("/reviews");
    if (!d.reviews.length) return box.append(el("p", { textContent: "No reviews yet." }));
    d.reviews.forEach(r => box.append(el("div", { className: "card" }, `#${r.id} · ${r.language} · score ${r.overall_score} · ${r.issue_count} issues · highest ${r.highest_severity} · ${new Date(r.created_at).toLocaleString()} `,
      el("button", { textContent: "Open", onclick: async () => { const x = await api("/reviews/" + r.id); view("new"); $("#code").value = x.review.source_code; $("#lang").value = x.review.language; upd(); render(x.review); } }), " ",
      el("button", { textContent: "Report", onclick: () => location.href = `/api/reviews/${r.id}/report?format=pdf` }), " ",
      el("button", { textContent: "Delete", onclick: async () => { if (confirm("Delete this review?")) { await api("/reviews/" + r.id, "DELETE"); loadHistory(); } } }))));
  } catch (x) { toast(x.message); }
}
api("/auth/me").then(d => setUser(d.user)).catch(() => setUser(null));

async function loadDash() {
  const box = $("#dashbox"); box.replaceChildren();
  try {
    const [d, s] = await Promise.all([api("/dashboard"), api("/ai/status")]);
    const tile = (v, l) => el("div", { className: "stat" }, el("b", { textContent: v }), l);
    box.append(el("div", { className: "stats" }, tile(d.total, "Reviews"), tile(d.avg_score ?? "—", "Average score"), tile(d.issues, "Issues found"), tile(d.severity.CRITICAL + d.severity.HIGH, "Critical + High")));
    const ai = el("div", { className: "card" }, el("h3", { textContent: "AI connection" }),
      el("p", { textContent: s.configured ? `Settings found · ${s.provider} · model ${s.model}` : `Not configured. Missing in .env: ${s.missing.join(", ")}` }));
    ai.append(el("button", { textContent: "Test AI connection", onclick: async e => { const b = e.target; b.disabled = true; try { toast((await api("/ai/test", "POST")).message); } catch (x) { toast(x.message); } b.disabled = false; } }));
    box.append(ai);
    const max = Math.max(1, ...Object.values(d.severity)), bars = el("div", { className: "card" }, el("h3", { textContent: "Issues by severity" }));
    Object.entries(d.severity).forEach(([k, n]) => bars.append(el("div", { className: "brow" }, el("span", { textContent: k }), el("div", { className: "track" }, el("i", { style: `width:${n / max * 100}%;background:var(--${k})` })), el("span", { textContent: n }))));
    box.append(bars);
    const langs = Object.entries(d.languages).map(([k, n]) => `${LANGS[k] || k}: ${n}`).join(" · ");
    box.append(el("div", { className: "card" }, el("h3", { textContent: "Languages reviewed" }), el("p", { textContent: langs || "No reviews yet." })));
    const rec = el("div", { className: "card" }, el("h3", { textContent: "Recent reviews" }));
    if (!d.recent.length) rec.append(el("p", { textContent: "No reviews yet. Start with New Review." }));
    d.recent.forEach(r => rec.append(el("p", {}, `#${r.id} · ${LANGS[r.language] || r.language} · score ${r.overall_score} · ${r.issue_count} issues `,
      el("button", { textContent: "Open", onclick: async () => { const x = await api("/reviews/" + r.id); view("new"); $("#code").value = x.review.source_code; $("#lang").value = x.review.language; upd(); render(x.review); } }))));
    box.append(rec, el("div", {}, el("button", { className: "primary", textContent: "New Review", onclick: () => view("new") })));
  } catch (x) { toast(x.message); }
}

const extras = new Map();
function showRun(box, d, code) {
  box.replaceChildren();
  if (d.kind === "preview") { const f = el("iframe", { className: "preview" }); f.setAttribute("sandbox", ""); f.srcdoc = d.html || code; box.append(el("p", { textContent: d.html ? "Preview on a sample page (scripts disabled):" : "Live preview (scripts disabled):" }), f); return; }
  if (d.kind !== "ran") return box.append(el("p", { textContent: d.message }));
  const bad = d.phase === "compile";
  box.append(el("p", { className: bad ? "err" : "", textContent: bad ? `Compilation failed (exit ${d.exit_code})` : `Exit code ${d.exit_code} · ${d.duration_ms} ms${d.timed_out ? " · timed out" : ""}` }));
  if (d.stdout) box.append(el("pre", { textContent: d.stdout }));
  if (d.stderr) box.append(el("pre", { className: "stderr", textContent: d.stderr }));
  if (!d.stdout && !d.stderr) box.append(el("p", { textContent: "(no output)" }));
  if (debugOn() && d.steps) box.append(el("div", { className: "card dbg" }, el("b", { textContent: "🐞 Debug: steps" }), ...d.steps.map(s => el("p", { textContent: `${s.step}: ${s.cmd} → exit ${s.exit}, ${s.ms} ms${s.timed_out ? " (timed out)" : ""}` }))));
}
function getExtras(r) {
  if (extras.has(r.id)) return extras.get(r.id);
  let suggested = null;
  const sug = el("div", { className: "card" }, el("h3", { textContent: "Suggested Code" }), el("p", { textContent: "Preparing suggested code..." }));
  const res = el("div"), outc = el("div", { className: "card" }, el("h3", { textContent: "Output" }), el("p", { textContent: "Run the code to see what it prints." }));
  const runBtn = (label, get) => el("button", { textContent: label, onclick: async e => {
    const b = e.target, code = get(); if (!code) return toast("Suggested code is not ready yet."); b.disabled = true; res.replaceChildren(el("p", { textContent: "Running..." }));
    try { showRun(res, await api("/run", "POST", { language: r.language, code }), code); } catch (x) { res.replaceChildren(el("p", { className: "err", textContent: x.message })); }
    b.disabled = false; } });
  outc.append(runBtn("▶ Run original", () => r.source_code), " ", runBtn("▶ Run suggested", () => suggested), res);
  api(`/reviews/${r.id}/suggestion`).then(s => {
    suggested = s.code; sug.replaceChildren(el("h3", { textContent: "Suggested Code" }));
    if (s.unchanged) return sug.append(el("p", { textContent: "No automatic correction is available for these findings. See the details below for manual fixes." }), ...(s.note ? [el("p", { textContent: s.note })] : []));
    sug.append(el("p", {}, el("b", { textContent: s.source === "ai" ? "AI-corrected" : "Automatic fixes" }), ` · static score ${s.score_before} → ${s.score_after}`));
    if (s.note) sug.append(el("p", { textContent: s.note }));
    if (s.changes.length) sug.append(el("ul", {}, ...s.changes.map(c => el("li", { textContent: c }))));
    const code = el("pre", { textContent: s.code }), diff = el("pre", {}, ...s.diff.split("\n").map(l => el("div", { className: /^\+(?!\+\+)/.test(l) ? "add" : /^-(?!--)/.test(l) ? "del" : "", textContent: l || " " })));
    diff.hidden = true;
    const tab = (t, show) => el("button", { textContent: t, onclick: () => { code.hidden = show !== "code"; diff.hidden = show !== "diff"; } });
    sug.append(tab("Suggested code", "code"), " ", tab("Diff vs original", "diff"), code, diff,
      el("button", { textContent: "Copy", onclick: () => navigator.clipboard.writeText(s.code).then(() => toast("Copied")) }), " ",
      el("button", { textContent: "Load into editor", onclick: () => { view("new"); $("#code").value = s.code; $("#lang").value = r.language; upd(); toast("Loaded. Click Review Code to re-check it."); } }));
  }).catch(x => sug.append(el("p", { className: "err", textContent: x.message })));
  const pair = [sug, outc]; extras.set(r.id, pair); return pair;
}

setMode("login");

const EXT = { py: "python", js: "javascript", jsx: "javascript", mjs: "javascript", ts: "typescript", tsx: "typescript", java: "java", c: "c", h: "c", cpp: "cpp", cc: "cpp", hpp: "cpp", cs: "csharp", go: "go", php: "php", rb: "ruby", rs: "rust", sh: "bash", kt: "kotlin", swift: "swift", sql: "sql", html: "html", htm: "html", css: "css" };
async function importFile(f) {
  if (!f) return; if (f.size > 200000) return toast("File is too large (max 200 KB).");
  const text = await f.text(); if (text.includes("\0")) return toast("That looks like a binary file, not source code.");
  const l = EXT[f.name.split(".").pop().toLowerCase()]; $("#code").value = text; if (l) $("#lang").value = l; upd(); $("#result").replaceChildren();
  toast(`Imported ${f.name}` + (l ? "" : " - please pick the language"));
}
$("#import").onclick = () => $("#file").click(); $("#file").onchange = e => { importFile(e.target.files[0]); e.target.value = ""; };
$("#code").ondragover = e => e.preventDefault(); $("#code").ondrop = e => { e.preventDefault(); importFile(e.dataTransfer.files[0]); };

async function openReview(id) { const x = await api("/reviews/" + id); view("new"); $("#code").value = x.review.source_code; $("#lang").value = x.review.language; upd(); render(x.review); }
async function loadSettings() {
  const box = $("#setbox"); box.replaceChildren();
  try {
    const [s, h] = await Promise.all([api("/settings"), api("/reviews")]), u = s.user, field = (l, i) => el("label", {}, l, i);
    const langSel = () => { const x = el("select"); Object.entries(LANGS).forEach(([k, v]) => x.append(new Option(v, k))); return x; };
    const run = (fn, ok) => async () => { try { await fn(); if (ok) toast(ok); } catch (x) { toast(x.message); } };
    const uname = el("input", { value: u.username }), lang = langSel(); lang.value = u.default_language;
    box.append(el("div", { className: "card" }, el("h3", { textContent: "Profile" }),
      el("p", { textContent: `Email: ${u.email || "not set"} · Member since ${u.created_at.slice(0, 10)}` }),
      el("div", { className: "row" }, field("Username", uname), field("Default language", lang),
        el("button", { className: "primary", textContent: "Save", onclick: run(async () => { await api("/settings", "PUT", { username: uname.value, default_language: lang.value }); $("#who").textContent = uname.value; }, "Saved") }))));
    const cur = el("input", { type: "password" }), n1 = el("input", { type: "password" }), n2 = el("input", { type: "password" });
    box.append(el("div", { className: "card" }, el("h3", { textContent: u.has_password ? "Change password" : "Set a password" }),
      el("div", { className: "row" }, ...(u.has_password ? [field("Current password", cur)] : []), field("New password", n1), field("Confirm", n2),
        el("button", { className: "primary", textContent: "Update", onclick: run(async () => { if (n1.value !== n2.value) throw new Error("Passwords do not match."); await api("/settings/password", "PUT", { current_password: cur.value, new_password: n1.value }); loadSettings(); }, "Password updated") }))));
    const q = el("input", { placeholder: "Search #id, language or summary" }), fl = el("select"), fs = el("select"), list = el("div");
    fl.append(new Option("All languages", "")); Object.entries(LANGS).forEach(([k, v]) => fl.append(new Option(v, k)));
    fs.append(new Option("Any severity", "")); ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"].forEach(x => fs.append(new Option(x, x)));
    const draw = () => { list.replaceChildren(); const t = q.value.toLowerCase();
      const rows = h.reviews.filter(r => (!fl.value || r.language === fl.value) && (!fs.value || r.highest_severity === fs.value) && (!t || `#${r.id} ${r.language} ${r.summary}`.toLowerCase().includes(t)));
      if (!rows.length) list.append(el("p", { textContent: "No reviews match." }));
      rows.forEach(r => list.append(el("div", { className: "card" }, `#${r.id} · ${LANGS[r.language] || r.language} · score ${r.overall_score} · ${r.issue_count} issues · highest ${r.highest_severity} · ${new Date(r.created_at).toLocaleString()} `,
        el("button", { textContent: "Open", onclick: run(() => openReview(r.id)) }), " ", el("button", { textContent: "PDF", onclick: () => location.href = `/api/reviews/${r.id}/report?format=pdf` }), " ",
        el("button", { textContent: "Delete", onclick: run(async () => { if (!confirm("Delete this review?")) return; await api("/reviews/" + r.id, "DELETE"); h.reviews = h.reviews.filter(x => x.id !== r.id); draw(); }) })))); };
    [q, fl, fs].forEach(i => i.oninput = draw);
    box.append(el("div", { className: "card" }, el("h3", { textContent: `All history (${h.reviews.length})` }), el("div", { className: "row" }, q, fl, fs,
      el("button", { textContent: "Delete all", onclick: run(async () => { if (h.reviews.length && confirm("Delete ALL review history? This cannot be undone.")) { await api("/reviews", "DELETE"); loadSettings(); } }) })), list)); draw();
    const cf = el("input", { placeholder: "Type DELETE" }), cp = el("input", { type: "password", placeholder: "Password" });
    box.append(el("div", { className: "card danger" }, el("h3", { textContent: "Delete account" }), el("p", { textContent: "Permanently deletes your account and all reviews." }),
      el("div", { className: "row" }, cf, ...(u.has_password ? [cp] : []), el("button", { textContent: "Delete my account", onclick: run(async () => { await api("/account", "DELETE", { confirm: cf.value, password: cp.value }); setUser(null); }, "Account deleted") }))));
  } catch (x) { toast(x.message); }
}

let loaderAt = 0;
const showLoader = (title, sub) => { $("#ltitle").textContent = title; $("#lsub").textContent = sub || ""; $("#loader").hidden = false; loaderAt = Date.now(); };
const hideLoader = async (min = 700) => { const w = min - (Date.now() - loaderAt); if (w > 0 && !$("#loader").hidden) await new Promise(r => setTimeout(r, w)); $("#loader").hidden = true; };

async function loadProfile() {
  const box = $("#profbox"); box.replaceChildren();
  try {
    const [s, d] = await Promise.all([api("/settings"), api("/dashboard")]), u = s.user, tile = (v, l) => el("div", { className: "stat" }, el("b", { textContent: v }), l);
    box.append(el("div", { className: "card phead" }, el("div", { className: "avatar", textContent: u.username.slice(0, 2).toUpperCase() }),
      el("div", {}, el("h2", { textContent: u.username, style: "margin:0" }), el("p", { textContent: `${u.email || "No email"} · Member since ${new Date(u.created_at).toLocaleDateString()}` }),
        el("p", { textContent: `Default language: ${LANGS[u.default_language] || u.default_language} · Password: ${u.has_password ? "set" : "not set"}` })),
      el("button", { textContent: "Edit in Settings", onclick: () => view("set") })));
    box.append(el("div", { className: "stats" }, tile(d.total, "Reviews"), tile(d.avg_score ?? "—", "Average score"), tile(d.best_score ?? "—", "Best score"), tile(d.issues, "Issues found"), tile(d.severity.CRITICAL + d.severity.HIGH, "Critical + High")));
    box.append(el("div", { className: "card" }, el("h3", { textContent: "Languages reviewed" }), el("p", { textContent: Object.entries(d.languages).map(([k, n]) => `${LANGS[k] || k}: ${n}`).join(" · ") || "No reviews yet." })));
    const rec = el("div", { className: "card" }, el("h3", { textContent: "Recent activity" }));
    if (!d.recent.length) rec.append(el("p", { textContent: "No reviews yet." }));
    d.recent.forEach(r => rec.append(el("p", {}, `#${r.id} · ${LANGS[r.language] || r.language} · score ${r.overall_score} · ${r.issue_count} issues · ${new Date(r.created_at).toLocaleString()} `, el("button", { textContent: "Open", onclick: () => openReview(r.id) }))));
    box.append(rec);
  } catch (x) { toast(x.message); }
}

function openMenu() { $("#drawer").classList.add("open"); $("#scrim").hidden = false; $("#menu").setAttribute("aria-expanded", "true"); const b = $("#nav button"); if (b) b.focus(); }
function closeMenu() { $("#drawer").classList.remove("open"); $("#scrim").hidden = true; $("#menu").setAttribute("aria-expanded", "false"); }
$("#menu").onclick = () => $("#drawer").classList.contains("open") ? closeMenu() : openMenu();
$("#dclose").onclick = $("#scrim").onclick = closeMenu;
document.addEventListener("keydown", e => { if (e.key === "Escape") { closeMenu(); $("#menu").focus(); } });

let toolsLoaded = false;
function debugOn() { return localStorage.getItem("debug") !== "off"; }
function paintDebug() {
  const on = debugOn(), b = $("#dbgpill"); b.textContent = "🐞 Debug mode: " + (on ? "ON" : "OFF"); b.classList.toggle("on", on); b.setAttribute("aria-pressed", String(on));
  if (!on) { $("#dbgtools").replaceChildren(); $("#dbgout").replaceChildren(); toolsLoaded = false; } else if (!$("#nav").hidden) loadTools();
}
$("#dbgpill").onclick = () => { localStorage.setItem("debug", debugOn() ? "off" : "on"); paintDebug(); };
async function loadTools() {
  if (toolsLoaded) return; const box = $("#dbgtools"); box.replaceChildren(el("p", { textContent: "Checking toolchains…" }));
  try {
    const d = await api("/debug/status"); toolsLoaded = true; box.replaceChildren();
    const rows = Object.values(d.languages).map(v => el("tr", {}, el("td", { textContent: v.name }), el("td", { textContent: v.engine }), el("td", { className: v.check ? "ok" : "", textContent: v.check || "—" }),
      el("td", { className: v.run ? "ok" : "no", textContent: v.run ? `✓ ${v.run_tool}${v.version ? " (" + v.version + ")" : ""}` : "✗ " + v.hint })));
    box.append(el("details", { className: "card dbg", open: true }, el("summary", { textContent: `🐞 Debug mode: ON — toolchains on this ${d.hosted ? "server" : "computer"} · code execution ${d.execution_enabled ? "enabled" : "disabled"} · compiler checks ${d.compiler_checks ? "enabled" : "disabled"} · Python ${d.python}` }),
      el("div", { style: "overflow-x:auto" }, el("table", { className: "tools" }, el("tr", {}, ...["Language", "Review engine", "Compiler check", "Run"].map(t => el("th", { textContent: t }))), ...rows))));
  } catch (x) { box.replaceChildren(); }
}
function showDebug(info) {
  const box = $("#dbgout"); box.replaceChildren(); if (!debugOn() || !info) return;
  const c = info.compiler || {}, src = Object.entries(info.by_source || {}).map(([k, v]) => `${k}: ${v}`).join(", ");
  const rows = [["Language", info.language], ["Review engine", info.engine], ["Analysis time", `${info.analysis_ms} ms`], ["Findings", `${info.findings}${src ? " (" + src + ")" : ""}`], ["Syntax / compiler errors", info.syntax_errors], ["AI", info.ai],
    ["Compiler check", c.ran ? `${c.cmd} → exit ${c.exit}, ${c.ms} ms, ${c.errors} error(s), ${c.warnings} warning(s)` + (c.skipped ? ` — ignored: ${c.skipped}` : "") : `skipped — ${c.skipped || "n/a"}`]];
  box.append(el("div", { className: "card dbg" }, el("h3", { textContent: "🐞 Debug info for this review" }), ...rows.map(([k, v]) => el("p", {}, el("b", { textContent: k + ": " }), String(v)))));
}
paintDebug();
