/* In-process E2E test: starts app on ephemeral port, exercises the API, exits. */
process.env.SESSION_SECRET = "test-secret-123";
process.env.PORT = "0";
const _wd=setTimeout(()=>{console.log("WATCHDOG");process.exit(9)},40000); if(_wd.unref)_wd.unref();
const { app, ready } = require("./server");
const D = require("./db");

function once(server) { return new Promise(r => server.on("listening", r)); }

(async () => {
  await ready;
  await D.seedDemo();
  const server = app.listen(0);
  await once(server);
  const base = "http://127.0.0.1:" + server.address().port;
  let pass = 0, fail = 0;
  const ck = (name, cond, extra) => { (cond ? pass++ : fail++); console.log(`  ${cond ? "✅" : "❌"} ${name}${extra ? "  ("+extra+")" : ""}`); };

  // cookie jar
  let cookies = {};
  function jarHeader() { return Object.entries(cookies).map(([k, v]) => k + "=" + v).join("; "); }
  async function call(path, method, body, useJar) {
    const h = { "Content-Type": "application/json" };
    if (useJar) h["Cookie"] = jarHeader();
    const res = await fetch(base + path, { method: method || "GET", headers: h, body: body != null ? JSON.stringify(body) : undefined });
    const sc = res.headers.get("set-cookie");
    if (sc) { const m = sc.match(/^([^=]+)=([^;]*)/); if (m) cookies[m[1]] = m[2]; }
    let data = null; try { data = await res.json(); } catch (e) {}
    return { status: res.status, data };
  }

  console.log("\n=== AUTH & PERMISSIONS ===");
  let r = await call("/api/bootstrap", "GET", null, false);
  ck("unauthenticated bootstrap blocked (401)", r.status === 401, "HTTP " + r.status);

  r = await call("/api/login", "POST", { username: "admin", password: "wrong" }, false);
  ck("wrong password rejected (401)", r.status === 401);

  r = await call("/api/login", "POST", { username: "admin", password: process.env.ADMIN_PASSWORD || "Admin#Test1" }, false);
  ck("admin login (200 + cookie)", r.status === 200 && !!cookies.rt_session);

  const adminCookie = cookies.rt_session;
  r = await call("/api/bootstrap", "GET", null, true);
  const boot = r.data;
  ck("admin bootstrap ok", r.status === 200 && boot && boot.me.username === "admin");
  ck("admin sees full team", boot.users.length >= 6, "users=" + boot.users.length);
  ck("admin has all 9 perms", boot.me.perms.length === 9, "perms=" + boot.me.perms.length);
  console.log(`     users=${boot.users.length} reports=${boot.reports.length} targets=${boot.targets.length} activity=${boot.activity.length}`);

  // Ahmed employee scope
  console.log("\n=== EMPLOYEE SCOPE ===");
  cookies = {};
  r = await call("/api/login", "POST", { username: "ahmed", password: "pass123" }, false);
  ck("employee login", r.status === 200);
  const aBoot = (await call("/api/bootstrap", "GET", null, true)).data;
  ck("employee sees only self", aBoot.users.length === 1 && aBoot.users[0].username === "ahmed", "users=" + aBoot.users.length);
  ck("employee sees only own reports", aBoot.reports.every(x => x.employeeId === aBoot.me.id), "reports=" + aBoot.reports.length);
  ck("employee activity hidden", aBoot.activity.length === 0);
  ck("employee lacks review perm", !aBoot.me.perms.includes("review_reports"));

  console.log("\n=== EMPLOYEE ACTIONS ===");
  r = await call("/api/users", "POST", { name: "hack", username: "hacker9" }, true);
  ck("employee cannot create users (403)", r.status === 403, "HTTP " + r.status);

  const assigned = aBoot.reports.find(x => x.status === "assigned");
  r = await call("/api/reports/" + assigned.id + "/submit", "POST", { attachments: [{ name: "z.pdf" }] }, true);
  ck("employee submits own report", r.status === 200);

  // employee cannot approve
  r = await call("/api/reports/" + assigned.id + "/approve", "POST", { completeness: 90, quality: 90 }, true);
  ck("employee cannot approve (403)", r.status === 403, "HTTP " + r.status);

  // employee cannot submit someone else's report
  const otherRep = boot.reports.find(x => x.employeeId !== aBoot.me.id && x.status === "assigned");
  if (otherRep) {
    r = await call("/api/reports/" + otherRep.id + "/submit", "POST", {}, true);
    ck("employee cannot submit others' report (403/400)", r.status === 403 || r.status === 400, "HTTP " + r.status);
  }

  console.log("\n=== MANAGER REVIEW & BALANCE DEDUCTION ===");
  cookies = {};
  await call("/api/login", "POST", { username: "sara", password: "pass123" }, false);
  let sBoot = (await call("/api/bootstrap", "GET", null, true)).data;
  ck("manager can view all", sBoot.me.perms.includes("view_all_reports"));
  ck("manager can review", sBoot.me.perms.includes("review_reports"));
  ck("manager cannot manage users", !sBoot.me.perms.includes("manage_users"));

  // find a review report (ahmed just submitted one)
  const reviewRep = sBoot.reports.find(x => x.status === "review");
  const emp = reviewRep.employeeId;
  const approvedBefore = sBoot.reports.filter(x => x.employeeId === emp && x.status === "approved").length;
  r = await call("/api/reports/" + reviewRep.id + "/approve", "POST", { completeness: 92, quality: 88 }, true);
  ck("manager approves report", r.status === 200);
  sBoot = (await call("/api/bootstrap", "GET", null, true)).data;
  const approvedAfter = sBoot.reports.filter(x => x.employeeId === emp && x.status === "approved").length;
  ck("balance deducted on approval (+1 approved)", approvedAfter === approvedBefore + 1, `${approvedBefore}->${approvedAfter}`);

  // return requires reason
  const reviewRep2 = sBoot.reports.find(x => x.status === "review");
  if (reviewRep2) {
    r = await call("/api/reports/" + reviewRep2.id + "/return", "POST", { reason: "" }, true);
    ck("return without reason rejected (400)", r.status === 400);
    r = await call("/api/reports/" + reviewRep2.id + "/return", "POST", { reason: "نقص في المؤشرات" }, true);
    ck("return with reason ok", r.status === 200);
  }

  console.log("\n=== ADMIN: USERS, TARGETS, PERMISSIONS, SETTINGS ===");
  cookies = {};
  await call("/api/login", "POST", { username: "admin", password: process.env.ADMIN_PASSWORD || "Admin#Test1" }, false);

  r = await call("/api/users", "POST", { name: "موظف جديد", username: "newemp1", role: "employee", dept: "فريق", title: "مقيّم" }, true);
  ck("admin creates user (returns temp password)", r.status === 200 && !!r.data.tempPassword, r.data && r.data.tempPassword);
  const newId = r.data.id;

  r = await call("/api/users", "POST", { name: "dup", username: "admin" }, true);
  ck("duplicate username rejected (400)", r.status === 400);

  r = await call("/api/targets", "POST", { employeeId: newId, quarter: "2026-Q3", target: 4 }, true);
  ck("admin sets target", r.status === 200);
  let aBoot2 = (await call("/api/bootstrap", "GET", null, true)).data;
  const slots = aBoot2.reports.filter(x => x.employeeId === newId && x.quarter === "2026-Q3").length;
  ck("target auto-generated 4 report slots", slots === 4, "slots=" + slots);

  r = await call("/api/targets", "POST", { employeeId: newId, quarter: "2026-Q3", target: 2 }, true);
  aBoot2 = (await call("/api/bootstrap", "GET", null, true)).data;
  const slots2 = aBoot2.reports.filter(x => x.employeeId === newId && x.quarter === "2026-Q3").length;
  ck("reducing target removes unused slots", slots2 === 2, "slots=" + slots2);

  r = await call("/api/users/" + newId + "/toggle", "POST", null, true);
  ck("admin disables user", r.status === 200 && r.data.active === false);

  // disabled user cannot login
  const saved = { ...cookies }; cookies = {};
  r = await call("/api/login", "POST", { username: "newemp1", password: r.data.tempPassword || "x" }, false);
  ck("disabled user cannot login (403/401)", r.status === 403 || r.status === 401, "HTTP " + r.status);
  cookies = saved;

  r = await call("/api/permissions", "PUT", { role: "manager", perm: "manage_settings" }, true);
  ck("admin grants perm to manager role", r.status === 200);
  r = await call("/api/permissions", "PUT", { role: "admin", perm: "manage_users" }, true);
  ck("cannot modify admin perms (400)", r.status === 400);

  r = await call("/api/settings/weights", "PUT", { timeliness: 10, completeness: 10, quality: 10, closure: 10 }, true);
  ck("weights must sum to 100 (400)", r.status === 400);
  r = await call("/api/settings/weights", "PUT", { timeliness: 25, completeness: 25, quality: 30, closure: 20 }, true);
  ck("valid weights accepted", r.status === 200);

  console.log("\n=== PASSWORD CHANGE ===");
  r = await call("/api/me/password", "POST", { current: "wrong", next: "NewPass#9" }, true);
  ck("wrong current password rejected (400)", r.status === 400);
  r = await call("/api/me/password", "POST", { current: process.env.ADMIN_PASSWORD || "Admin#Test1", next: "NewPass#9" }, true);
  ck("admin changes own password", r.status === 200);
  cookies = {};
  r = await call("/api/login", "POST", { username: "admin", password: "NewPass#9" }, false);
  ck("login works with new password", r.status === 200);

  console.log("\n=== STATIC FRONTEND ===");
  const idx = await fetch(base + "/");
  ck("index.html served (200)", idx.status === 200);
  const html = await idx.text();
  ck("frontend references /api", html.includes('/api'), "");

  console.log(`\n================  ${pass} passed, ${fail} failed  ================\n`);
  server.close();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error("HARNESS ERROR:", e); process.exit(2); });
