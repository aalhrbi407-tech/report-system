/* =========================================================
   server.js — Express API + static hosting (async / Postgres)
   ========================================================= */
"use strict";
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const bcrypt = require("bcryptjs");
const D = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;
const SECURE_COOKIE = process.env.SECURE_COOKIE === "1";
const SESSION_SECRET = process.env.SESSION_SECRET
  || crypto.createHash("sha256").update("rt-" + (process.env.ADMIN_PASSWORD || "seed") + "-secret").digest("hex");
if (!process.env.SESSION_SECRET) {
  console.warn("⚠️  SESSION_SECRET غير محدّد — يُشتق مؤقتًا. حدّده في بيئة الإنتاج لثبات الجلسات.");
}
const SESSION_DAYS = 7;

app.set("trust proxy", 1); // خلف وكيل عكسي / منصّة سحابية
app.use(express.json({ limit: "1mb" }));

/* ---------- helpers ---------- */
function clampInt(v, min, max, dflt) { let n = parseInt(v, 10); if (isNaN(n)) n = dflt; return Math.max(min, Math.min(max, n)); }
function sanitizeExtra(arr) { return Array.isArray(arr) ? arr.filter(p => D.PERMS.includes(p)) : []; }
// يبقي فقط المعرّفات التي تخصّ مشرفين فعليين
async function sanitizeSupervisors(arr) {
  if (!Array.isArray(arr)) return [];
  const ids = arr.filter(x => typeof x === "string");
  if (!ids.length) return [];
  const rows = (await D.query("SELECT id FROM users WHERE role='manager'")).rows.map(r => r.id);
  return ids.filter(id => rows.includes(id));
}
function asyncH(fn) { return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next); }

/* =========================================================
   AUTH — signed httpOnly cookie (stateless)
   ========================================================= */
function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  return body + "." + sig;
}
function verify(token) {
  if (!token || token.indexOf(".") < 0) return null;
  const [body, sig] = token.split(".");
  const expect = crypto.createHmac("sha256", SESSION_SECRET).update(body).digest("base64url");
  try {
    const a = Buffer.from(sig), b = Buffer.from(expect);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    if (p.exp && Date.now() > p.exp) return null;
    return p;
  } catch (e) { return null; }
}
function getCookie(req, name) {
  const h = req.headers.cookie || "";
  const m = h.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return m ? decodeURIComponent(m[1]) : null;
}
function issueCookie(res, userId) {
  const token = sign({ uid: userId, exp: Date.now() + SESSION_DAYS * 864e5 });
  const parts = [`rt_session=${token}`, "HttpOnly", "Path=/", "SameSite=Lax", `Max-Age=${SESSION_DAYS * 86400}`];
  if (SECURE_COOKIE) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}
function clearCookie(res) { res.setHeader("Set-Cookie", "rt_session=; HttpOnly; Path=/; Max-Age=0"); }

async function currentUser(req) {
  const p = verify(getCookie(req, "rt_session"));
  if (!p) return null;
  const u = await D.getUserById(p.uid);
  if (!u || !u.active) return null;
  return u;
}
const requireAuth = asyncH(async (req, res, next) => {
  const u = await currentUser(req);
  if (!u) return res.status(401).json({ error: "يجب تسجيل الدخول." });
  req.user = u;
  req.perms = await D.effectivePerms(u);
  next();
});
function requirePerm(perm) {
  return (req, res, next) => {
    if (!req.perms.includes(perm)) return res.status(403).json({ error: "لا تملك صلاحية لهذا الإجراء." });
    next();
  };
}

/* =========================================================
   AUTH ROUTES
   ========================================================= */
app.post("/api/login", asyncH(async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "أدخل اسم المستخدم وكلمة المرور." });
  const u = await D.getUserByUsername(String(username).trim());
  const ok = u && bcrypt.compareSync(String(password), u.password_hash);
  if (!ok) return res.status(401).json({ error: "اسم المستخدم أو كلمة المرور غير صحيحة." });
  if (!u.active) return res.status(403).json({ error: "هذا الحساب معطّل. راجع مدير النظام." });
  await D.logActivity(u.id, "سجّل الدخول إلى النظام", "auth");
  issueCookie(res, u.id);
  res.json({ ok: true });
}));

app.post("/api/logout", requireAuth, asyncH(async (req, res) => {
  await D.logActivity(req.user.id, "سجّل الخروج", "auth");
  clearCookie(res);
  res.json({ ok: true });
}));

app.get("/api/bootstrap", requireAuth, asyncH(async (req, res) => {
  res.json(await D.bootstrap(req.user));
}));

// نصوص صفحة الدخول (عامّة، بلا مصادقة)
app.get("/api/branding", asyncH(async (req, res) => {
  res.json(await D.getBranding());
}));

app.post("/api/me/password", requireAuth, asyncH(async (req, res) => {
  const { current, next: newPass } = req.body || {};
  if (!newPass || String(newPass).length < 6) return res.status(400).json({ error: "كلمة المرور الجديدة يجب ألا تقل عن 6 أحرف." });
  if (!bcrypt.compareSync(String(current || ""), req.user.password_hash))
    return res.status(400).json({ error: "كلمة المرور الحالية غير صحيحة." });
  await D.query("UPDATE users SET password_hash=$1 WHERE id=$2", [bcrypt.hashSync(String(newPass), 10), req.user.id]);
  await D.logActivity(req.user.id, "غيّر كلمة المرور الخاصة به", "auth");
  res.json({ ok: true });
}));

/* =========================================================
   REPORT WORKFLOW
   ========================================================= */
app.post("/api/reports/:id/submit", requireAuth, requirePerm("submit_reports"), asyncH(async (req, res) => {
  const r = await D.getReportById(req.params.id);
  if (!r) return res.status(404).json({ error: "التقرير غير موجود." });
  if (r.employee_id !== req.user.id) return res.status(403).json({ error: "لا يمكنك رفع تقرير موظف آخر." });
  if (!(r.status === "assigned" || r.status === "returned"))
    return res.status(400).json({ error: "لا يمكن رفع هذا التقرير في حالته الحالية." });
  const atts = Array.isArray(req.body && req.body.attachments) ? req.body.attachments.slice(0, 20) : JSON.parse(r.attachments || "[]");
  const note = String((req.body && req.body.note) || "").slice(0, 2000);
  await D.query("UPDATE reports SET status='review', upload_date=$1, attachments=$2, submit_note=$3 WHERE id=$4",
    [D.iso(D.NOW), JSON.stringify(atts), note, r.id]);
  await D.query("INSERT INTO report_history(report_id,ts,actor,action,note) VALUES($1,$2,$3,'submitted','')",
    [r.id, D.iso(D.NOW), req.user.id]);
  await D.logActivity(req.user.id, `رفع تقرير «${r.title}» للمراجعة`, "submit");
  res.json({ ok: true });
}));

app.post("/api/reports/:id/approve", requireAuth, requirePerm("review_reports"), asyncH(async (req, res) => {
  const r = await D.getReportById(req.params.id);
  if (!r) return res.status(404).json({ error: "التقرير غير موجود." });
  if (!(await D.canManage(req.user, r.employee_id))) return res.status(403).json({ error: "هذا التقرير ليس ضمن فريقك." });
  if (r.status !== "review") return res.status(400).json({ error: "لا يمكن اعتماد تقرير ليس تحت المراجعة." });
  const c = clampInt(req.body && req.body.completeness, 0, 100, 85);
  const qy = clampInt(req.body && req.body.quality, 0, 100, 85);
  const note = String((req.body && req.body.note) || "").slice(0, 2000);
  await D.query("UPDATE reports SET status='approved', m_completeness=$1, m_quality=$2, return_reason=NULL, review_note=$3 WHERE id=$4",
    [c, qy, note, r.id]);
  await D.query("INSERT INTO report_history(report_id,ts,actor,action,note) VALUES($1,$2,$3,'approved','')",
    [r.id, D.iso(D.NOW), req.user.id]);
  const emp = await D.getUserById(r.employee_id);
  await D.logActivity(req.user.id, `اعتمد تقرير «${r.title}» لـ${emp ? emp.name : ""}`, "approve");
  res.json({ ok: true });
}));

app.post("/api/reports/:id/return", requireAuth, requirePerm("review_reports"), asyncH(async (req, res) => {
  const r = await D.getReportById(req.params.id);
  if (!r) return res.status(404).json({ error: "التقرير غير موجود." });
  if (!(await D.canManage(req.user, r.employee_id))) return res.status(403).json({ error: "هذا التقرير ليس ضمن فريقك." });
  if (r.status !== "review") return res.status(400).json({ error: "لا يمكن إعادة تقرير ليس تحت المراجعة." });
  const reason = String((req.body && req.body.reason) || "").trim();
  if (!reason) return res.status(400).json({ error: "سبب الإعادة إلزامي." });
  await D.query("UPDATE reports SET status='returned', return_reason=$1 WHERE id=$2", [reason, r.id]);
  await D.query("INSERT INTO report_history(report_id,ts,actor,action,note) VALUES($1,$2,$3,'returned',$4)",
    [r.id, D.iso(D.NOW), req.user.id, reason]);
  const emp = await D.getUserById(r.employee_id);
  await D.logActivity(req.user.id, `أعاد تقرير «${r.title}» لـ${emp ? emp.name : ""} للتعديل`, "return");
  res.json({ ok: true });
}));

/* =========================================================
   TARGETS
   ========================================================= */
// إضافة مستهدف واحد باسمه وتاريخه لموظف
app.post("/api/targets", requireAuth, requirePerm("assign_targets"), asyncH(async (req, res) => {
  const empId = String((req.body && req.body.employeeId) || "");
  const quarter = String((req.body && req.body.quarter) || D.CUR_Q);
  const title = String((req.body && req.body.title) || "").trim();
  const dueDate = String((req.body && req.body.dueDate) || "").trim() || D.dayShift(14);
  const emp = await D.getUserById(empId);
  if (!emp || emp.role !== "employee") return res.status(400).json({ error: "موظف غير صالح." });
  if (!/^\d{4}-Q[1-4]$/.test(quarter)) return res.status(400).json({ error: "ربع غير صالح." });
  if (!title) return res.status(400).json({ error: "اسم المستهدف مطلوب." });
  if (!(await D.canManage(req.user, empId))) return res.status(403).json({ error: "هذا الموظف ليس ضمن فريقك." });
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dueDate)) return res.status(400).json({ error: "تاريخ الاستحقاق غير صالح." });

  const maxSlot = (await D.query("SELECT COALESCE(MAX(slot_no),0)::int AS m FROM reports WHERE employee_id=$1 AND quarter=$2", [empId, quarter])).rows[0].m;
  await D.query(`INSERT INTO reports(id,slot_no,employee_id,type_id,quarter,title,status,due_date,attachments)
    VALUES($1,$2,$3,'general',$4,$5,'assigned',$6,'[]')`,
    [D.uid("r"), maxSlot + 1, empId, quarter, title, dueDate]);
  await D.syncTargetCount(empId, quarter);
  await D.logActivity(req.user.id, `أسند مستهدف «${title}» لـ${emp.name} (${quarter})`, "target");
  res.json({ ok: true });
}));

// حذف مستهدف مفرد (فقط إن لم يُرفع/يُعتمد بعد)
app.post("/api/targets/:reportId/delete", requireAuth, requirePerm("assign_targets"), asyncH(async (req, res) => {
  const r = await D.getReportById(req.params.reportId);
  if (!r) return res.status(404).json({ error: "المستهدف غير موجود." });
  if (!(await D.canManage(req.user, r.employee_id))) return res.status(403).json({ error: "هذا الموظف ليس ضمن فريقك." });
  if (!(r.status === "assigned" || r.status === "returned"))
    return res.status(400).json({ error: "لا يمكن حذف مستهدف تم رفعه أو اعتماده." });
  await D.query("DELETE FROM report_history WHERE report_id=$1", [r.id]);
  await D.query("DELETE FROM reports WHERE id=$1", [r.id]);
  await D.syncTargetCount(r.employee_id, r.quarter);
  const emp = await D.getUserById(r.employee_id);
  await D.logActivity(req.user.id, `حذف مستهدف «${r.title}» من ${emp ? emp.name : ""}`, "target");
  res.json({ ok: true });
}));

/* =========================================================
   USERS
   ========================================================= */
app.post("/api/users", requireAuth, requirePerm("manage_users"), asyncH(async (req, res) => {
  const b = req.body || {};
  const name = String(b.name || "").trim(), username = String(b.username || "").trim();
  if (!name || !username) return res.status(400).json({ error: "الاسم واسم المستخدم مطلوبان." });
  if (!/^[a-zA-Z0-9._-]{3,}$/.test(username)) return res.status(400).json({ error: "اسم المستخدم: أحرف لاتينية/أرقام، 3 على الأقل." });
  if (await D.getUserByUsername(username)) return res.status(400).json({ error: "اسم المستخدم مستخدم بالفعل." });
  const role = D.ROLES.includes(b.role) ? b.role : "employee";
  const pass = String(b.password || "").length >= 6 ? String(b.password) : "Welcome#2026";
  const extra = sanitizeExtra(b.extraPerms);
  const supervisors = await sanitizeSupervisors(b.supervisors);
  const id = D.uid("u");
  await D.query(`INSERT INTO users(id,name,username,password_hash,role,dept,title,active,extra_perms,supervisors,created_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,$10)`,
    [id, name, username, bcrypt.hashSync(pass, 10), role, String(b.dept || ""), String(b.title || ""), JSON.stringify(extra), JSON.stringify(supervisors), D.iso(D.NOW)]);
  await D.logActivity(req.user.id, `أنشأ حساب المستخدم «${name}»`, "user");
  res.json({ ok: true, id, tempPassword: b.password ? undefined : pass });
}));

app.put("/api/users/:id", requireAuth, requirePerm("manage_users"), asyncH(async (req, res) => {
  const u = await D.getUserById(req.params.id);
  if (!u) return res.status(404).json({ error: "المستخدم غير موجود." });
  const b = req.body || {};
  const name = String(b.name || u.name).trim();
  const username = String(b.username || u.username).trim();
  const dup = await D.getUserByUsername(username);
  if (dup && dup.id !== u.id) return res.status(400).json({ error: "اسم المستخدم مستخدم بالفعل." });
  const role = D.ROLES.includes(b.role) ? b.role : u.role;
  const extra = sanitizeExtra(b.extraPerms);
  const supervisors = await sanitizeSupervisors(b.supervisors);
  await D.query("UPDATE users SET name=$1, username=$2, role=$3, dept=$4, title=$5, extra_perms=$6, supervisors=$7 WHERE id=$8",
    [name, username, role, String(b.dept || ""), String(b.title || ""), JSON.stringify(extra), JSON.stringify(supervisors), u.id]);
  if (b.password && String(b.password).length >= 6)
    await D.query("UPDATE users SET password_hash=$1 WHERE id=$2", [bcrypt.hashSync(String(b.password), 10), u.id]);
  await D.logActivity(req.user.id, `عدّل حساب المستخدم «${name}»`, "user");
  res.json({ ok: true });
}));

app.post("/api/users/:id/toggle", requireAuth, requirePerm("manage_users"), asyncH(async (req, res) => {
  const u = await D.getUserById(req.params.id);
  if (!u) return res.status(404).json({ error: "المستخدم غير موجود." });
  if (u.id === req.user.id) return res.status(400).json({ error: "لا يمكنك تعطيل حسابك." });
  const active = u.active ? 0 : 1;
  await D.query("UPDATE users SET active=$1 WHERE id=$2", [active, u.id]);
  await D.logActivity(req.user.id, `${active ? "فعّل" : "عطّل"} حساب «${u.name}»`, "user");
  res.json({ ok: true, active: !!active });
}));

/* =========================================================
   PERMISSIONS (role matrix)
   ========================================================= */
app.put("/api/permissions", requireAuth, requirePerm("manage_permissions"), asyncH(async (req, res) => {
  const role = String((req.body && req.body.role) || "");
  const perm = String((req.body && req.body.perm) || "");
  if (role === "admin") return res.status(400).json({ error: "لا يمكن تعديل صلاحيات مدير النظام." });
  if (!["general_manager", "manager", "employee"].includes(role)) return res.status(400).json({ error: "دور غير صالح." });
  if (!D.PERMS.includes(perm)) return res.status(400).json({ error: "صلاحية غير صالحة." });
  const rp = await D.getRolePerms();
  const arr = rp[role] || [];
  const i = arr.indexOf(perm);
  if (i >= 0) arr.splice(i, 1); else arr.push(perm);
  await D.setRolePerm(role, arr);
  await D.logActivity(req.user.id, `${i >= 0 ? "ألغى" : "منح"} صلاحية «${perm}» لدور «${role}»`, "perm");
  res.json({ ok: true });
}));

/* =========================================================
   SETTINGS
   ========================================================= */
app.put("/api/settings/weights", requireAuth, requirePerm("manage_settings"), asyncH(async (req, res) => {
  const w = req.body || {};
  const keys = ["timeliness", "completeness", "quality", "closure"];
  const out = {}; let sum = 0;
  for (const k of keys) { out[k] = clampInt(w[k], 0, 100, 0); sum += out[k]; }
  if (sum !== 100) return res.status(400).json({ error: "مجموع الأوزان يجب أن يكون 100%." });
  await D.setSetting("weights", out);
  await D.logActivity(req.user.id, "حدّث أوزان نموذج التقييم", "settings");
  res.json({ ok: true });
}));

app.put("/api/settings/org", requireAuth, requirePerm("manage_settings"), asyncH(async (req, res) => {
  const b = req.body || {};
  if (b.orgName) await D.setSetting("orgName", String(b.orgName).slice(0, 120));
  if (b.program) await D.setSetting("program", String(b.program).slice(0, 120));
  await D.logActivity(req.user.id, "حدّث هوية النظام", "settings");
  res.json({ ok: true });
}));

// نصوص صفحة الدخول
app.put("/api/settings/branding", requireAuth, requirePerm("manage_settings"), asyncH(async (req, res) => {
  const b = req.body || {};
  const str = (v, n) => String(v == null ? "" : v).slice(0, n);
  if (b.systemName != null) await D.setSetting("systemName", str(b.systemName, 80) || "نظام تكليف");
  if (b.logo != null) {
    const logo = String(b.logo || "");
    if (logo === "") {
      await D.setSetting("logo", "");                       // إزالة الشعار
    } else {
      if (!/^data:image\/(png|jpeg|jpg|svg\+xml|webp|gif);base64,/.test(logo))
        return res.status(400).json({ error: "صيغة الشعار غير مدعومة (استخدم PNG أو SVG أو JPG)." });
      if (logo.length > 700000)
        return res.status(400).json({ error: "حجم الشعار كبير — استخدم صورة أصغر من 500 كيلوبايت." });
      await D.setSetting("logo", logo);
    }
  }
  if (b.orgName != null) await D.setSetting("orgName", str(b.orgName, 120));
  if (b.program != null) await D.setSetting("program", str(b.program, 120));
  if (b.loginTitle1 != null) await D.setSetting("loginTitle1", str(b.loginTitle1, 120));
  if (b.loginTitle2 != null) await D.setSetting("loginTitle2", str(b.loginTitle2, 120));
  if (b.loginIntro != null) await D.setSetting("loginIntro", str(b.loginIntro, 600));
  if (Array.isArray(b.loginPoints)) await D.setSetting("loginPoints", b.loginPoints.slice(0, 6).map(x => str(x, 100)).filter(Boolean));
  if (b.loginFooter != null) await D.setSetting("loginFooter", str(b.loginFooter, 160));
  await D.logActivity(req.user.id, "حدّث نصوص صفحة الدخول", "settings");
  res.json({ ok: true });
}));

// حذف جميع بيانات التقارير والمستهدفات (يُبقي المستخدمين والإعدادات)
app.post("/api/data/reset-assignments", requireAuth, requirePerm("manage_settings"), asyncH(async (req, res) => {
  if (!(req.body && req.body.confirm === "DELETE"))
    return res.status(400).json({ error: "التأكيد مطلوب." });
  await D.resetAssignments();
  await D.logActivity(req.user.id, "مسح جميع بيانات التقارير والمستهدفات", "settings");
  res.json({ ok: true });
}));

/* =========================================================
   EXPORT — تصدير التقارير إلى Excel
   ========================================================= */
function daysBetween(a, b) {
  const d1 = new Date(a), d2 = new Date(b);
  return Math.round((d2 - d1) / 86400000);
}
function timelinessScore(r) {
  if (!r.upload_date) return 0;
  const late = daysBetween(r.due_date, r.upload_date);
  if (late <= 0) return 100;
  return Math.max(0, 100 - late * 10);
}
function closureScore(hist) {
  const returns = (hist || []).filter(h => h.action === "returned").length;
  return Math.max(0, 100 - returns * 25);
}
function scoreReport(r, hist, w) {
  if (r.status !== "approved") return null;
  const t = timelinessScore(r);
  const c = r.m_completeness != null ? r.m_completeness : 0;
  const qy = r.m_quality != null ? r.m_quality : 0;
  const cl = closureScore(hist);
  return Math.round((t * w.timeliness + c * w.completeness + qy * w.quality + cl * w.closure) / 100);
}
const STATUS_AR = { assigned: "مسندة", review: "تحت المراجعة", approved: "معتمدة", returned: "معادة" };

app.get("/api/export/xlsx", requireAuth, requirePerm("view_statistics"), asyncH(async (req, res) => {
  const XLSX = require("xlsx");
  const quarter = String(req.query.quarter || D.CUR_Q);
  if (!/^\d{4}-Q[1-4]$/.test(quarter)) return res.status(400).json({ error: "ربع غير صالح." });

  const settings = await D.getSettings();
  const w = settings.weights;
  const scopeIds = await D.managedEmployeeIds(req.user);      // نطاق صلاحية المستخدم
  const allUsers = (await D.query("SELECT * FROM users")).rows;
  const byId = {}; allUsers.forEach(u => byId[u.id] = u);
  const emps = allUsers.filter(u => u.role === "employee" && scopeIds.includes(u.id) && u.active);

  const reps = (await D.query("SELECT * FROM reports WHERE quarter=$1", [quarter])).rows
    .filter(r => scopeIds.includes(r.employee_id));
  const tgts = (await D.query("SELECT * FROM targets WHERE quarter=$1", [quarter])).rows;
  const hists = (await D.query("SELECT * FROM report_history ORDER BY id ASC")).rows;
  const histBy = {}; hists.forEach(h => (histBy[h.report_id] = histBy[h.report_id] || []).push(h));

  const supNames = e => {
    const ids = JSON.parse(e.supervisors || "[]");
    return ids.map(id => byId[id] ? byId[id].name : "").filter(Boolean).join("، ") || "—";
  };

  // ورقة 1: ملخّص الموظفين — مرتّبة حسب الأداء العام (الأعلى أولًا)
  const stats = emps.map(e => {
    const mine = reps.filter(r => r.employee_id === e.id);
    const t = (tgts.find(x => x.employee_id === e.id) || {}).target || 0;
    const appr = mine.filter(r => r.status === "approved");
    const late = mine.filter(r => r.status !== "approved" && new Date(r.due_date) < new Date()).length;
    const pct = t ? Math.round(appr.length / t * 100) : 0;
    const scores = appr.map(r => scoreReport(r, histBy[r.id], w)).filter(x => x != null);
    const avg = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
    return { e, t, appr: appr.length, late, pct, avg, perf: Math.round(pct * avg / 100) };
  }).sort((a, b) => b.perf - a.perf || b.pct - a.pct);

  const sum = [["#", "الموظف", "الإدارة", "المشرف", "المستهدف", "معتمدة", "متبقّي", "نسبة الإنجاز %", "متوسط الدرجة %", "متأخرة", "الأداء العام %"]];
  stats.forEach((s, i) => {
    sum.push([i + 1, s.e.name, s.e.dept || "—", supNames(s.e), s.t, s.appr,
      Math.max(0, s.t - s.appr), s.pct, s.avg || "—", s.late, s.perf]);
  });

  // ورقة 2: تفاصيل المهام — بنفس ترتيب الأداء
  const order = {}; stats.forEach((s, i) => order[s.e.id] = i);
  const det = [["الموظف", "اسم المهمة", "الحالة", "تاريخ الاستحقاق", "تاريخ التسليم", "الاكتمال %", "الجودة %", "الدرجة %", "متأخرة", "ملاحظة الموظف", "ملاحظة المشرف"]];
  reps.sort((a, b) => (order[a.employee_id] ?? 999) - (order[b.employee_id] ?? 999) || a.slot_no - b.slot_no);
  reps.forEach(r => {
    const e = byId[r.employee_id]; if (!e) return;
    const sc = scoreReport(r, histBy[r.id], w);
    const late = r.status !== "approved" && new Date(r.due_date) < new Date();
    det.push([e.name, r.title || "—", STATUS_AR[r.status] || r.status, r.due_date || "—", r.upload_date || "—",
      r.m_completeness != null ? r.m_completeness : "—", r.m_quality != null ? r.m_quality : "—",
      sc != null ? sc : "—", late ? "نعم" : "لا", r.submit_note || "—", r.review_note || r.return_reason || "—"]);
  });

  const wb = XLSX.utils.book_new();
  const ws1 = XLSX.utils.aoa_to_sheet(sum);
  ws1["!cols"] = [{ wch: 5 }, { wch: 22 }, { wch: 20 }, { wch: 20 }, { wch: 10 }, { wch: 10 }, { wch: 10 }, { wch: 14 }, { wch: 15 }, { wch: 9 }, { wch: 14 }];
  const ws2 = XLSX.utils.aoa_to_sheet(det);
  ws2["!cols"] = [{ wch: 22 }, { wch: 30 }, { wch: 13 }, { wch: 14 }, { wch: 14 }, { wch: 11 }, { wch: 10 }, { wch: 10 }, { wch: 9 }, { wch: 30 }, { wch: 30 }];
  XLSX.utils.book_append_sheet(wb, ws1, "ملخص الموظفين");
  XLSX.utils.book_append_sheet(wb, ws2, "تفاصيل المهام");

  const buf = XLSX.write(wb, { type: "buffer", bookType: "xlsx" });
  await D.logActivity(req.user.id, `صدّر تقرير الأداء (${quarter}) إلى Excel`, "export");
  res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
  res.setHeader("Content-Disposition", `attachment; filename="taklif-${quarter}.xlsx"`);
  res.send(buf);
}));

/* =========================================================
   STATIC HOSTING (frontend embedded — no external folder)
   ========================================================= */
const HTML = require("./frontend");
app.get("*", (req, res) => {
  if (req.path.startsWith("/api/")) return res.status(404).json({ error: "غير موجود." });
  res.type("html").send(HTML);
});

/* error guard */
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: "خطأ داخلي في الخادم." });
});

/* =========================================================
   STARTUP
   ========================================================= */
const ready = (async () => {
  await D.init();
  await D.seedBase(false);
  console.log(`   قاعدة البيانات: ${D.backend()}`);
})();

if (require.main === module) {
  ready.then(() => {
    app.listen(PORT, () => {
      console.log(`\n🚀 نظام متابعة التقارير يعمل على المنفذ ${PORT}`);
      console.log(`   افتح: http://localhost:${PORT}\n`);
    });
  }).catch(e => { console.error("فشل بدء التشغيل:", e); process.exit(1); });
}

module.exports = { app, ready };
