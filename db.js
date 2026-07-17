/* =========================================================
   db.js — Postgres data layer (async)
   يعمل مع:
     • Neon / أي Postgres عبر DATABASE_URL  (الإنتاج)
     • PGlite محليًا بدون أي إعداد            (التطوير/الاختبار)
   ========================================================= */
"use strict";
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");

/* ---------- catalog ---------- */
const PERMS = [
  "manage_users", "manage_permissions", "manage_settings", "assign_targets",
  "review_reports", "view_all_reports", "view_statistics", "view_activity", "submit_reports"
];
const DEFAULT_ROLE_PERMS = {
  admin: PERMS.slice(),
  general_manager: ["assign_targets", "review_reports", "view_all_reports", "view_statistics", "view_activity"],
  manager: ["assign_targets", "review_reports", "view_all_reports", "view_statistics", "view_activity"],
  employee: ["submit_reports"]
};
const ROLES = ["admin", "general_manager", "manager", "employee"];
// من يرى كل الفرق دون تقييد بربط:
function roleSeesAll(role) { return role === "admin" || role === "general_manager"; }
const QUARTERS = ["2026-Q1", "2026-Q2", "2026-Q3"];
const CUR_Q = "2026-Q3";

/* ---------- date helpers ---------- */
const NOW = new Date();
const iso = d => d.toISOString().slice(0, 10);
const dayShift = n => { const d = new Date(NOW); d.setDate(d.getDate() + n); return iso(d); };
function uid(prefix) { return prefix + "_" + Date.now().toString(36) + Math.random().toString(36).slice(2, 7); }

/* =========================================================
   EXECUTOR  (abstracts pg Pool vs PGlite)
   X.query(sql, params) -> { rows }
   X.tx(async (q) => { ... })   // q(sql, params) inside a transaction
   ========================================================= */
let X = null;
let BACKEND = "";

async function init() {
  if (X) return X;
  if (process.env.DATABASE_URL) {
    // ---- Production: real Postgres (Neon, etc.) ----
    const { Pool } = require("pg");
    const useSSL = !/localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL);
    const pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: useSSL ? { rejectUnauthorized: false } : false,
      max: 5
    });
    X = {
      query: (sql, params) => pool.query(sql, params),
      tx: async (fn) => {
        const c = await pool.connect();
        try { await c.query("BEGIN"); const r = await fn((s, p) => c.query(s, p)); await c.query("COMMIT"); return r; }
        catch (e) { await c.query("ROLLBACK"); throw e; }
        finally { c.release(); }
      },
      end: () => pool.end()
    };
    BACKEND = "postgres";
  } else {
    // ---- Local/dev/test: PGlite (in-process Postgres) ----
    const { PGlite } = require("@electric-sql/pglite");
    const dir = process.env.PGLITE_DIR || path.join(process.env.DATA_DIR || path.join(__dirname, "data"), "pg");
    let pg;
    if (dir === ":memory:") { pg = new PGlite(); }
    else { fs.mkdirSync(path.dirname(dir), { recursive: true }); pg = new PGlite(dir); }
    await pg.waitReady;
    X = {
      query: (sql, params) => pg.query(sql, params || []),
      tx: async (fn) => pg.transaction(async (tx) => fn((s, p) => tx.query(s, p || []))),
      end: () => pg.close()
    };
    BACKEND = "pglite";
  }
  await migrate();
  return X;
}
function backend() { return BACKEND; }

/* =========================================================
   SCHEMA
   ========================================================= */
async function migrate() {
  await X.query(`
    CREATE TABLE IF NOT EXISTS users(
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      dept TEXT,
      title TEXT,
      active INTEGER NOT NULL DEFAULT 1,
      extra_perms TEXT NOT NULL DEFAULT '[]',
      supervisors TEXT NOT NULL DEFAULT '[]',
      created_at TEXT
    )`);
  // ترقية قواعد البيانات القائمة:
  await X.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS supervisors TEXT NOT NULL DEFAULT '[]'`);
  await X.query(`
    CREATE TABLE IF NOT EXISTS targets(
      id TEXT PRIMARY KEY,
      employee_id TEXT NOT NULL,
      quarter TEXT NOT NULL,
      target INTEGER NOT NULL DEFAULT 0,
      UNIQUE(employee_id, quarter)
    )`);
  await X.query(`
    CREATE TABLE IF NOT EXISTS reports(
      id TEXT PRIMARY KEY,
      slot_no INTEGER,
      employee_id TEXT NOT NULL,
      type_id TEXT,
      quarter TEXT NOT NULL,
      title TEXT,
      status TEXT NOT NULL DEFAULT 'assigned',
      due_date TEXT,
      upload_date TEXT,
      weight REAL DEFAULT 1,
      m_completeness INTEGER,
      m_quality INTEGER,
      return_reason TEXT,
      attachments TEXT NOT NULL DEFAULT '[]'
    )`);
  await X.query(`
    CREATE TABLE IF NOT EXISTS report_history(
      id BIGSERIAL PRIMARY KEY,
      report_id TEXT NOT NULL,
      ts TEXT, actor TEXT, action TEXT, note TEXT
    )`);
  await X.query(`
    CREATE TABLE IF NOT EXISTS activity(
      id BIGSERIAL PRIMARY KEY,
      ts TEXT, actor TEXT, action TEXT, type TEXT
    )`);
  await X.query(`CREATE TABLE IF NOT EXISTS role_perms(role TEXT PRIMARY KEY, perms TEXT NOT NULL DEFAULT '[]')`);
  await X.query(`CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT)`);
  await X.query(`CREATE INDEX IF NOT EXISTS idx_reports_emp ON reports(employee_id, quarter)`);
  await X.query(`CREATE INDEX IF NOT EXISTS idx_hist_report ON report_history(report_id)`);
}

/* =========================================================
   SETTINGS / ROLE PERMS
   ========================================================= */
async function getSetting(key, fallback) {
  const { rows } = await X.query("SELECT value FROM settings WHERE key=$1", [key]);
  return rows.length ? JSON.parse(rows[0].value) : fallback;
}
async function setSetting(key, value) {
  await X.query(
    "INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",
    [key, JSON.stringify(value)]);
}
const DEFAULT_TYPES = [
  { id: "mystery", n: "الزائر السري", w: 1 },
  { id: "field", n: "زيارة ميدانية", w: 1 },
  { id: "deep", n: "تقرير معمّق", w: 1.5 }
];
async function getReportTypes() { return getSetting("reportTypes", DEFAULT_TYPES); }
async function getSettings() {
  return {
    weights: await getSetting("weights", { timeliness: 30, completeness: 25, quality: 30, closure: 15 }),
    orgName: await getSetting("orgName", "إدارة الجودة وتجربة المستفيد"),
    program: await getSetting("program", "برنامج الزائر السري")
  };
}
async function getRolePerms() {
  const { rows } = await X.query("SELECT role,perms FROM role_perms");
  const out = {};
  rows.forEach(r => out[r.role] = JSON.parse(r.perms));
  ROLES.forEach(r => { if (!out[r]) out[r] = DEFAULT_ROLE_PERMS[r].slice(); });
  out.admin = PERMS.slice();
  return out;
}
async function setRolePerm(role, perms) {
  await X.query(
    "INSERT INTO role_perms(role,perms) VALUES($1,$2) ON CONFLICT(role) DO UPDATE SET perms=EXCLUDED.perms",
    [role, JSON.stringify(perms)]);
}

/* =========================================================
   MAPPERS
   ========================================================= */
function mapUser(r, includeHash) {
  if (!r) return null;
  const u = { id: r.id, name: r.name, username: r.username, role: r.role, dept: r.dept, title: r.title,
    active: !!r.active, extraPerms: JSON.parse(r.extra_perms || "[]"),
    supervisors: JSON.parse(r.supervisors || "[]") };
  if (includeHash) u.password_hash = r.password_hash;
  return u;
}
function mapTarget(r) { return { id: r.id, employeeId: r.employee_id, quarter: r.quarter, target: r.target }; }
async function mapReport(r) {
  const { rows } = await X.query(
    "SELECT ts,actor,action,note FROM report_history WHERE report_id=$1 ORDER BY id ASC", [r.id]);
  return {
    id: r.id, slotNo: r.slot_no, employeeId: r.employee_id, typeId: r.type_id, quarter: r.quarter,
    title: r.title, status: r.status, dueDate: r.due_date, uploadDate: r.upload_date, weight: r.weight,
    mCompleteness: r.m_completeness, mQuality: r.m_quality, returnReason: r.return_reason,
    attachments: JSON.parse(r.attachments || "[]"),
    history: rows.map(h => ({ ts: h.ts, actor: h.actor, action: h.action, note: h.note || "" }))
  };
}
function mapActivity(r) { return { id: Number(r.id), ts: r.ts, actor: r.actor, action: r.action, type: r.type }; }

/* =========================================================
   ACCESSORS
   ========================================================= */
async function getUserById(id) { const { rows } = await X.query("SELECT * FROM users WHERE id=$1", [id]); return rows[0] || null; }
async function getUserByUsername(u) { const { rows } = await X.query("SELECT * FROM users WHERE username=$1", [u]); return rows[0] || null; }
async function getReportById(id) { const { rows } = await X.query("SELECT * FROM reports WHERE id=$1", [id]); return rows[0] || null; }

async function effectivePerms(userRow) {
  if (!userRow) return [];
  const rp = await getRolePerms();
  const base = rp[userRow.role] || [];
  const ex = JSON.parse(userRow.extra_perms || "[]");
  const s = new Set([...base, ...ex]);
  if (userRow.role === "admin") PERMS.forEach(p => s.add(p));
  return [...s];
}

async function logActivity(actor, action, type) {
  await X.query("INSERT INTO activity(ts,actor,action,type) VALUES($1,$2,$3,$4)", [iso(NOW), actor, action, type || "info"]);
}

/* ---------- team scoping ---------- */
// أسماء الموظفين الذين يراهم هذا المستخدم:
//   admin / general_manager -> كل الموظفين
//   manager -> الموظفون المرتبطون به فقط
//   employee -> نفسه فقط
async function managedEmployeeIds(userRow) {
  const emps = (await X.query("SELECT id, role, supervisors FROM users WHERE role='employee'")).rows;
  if (roleSeesAll(userRow.role)) return emps.map(e => e.id);
  if (userRow.role === "manager")
    return emps.filter(e => JSON.parse(e.supervisors || "[]").includes(userRow.id)).map(e => e.id);
  return [userRow.id];
}
// هل يحق لهذا المستخدم التصرّف على تقارير/مستهدفات هذا الموظف؟
async function canManage(userRow, employeeId) {
  if (roleSeesAll(userRow.role)) return true;
  if (userRow.role !== "manager") return false;
  const emp = await getUserById(employeeId);
  if (!emp) return false;
  return JSON.parse(emp.supervisors || "[]").includes(userRow.id);
}

/* =========================================================
   BOOTSTRAP (permission-scoped snapshot)
   ========================================================= */
async function bootstrap(userRow) {
  const perms = await effectivePerms(userRow);
  const seesAll = roleSeesAll(userRow.role);
  const isManager = userRow.role === "manager";
  const canActivity = perms.includes("view_activity");
  const allUsers = (await X.query("SELECT * FROM users")).rows;

  let users, empScope;
  if (seesAll) {
    users = allUsers.map(u => mapUser(u));
    empScope = null; // كل الموظفين
  } else if (isManager) {
    const managed = await managedEmployeeIds(userRow); // ids الموظفين المرتبطين
    const set = new Set(managed);
    // يرى نفسه + المشرفين المشاركين + موظفيه (حتى تظهر الأسماء في الواجهة)
    users = allUsers.filter(u => u.id === userRow.id || set.has(u.id) || u.role === "manager" || u.role === "general_manager").map(u => mapUser(u));
    empScope = set;
  } else {
    users = [mapUser(userRow)];
    empScope = new Set([userRow.id]);
  }

  const inScope = r => empScope === null ? true : empScope.has(r.employee_id);
  const allReports = (await X.query("SELECT * FROM reports")).rows.filter(inScope);
  const reports = [];
  for (const r of allReports) reports.push(await mapReport(r));

  const targets = (await X.query("SELECT * FROM targets")).rows.filter(inScope).map(mapTarget);

  let activity = [];
  if (canActivity) {
    const rows = (await X.query("SELECT * FROM activity ORDER BY id DESC LIMIT 200")).rows;
    if (seesAll) activity = rows.map(mapActivity);
    else {
      const actors = new Set([userRow.id, ...(empScope ? [...empScope] : [])]);
      activity = rows.filter(a => actors.has(a.actor)).map(mapActivity);
    }
  }

  const meObj = mapUser(userRow); meObj.perms = perms;
  return {
    session: userRow.id, me: meObj, users, reports, targets, activity,
    rolePerms: await getRolePerms(), settings: await getSettings(),
    quarters: QUARTERS, currentQuarter: CUR_Q, permsCatalog: PERMS
  };
}

/* =========================================================
   SEED
   ========================================================= */
async function isEmpty() { const { rows } = await X.query("SELECT COUNT(*)::int AS c FROM users"); return rows[0].c === 0; }

async function seedBase(force) {
  if (!force && !(await isEmpty())) return false;
  for (const r of Object.keys(DEFAULT_ROLE_PERMS)) await setRolePerm(r, DEFAULT_ROLE_PERMS[r]);
  await setSetting("weights", { timeliness: 30, completeness: 25, quality: 30, closure: 15 });
  await setSetting("orgName", process.env.ORG_NAME || "إدارة الجودة وتجربة المستفيد");
  await setSetting("program", process.env.PROGRAM_NAME || "برنامج الزائر السري");
  await setSetting("reportTypes", DEFAULT_TYPES);

  const adminUser = process.env.ADMIN_USERNAME || "admin";
  const adminPass = process.env.ADMIN_PASSWORD || "ChangeMe#2026";
  const adminName = process.env.ADMIN_NAME || "مدير النظام";
  const hash = bcrypt.hashSync(adminPass, 10);
  await X.query(
    `INSERT INTO users(id,name,username,password_hash,role,dept,title,active,extra_perms,created_at)
     VALUES('u_admin',$1,$2,$3,'admin','إدارة النظام','مدير النظام',1,'[]',$4)
     ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name, username=EXCLUDED.username, password_hash=EXCLUDED.password_hash`,
    [adminName, adminUser, hash, iso(NOW)]);
  await logActivity("u_admin", "تهيئة النظام وإنشاء حساب مدير النظام", "settings");
  console.log(`\n✅ تم تهيئة قاعدة البيانات (${BACKEND}).`);
  console.log(`   حساب مدير النظام:  المستخدم = ${adminUser}  |  كلمة المرور = ${adminPass}`);
  console.log(`   ⚠️  غيّر كلمة المرور فور أول دخول.\n`);
  return true;
}

async function seedDemo() {
  const H = pw => bcrypt.hashSync(pw, 10);
  const U = (id, name, username, role, dept, title, active) =>
    X.query(`INSERT INTO users(id,name,username,password_hash,role,dept,title,active,extra_perms,created_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,'[]',$9) ON CONFLICT(id) DO NOTHING`,
      [id, name, username, H("pass123"), role, dept, title, active ? 1 : 0, iso(NOW)]);
  await U("u_gm", "بدر العنزي", "gm", "general_manager", "الإدارة العليا", "مدير عام", 1);
  await U("u_sara", "سارة الشهري", "sara", "manager", "إدارة الجودة وتجربة المستفيد", "مشرفة برنامج الزائر السري", 1);
  await U("u_ahmed", "أحمد محمد", "ahmed", "employee", "فريق الزائر السري", "مقيّم تجربة المستفيد", 1);
  await U("u_khaled", "خالد العتيبي", "khaled", "employee", "فريق الزائر السري", "مقيّم ميداني", 1);
  await U("u_noura", "نورة القحطاني", "noura", "employee", "فريق الزائر السري", "مقيّمة تجربة المستفيد", 1);
  await U("u_maha", "مها السالم", "maha", "employee", "فريق الزائر السري", "مقيّمة تجربة المستفيد", 1);
  // ربط الموظفين بالمشرفة سارة (نموذج تجريبي)
  await X.query("UPDATE users SET supervisors='[\"u_sara\"]' WHERE id IN ('u_ahmed','u_khaled','u_noura','u_maha')");

  const T = (emp, quarter, target) =>
    X.query("INSERT INTO targets(id,employee_id,quarter,target) VALUES($1,$2,$3,$4) ON CONFLICT(employee_id,quarter) DO NOTHING",
      [uid("t"), emp, quarter, target]);
  const R = async (o) => {
    const r = Object.assign({ id: uid("r"), slot_no: 0, type_id: "mystery", quarter: CUR_Q, status: "assigned",
      due_date: dayShift(15), upload_date: null, weight: 1, m_completeness: null, m_quality: null,
      return_reason: null, attachments: "[]" }, o);
    await X.query(`INSERT INTO reports(id,slot_no,employee_id,type_id,quarter,title,status,due_date,upload_date,weight,m_completeness,m_quality,return_reason,attachments)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
      [r.id, r.slot_no, r.employee_id, r.type_id, r.quarter, r.title, r.status, r.due_date, r.upload_date, r.weight, r.m_completeness, r.m_quality, r.return_reason, r.attachments]);
    for (const h of (o._hist || []))
      await X.query("INSERT INTO report_history(report_id,ts,actor,action,note) VALUES($1,$2,$3,$4,$5)", [r.id, h.ts, h.actor, h.action, h.note || ""]);
  };
  const t = ["تجربة العيادات الخارجية", "المراكز الصحية الأولية", "غرف العمليات", "العناية المركزة", "الوصول الشامل", "قسم الطوارئ", "الصيدلية الخارجية"];

  await T("u_ahmed", CUR_Q, 5);
  await R({ employee_id: "u_ahmed", slot_no: 1, title: t[0], status: "approved", due_date: dayShift(-28), upload_date: dayShift(-30), m_completeness: 96, m_quality: 92, _hist: [{ ts: dayShift(-30), actor: "u_ahmed", action: "submitted" }, { ts: dayShift(-28), actor: "u_sara", action: "approved" }] });
  await R({ employee_id: "u_ahmed", slot_no: 2, title: t[1], status: "approved", due_date: dayShift(-14), upload_date: dayShift(-16), m_completeness: 90, m_quality: 86, _hist: [{ ts: dayShift(-16), actor: "u_ahmed", action: "submitted" }, { ts: dayShift(-14), actor: "u_sara", action: "approved" }] });
  await R({ employee_id: "u_ahmed", slot_no: 3, title: t[2], status: "approved", due_date: dayShift(-4), upload_date: dayShift(-6), m_completeness: 93, m_quality: 90, _hist: [{ ts: dayShift(-6), actor: "u_ahmed", action: "submitted" }, { ts: dayShift(-4), actor: "u_sara", action: "approved" }] });
  await R({ employee_id: "u_ahmed", slot_no: 4, title: t[3], status: "assigned", due_date: dayShift(12) });
  await R({ employee_id: "u_ahmed", slot_no: 5, title: t[4], status: "assigned", due_date: dayShift(28) });

  await T("u_khaled", CUR_Q, 4);
  await R({ employee_id: "u_khaled", slot_no: 1, title: t[5], status: "approved", due_date: dayShift(-12), upload_date: dayShift(-13), m_completeness: 84, m_quality: 80, _hist: [{ ts: dayShift(-13), actor: "u_khaled", action: "submitted" }, { ts: dayShift(-12), actor: "u_sara", action: "approved" }] });
  await R({ employee_id: "u_khaled", slot_no: 2, title: t[6], status: "review", due_date: dayShift(4), upload_date: dayShift(-2), attachments: JSON.stringify([{ name: "تقرير_الصيدلية.pdf" }]), _hist: [{ ts: dayShift(-2), actor: "u_khaled", action: "submitted" }] });
  await R({ employee_id: "u_khaled", slot_no: 3, title: t[0], status: "assigned", due_date: dayShift(-3) });
  await R({ employee_id: "u_khaled", slot_no: 4, title: t[1], status: "assigned", due_date: dayShift(19) });

  await T("u_noura", CUR_Q, 5);
  const nd = [[0, 95, 93], [1, 92, 90], [2, 97, 95], [3, 88, 91], [4, 94, 89]];
  for (let i = 0; i < nd.length; i++)
    await R({ employee_id: "u_noura", slot_no: i + 1, title: t[nd[i][0]], status: "approved", due_date: dayShift(-30 + i * 5), upload_date: dayShift(-32 + i * 5), m_completeness: nd[i][1], m_quality: nd[i][2], _hist: [{ ts: dayShift(-32 + i * 5), actor: "u_noura", action: "submitted" }, { ts: dayShift(-30 + i * 5), actor: "u_sara", action: "approved" }] });

  await T("u_maha", CUR_Q, 4);
  await R({ employee_id: "u_maha", slot_no: 1, title: t[0], status: "approved", due_date: dayShift(-20), upload_date: dayShift(-22), m_completeness: 91, m_quality: 88, _hist: [{ ts: dayShift(-22), actor: "u_maha", action: "submitted" }, { ts: dayShift(-20), actor: "u_sara", action: "approved" }] });
  await R({ employee_id: "u_maha", slot_no: 2, title: t[3], status: "review", due_date: dayShift(6), upload_date: dayShift(-1), attachments: JSON.stringify([{ name: "الوصول_الشامل.pdf" }]), _hist: [{ ts: dayShift(-1), actor: "u_maha", action: "submitted" }] });
  await R({ employee_id: "u_maha", slot_no: 3, title: t[5], status: "assigned", due_date: dayShift(15) });
  await R({ employee_id: "u_maha", slot_no: 4, title: t[6], status: "assigned", due_date: dayShift(30) });

  await logActivity("u_admin", "تحميل بيانات العرض التجريبي", "settings");
  console.log("✅ تم تحميل بيانات الفريق التجريبي (كلمات المرور: pass123، المشرفة: sara).");
}

// يجعل عدّاد المستهدف = عدد التقارير المُسندة للموظف في هذا الربع
async function syncTargetCount(empId, quarter) {
  const c = (await X.query("SELECT COUNT(*)::int AS c FROM reports WHERE employee_id=$1 AND quarter=$2", [empId, quarter])).rows[0].c;
  if (c === 0) { await X.query("DELETE FROM targets WHERE employee_id=$1 AND quarter=$2", [empId, quarter]); return 0; }
  await X.query(
    `INSERT INTO targets(id,employee_id,quarter,target) VALUES($1,$2,$3,$4)
     ON CONFLICT(employee_id,quarter) DO UPDATE SET target=EXCLUDED.target`,
    [uid("t"), empId, quarter, c]);
  return c;
}

// يمسح المستهدفات والتقارير فقط (تُبقي المستخدمين والإعدادات)
async function resetAssignments() {
  await X.query("DELETE FROM report_history");
  await X.query("DELETE FROM reports");
  await X.query("DELETE FROM targets");
  console.log("🗑️  تم مسح جميع المستهدفات والتقارير (المستخدمون والإعدادات محفوظون).");
}

async function resetAll() {
  await X.query("DELETE FROM report_history"); await X.query("DELETE FROM reports");
  await X.query("DELETE FROM targets"); await X.query("DELETE FROM activity");
  await X.query("DELETE FROM users"); await X.query("DELETE FROM role_perms"); await X.query("DELETE FROM settings");
  console.log("🗑️  تم مسح جميع البيانات.");
}

module.exports = {
  init, backend,
  PERMS, QUARTERS, CUR_Q, ROLES, DEFAULT_ROLE_PERMS, roleSeesAll, uid, iso, dayShift, NOW,
  query: (s, p) => X.query(s, p), tx: (fn) => X.tx(fn),
  getUserById, getUserByUsername, getReportById, effectivePerms, logActivity,
  managedEmployeeIds, canManage,
  getSettings, setSetting, getReportTypes, getRolePerms, setRolePerm,
  mapUser, mapReport, mapTarget, bootstrap, seedBase, seedDemo, resetAll,
  syncTargetCount, resetAssignments
};
