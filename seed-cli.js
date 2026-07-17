/* seed-cli.js — أدوات سطر الأوامر لتهيئة قاعدة البيانات
   الاستخدام:
     node seed-cli.js          تهيئة أساسية (حساب مدير فقط) إن كانت فارغة
     node seed-cli.js --demo   تهيئة أساسية + بيانات فريق تجريبية
     node seed-cli.js --reset  مسح كل البيانات ثم إعادة تهيئة أساسية  ⚠️
*/
"use strict";
const D = require("./db");

(async () => {
  await D.init();
  const arg = process.argv[2];
  if (arg === "--reset") { await D.resetAll(); await D.seedBase(true); }
  else if (arg === "--demo") { await D.seedBase(false); await D.seedDemo(); }
  else if (arg === "--clear-assignments") { await D.resetAssignments(); }
  else { await D.seedBase(false); }
  process.exit(0);
})().catch(e => { console.error(e); process.exit(1); });
