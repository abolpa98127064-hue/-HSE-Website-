const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const { Pool } = require("pg");

const app = express();
const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!JWT_SECRET || !ADMIN_EMAIL || !ADMIN_PASSWORD) {
  console.error("Missing JWT_SECRET, ADMIN_EMAIL or ADMIN_PASSWORD.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes("localhost")
    ? { rejectUnauthorized: false } : false
});

const uploadsDir = path.join(__dirname, "public", "uploads");
fs.mkdirSync(uploadsDir, { recursive: true });

app.set("trust proxy", 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
app.use(compression());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});
app.use("/api/login", loginLimiter);

const upload = multer({
  storage: multer.diskStorage({
    destination: uploadsDir,
    filename: (_, file, cb) => {
      const ext = path.extname(file.originalname).toLowerCase();
      cb(null, `${Date.now()}-${crypto.randomBytes(6).toString("hex")}${ext}`);
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    const ok = ["image/jpeg","image/png","image/webp","image/svg+xml"].includes(file.mimetype);
    cb(ok ? null : new Error("Only image files are allowed"), ok);
  }
});

const DEFAULT_SETTINGS = {
  owner: "مهندس علی نعمتی‌نیا",
  title: "HSE | ایمنی، بهداشت حرفه‌ای و محیط زیست",
  tagline: "راهکارهای حرفه‌ای برای محیط کار ایمن‌تر",
  heroText: "ارائه خدمات تخصصی HSE با تمرکز بر شناسایی خطر، ارزیابی و کنترل ریسک، آموزش، بازرسی و بهبود مستمر فرآیندهای ایمنی.",
  aboutTitle: "درباره من",
  aboutSubtitle: "هدف، تبدیل الزامات HSE به اقدامات عملی، قابل اجرا و قابل پیگیری در محیط واقعی کار است.",
  about: "در حوزه HSE، پیشگیری و کنترل ریسک زمانی اثربخش است که شناسایی خطر، آموزش، بازرسی، مستندسازی و پیگیری اقدامات اصلاحی در کنار یکدیگر قرار بگیرند.",
  approach: "تمرکز بر شناسایی خطرات، ارزیابی و کنترل ریسک، پیشگیری از حوادث، ارتقای فرهنگ ایمنی و ایجاد فرآیندهای قابل پیگیری.",
  phone: "برای تکمیل توسط مدیر",
  email: "برای تکمیل توسط مدیر",
  location: "کاشان",
  servicesTitle: "خدمات تخصصی HSE",
  servicesSubtitle: "خدمات متناسب با نوع فعالیت، شرایط محیط کار و نیازهای واقعی مجموعه.",
  projectsTitle: "پروژه‌ها و نمونه‌کارها",
  projectsSubtitle: "نمونه‌ای از فعالیت‌ها و پروژه‌های قابل ارائه در حوزه HSE.",
  detailsTitle: "شرح خدمات",
  detailsSubtitle: "توضیحات تکمیلی درباره حوزه‌های خدماتی و نحوه همکاری.",
  certificatesTitle: "گواهینامه‌ها و مدارک",
  certificatesSubtitle: "مدارک و گواهینامه‌های حرفه‌ای قابل نمایش در این بخش هستند.",
  contactTitle: "ارتباط با من",
  contactSubtitle: "برای دریافت مشاوره یا هماهنگی همکاری، اطلاعات تماس زیر را مشاهده کنید."
};

const DEFAULT_ITEMS = [
  ["service","ارزیابی و مدیریت ریسک","شناسایی خطرات، ارزیابی احتمال و شدت پیامدها و تعیین اقدامات کنترلی.","این خدمت با بررسی نظام‌مند فعالیت‌ها، تجهیزات و شرایط محیط کار آغاز می‌شود. خطرات شناسایی و اولویت‌بندی و اقدامات کنترلی برای آن‌ها تعیین می‌شود."],
  ["service","بازرسی و پایش ایمنی","بازرسی محیط کار، ثبت عدم انطباق‌ها و پیگیری اقدامات اصلاحی.","بازرسی‌ها با تمرکز بر شرایط ناایمن، تجهیزات، مسیرهای تردد و وضعیت اجرای اقدامات کنترلی انجام می‌شوند."],
  ["service","آموزش HSE","آموزش‌های کاربردی ایمنی، آمادگی اضطراری و فرهنگ‌سازی رفتار ایمن.","محتوای آموزشی بر اساس نوع فعالیت، ریسک‌های شغلی و سطح مسئولیت افراد تنظیم می‌شود."],
  ["service","مستندسازی HSE","تنظیم دستورالعمل‌ها، فرم‌ها، چک‌لیست‌ها، گزارش‌ها و مستندات.","مستندسازی مناسب باعث می‌شود فعالیت‌های HSE ساختارمند، قابل پیگیری و قابل ارزیابی باشند."],
  ["service","مدیریت حوادث و شبه‌حوادث","بررسی رخدادها، عوامل مؤثر و اقدامات اصلاحی و پیشگیرانه.","ثبت و بررسی حوادث و شبه‌حوادث اطلاعات ارزشمندی برای پیشگیری از تکرار فراهم می‌کند."],
  ["service","مشاوره و همراهی HSE","ارائه راهکار متناسب با شرایط واقعی مجموعه و همراهی در مسیر بهبود.","فرآیند مشاوره بر شناخت نیاز واقعی، اولویت‌بندی اقدامات و پیگیری نتایج استوار است."],
  ["project","استقرار برنامه بازرسی HSE","طراحی چرخه بازرسی، ثبت یافته‌ها و پیگیری اقدامات اصلاحی.","نمونه ساختار پروژه برای ایجاد روند منظم بازرسی و پیگیری رفع عدم انطباق‌ها."],
  ["project","ارزیابی ریسک فعالیت‌ها","شناسایی خطرات و تدوین اقدامات کنترلی برای فعالیت‌های منتخب.","نمونه ساختار پروژه برای تحلیل ریسک و تبدیل نتایج به برنامه عملیاتی."],
  ["detail","مجوز کار","مدیریت فرآیند مجوزهای کار و کنترل پیش‌نیازهای ایمنی.","ساختار قابل توسعه برای مجوزهای کار گرم، سرد، ارتفاع، فضای بسته، برق، حفاری و LOTO."],
  ["detail","ارزیابی ریسک JSA/JHA","ثبت مراحل کار، خطرات، ریسک اولیه، کنترل‌ها و ریسک باقیمانده.","قابل توسعه به ماتریس ریسک و امتیازدهی احتمال و شدت."],
  ["detail","بازرسی و چک‌لیست","چک‌لیست‌های بازرسی تجهیزات، ماشین‌آلات، داربست، جرثقیل، PPE و محیط کار.","نتایج بازرسی می‌توانند به اقدامات اصلاحی و گزارش مدیریتی متصل شوند."],
  ["detail","حادثه، Near Miss و CAPA","ثبت رخداد، علت‌های مؤثر، اقدام اصلاحی و اقدام پیشگیرانه.","ساختار مناسب برای پیگیری وضعیت اقدامات تا بسته شدن مورد."],
  ["certificate","گواهینامه و مدارک حرفه‌ای","این بخش برای نمایش مدارک و گواهینامه‌های حرفه‌ای اختصاص دارد.","مدارک واقعی پس از بارگذاری توسط مدیر در پنل مدیریت نمایش داده می‌شوند."]
];

async function dbInit() {
  await pool.query(fs.readFileSync(path.join(__dirname, "schema.sql"), "utf8"));
  const admin = await pool.query("SELECT id FROM admins WHERE email=$1", [ADMIN_EMAIL]);
  if (!admin.rowCount) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    await pool.query("INSERT INTO admins(email,password_hash) VALUES($1,$2)", [ADMIN_EMAIL, hash]);
  }
  const settings = await pool.query("SELECT id FROM site_settings WHERE id=1");
  if (!settings.rowCount) {
    await pool.query("INSERT INTO site_settings(id,data) VALUES(1,$1)", [DEFAULT_SETTINGS]);
  }
  const count = await pool.query("SELECT COUNT(*)::int AS c FROM content_items");
  if (count.rows[0].c === 0) {
    for (let i=0; i<DEFAULT_ITEMS.length; i++) {
      const [type,title,short_text,detail_text] = DEFAULT_ITEMS[i];
      await pool.query(
        "INSERT INTO content_items(type,title,short_text,detail_text,sort_order) VALUES($1,$2,$3,$4,$5)",
        [type,title,short_text,detail_text,i]
      );
    }
  }
}

function auth(req,res,next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({error:"احراز هویت لازم است"});
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({error:"نشست مدیریتی منقضی یا نامعتبر است"}); }
}

async function audit(action, details={}) {
  await pool.query("INSERT INTO audit_logs(action,details) VALUES($1,$2)", [action, details]);
}

app.get("/api/health", async (_,res) => {
  try { await pool.query("SELECT 1"); res.json({ok:true,database:true}); }
  catch { res.status(503).json({ok:false,database:false}); }
});

app.get("/api/site", async (_,res) => {
  const settings = (await pool.query("SELECT data FROM site_settings WHERE id=1")).rows[0]?.data || DEFAULT_SETTINGS;
  const items = (await pool.query("SELECT id,type,title,short_text,detail_text,image_url,sort_order FROM content_items ORDER BY sort_order,id")).rows;
  res.json({settings, items});
});

app.post("/api/visit", async (req,res) => {
  try {
    await pool.query("INSERT INTO visits(path,user_agent) VALUES($1,$2)", [
      String(req.body?.path || "/").slice(0,500),
      String(req.headers["user-agent"] || "").slice(0,500)
    ]);
  } catch {}
  res.json({ok:true});
});

app.post("/api/messages", async (req,res) => {
  const {name,phone="",email="",message} = req.body || {};
  if (!name || !message) return res.status(400).json({error:"نام و پیام الزامی است"});
  await pool.query("INSERT INTO messages(name,phone,email,message) VALUES($1,$2,$3,$4)", [
    String(name).slice(0,120), String(phone).slice(0,60), String(email).slice(0,160), String(message).slice(0,4000)
  ]);
  res.status(201).json({ok:true});
});

app.post("/api/login", async (req,res) => {
  const {email,password} = req.body || {};
  const row = (await pool.query("SELECT id,email,password_hash FROM admins WHERE email=$1", [email])).rows[0];
  if (!row || !(await bcrypt.compare(String(password||""), row.password_hash))) {
    return res.status(401).json({error:"ایمیل یا رمز عبور نادرست است"});
  }
  const token = jwt.sign({id:row.id,email:row.email}, JWT_SECRET, {expiresIn:"12h"});
  await audit("admin_login",{email:row.email});
  res.json({token});
});

app.get("/api/admin/dashboard", auth, async (_,res) => {
  const [visits,msgs,services,projects,risks] = await Promise.all([
    pool.query("SELECT COUNT(*)::int c FROM visits"),
    pool.query("SELECT COUNT(*)::int c FROM messages WHERE read_at IS NULL"),
    pool.query("SELECT COUNT(*)::int c FROM content_items WHERE type='service'"),
    pool.query("SELECT COUNT(*)::int c FROM content_items WHERE type='project'"),
    pool.query("SELECT COUNT(*)::int c FROM content_items WHERE type='detail'")
  ]);
  res.json({
    visits:visits.rows[0].c, unreadMessages:msgs.rows[0].c,
    services:services.rows[0].c, projects:projects.rows[0].c,
    hseTools:risks.rows[0].c
  });
});

app.put("/api/admin/settings", auth, async (req,res) => {
  await pool.query("UPDATE site_settings SET data=$1,updated_at=NOW() WHERE id=1", [req.body]);
  await audit("settings_update");
  res.json({ok:true});
});

app.get("/api/admin/content", auth, async (_,res) => {
  res.json((await pool.query("SELECT * FROM content_items ORDER BY sort_order,id")).rows);
});

app.post("/api/admin/content", auth, async (req,res) => {
  const {type,title,short_text="",detail_text="",image_url="",sort_order=0} = req.body;
  if (!["service","project","detail","certificate"].includes(type) || !title) {
    return res.status(400).json({error:"نوع و عنوان معتبر لازم است"});
  }
  const r = await pool.query(
    "INSERT INTO content_items(type,title,short_text,detail_text,image_url,sort_order) VALUES($1,$2,$3,$4,$5,$6) RETURNING *",
    [type,title,short_text,detail_text,image_url,sort_order]
  );
  await audit("content_create",{id:r.rows[0].id,type});
  res.status(201).json(r.rows[0]);
});

app.put("/api/admin/content/:id", auth, async (req,res) => {
  const {type,title,short_text="",detail_text="",image_url="",sort_order=0} = req.body;
  const r = await pool.query(
    "UPDATE content_items SET type=$1,title=$2,short_text=$3,detail_text=$4,image_url=$5,sort_order=$6,updated_at=NOW() WHERE id=$7 RETURNING *",
    [type,title,short_text,detail_text,image_url,sort_order,req.params.id]
  );
  if (!r.rowCount) return res.status(404).json({error:"مورد پیدا نشد"});
  await audit("content_update",{id:req.params.id});
  res.json(r.rows[0]);
});

app.delete("/api/admin/content/:id", auth, async (req,res) => {
  await pool.query("DELETE FROM content_items WHERE id=$1", [req.params.id]);
  await audit("content_delete",{id:req.params.id});
  res.json({ok:true});
});

app.get("/api/admin/messages", auth, async (_,res) => {
  res.json((await pool.query("SELECT * FROM messages ORDER BY created_at DESC LIMIT 200")).rows);
});

app.put("/api/admin/messages/:id/read", auth, async (req,res) => {
  await pool.query("UPDATE messages SET read_at=NOW() WHERE id=$1", [req.params.id]);
  res.json({ok:true});
});

app.put("/api/admin/password", auth, async (req,res) => {
  const {currentPassword,newPassword} = req.body || {};
  if (!newPassword || String(newPassword).length < 10) {
    return res.status(400).json({error:"رمز جدید باید حداقل ۱۰ کاراکتر باشد"});
  }
  const row = (await pool.query("SELECT password_hash FROM admins WHERE id=$1",[req.user.id])).rows[0];
  if (!row || !(await bcrypt.compare(String(currentPassword||""),row.password_hash))) {
    return res.status(400).json({error:"رمز فعلی نادرست است"});
  }
  const hash = await bcrypt.hash(String(newPassword),12);
  await pool.query("UPDATE admins SET password_hash=$1,updated_at=NOW() WHERE id=$2",[hash,req.user.id]);
  await audit("password_change");
  res.json({ok:true});
});

app.post("/api/admin/upload", auth, upload.single("image"), (req,res) => {
  if (!req.file) return res.status(400).json({error:"فایل تصویر ارسال نشده است"});
  res.json({ok:true,url:`/uploads/${req.file.filename}`});
});

app.get("/api/admin/audit", auth, async (_,res) => {
  res.json((await pool.query("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200")).rows);
});

app.use(express.static(path.join(__dirname,"public")));
app.use((req,res,next) => {
  if (req.path.startsWith("/api/")) return next();
  res.sendFile(path.join(__dirname,"public","index.html"));
});

dbInit()
  .then(() => app.listen(PORT,"0.0.0.0",() => console.log(`HSE server listening on ${PORT}`)))
  .catch(err => { console.error("Database initialization failed",err); process.exit(1); });
