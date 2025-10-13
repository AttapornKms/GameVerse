import express from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import pg from "pg";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";




const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, ".env") });

const app = express();
const port = process.env.PORT || 3000;

const { Pool } = pg;
const cs = process.env.DATABASE_URL;
const pool = cs ? new Pool({ connectionString: cs }) : new Pool({
  host: process.env.PGHOST || "localhost",
  port: +(process.env.PGPORT || 5432),
  user: process.env.PGUSER || "postgres",
  password: process.env.PGPASSWORD || "",
  database: process.env.PGDATABASE || "gamemag",
});
console.log("DATABASE_URL =", process.env.DATABASE_URL);

const PgSession = connectPgSimple(session);
app.use(session({
  store: new PgSession({ pool, tableName: "session", createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || "dev-secret",
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", maxAge: 1000*60*60*24 }
}));
// ให้แน่ใจว่ามีโฟลเดอร์ Image
const IMG_DIR = path.join(__dirname, 'Image');
if (!fs.existsSync(IMG_DIR)) fs.mkdirSync(IMG_DIR, { recursive: true });

// เสิร์ฟแบบ static ที่ path /Image/*
app.use('/Image', express.static(IMG_DIR, {
  maxAge: '30d',
  immutable: true,
}));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.post("/login", async (req, res) => {
  const { username, password } = req.body || {};
  try {
    const q = `
      SELECT user_id, fullname, username, role, status, password
      FROM users WHERE username=$1 AND status=TRUE LIMIT 1
    `;
    const { rows } = await pool.query(q, [username]);
    const u = rows[0];
    if (!u) return res.status(401).json({ error: "user_not_found" });

    const vr = await pool.query("SELECT $1 = crypt($2, $1) AS ok", [u.password, password]);
    if (!vr.rows[0].ok) return res.status(401).json({ error: "bad_password" });

    // เก็บ user ที่จำเป็นลง session
    const user = { user_id: u.user_id, fullname: u.fullname, username: u.username, role: u.role };
    req.session.user = user;

    // ส่งกลับ user ด้วย เพื่อให้ frontend sync สถานะได้
    res.json({ ok: true, user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "internal" });
  }
});
// Helpers
function requireAuth(req, res, next){ if(!req.session.user) return res.status(401).json({error:'unauthorized'}); next(); }
function requireAdmin(req, res, next){ if(!req.session.user) return res.status(401).json({error:'unauthorized'}); if(req.session.user.role!=='admin') return res.status(403).json({error:'forbidden'}); next(); }

// Auth
app.get("/api/auth/me", (req,res)=> res.json(req.session.user || null));

app.post("/login", async (req, res) => {
  const { username, password } = req.body||{};
  try{
    const { rows } = await pool.query(`select user_id, fullname, username, role, status, password from users where username=$1 and status=true limit 1`, [username]);
    const u = rows[0]; if(!u) return res.status(401).json({error:'user_not_found'});
    const vr = await pool.query("select $1 = crypt($2, $1) as ok", [u.password, password]);
    if(!vr.rows[0].ok) return res.status(401).json({error:'bad_password'});
    req.session.user = { user_id:u.user_id, fullname:u.fullname, username:u.username, role:u.role };
    res.json({ ok:true });
  }catch(e){ console.error(e); res.status(500).json({error:'internal'}); }
});
app.post("/logout", (req,res)=> req.session.destroy(()=>res.json({ok:true})));

app.post("/register", async (req,res)=>{
  const { displayName, username, password } = req.body||{};
  if(!displayName || !username || !password) return res.status(400).json({error:'missing'});
  try{
    const dup = await pool.query(`select 1 from users where username=$1 limit 1`, [username]);
    if(dup.rowCount) return res.status(409).json({error:'dup_user'});
    await pool.query(`insert into users (fullname, username, password, role, status) values ($1,$2,crypt($3, gen_salt('bf')), 'user', true)`, [displayName, username, password]);
    res.json({ ok:true });
  }catch(e){ console.error(e); res.status(500).json({error:'internal'}); }
});

// Home config
app.get("/api/config/home", async (_req,res)=>{
  const { rows } = await pool.query(`select data from home_config where id=1`);
  res.json(rows[0]?.data || {});
});
app.put("/api/config/home", requireAdmin, async (req,res)=>{
  await pool.query(`update home_config set data=$1, updated_at=now() where id=1`, [req.body||{}]);
  res.json({ ok:true });
});

// ----- Articles -----
// รายการบทความ (admin ใช้ดึงมาแสดงใน modal import)
app.get("/api/articles", requireAuth, async (req,res)=>{
  try{
    const q = (req.query.q || "").trim();
    let sql = `
      SELECT slug, title, image_url, badge, published_at
      FROM articles
    `;
    const params = [];
    if(q){
      sql += " WHERE title ILIKE $1 OR coalesce(badge,'') ILIKE $1 ";
      params.push(`%${q}%`);
    }
    sql += " ORDER BY published_at DESC LIMIT 50";
    const { rows } = await pool.query(sql, params);
    res.json(rows);
  }catch(e){
    console.error(e);
    res.status(500).json({ error: "internal" });
  }
});

// อ่านรายละเอียดบทความตาม slug (ใช้ใน “แก้ไขข่าวเต็ม”)
app.get("/api/articles/:slug", requireAuth, async (req,res)=>{
  try{
    const { slug } = req.params;
    const { rows } = await pool.query(
      `SELECT slug, title, content, image_url, badge, published_at
       FROM articles WHERE slug=$1`,
      [slug]
    );
    if(!rows[0]) return res.status(404).json({error:'not_found'});
    res.json(rows[0]);
  }catch(e){
    console.error(e);
    res.status(500).json({ error: "internal" });
  }
});

// สร้าง/อัปเดต (upsert) — ต้องเป็นแอดมินเท่านั้น
app.post("/api/articles", requireAdmin, async (req,res)=>{
  const { slug, title, content, image_url, badge, published_at } = req.body||{};
  if(!slug || !title || !content) return res.status(400).json({error:'missing'});
  await pool.query(`
    INSERT INTO articles (slug,title,content,image_url,badge,published_at)
    VALUES ($1,$2,$3,$4, COALESCE($5,'ข่าวเกม'), COALESCE($6, NOW()))
    ON CONFLICT (slug) DO UPDATE
      SET title=EXCLUDED.title,
          content=EXCLUDED.content,
          image_url=EXCLUDED.image_url,
          badge=EXCLUDED.badge,
          published_at=EXCLUDED.published_at
  `, [slug, title, content, image_url||null, badge||null, published_at||null]);
  res.json({ ok:true });
});
app.post('/api/admin/promote', requireAdmin, async (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: 'missing_username' });
  await pool.query(`UPDATE users SET role='admin' WHERE username=$1`, [username]);
  res.json({ ok: true });
});
// Pages
app.get("/login", (_req,res)=>res.sendFile(path.join(__dirname,"public/login.html")));
app.get("/register", (_req,res)=>res.sendFile(path.join(__dirname,"public/register.html")));
app.get("/admin", (_req,res)=>res.sendFile(path.join(__dirname,"public/admin.html")));
app.get("/", (_req,res)=>res.render("index.ejs", {image:["/Image/valorant.jpg","/Image/7krb.jpg","/Image/battlefield-6.webp"]}));

app.listen(port, ()=>console.log(`Listening on http://localhost:${port}`));
