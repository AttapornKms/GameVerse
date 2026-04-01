// app.mjs (Express ESM)

// ─────────────────────────────────────────────────────────────────────────────
// Imports
// ─────────────────────────────────────────────────────────────────────────────
import express from "express";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import pg from "pg";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";


// ─────────────────────────────────────────────────────────────────────────────
// Bootstrap / Env
// ─────────────────────────────────────────────────────────────────────────────
const __dirname = path.dirname(fileURLToPath(import.meta.url));
dotenv.config({ path: path.join(__dirname, ".env") });

const app = express();
const port = process.env.PORT || 3000;

// ─────────────────────────────────────────────────────────────────────────────
// Database
// ─────────────────────────────────────────────────────────────────────────────
const { Pool } = pg;
const cs = process.env.DATABASE_URL;
const pool = cs
  ? new Pool({ connectionString: cs })
  : new Pool({
      host: process.env.PGHOST || "localhost",
      port: +(process.env.PGPORT || 5432),
      user: process.env.PGUSER || "postgres",
      password: process.env.PGPASSWORD || "",
      database: process.env.PGDATABASE || "gamemag",
    });

console.log("DATABASE_URL =", process.env.DATABASE_URL);

// ─────────────────────────────────────────────────────────────────────────────
/** Helpers (DB-level, DRY) */
// ─────────────────────────────────────────────────────────────────────────────
const ARTICLE_COLS = "slug, title, content, image_url, badge, published_at";

/** อ่าน home_config.data (id=1) */
async function getHomeConfig(pool) {
  const { rows } = await pool.query(`SELECT data FROM home_config WHERE id=1`);
  return rows[0]?.data || {};
}

/** upsert บทความหนึ่งชิ้นลงตาราง articles */
async function upsertArticle(clientOrPool, { slug, title, content, image_url, badge, published_at }) {
  return clientOrPool.query(
    `
    INSERT INTO articles (slug, title, content, image_url, badge, published_at)
    VALUES ($1, $2, $3, $4, COALESCE($5,'ข่าวเกม'), COALESCE($6, NOW()))
    ON CONFLICT (slug) DO UPDATE SET
      title        = EXCLUDED.title,
      content      = EXCLUDED.content,
      image_url    = EXCLUDED.image_url,
      badge        = EXCLUDED.badge,
      published_at = EXCLUDED.published_at
  `,
    [slug, title, content, image_url || null, badge || null, published_at || null]
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sessions
// ─────────────────────────────────────────────────────────────────────────────
const PgSession = connectPgSimple(session);

app.use(
  session({
    store: new PgSession({ pool, tableName: "session", createTableIfMissing: true }),
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24, // 1 day
    },
  })
);

// ─────────────────────────────────────────────────────────────────────────────
// Views & Static
// ─────────────────────────────────────────────────────────────────────────────
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

// Ensure /Image exists
const IMG_DIR = path.join(__dirname, "Image");
if (!fs.existsSync(IMG_DIR)) fs.mkdirSync(IMG_DIR, { recursive: true });

// Serve /Image/*
app.use(
  "/Image",
  express.static(IMG_DIR, {
    maxAge: "30d",
    immutable: true,
  })
);

// Public assets
app.use(express.static(path.join(__dirname, "public")));

// Body parsers
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ─────────────────────────────────────────────────────────────────────────────
// Auth Middlewares (DRY)
// ─────────────────────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "unauthorized" });
  next();
}

function requireAdminOnly(req, res, next) {
  if (req.session.user?.role !== "admin") return res.status(403).json({ error: "เฉพาะแอดมินเด้อ" });
  next();
}

function requireAdminOrEditer(req, res, next) {
  const role = req.session?.user?.role;
  if (!role) {
    const nextUrl = encodeURIComponent(req.originalUrl || "/");
    return res.redirect(`/login?next=${nextUrl}`);
  }
  if (role !== "admin" && role !== "editor") {
    return res.redirect("/"); // หรือ res.status(403).render("403")
  }
  next();
}


/** ใช้กับหน้าที่ต้องล็อกอิน (EJS pages) → redirect ไป login พร้อม next */
function requireAuthPage(req, res, next) {
  if (!req.session.user) {
    return res.redirect(`/login?next=${encodeURIComponent(req.originalUrl)}`);
  }
  next();
}

// ─────────────────────────────────────────────────────────────────────────────
// Auth Routes
// ─────────────────────────────────────────────────────────────────────────────
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

    // keep minimal user in session
    const user = { user_id: u.user_id, fullname: u.fullname, username: u.username, role: u.role };
    req.session.user = user;

    // send user back for FE to sync state
    res.json({ ok: true, user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "internal" });
  }
});

app.post("/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.post("/register", async (req, res) => {
  const { displayName, username, password } = req.body || {};
  if (!displayName || !username || !password) return res.status(400).json({ error: "missing" });
  try {
    const dup = await pool.query(`SELECT 1 FROM users WHERE username=$1 LIMIT 1`, [username]);
    if (dup.rowCount) return res.status(409).json({ error: "dup_user" });

    await pool.query(
      `INSERT INTO users (fullname, username, password, role, status)
       VALUES ($1, $2, crypt($3, gen_salt('bf')), 'user', true)`,
      [displayName, username, password]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "internal" });
  }
});

app.get("/api/auth/me", (req, res) => res.json(req.session.user || null));

// ─────────────────────────────────────────────────────────────────────────────
// Home Config
// ─────────────────────────────────────────────────────────────────────────────
app.get("/api/config/home", async (_req, res) => {
  const data = await getHomeConfig(pool);
  res.json(data);
});

app.put("/api/config/home", requireAuth, requireAdminOnly, async (req, res) => {
  await pool.query(`UPDATE home_config SET data=$1, updated_at=now() WHERE id=1`, [req.body || {}]);
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// Articles
// ─────────────────────────────────────────────────────────────────────────────

/** revision list for given slug (admin) */
app.get("/api/articles/:slug/revisions", requireAuth, requireAdminOnly,async (req, res) => {
  const { rows } = await pool.query(
    `
    SELECT rev_id, slug, title, edited_by,
           to_char(edited_at,'YYYY-MM-DD HH24:MI') AS edited_at
      FROM article_revisions
     WHERE slug=$1
     ORDER BY rev_id DESC
     LIMIT 50
  `,
    [req.params.slug]
  );
  res.json(rows);
});

/** read one revision (admin) */
app.get("/api/articles/revision/:rev_id", requireAuth, requireAdminOnly,async (req, res) => {
  const { rows } = await pool.query(
    `
    SELECT rev_id, ${ARTICLE_COLS}, edited_by, edited_at
      FROM article_revisions
     WHERE rev_id=$1
  `,
    [req.params.rev_id]
  );
  if (!rows[0]) return res.status(404).json({ error: "not_found" });
  res.json(rows[0]);
});

/** restore revision into articles (admin) */
app.post("/api/articles/revision/:rev_id/restore", requireAuth, requireAdminOnly,async (req, res) => {
  const { rows } = await pool.query(
    `
    SELECT ${ARTICLE_COLS}
      FROM article_revisions
     WHERE rev_id=$1
  `,
    [req.params.rev_id]
  );
  const r = rows[0];
  if (!r) return res.status(404).json({ error: "not_found" });

  await upsertArticle(pool, r);
  res.json({ ok: true });
});

/** read one article by slug (admin, used by full editor) */
app.get("/api/articles/:slug", requireAuth, requireAdminOrEditer,async (req, res) => {
  try {
    const { slug } = req.params;
    const { rows } = await pool.query(
      `
      SELECT ${ARTICLE_COLS}
        FROM articles
       WHERE slug=$1
    `,
      [slug]
    );
    if (!rows[0]) return res.status(404).json({ error: "not_found" });
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "internal" });
  }
});

/** create/update article (admin) */
app.post("/api/articles", requireAuth, requireAdminOrEditer, async (req, res) => {
  const { slug, title, content, image_url, badge, published_at } = req.body || {};
  if (!slug || !title || !content) return res.status(400).json({ error: "missing" });

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // snapshot old -> revisions (ถ้ามี)
    const old = await client.query(
      `SELECT ${ARTICLE_COLS} FROM articles WHERE slug=$1`,
      [slug]
    );
    if (old.rowCount) {
      const o = old.rows[0];
      await client.query(
        `
        INSERT INTO article_revisions
          (${ARTICLE_COLS}, edited_by)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
      `,
        [o.slug, o.title, o.content, o.image_url, o.badge, o.published_at, req.session.user?.username || null]
      );
    }

    // upsert new
    await upsertArticle(client, { slug, title, content, image_url, badge, published_at });

    await client.query("COMMIT");
    res.json({ ok: true });
  } catch (e) {
    await client.query("ROLLBACK");
    console.error(e);
    res.status(500).json({ error: "internal" });
  } finally {
    client.release();
  }
});

/** promote user to admin (admin) */
app.post("/api/admin/promote", requireAuth, requireAdminOnly, async (req, res) => {
  const { username } = req.body || {};
  if (!username) return res.status(400).json({ error: "missing_username" });
  await pool.query(`UPDATE users SET role='admin' WHERE username=$1`, [username]);
  res.json({ ok: true });
});

// ─────────────────────────────────────────────────────────────────────────────
// Pages (EJS)
// ─────────────────────────────────────────────────────────────────────────────
app.get("/login", (_req, res) => res.render("login.ejs"));
app.get("/register", (_req, res) => res.render("register.ejs"));
app.get("/admin", requireAuthPage, (_req, res) => res.render("admin.ejs"))


/** หน้าแรก: ใช้ getHomeConfig() (DRY) */
app.get("/", async (_req, res, next) => {
  try {
    const data = await getHomeConfig(pool);
    const images = Array.isArray(data?.hero?.images) ? data.hero.images : [];
    res.render("index.ejs", { image: images });
  } catch (e) {
    next(e);
  }
});

/** บทความแบบ server-render (ต้องล็อกอิน) */
app.get("/article/:slug", requireAuthPage, async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `
      SELECT slug, title, content, image_url, badge,
             to_char(published_at,'YYYY-MM-DD') AS pub_date
        FROM articles
       WHERE slug=$1
    `,
      [req.params.slug]
    );
    const article = rows[0];
    if (!article) return res.status(404).render("article.ejs", { article: null });
    res.render("article.ejs", { article });
  } catch (e) {
    next(e);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 404 (HTML-only)
// ─────────────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  if (req.accepts("html")) {
    return res.status(404).render("404.ejs");
  }
  res.status(404).json({ error: "not_found" });
});

// ─────────────────────────────────────────────────────────────────────────────
// Start
// ─────────────────────────────────────────────────────────────────────────────
app.listen(port, () => console.log(`Listening on http://localhost:${port}`));
