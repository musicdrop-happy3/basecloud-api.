const express = require("express");
const { Pool } = require("pg");
const crypto = require("crypto");
const { promisify } = require("util");

const app = express();
const PORT = process.env.PORT || 10000;
const scrypt = promisify(crypto.scrypt);

app.disable("x-powered-by");
app.use(express.json({ limit: "20kb" }));

// Allow requests from your website.
// Bearer-token authentication is used instead of cookies.
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET,POST,PUT,DELETE,OPTIONS"
  );
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type,Authorization"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      connectionTimeoutMillis: 10000,
      max: 5
    })
  : null;

function db() {
  if (!pool) {
    const error = new Error("Database is not configured.");
    error.status = 503;
    throw error;
  }
  return pool;
}

// Simple in-memory limit for account endpoints.
// For a public launch, use a shared rate limiter.
const attempts = new Map();

function limitAuth(req, res, next) {
  const key = req.ip || "unknown";
  const now = Date.now();
  let entry = attempts.get(key);

  if (!entry || now - entry.start > 60000) {
    entry = { start: now, count: 0 };
  }

  entry.count++;
  attempts.set(key, entry);

  if (attempts.size > 5000) {
    for (const [ip, item] of attempts) {
      if (now - item.start > 60000) attempts.delete(ip);
    }
  }

  if (entry.count > 15) {
    return res.status(429).json({
      error: "Too many account requests. Try again in one minute."
    });
  }

  next();
}

function makeToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derived = await scrypt(password, salt, 64);

  return salt.toString("hex") + ":" + derived.toString("hex");
}

async function verifyPassword(password, stored) {
  if (typeof stored !== "string") return false;

  const parts = stored.split(":");
  if (parts.length !== 2) return false;

  const salt = Buffer.from(parts[0], "hex");
  const expected = Buffer.from(parts[1], "hex");

  if (salt.length !== 16 || expected.length !== 64) {
    return false;
  }

  const actual = await scrypt(password, salt, 64);

  return crypto.timingSafeEqual(actual, expected);
}

async function createSession(userId) {
  const token = makeToken();
  const expiresAt = new Date(
    Date.now() + 7 * 24 * 60 * 60 * 1000
  );

  await db().query(
    `INSERT INTO public.bc_user_sessions
       (user_id, token_hash, expires_at)
     VALUES ($1, $2, $3)`,
    [userId, hashToken(token), expiresAt]
  );

  return { token, expiresAt };
}

async function requireAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const match = header.match(/^Bearer ([a-f0-9]{64})$/i);

    if (!match) {
      return res.status(401).json({
        error: "Please sign in to continue."
      });
    }

    const result = await db().query(
      `SELECT u.id, u.email, u.display_name
       FROM public.bc_user_sessions s
       JOIN public.bc_users u ON u.id = s.user_id
       WHERE s.token_hash = $1
         AND s.expires_at > NOW()
         AND s.revoked_at IS NULL
       LIMIT 1`,
      [hashToken(match[1])]
    );

    if (!result.rows.length) {
      return res.status(401).json({
        error: "Session expired or invalid. Please sign in again."
      });
    }

    req.user = result.rows[0];
    req.tokenHash = hashToken(match[1]);
    next();
  } catch (error) {
    next(error);
  }
}

function validProjectName(name) {
  return typeof name === "string" &&
    name.trim().length >= 1 &&
    name.trim().length <= 100;
}

// API home
app.get("/", (req, res) => {
  res.json({
    name: "BaseCloud API",
    status: "online",
    version: "1.1.0",
    message: "Welcome to the BaseCloud backend."
  });
});

// API health
app.get("/api/health", async (req, res, next) => {
  try {
    await db().query("SELECT 1");

    res.json({
      service: "BaseCloud API",
      server: "online",
      database: "connected"
    });
  } catch (error) {
    next(error);
  }
});

// Register
app.post("/api/auth/register", limitAuth, async (req, res, next) => {
  try {
    const email = typeof req.body.email === "string"
      ? req.body.email.trim().toLowerCase()
      : "";

    const password = req.body.password;
    const displayName = typeof req.body.display_name === "string"
      ? req.body.display_name.trim()
      : "";

    if (
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      return res.status(400).json({
        error: "Enter a valid email address."
      });
    }

    if (
      typeof password !== "string" ||
      password.length < 8 ||
      password.length > 128
    ) {
      return res.status(400).json({
        error: "Password must be 8 to 128 characters."
      });
    }

    if (displayName.length > 80) {
      return res.status(400).json({
        error: "Display name must be 80 characters or fewer."
      });
    }

    const passwordHash = await hashPassword(password);

    const result = await db().query(
      `INSERT INTO public.bc_users
         (email, display_name, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, email, display_name, created_at`,
      [email, displayName || email.split("@")[0], passwordHash]
    );

    const user = result.rows[0];
    const session = await createSession(user.id);

    res.status(201).json({
      message: "Account created successfully.",
      user,
      token: session.token,
      expires_at: session.expiresAt
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "An account with that email already exists."
      });
    }
    next(error);
  }
});

// Login
app.post("/api/auth/login", limitAuth, async (req, res, next) => {
  try {
    const email = typeof req.body.email === "string"
      ? req.body.email.trim().toLowerCase()
      : "";
    const password = req.body.password;

    if (typeof password !== "string" || password.length > 128) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const result = await db().query(
      `SELECT id, email, display_name, password_hash
       FROM public.bc_users
       WHERE email = $1
       LIMIT 1`,
      [email]
    );

    const user = result.rows[0];

    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const session = await createSession(user.id);

    res.json({
      message: "Signed in successfully.",
      user: {
        id: user.id,
        email: user.email,
        display_name: user.display_name
      },
      token: session.token,
      expires_at: session.expiresAt
    });
  } catch (error) {
    next(error);
  }
});

// Current user
app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// Logout
app.post("/api/auth/logout", requireAuth, async (req, res, next) => {
  try {
    await db().query(
      `UPDATE public.bc_user_sessions
       SET revoked_at = NOW()
       WHERE token_hash = $1`,
      [req.tokenHash]
    );

    res.json({ message: "Signed out successfully." });
  } catch (error) {
    next(error);
  }
});

// List the signed-in user's projects
app.get("/api/projects", requireAuth, async (req, res, next) => {
  try {
    const result = await db().query(
      `SELECT id, name, description, created_at
       FROM public.bc_projects
       WHERE owner_id = $1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json({ projects: result.rows });
  } catch (error) {
    next(error);
  }
});

// Create a project
app.post("/api/projects", requireAuth, async (req, res, next) => {
  const client = await db().connect();

  try {
    const { name, description = "" } = req.body;

    if (!validProjectName(name)) {
      client.release();
      return res.status(400).json({
        error: "Project name must be 1 to 100 characters."
      });
    }

    if (
      typeof description !== "string" ||
      description.length > 2000
    ) {
      client.release();
      return res.status(400).json({
        error: "Description must be 2000 characters or fewer."
      });
    }

    await client.query("BEGIN");

    const result = await client.query(
      `INSERT INTO public.bc_projects
         (name, description, owner_id)
       VALUES ($1, $2, $3)
       RETURNING id, name, description, created_at`,
      [name.trim(), description, req.user.id]
    );

    const project = result.rows[0];

    await client.query(
      `INSERT INTO public.bc_project_settings (project_id)
       VALUES ($1)
       ON CONFLICT (project_id) DO NOTHING`,
      [project.id]
    );

    await client.query("COMMIT");

    res.status(201).json({
      message: "Project created successfully.",
      project
    });
  } catch (error) {
    try {
      await client.query("ROLLBACK");
    } catch (_) {}
    next(error);
  } finally {
    client.release();
  }
});

// View one of the signed-in user's projects
app.get("/api/projects/:id", requireAuth, async (req, res, next) => {
  try {
    const result = await db().query(
      `SELECT id, name, description, created_at
       FROM public.bc_projects
       WHERE id = $1 AND owner_id = $2`,
      [req.params.id, req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Project not found."
      });
    }

    res.json({ project: result.rows[0] });
  } catch (error) {
    next(error);
  }
});

// Update a project
app.put("/api/projects/:id", requireAuth, async (req, res, next) => {
  try {
    const { name, description } = req.body;

    if (
      name !== undefined &&
      !validProjectName(name)
    ) {
      return res.status(400).json({
        error: "Project name must be 1 to 100 characters."
      });
    }

    if (
      description !== undefined &&
      (typeof description !== "string" ||
       description.length > 2000)
    ) {
      return res.status(400).json({
        error: "Description must be 2000 characters or fewer."
      });
    }

    const result = await db().query(
      `UPDATE public.bc_projects
       SET name = COALESCE($1, name),
           description = COALESCE($2, description)
       WHERE id = $3 AND owner_id = $4
       RETURNING id, name, description, created_at`,
      [
        name === undefined ? null : name.trim(),
        description === undefined ? null : description,
        req.params.id,
        req.user.id
      ]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Project not found."
      });
    }

    res.json({
      message: "Project updated successfully.",
      project: result.rows[0]
    });
  } catch (error) {
    next(error);
  }
});

// Delete a project
app.delete("/api/projects/:id", requireAuth, async (req, res, next) => {
  try {
    const result = await db().query(
      `DELETE FROM public.bc_projects
       WHERE id = $1 AND owner_id = $2
       RETURNING id`,
      [req.params.id, req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Project not found."
      });
    }

    res.json({ message: "Project deleted successfully." });
  } catch (error) {
    next(error);
  }
});

// Unknown endpoint
app.use((req, res) => {
  res.status(404).json({
    error: "Endpoint not found",
    path: req.path
  });
});

// Safe error response
app.use((error, req, res, next) => {
  console.error("API error:", error.message);

  if (res.headersSent) return next(error);

  if (error.type === "entity.parse.failed") {
    return res.status(400).json({
      error: "Invalid JSON request body."
    });
  }

  if (error.code === "23503" || error.code === "22P02") {
    return res.status(400).json({
      error: "Invalid project or user identifier."
    });
  }

  res.status(error.status || 500).json({
    error: error.status
      ? error.message
      : "An internal server error occurred."
  });
});

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log("BaseCloud API listening on port " + PORT);
});

async function shutdown() {
  server.close(async () => {
    if (pool) await pool.end();
    process.exit(0);
  });
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
