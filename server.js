require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 10000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || "*",
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Content-Type",
    "Authorization",
    "X-Telegram-Init-Data"
  ]
}));

app.use(express.json({ limit: "1mb" }));

// ================================
// DATABASE SETUP
// ================================

async function ensureDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      telegram_id BIGINT UNIQUE NOT NULL,
      first_name TEXT,
      last_name TEXT,
      username TEXT,
      language_code TEXT,
      photo_url TEXT,
      balance NUMERIC(12,2) NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
}

// ================================
// TELEGRAM INIT DATA VALIDATION
// ================================

function validateTelegramInitData(initData) {
  if (!initData) {
    return null;
  }

  const params = new URLSearchParams(initData);
  const hash = params.get("hash");

  if (!hash) {
    return null;
  }

  params.delete("hash");

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join("\n");

  const secretKey = crypto
    .createHmac("sha256", "WebAppData")
    .update(process.env.TELEGRAM_BOT_TOKEN)
    .digest();

  const calculatedHash = crypto
    .createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  if (calculatedHash !== hash) {
    return null;
  }

  const authDate = Number(params.get("auth_date"));

  if (!authDate) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);

  // Reject data older than 24 hours
  if (now - authDate > 86400) {
    return null;
  }

  const userRaw = params.get("user");

  if (!userRaw) {
    return null;
  }

  try {
    return JSON.parse(userRaw);
  } catch {
    return null;
  }
}

// ================================
// BASIC ROUTES
// ================================

app.get("/", (req, res) => {
  res.json({
    ok: true,
    app: "DDR Backend",
    version: "1.2.0",
    message: "Backend is running"
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "ddr-backend",
    time: new Date().toISOString()
  });
});

app.get("/api/config", (req, res) => {
  res.json({
    ok: true,
    appName: "Maya",
    backendVersion: "1.2.0",
    telegramMiniApp: true
  });
});

app.get("/api/db-test", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW() AS time");

    res.json({
      ok: true,
      database: "connected",
      time: result.rows[0].time
    });
  } catch (error) {
    console.error("Database error:", error.message);

    res.status(500).json({
      ok: false,
      database: "connection_failed"
    });
  }
});

// ================================
// TELEGRAM LOGIN / USER PROFILE
// ================================

app.post("/api/auth/telegram", async (req, res) => {
  try {
    const initData =
      req.headers["x-telegram-init-data"];

    const telegramUser =
      validateTelegramInitData(initData);

    if (!telegramUser) {
      return res.status(401).json({
        ok: false,
        error: "Invalid Telegram authentication"
      });
    }

    const result = await pool.query(
      `
      INSERT INTO users (
        telegram_id,
        first_name,
        last_name,
        username,
        language_code,
        photo_url,
        updated_at
      )
      VALUES ($1, $2, $3, $4, $5, $6, NOW())
      ON CONFLICT (telegram_id)
      DO UPDATE SET
        first_name = EXCLUDED.first_name,
        last_name = EXCLUDED.last_name,
        username = EXCLUDED.username,
        language_code = EXCLUDED.language_code,
        photo_url = EXCLUDED.photo_url,
        updated_at = NOW()
      RETURNING
        id,
        telegram_id,
        first_name,
        last_name,
        username,
        language_code,
        photo_url,
        balance,
        created_at,
        updated_at
      `,
      [
        telegramUser.id,
        telegramUser.first_name || null,
        telegramUser.last_name || null,
        telegramUser.username || null,
        telegramUser.language_code || null,
        telegramUser.photo_url || null
      ]
    );

    res.json({
      ok: true,
      user: result.rows[0]
    });

  } catch (error) {
    console.error("Telegram auth error:", error);

    res.status(500).json({
      ok: false,
      error: "Authentication failed"
    });
  }
});

// ================================
// 404
// ================================

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    error: "Route not found"
  });
});

// ================================
// ERROR HANDLER
// ================================

app.use((err, req, res, next) => {
  console.error(err);

  res.status(500).json({
    ok: false,
    error: "Internal server error"
  });
});

// ================================
// START SERVER
// ================================

async function startServer() {
  try {
    await ensureDatabase();

    console.log("Database tables ready");

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`DDR backend running on port ${PORT}`);
    });

  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

startServer();
