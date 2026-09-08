require("dotenv").config();

const express = require("express"); 
const cors = require("cors");
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

app.get("/", (req, res) => {
  res.json({
    ok: true,
    app: "DDR Backend",
    version: "1.1.0",
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
    backendVersion: "1.1.0",
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

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    error: "Route not found"
  });
});

app.use((err, req, res, next) => {
  console.error(err);

  res.status(500).json({
    ok: false,
    error: "Internal server error"
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`DDR backend running on port ${PORT}`);
});
