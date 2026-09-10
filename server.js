require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Pool } = require("pg");

// ============================================================
// ADMIN CONTROL CENTER MODULE
// ============================================================

const {
  ensureControlCenterDatabase,
  registerAdminControlCenter
} = require("./admin_control_center");

// ============================================================
// APP
// ============================================================

const app = express();
const PORT = process.env.PORT || 10000;

// ============================================================
// CONFIG
// ============================================================

const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_KEY = process.env.ADMIN_KEY;

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing");
}

if (!process.env.TELEGRAM_BOT_TOKEN) {
  console.error("TELEGRAM_BOT_TOKEN is missing");
}

if (!JWT_SECRET) {
  console.error("JWT_SECRET is missing");
}

if (!ADMIN_KEY) {
  console.error("ADMIN_KEY is missing");
}

// ============================================================
// DATABASE
// ============================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// ============================================================
// REGISTER ADMIN CONTROL CENTER
// ============================================================
// IMPORTANT:
// This must be registered before the 404 middleware.
// ============================================================

registerAdminControlCenter({
  app,
  pool,
  adminKey: ADMIN_KEY,
  jwtSecret: JWT_SECRET
});

// ============================================================
// MIDDLEWARE
// ============================================================

// ============================================================
// ALLOWED FRONTEND ORIGINS
// ============================================================
// Ad2Reward frontend + Maya Admin Control Center
// ============================================================

const allowedOrigins = [
  "https://ad2reward.netlify.app",
  "https://adcpm.netlify.app"
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) {
        return callback(null, true);
      }

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(
        new Error("CORS origin not allowed")
      );
    },

    methods: [
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS"
    ],

    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Telegram-Init-Data",
      "X-Admin-Key"
    ]
  })
);

app.use(
  express.json({
    limit: "1mb"
  })
);

// ============================================================
// HELPERS
// ============================================================

function cleanText(value) {
  if (
    value === undefined ||
    value === null
  ) {
    return null;
  }

  const text = String(value).trim();

  return text || null;
}

function normalizeEmail(email) {
  if (!email) {
    return null;
  }

  return String(email)
    .trim()
    .toLowerCase();
}

function normalizePhone(phone) {
  if (!phone) {
    return null;
  }

  return String(phone)
    .trim()
    .replace(/[^\d+]/g, "");
}

function normalizeUsername(username) {
  if (!username) {
    return null;
  }

  let value = String(username)
    .trim()
    .toLowerCase();

  value = value.replace(/^@/, "");

  if (!value) {
    return null;
  }

  return value;
}

function getClientIp(req) {
  return (
    req.headers["x-forwarded-for"]
      ?.split(",")[0]
      ?.trim() ||
    req.socket?.remoteAddress ||
    null
  );
}

// ============================================================
// PASSWORD HASHING
// ============================================================

function hashPassword(password) {
  const salt =
    crypto.randomBytes(16).toString("hex");

  const hash =
    crypto.scryptSync(
      password,
      salt,
      64
    ).toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(
  password,
  storedHash
) {
  if (!storedHash) {
    return false;
  }

  const parts =
    storedHash.split(":");

  if (parts.length !== 2) {
    return false;
  }

  const salt = parts[0];
  const stored = parts[1];

  try {
    const calculated =
      crypto.scryptSync(
        password,
        salt,
        64
      ).toString("hex");

    const a =
      Buffer.from(
        stored,
        "hex"
      );

    const b =
      Buffer.from(
        calculated,
        "hex"
      );

    if (a.length !== b.length) {
      return false;
    }

    return crypto.timingSafeEqual(
      a,
      b
    );

  } catch {
    return false;
  }
}

// ============================================================
// JWT
// ============================================================

function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function createJWT(
  payload,
  expiresInSeconds =
    60 * 60 * 24 * 30
) {
  if (!JWT_SECRET) {
    throw new Error(
      "JWT_SECRET is not configured"
    );
  }

  const header = {
    alg: "HS256",
    typ: "JWT"
  };

  const now =
    Math.floor(
      Date.now() / 1000
    );

  const body = {
    ...payload,
    iat: now,
    exp:
      now + expiresInSeconds
  };

  const encodedHeader =
    base64url(
      JSON.stringify(header)
    );

  const encodedBody =
    base64url(
      JSON.stringify(body)
    );

  const unsigned =
    `${encodedHeader}.${encodedBody}`;

  const signature =
    crypto
      .createHmac(
        "sha256",
        JWT_SECRET
      )
      .update(unsigned)
      .digest("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");

  return (
    `${unsigned}.${signature}`
  );
}

function verifyJWT(token) {
  try {
    if (
      !JWT_SECRET ||
      !token
    ) {
      return null;
    }

    const parts =
      token.split(".");

    if (parts.length !== 3) {
      return null;
    }

    const [
      header,
      payload,
      signature
    ] = parts;

    const unsigned =
      `${header}.${payload}`;

    const expected =
      crypto
        .createHmac(
          "sha256",
          JWT_SECRET
        )
        .update(unsigned)
        .digest("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");

    const a =
      Buffer.from(signature);

    const b =
      Buffer.from(expected);

    if (a.length !== b.length) {
      return null;
    }

    if (
      !crypto.timingSafeEqual(
        a,
        b
      )
    ) {
      return null;
    }

    const decoded =
      JSON.parse(
        Buffer.from(
          payload,
          "base64url"
        ).toString("utf8")
      );

    if (!decoded.exp) {
      return null;
    }

    if (
      Math.floor(
        Date.now() / 1000
      ) >= decoded.exp
    ) {
      return null;
    }

    if (!decoded.userId) {
      return null;
    }

    return decoded;

  } catch {
    return null;
  }
}

// ============================================================
// BEARER TOKEN
// ============================================================

function getBearerToken(req) {
  const header =
    req.headers.authorization || "";

  if (
    !header.startsWith(
      "Bearer "
    )
  ) {
    return null;
  }

  return header
    .substring(7)
    .trim();
}

// ============================================================
// AUTH MIDDLEWARE
// ============================================================

async function authenticateRequest(
  req,
  res,
  next
) {
  try {
    const token =
      getBearerToken(req);

    if (!token) {
      return res.status(401).json({
        ok: false,
        error:
          "Authentication required"
      });
    }

    const decoded =
      verifyJWT(token);

    if (
      !decoded ||
      !decoded.userId
    ) {
      return res.status(401).json({
        ok: false,
        error:
          "Invalid or expired session"
      });
    }

    const result =
      await pool.query(
        `
        SELECT
          id,
          telegram_id,
          first_name,
          last_name,
          username,
          language_code,
          photo_url,
          full_name,
          email,
          phone,
          password_hash,
          balance,
          status,
          last_login_source,
          last_login_at,
          created_at,
          updated_at
        FROM users
        WHERE id = $1
        LIMIT 1
        `,
        [decoded.userId]
      );

    if (
      result.rows.length === 0
    ) {
      return res.status(401).json({
        ok: false,
        error:
          "User account not found"
      });
    }

    const user =
      result.rows[0];

    if (
      user.status !== "active"
    ) {
      return res.status(403).json({
        ok: false,
        error:
          "Account is not active"
      });
    }

    req.user = user;

    next();

  } catch (error) {
    console.error(
      "Authentication middleware error:",
      error
    );

    return res.status(500).json({
      ok: false,
      error:
        "Authentication failed"
    });
  }
}

// ============================================================
// AUTH EVENT LOG
// ============================================================

async function logAuthEvent(
  req,
  userId,
  eventType,
  source,
  metadata = {}
) {
  try {
    await pool.query(
      `
      INSERT INTO auth_events (
        user_id,
        event_type,
        source,
        ip,
        user_agent,
        metadata,
        created_at
      )
      VALUES (
        $1,
        $2,
        $3,
        $4,
        $5,
        $6,
        NOW()
      )
      `,
      [
        userId || null,
        eventType,
        source || null,
        getClientIp(req),
        req.headers["user-agent"] ||
          null,
        JSON.stringify(metadata)
      ]
    );

  } catch (error) {
    console.error(
      "Auth event logging error:",
      error.message
    );
  }
}

// ============================================================
// DATABASE SETUP / MIGRATION
// ============================================================

async function ensureDatabase() {

  // ----------------------------------------------------------
  // USERS
  // ----------------------------------------------------------

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,

      telegram_id BIGINT UNIQUE,

      first_name TEXT,
      last_name TEXT,

      username TEXT,

      language_code TEXT,
      photo_url TEXT,

      full_name TEXT,

      email TEXT,
      phone TEXT,

      password_hash TEXT,

      balance NUMERIC(12,2)
        NOT NULL DEFAULT 0,

      status TEXT
        NOT NULL DEFAULT 'active',

      last_login_source TEXT,
      last_login_at TIMESTAMPTZ,

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW(),

      updated_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    )
  `);

  // ----------------------------------------------------------
  // OLD DATABASE COMPATIBILITY
  // ----------------------------------------------------------

  await pool.query(`
    ALTER TABLE users
    ALTER COLUMN telegram_id
    DROP NOT NULL
  `);

  // ----------------------------------------------------------
  // MISSING COLUMNS
  // ----------------------------------------------------------

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
    username TEXT
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
    full_name TEXT
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
    email TEXT
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
    phone TEXT
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
    password_hash TEXT
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
    status TEXT
    NOT NULL DEFAULT 'active'
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
    last_login_source TEXT
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS
    last_login_at TIMESTAMPTZ
  `);

  // ----------------------------------------------------------
  // UNIQUE USERNAME
  // ----------------------------------------------------------

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
    users_username_unique_idx
    ON users (LOWER(username))
    WHERE username IS NOT NULL
  `);

  // ----------------------------------------------------------
  // UNIQUE EMAIL
  // ----------------------------------------------------------

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
    users_email_unique_idx
    ON users (LOWER(email))
    WHERE email IS NOT NULL
  `);

  // ----------------------------------------------------------
  // UNIQUE PHONE
  // ----------------------------------------------------------

  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
    users_phone_unique_idx
    ON users (phone)
    WHERE phone IS NOT NULL
  `);

  // ----------------------------------------------------------
  // AUTH EVENTS
  // ----------------------------------------------------------

  await pool.query(`
    CREATE TABLE IF NOT EXISTS auth_events (
      id BIGSERIAL PRIMARY KEY,

      user_id BIGINT,

      event_type TEXT NOT NULL,

      source TEXT,

      ip TEXT,

      user_agent TEXT,

      metadata JSONB,

      created_at TIMESTAMPTZ
        NOT NULL DEFAULT NOW()
    )
  `);

  // ----------------------------------------------------------
  // AUTH EVENT INDEXES
  // ----------------------------------------------------------

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    auth_events_user_id_idx
    ON auth_events(user_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
    auth_events_created_at_idx
    ON auth_events(created_at)
  `);

  console.log(
    "Database migration completed"
  );
}

// ============================================================
// TELEGRAM INIT DATA VALIDATION
// ============================================================

function validateTelegramInitData(
  initData
) {
  if (!initData) {
    return null;
  }

  if (
    !process.env.TELEGRAM_BOT_TOKEN
  ) {
    return null;
  }

  try {
    const params =
      new URLSearchParams(
        initData
      );

    const hash =
      params.get("hash");

    if (!hash) {
      return null;
    }

    params.delete("hash");

    const dataCheckString =
      [...params.entries()]
        .sort(
          ([a], [b]) =>
            a.localeCompare(b)
        )
        .map(
          ([key, value]) =>
            `${key}=${value}`
        )
        .join("\n");

    const secretKey =
      crypto
        .createHmac(
          "sha256",
          "WebAppData"
        )
        .update(
          process.env.TELEGRAM_BOT_TOKEN
        )
        .digest();

    const calculatedHash =
      crypto
        .createHmac(
          "sha256",
          secretKey
        )
        .update(
          dataCheckString
        )
        .digest("hex");

    const a =
      Buffer.from(
        calculatedHash,
        "hex"
      );

    const b =
      Buffer.from(
        hash,
        "hex"
      );

    if (
      a.length !== b.length
    ) {
      return null;
    }

    if (
      !crypto.timingSafeEqual(
        a,
        b
      )
    ) {
      return null;
    }

    const authDate =
      Number(
        params.get(
          "auth_date"
        )
      );

    if (!authDate) {
      return null;
    }

    const now =
      Math.floor(
        Date.now() / 1000
      );

    // 24 hour validity
    if (
      now - authDate > 86400
    ) {
      return null;
    }

    // Reject future timestamp
    if (
      authDate - now > 60
    ) {
      return null;
    }

    const userRaw =
      params.get("user");

    if (!userRaw) {
      return null;
    }

    const telegramUser =
      JSON.parse(userRaw);

    if (!telegramUser.id) {
      return null;
    }

    return telegramUser;

  } catch (error) {
    console.error(
      "Telegram validation error:",
      error.message
    );

    return null;
  }
}

// ============================================================
// PUBLIC USER
// ============================================================

function publicUser(user) {
  if (!user) {
    return null;
  }

  return {
    id: user.id,

    telegram_id:
      user.telegram_id,

    first_name:
      user.first_name,

    last_name:
      user.last_name,

    username:
      user.username,

    language_code:
      user.language_code,

    photo_url:
      user.photo_url,

    full_name:
      user.full_name,

    email:
      user.email,

    phone:
      user.phone,

    balance:
      user.balance,

    status:
      user.status,

    last_login_source:
      user.last_login_source,

    last_login_at:
      user.last_login_at,

    created_at:
      user.created_at,

    updated_at:
      user.updated_at
  };
}

// ============================================================
// BASIC ROUTES
// ============================================================

app.get("/", (req, res) => {
  res.json({
    ok: true,
    app: "DDR Backend",
    version: "3.1.0",
    message:
      "Unified Account Backend with Maya Control Center is running"
  });
});

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      ok: true,
      service:
        "ddr-backend",
      version: "3.1.0",
      controlCenter:
        true,
      time:
        new Date().toISOString()
    });
  }
);

app.get(
  "/api/config",
  (req, res) => {
    res.json({
      ok: true,

      appName: "Maya",

      backendVersion:
        "3.1.0",

      telegramMiniApp:
        true,

      controlCenter:
        true,

      authentication: {
        username: true,
        email: true,
        phone: true,
        password: true,
        telegram: true,

        google: false,
        facebook: false
      }
    });
  }
);

app.get(
  "/api/db-test",
  async (req, res) => {
    try {
      const result =
        await pool.query(
          "SELECT NOW() AS time"
        );

      res.json({
        ok: true,
        database:
          "connected",
        time:
          result.rows[0].time
      });

    } catch (error) {
      console.error(
        "Database error:",
        error.message
      );

      res.status(500).json({
        ok: false,
        database:
          "connection_failed"
      });
    }
  }
);

// ============================================================
// REGISTER
// ============================================================

app.post(
  "/api/auth/register",
  async (req, res) => {
    try {
      const name =
        cleanText(
          req.body.name
        );

      const username =
        normalizeUsername(
          req.body.username
        );

      const email =
        normalizeEmail(
          req.body.email
        );

      const phone =
        normalizePhone(
          req.body.phone
        );

      const password =
        String(
          req.body.password || ""
        );

      if (!name) {
        return res.status(400).json({
          ok: false,
          error:
            "Name is required"
        });
      }

      if (!username) {
        return res.status(400).json({
          ok: false,
          error:
            "Username is required"
        });
      }

      if (
        !/^[a-z0-9_]{3,32}$/i.test(
          username
        )
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Username must be 3-32 characters and contain only letters, numbers or underscore"
        });
      }

      if (!email && !phone) {
        return res.status(400).json({
          ok: false,
          error:
            "Email or phone is required"
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          ok: false,
          error:
            "Password must be at least 8 characters"
        });
      }

      const usernameResult =
        await pool.query(
          `
          SELECT id
          FROM users
          WHERE LOWER(username)
                = LOWER($1)
          LIMIT 1
          `,
          [username]
        );

      if (
        usernameResult.rows.length
      ) {
        return res.status(409).json({
          ok: false,
          error:
            "Username is already used"
        });
      }

      if (email) {
        const emailResult =
          await pool.query(
            `
            SELECT id
            FROM users
            WHERE LOWER(email)
                  = LOWER($1)
            LIMIT 1
            `,
            [email]
          );

        if (
          emailResult.rows.length
        ) {
          return res.status(409).json({
            ok: false,
            error:
              "Email is already used"
          });
        }
      }

      if (phone) {
        const phoneResult =
          await pool.query(
            `
            SELECT id
            FROM users
            WHERE phone = $1
            LIMIT 1
            `,
            [phone]
          );

        if (
          phoneResult.rows.length
        ) {
          return res.status(409).json({
            ok: false,
            error:
              "Phone is already used"
          });
        }
      }

      const passwordHash =
        hashPassword(
          password
        );

      const result =
        await pool.query(
          `
          INSERT INTO users (
            first_name,
            full_name,
            username,
            email,
            phone,
            password_hash,
            status,
            last_login_source,
            last_login_at,
            updated_at
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            'active',
            'password',
            NOW(),
            NOW()
          )
          RETURNING *
          `,
          [
            name,
            name,
            username,
            email,
            phone,
            passwordHash
          ]
        );

      const user =
        result.rows[0];

      await logAuthEvent(
        req,
        user.id,
        "register",
        "password"
      );

      const token =
        createJWT({
          userId: user.id
        });

      res.status(201).json({
        ok: true,
        token,
        user:
          publicUser(user)
      });

    } catch (error) {
      console.error(
        "Register error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Registration failed"
      });
    }
  }
);

// ============================================================
// LOGIN
// ============================================================

app.post(
  "/api/auth/login",
  async (req, res) => {
    try {
      const login =
        cleanText(
          req.body.login
        );

      const password =
        String(
          req.body.password || ""
        );

      if (
        !login ||
        !password
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Username, email or phone and password are required"
        });
      }

      const username =
        normalizeUsername(
          login
        );

      const email =
        normalizeEmail(
          login
        );

      const phone =
        normalizePhone(
          login
        );

      const result =
        await pool.query(
          `
          SELECT *
          FROM users
          WHERE
            (
              username IS NOT NULL
              AND LOWER(username)
                  = LOWER($1)
            )
            OR
            (
              email IS NOT NULL
              AND LOWER(email)
                  = LOWER($2)
            )
            OR
            (
              phone IS NOT NULL
              AND phone = $3
            )
          LIMIT 1
          `,
          [
            username,
            email,
            phone
          ]
        );

      if (
        result.rows.length === 0
      ) {
        await logAuthEvent(
          req,
          null,
          "login_failed",
          "password"
        );

        return res.status(401).json({
          ok: false,
          error:
            "Invalid login or password"
        });
      }

      const user =
        result.rows[0];

      if (
        user.status !== "active"
      ) {
        return res.status(403).json({
          ok: false,
          error:
            "This account is not active"
        });
      }

      if (
        !verifyPassword(
          password,
          user.password_hash
        )
      ) {
        await logAuthEvent(
          req,
          user.id,
          "login_failed",
          "password"
        );

        return res.status(401).json({
          ok: false,
          error:
            "Invalid login or password"
        });
      }

      const updated =
        await pool.query(
          `
          UPDATE users
          SET
            last_login_source =
              'password',
            last_login_at =
              NOW(),
            updated_at =
              NOW()
          WHERE id = $1
          RETURNING *
          `,
          [user.id]
        );

      const updatedUser =
        updated.rows[0];

      await logAuthEvent(
        req,
        user.id,
        "login",
        "password"
      );

      const token =
        createJWT({
          userId:
            user.id
        });

      res.json({
        ok: true,
        token,
        user:
          publicUser(
            updatedUser
          )
      });

    } catch (error) {
      console.error(
        "Login error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Login failed"
      });
    }
  }
);

// ============================================================
// TELEGRAM LOGIN / LINK
// ============================================================

app.post(
  "/api/auth/telegram",
  async (req, res) => {
    try {
      const initData =
        req.headers[
          "x-telegram-init-data"
        ];

      const telegramUser =
        validateTelegramInitData(
          initData
        );

      if (!telegramUser) {
        return res.status(401).json({
          ok: false,
          error:
            "Invalid Telegram authentication"
        });
      }

      const telegramId =
        String(
          telegramUser.id
        );

      const bearer =
        getBearerToken(req);

      const jwtUser =
        bearer
          ? verifyJWT(bearer)
          : null;

      // ======================================================
      // EXISTING LOGGED-IN ACCOUNT
      // LINK TELEGRAM
      // ======================================================

      if (
        jwtUser &&
        jwtUser.userId
      ) {
        const existingTelegram =
          await pool.query(
            `
            SELECT *
            FROM users
            WHERE telegram_id = $1
            LIMIT 1
            `,
            [telegramId]
          );

        if (
          existingTelegram.rows.length &&
          String(
            existingTelegram.rows[0].id
          ) !==
            String(
              jwtUser.userId
            )
        ) {
          return res.status(409).json({
            ok: false,
            error:
              "This Telegram account is already linked to another account"
          });
        }

        const result =
          await pool.query(
            `
            UPDATE users
            SET
              telegram_id = $1,

              first_name =
                COALESCE(
                  $2,
                  first_name
                ),

              last_name =
                COALESCE(
                  $3,
                  last_name
                ),

              language_code =
                COALESCE(
                  $4,
                  language_code
                ),

              photo_url =
                COALESCE(
                  $5,
                  photo_url
                ),

              last_login_source =
                'telegram',

              last_login_at =
                NOW(),

              updated_at =
                NOW()

            WHERE id = $6

            RETURNING *
            `,
            [
              telegramId,
              telegramUser.first_name ||
                null,
              telegramUser.last_name ||
                null,
              telegramUser.language_code ||
                null,
              telegramUser.photo_url ||
                null,
              jwtUser.userId
            ]
          );

        const user =
          result.rows[0];

        await logAuthEvent(
          req,
          user.id,
          "telegram_link",
          "telegram",
          {
            telegram_id:
              telegramId
          }
        );

        const token =
          createJWT({
            userId:
              user.id
          });

        return res.json({
          ok: true,
          linked: true,
          token,
          user:
            publicUser(user)
        });
      }

      // ======================================================
      // TELEGRAM ACCOUNT EXISTS
      // ======================================================

      const existing =
        await pool.query(
          `
          SELECT *
          FROM users
          WHERE telegram_id = $1
          LIMIT 1
          `,
          [telegramId]
        );

      if (
        existing.rows.length
      ) {
        const result =
          await pool.query(
            `
            UPDATE users
            SET
              first_name = $1,
              last_name = $2,
              language_code = $3,
              photo_url = $4,

              last_login_source =
                'telegram',

              last_login_at =
                NOW(),

              updated_at =
                NOW()

            WHERE telegram_id = $5

            RETURNING *
            `,
            [
              telegramUser.first_name ||
                null,
              telegramUser.last_name ||
                null,
              telegramUser.language_code ||
                null,
              telegramUser.photo_url ||
                null,
              telegramId
            ]
          );

        const user =
          result.rows[0];

        await logAuthEvent(
          req,
          user.id,
          "login",
          "telegram"
        );

        const token =
          createJWT({
            userId:
              user.id
          });

        console.log(
          "Telegram auth success"
        );

        return res.json({
          ok: true,
          linked: true,
          token,
          user:
            publicUser(user)
        });
      }

      // ======================================================
      // NEW TELEGRAM ACCOUNT
      // ======================================================

      const result =
        await pool.query(
          `
          INSERT INTO users (
            telegram_id,
            first_name,
            last_name,
            username,
            language_code,
            photo_url,
            status,
            last_login_source,
            last_login_at,
            updated_at
          )
          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            'active',
            'telegram',
            NOW(),
            NOW()
          )
          RETURNING *
          `,
          [
            telegramId,

            telegramUser.first_name ||
              null,

            telegramUser.last_name ||
              null,

            telegramUser.username
              ? normalizeUsername(
                  telegramUser.username
                )
              : null,

            telegramUser.language_code ||
              null,

            telegramUser.photo_url ||
              null
          ]
        );

      const user =
        result.rows[0];

      await logAuthEvent(
        req,
        user.id,
        "register",
        "telegram"
      );

      const token =
        createJWT({
          userId:
            user.id
        });

      console.log(
        "Telegram auth success"
      );

      res.status(201).json({
        ok: true,
        linked: false,
        token,
        user:
          publicUser(user)
      });

    } catch (error) {
      console.error(
        "Telegram auth error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Telegram authentication failed"
      });
    }
  }
);

// ============================================================
// SET CREDENTIALS
// ============================================================

app.post(
  "/api/auth/set-credentials",
  authenticateRequest,
  async (req, res) => {
    try {
      const username =
        normalizeUsername(
          req.body.username
        );

      const email =
        normalizeEmail(
          req.body.email
        );

      const phone =
        normalizePhone(
          req.body.phone
        );

      const password =
        String(
          req.body.password || ""
        );

      if (!username) {
        return res.status(400).json({
          ok: false,
          error:
            "Username is required"
        });
      }

      if (
        !/^[a-z0-9_]{3,32}$/i.test(
          username
        )
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Invalid username"
        });
      }

      if (!email && !phone) {
        return res.status(400).json({
          ok: false,
          error:
            "Email or phone is required"
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          ok: false,
          error:
            "Password must be at least 8 characters"
        });
      }

      const usernameConflict =
        await pool.query(
          `
          SELECT id
          FROM users
          WHERE
            LOWER(username)
              = LOWER($1)
            AND id <> $2
          LIMIT 1
          `,
          [
            username,
            req.user.id
          ]
        );

      if (
        usernameConflict.rows.length
      ) {
        return res.status(409).json({
          ok: false,
          error:
            "Username is already used by another account"
        });
      }

      if (email) {
        const result =
          await pool.query(
            `
            SELECT id
            FROM users
            WHERE
              LOWER(email)
                = LOWER($1)
              AND id <> $2
            LIMIT 1
            `,
            [
              email,
              req.user.id
            ]
          );

        if (
          result.rows.length
        ) {
          return res.status(409).json({
            ok: false,
            error:
              "Email is already used by another account"
          });
        }
      }

      if (phone) {
        const result =
          await pool.query(
            `
            SELECT id
            FROM users
            WHERE
              phone = $1
              AND id <> $2
            LIMIT 1
            `,
            [
              phone,
              req.user.id
            ]
          );

        if (
          result.rows.length
        ) {
          return res.status(409).json({
            ok: false,
            error:
              "Phone is already used by another account"
          });
        }
      }

      const passwordHash =
        hashPassword(
          password
        );

      const result =
        await pool.query(
          `
          UPDATE users
          SET
            username = $1,
            email =
              COALESCE(
                $2,
                email
              ),
            phone =
              COALESCE(
                $3,
                phone
              ),
            password_hash = $4,
            updated_at = NOW()

          WHERE id = $5

          RETURNING *
          `,
          [
            username,
            email,
            phone,
            passwordHash,
            req.user.id
          ]
        );

      const user =
        result.rows[0];

      await logAuthEvent(
        req,
        user.id,
        "credentials_updated",
        "account"
      );

      const token =
        createJWT({
          userId:
            user.id
        });

      res.json({
        ok: true,
        token,
        user:
          publicUser(user)
      });

    } catch (error) {
      console.error(
        "Set credentials error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Could not update credentials"
      });
    }
  }
);

// ============================================================
// GET CURRENT USER
// ============================================================

app.get(
  "/api/me",
  authenticateRequest,
  async (req, res) => {
    res.json({
      ok: true,
      user:
        publicUser(
          req.user
        )
    });
  }
);

// ============================================================
// UPDATE PROFILE
// ============================================================

app.patch(
  "/api/me",
  authenticateRequest,
  async (req, res) => {
    try {
      const fullName =
        cleanText(
          req.body.full_name
        );

      const firstName =
        cleanText(
          req.body.first_name
        );

      const lastName =
        cleanText(
          req.body.last_name
        );

      const username =
        normalizeUsername(
          req.body.username
        );

      const email =
        normalizeEmail(
          req.body.email
        );

      const phone =
        normalizePhone(
          req.body.phone
        );

      if (username) {
        if (
          !/^[a-z0-9_]{3,32}$/i.test(
            username
          )
        ) {
          return res.status(400).json({
            ok: false,
            error:
              "Invalid username"
          });
        }

        const conflict =
          await pool.query(
            `
            SELECT id
            FROM users
            WHERE
              LOWER(username)
                = LOWER($1)
              AND id <> $2
            LIMIT 1
            `,
            [
              username,
              req.user.id
            ]
          );

        if (
          conflict.rows.length
        ) {
          return res.status(409).json({
            ok: false,
            error:
              "Username already belongs to another account"
          });
        }
      }

      if (email) {
        const conflict =
          await pool.query(
            `
            SELECT id
            FROM users
            WHERE
              LOWER(email)
                = LOWER($1)
              AND id <> $2
            LIMIT 1
            `,
            [
              email,
              req.user.id
            ]
          );

        if (
          conflict.rows.length
        ) {
          return res.status(409).json({
            ok: false,
            error:
              "Email already belongs to another account"
          });
        }
      }

      if (phone) {
        const conflict =
          await pool.query(
            `
            SELECT id
            FROM users
            WHERE
              phone = $1
              AND id <> $2
            LIMIT 1
            `,
            [
              phone,
              req.user.id
            ]
          );

        if (
          conflict.rows.length
        ) {
          return res.status(409).json({
            ok: false,
            error:
              "Phone already belongs to another account"
          });
        }
      }

      const result =
        await pool.query(
          `
          UPDATE users
          SET
            full_name =
              COALESCE(
                $1,
                full_name
              ),

            first_name =
              COALESCE(
                $2,
                first_name
              ),

            last_name =
              COALESCE(
                $3,
                last_name
              ),

            username =
              COALESCE(
                $4,
                username
              ),

            email =
              COALESCE(
                $5,
                email
              ),

            phone =
              COALESCE(
                $6,
                phone
              ),

            updated_at =
              NOW()

          WHERE id = $7

          RETURNING *
          `,
          [
            fullName,
            firstName,
            lastName,
            username,
            email,
            phone,
            req.user.id
          ]
        );

      const user =
        result.rows[0];

      await logAuthEvent(
        req,
        user.id,
        "profile_updated",
        "account"
      );

      res.json({
        ok: true,
        user:
          publicUser(user)
      });

    } catch (error) {
      console.error(
        "Profile update error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Profile update failed"
      });
    }
  }
);

// ============================================================
// ADMIN AUTHENTICATION
// ============================================================

function requireAdmin(
  req,
  res,
  next
) {
  const key =
    req.headers[
      "x-admin-key"
    ];

  if (
    !ADMIN_KEY ||
    !key ||
    key !== ADMIN_KEY
  ) {
    return res.status(403).json({
      ok: false,
      error:
        "Admin access denied"
    });
  }

  next();
}

// ============================================================
// ADMIN - USERS
// ============================================================

app.get(
  "/api/admin/users",
  requireAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            id,
            telegram_id,
            first_name,
            last_name,
            username,
            full_name,
            email,
            phone,
            balance,
            status,
            last_login_source,
            last_login_at,
            created_at,
            updated_at
          FROM users
          ORDER BY id DESC
          LIMIT 1000
          `
        );

      res.json({
        ok: true,
        count:
          result.rows.length,
        users:
          result.rows
      });

    } catch (error) {
      console.error(
        "Admin users error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Could not load users"
      });
    }
  }
);

// ============================================================
// ADMIN - AUTH EVENTS
// ============================================================

app.get(
  "/api/admin/auth-events",
  requireAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(
          `
          SELECT
            id,
            user_id,
            event_type,
            source,
            ip,
            user_agent,
            metadata,
            created_at
          FROM auth_events
          ORDER BY id DESC
          LIMIT 1000
          `
        );

      res.json({
        ok: true,
        count:
          result.rows.length,
        events:
          result.rows
      });

    } catch (error) {
      console.error(
        "Admin auth events error:",
        error
      );

      res.status(500).json({
        ok: false,
        error:
          "Could not load authentication events"
      });
    }
  }
);

// ============================================================
// PLACEHOLDER TELEGRAM LINK
// ============================================================

app.post(
  "/api/auth/telegram-link",
  authenticateRequest,
  async (req, res) => {
    res.status(400).json({
      ok: false,
      error:
        "Use /api/auth/telegram with X-Telegram-Init-Data to link Telegram"
    });
  }
);

// ============================================================
// 404
// ============================================================

app.use(
  (req, res) => {
    res.status(404).json({
      ok: false,
      error:
        "Route not found"
    });
  }
);

// ============================================================
// ERROR HANDLER
// ============================================================

app.use(
  (
    err,
    req,
    res,
    next
  ) => {
    console.error(
      "Unhandled error:",
      err
    );

    res.status(500).json({
      ok: false,
      error:
        "Internal server error"
    });
  }
);

// ============================================================
// START SERVER
// ============================================================

async function startServer() {
  try {
    await ensureDatabase();

    // ========================================================
    // MAYA ADMIN CONTROL CENTER DATABASE
    // ========================================================

    await ensureControlCenterDatabase(pool);

    console.log(
      "Database tables ready"
    );

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `DDR backend running on port ${PORT}`
        );

        console.log(
          "Maya Admin Control Center routes enabled"
        );
      }
    );

  } catch (error) {
    console.error(
      "Failed to start server:",
      error
    );

    process.exit(1);
  }
}

startServer();