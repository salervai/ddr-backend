const crypto = require("crypto");

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(String(password), salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  try {
    if (!stored || !stored.includes(":")) return false;

    const [salt, oldHash] = stored.split(":");
    const newHash = crypto.scryptSync(String(password), salt, 64).toString("hex");

    const a = Buffer.from(oldHash, "hex");
    const b = Buffer.from(newHash, "hex");

    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function base64url(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function signToken(payload, secret, expires = 86400 * 30) {
  const now = Math.floor(Date.now() / 1000);

  const header = base64url(
    JSON.stringify({
      alg: "HS256",
      typ: "JWT"
    })
  );

  const body = base64url(
    JSON.stringify({
      ...payload,
      iat: now,
      exp: now + expires
    })
  );

  const unsigned = `${header}.${body}`;

  const signature = crypto
    .createHmac("sha256", secret)
    .update(unsigned)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

  return `${unsigned}.${signature}`;
}

function verifyToken(token, secret) {
  try {
    if (!token || !secret) return null;

    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const [header, body, signature] = parts;
    const unsigned = `${header}.${body}`;

    const expected = crypto
      .createHmac("sha256", secret)
      .update(unsigned)
      .digest("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (a.length !== b.length) return null;

    if (!crypto.timingSafeEqual(a, b)) return null;

    const decoded = JSON.parse(
      Buffer.from(body, "base64url").toString("utf8")
    );

    if (!decoded.exp) return null;

    if (Math.floor(Date.now() / 1000) >= decoded.exp) {
      return null;
    }

    return decoded;
  } catch {
    return null;
  }
}

function getBearer(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.substring(7).trim();
}

async function ensureControlCenterDatabase(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS roles (
      id BIGSERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS permissions (
      id BIGSERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      description TEXT
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS role_permissions (
      role_id BIGINT REFERENCES roles(id) ON DELETE CASCADE,
      permission_id BIGINT REFERENCES permissions(id) ON DELETE CASCADE,
      PRIMARY KEY(role_id, permission_id)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS staff_users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT,
      role_id BIGINT REFERENCES roles(id),
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id BIGSERIAL PRIMARY KEY,
      staff_id BIGINT,
      action TEXT NOT NULL,
      target_type TEXT,
      target_id TEXT,
      metadata JSONB,
      ip TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS registration_fields (
      id BIGSERIAL PRIMARY KEY,
      field_key TEXT UNIQUE NOT NULL,
      label TEXT NOT NULL,
      field_type TEXT NOT NULL DEFAULT 'text',
      required BOOLEAN NOT NULL DEFAULT false,
      enabled BOOLEAN NOT NULL DEFAULT true,
      placeholder TEXT,
      options JSONB NOT NULL DEFAULT '[]'::jsonb,
      validation JSONB NOT NULL DEFAULT '{}'::jsonb,
      sort_order INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ad_placements (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      placement_key TEXT UNIQUE NOT NULL,
      provider TEXT NOT NULL DEFAULT 'monetag',
      zone_id TEXT,
      ad_type TEXT NOT NULL DEFAULT 'rewarded',
      enabled BOOLEAN NOT NULL DEFAULT true,
      frequency_minutes INTEGER,
      page_views INTEGER,
      video_count INTEGER,
      daily_limit INTEGER,
      start_at TIMESTAMPTZ,
      end_at TIMESTAMPTZ,
      settings JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ad_creatives (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      title TEXT,
      subtitle TEXT,
      description TEXT,
      button_text TEXT,
      icon TEXT,
      image_url TEXT,
      link_url TEXT,
      enabled BOOLEAN NOT NULL DEFAULT true,
      settings JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ad_placement_creatives (
      placement_id BIGINT REFERENCES ad_placements(id) ON DELETE CASCADE,
      creative_id BIGINT REFERENCES ad_creatives(id) ON DELETE CASCADE,
      PRIMARY KEY(placement_id, creative_id)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ad_campaigns (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      placement_id BIGINT REFERENCES ad_placements(id) ON DELETE SET NULL,
      creative_id BIGINT REFERENCES ad_creatives(id) ON DELETE SET NULL,
      enabled BOOLEAN NOT NULL DEFAULT true,
      start_at TIMESTAMPTZ,
      end_at TIMESTAMPTZ,
      settings JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS cms_components (
      id BIGSERIAL PRIMARY KEY,
      component_key TEXT UNIQUE NOT NULL,
      component_type TEXT NOT NULL DEFAULT 'box',
      title TEXT,
      subtitle TEXT,
      content TEXT,
      image_url TEXT,
      link_url TEXT,
      enabled BOOLEAN NOT NULL DEFAULT true,
      sort_order INTEGER NOT NULL DEFAULT 0,
      settings JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS social_settings (
      id BIGSERIAL PRIMARY KEY,
      platform TEXT UNIQUE NOT NULL,
      enabled BOOLEAN NOT NULL DEFAULT false,
      url TEXT,
      chat_id TEXT,
      settings JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const roles = [
    ["Admin", "Full system administration"],
    ["Designer", "Frontend design and CMS"],
    ["Moderator", "Content moderation"],
    ["Publisher", "Video publishing"]
  ];

  for (const [name, description] of roles) {
    await pool.query(
      `
      INSERT INTO roles(name, description)
      VALUES($1, $2)
      ON CONFLICT(name) DO NOTHING
      `,
      [name, description]
    );
  }

  const permissions = [
    "users.view",
    "users.manage",
    "staff.view",
    "staff.manage",
    "frontend.view",
    "frontend.manage",
    "registration.view",
    "registration.manage",
    "ads.view",
    "ads.manage",
    "content.view",
    "content.manage",
    "settings.view",
    "settings.manage",
    "audit.view",
    "social.view",
    "social.manage"
  ];

  for (const permission of permissions) {
    await pool.query(
      `
      INSERT INTO permissions(name)
      VALUES($1)
      ON CONFLICT(name) DO NOTHING
      `,
      [permission]
    );
  }

  const adminRole = await pool.query(
    `SELECT id FROM roles WHERE name = 'Admin' LIMIT 1`
  );

  const allPermissions = await pool.query(
    `SELECT id FROM permissions`
  );

  if (adminRole.rows.length) {
    for (const permission of allPermissions.rows) {
      await pool.query(
        `
        INSERT INTO role_permissions(role_id, permission_id)
        VALUES($1, $2)
        ON CONFLICT DO NOTHING
        `,
        [adminRole.rows[0].id, permission.id]
      );
    }
  }

  const defaults = {
    app_name: "Maya",
    frontend_reference: "DDR V18",
    monetag_zone: "11748430",
    authentication: {
      username: true,
      email: true,
      phone: true,
      password: true,
      telegram: true,
      google: false,
      facebook: false
    }
  };

  for (const [key, value] of Object.entries(defaults)) {
    await pool.query(
      `
      INSERT INTO app_settings(key, value)
      VALUES($1, $2)
      ON CONFLICT(key) DO NOTHING
      `,
      [key, JSON.stringify(value)]
    );
  }

  console.log("Admin Control Center database ready");
}

function registerAdminControlCenter({
  app,
  pool,
  adminKey,
  jwtSecret
}) {
  if (!app || !pool) {
    throw new Error("Admin Control Center requires app and pool");
  }

  function requireStaff(req, res, next) {
    try {
      const token = getBearer(req);
      const staff = verifyToken(token, jwtSecret);

      if (!staff || !staff.staffId) {
        return res.status(401).json({
          ok: false,
          error: "Staff authentication required"
        });
      }

      req.staff = staff;
      next();
    } catch {
      return res.status(401).json({
        ok: false,
        error: "Invalid staff session"
      });
    }
  }

  async function audit(req, action, targetType = null, targetId = null, metadata = {}) {
    try {
      await pool.query(
        `
        INSERT INTO audit_logs(
          staff_id,
          action,
          target_type,
          target_id,
          metadata,
          ip
        )
        VALUES($1,$2,$3,$4,$5,$6)
        `,
        [
          req.staff?.staffId || null,
          action,
          targetType,
          targetId ? String(targetId) : null,
          JSON.stringify(metadata),
          req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
            req.socket?.remoteAddress ||
            null
        ]
      );
    } catch (error) {
      console.error("Audit error:", error.message);
    }
  }

  // ----------------------------------------------------------
  // BOOTSTRAP ADMIN
  // ----------------------------------------------------------

  app.post(
    "/api/admin/control/bootstrap",
    async (req, res) => {
      try {
        const key = req.headers["x-admin-key"];

        if (!adminKey || key !== adminKey) {
          return res.status(403).json({
            ok: false,
            error: "Admin bootstrap denied"
          });
        }

        const username =
          String(req.body.username || "admin")
            .trim()
            .toLowerCase();

        const password =
          String(req.body.password || "");

        if (password.length < 8) {
          return res.status(400).json({
            ok: false,
            error: "Password must be at least 8 characters"
          });
        }

        const role = await pool.query(
          `SELECT id FROM roles WHERE name = 'Admin' LIMIT 1`
        );

        const existing = await pool.query(
          `SELECT id FROM staff_users WHERE username = $1 LIMIT 1`,
          [username]
        );

        if (existing.rows.length) {
          return res.status(409).json({
            ok: false,
            error: "Staff username already exists"
          });
        }

        const result = await pool.query(
          `
          INSERT INTO staff_users(
            username,
            password_hash,
            role_id,
            status
          )
          VALUES($1,$2,$3,'active')
          RETURNING id, username, role_id, status, created_at
          `,
          [
            username,
            hashPassword(password),
            role.rows[0]?.id || null
          ]
        );

        res.status(201).json({
          ok: true,
          staff: result.rows[0]
        });
      } catch (error) {
        console.error("Admin bootstrap error:", error);

        res.status(500).json({
          ok: false,
          error: "Could not create admin"
        });
      }
    }
  );

  // ----------------------------------------------------------
  // STAFF LOGIN
  // ----------------------------------------------------------

  app.post(
    "/api/admin/control/login",
    async (req, res) => {
      try {
        const username =
          String(req.body.username || "")
            .trim()
            .toLowerCase();

        const password =
          String(req.body.password || "");

        const result = await pool.query(
          `
          SELECT
            s.*,
            r.name AS role_name
          FROM staff_users s
          LEFT JOIN roles r
            ON r.id = s.role_id
          WHERE LOWER(s.username) = LOWER($1)
          LIMIT 1
          `,
          [username]
        );

        if (!result.rows.length) {
          return res.status(401).json({
            ok: false,
            error: "Invalid staff login"
          });
        }

        const staff = result.rows[0];

        if (staff.status !== "active") {
          return res.status(403).json({
            ok: false,
            error: "Staff account is not active"
          });
        }

        if (!verifyPassword(password, staff.password_hash)) {
          return res.status(401).json({
            ok: false,
            error: "Invalid staff login"
          });
        }

        const token = signToken(
          {
            staffId: staff.id,
            username: staff.username,
            role: staff.role_name
          },
          jwtSecret
        );

        await pool.query(
          `
          UPDATE staff_users
          SET updated_at = NOW()
          WHERE id = $1
          `,
          [staff.id]
        );

        res.json({
          ok: true,
          token,
          staff: {
            id: staff.id,
            username: staff.username,
            role: staff.role_name,
            status: staff.status
          }
        });
      } catch (error) {
        console.error("Staff login error:", error);

        res.status(500).json({
          ok: false,
          error: "Staff login failed"
        });
      }
    }
  );

  // ----------------------------------------------------------
  // CONFIG
  // ----------------------------------------------------------

  app.get(
    "/api/control/config",
    async (req, res) => {
      try {
        const settings = await pool.query(
          `
          SELECT key, value
          FROM app_settings
          ORDER BY key
          `
        );

        const cms = await pool.query(
          `
          SELECT *
          FROM cms_components
          WHERE enabled = true
          ORDER BY sort_order ASC, id ASC
          `
        );

        const placements = await pool.query(
          `
          SELECT *
          FROM ad_placements
          WHERE enabled = true
          ORDER BY id ASC
          `
        );

        const creatives = await pool.query(
          `
          SELECT *
          FROM ad_creatives
          WHERE enabled = true
          ORDER BY id ASC
          `
        );

        res.json({
          ok: true,
          settings: Object.fromEntries(
            settings.rows.map(row => [row.key, row.value])
          ),
          cms: cms.rows,
          adPlacements: placements.rows,
          adCreatives: creatives.rows
        });
      } catch (error) {
        console.error("Control config error:", error);

        res.status(500).json({
          ok: false,
          error: "Could not load control configuration"
        });
      }
    }
  );

  // ----------------------------------------------------------
  // DASHBOARD
  // ----------------------------------------------------------

  app.get(
    "/api/admin/control/dashboard",
    requireStaff,
    async (req, res) => {
      try {
        const users = await pool.query(
          `SELECT COUNT(*)::int AS count FROM users`
        );

        const staff = await pool.query(
          `SELECT COUNT(*)::int AS count FROM staff_users`
        );

        const videos = await pool.query(
          `SELECT COUNT(*)::int AS count FROM videos`
        ).catch(() => ({ rows: [{ count: 0 }] }));

        const placements = await pool.query(
          `SELECT COUNT(*)::int AS count FROM ad_placements`
        );

        res.json({
          ok: true,
          dashboard: {
            users: users.rows[0].count,
            staff: staff.rows[0].count,
            videos: videos.rows[0].count,
            adPlacements: placements.rows[0].count
          }
        });
      } catch (error) {
        res.status(500).json({
          ok: false,
          error: "Could not load dashboard"
        });
      }
    }
  );

  // ----------------------------------------------------------
  // USERS
  // ----------------------------------------------------------

  app.get(
    "/api/admin/control/users",
    requireStaff,
    async (req, res) => {
      try {
        const result = await pool.query(`
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
          LIMIT 2000
        `);

        res.json({
          ok: true,
          count: result.rows.length,
          users: result.rows
        });
      } catch (error) {
        res.status(500).json({
          ok: false,
          error: "Could not load users"
        });
      }
    }
  );

  app.patch(
    "/api/admin/control/users/:id/status",
    requireStaff,
    async (req, res) => {
      try {
        const status =
          String(req.body.status || "active");

        const allowed = [
          "active",
          "suspended",
          "blocked"
        ];

        if (!allowed.includes(status)) {
          return res.status(400).json({
            ok: false,
            error: "Invalid status"
          });
        }

        const result = await pool.query(
          `
          UPDATE users
          SET
            status = $1,
            updated_at = NOW()
          WHERE id = $2
          RETURNING id, username, status
          `,
          [status, req.params.id]
        );

        if (!result.rows.length) {
          return res.status(404).json({
            ok: false,
            error: "User not found"
          });
        }

        await audit(
          req,
          "user_status_changed",
          "user",
          req.params.id,
          { status }
        );

        res.json({
          ok: true,
          user: result.rows[0]
        });
      } catch (error) {
        res.status(500).json({
          ok: false,
          error: "Could not update user"
        });
      }
    }
  );

  // ----------------------------------------------------------
  // STAFF
  // ----------------------------------------------------------

  app.get(
    "/api/admin/control/staff",
    requireStaff,
    async (req, res) => {
      try {
        const result = await pool.query(`
          SELECT
            s.id,
            s.username,
            s.status,
            s.created_at,
            s.updated_at,
            r.name AS role
          FROM staff_users s
          LEFT JOIN roles r
            ON r.id = s.role_id
          ORDER BY s.id DESC
        `);

        res.json({
          ok: true,
          staff: result.rows
        });
      } catch {
        res.status(500).json({
          ok: false,
          error: "Could not load staff"
        });
      }
    }
  );

  app.get(
    "/api/admin/control/roles",
    requireStaff,
    async (req, res) => {
      try {
        const result = await pool.query(`
          SELECT
            r.id,
            r.name,
            r.description,
            COALESCE(
              json_agg(
                p.name
                ORDER BY p.name
              )
              FILTER(WHERE p.id IS NOT NULL),
              '[]'
            ) AS permissions
          FROM roles r
          LEFT JOIN role_permissions rp
            ON rp.role_id = r.id
          LEFT JOIN permissions p
            ON p.id = rp.permission_id
          GROUP BY r.id
          ORDER BY r.id
        `);

        res.json({
          ok: true,
          roles: result.rows
        });
      } catch {
        res.status(500).json({
          ok: false,
          error: "Could not load roles"
        });
      }
    }
  );

  app.post(
    "/api/admin/control/staff",
    requireStaff,
    async (req, res) => {
      try {
        const username =
          String(req.body.username || "")
            .trim()
            .toLowerCase();

        const password =
          String(req.body.password || "");

        const roleName =
          String(req.body.role || "Moderator");

        if (!username || password.length < 8) {
          return res.status(400).json({
            ok: false,
            error: "Username and password are required"
          });
        }

        const role = await pool.query(
          `SELECT id FROM roles WHERE name = $1 LIMIT 1`,
          [roleName]
        );

        if (!role.rows.length) {
          return res.status(400).json({
            ok: false,
            error: "Role not found"
          });
        }

        const result = await pool.query(
          `
          INSERT INTO staff_users(
            username,
            password_hash,
            role_id,
            status
          )
          VALUES($1,$2,$3,'active')
          RETURNING id, username, role_id, status, created_at
          `,
          [
            username,
            hashPassword(password),
            role.rows[0].id
          ]
        );

        await audit(
          req,
          "staff_created",
          "staff",
          result.rows[0].id,
          { username, role: roleName }
        );

        res.status(201).json({
          ok: true,
          staff: result.rows[0]
        });
      } catch (error) {
        if (error.code === "23505") {
          return res.status(409).json({
            ok: false,
            error: "Staff username already exists"
          });
        }

        res.status(500).json({
          ok: false,
          error: "Could not create staff"
        });
      }
    }
  );

  // ----------------------------------------------------------
  // SETTINGS
  // ----------------------------------------------------------

  app.get(
    "/api/admin/control/settings",
    requireStaff,
    async (req, res) => {
      try {
        const result = await pool.query(`
          SELECT key, value, updated_at
          FROM app_settings
          ORDER BY key
        `);

        res.json({
          ok: true,
          settings: result.rows
        });
      } catch {
        res.status(500).json({
          ok: false,
          error: "Could not load settings"
        });
      }
    }
  );

  app.put(
    "/api/admin/control/settings/:key",
    requireStaff,
    async (req, res) => {
      try {
        const value =
          req.body.value === undefined
            ? null
            : req.body.value;

        await pool.query(
          `
          INSERT INTO app_settings(key, value, updated_at)
          VALUES($1,$2,NOW())
          ON CONFLICT(key)
          DO UPDATE SET
            value = EXCLUDED.value,
            updated_at = NOW()
          `,
          [
            req.params.key,
            JSON.stringify(value)
          ]
        );

        await audit(
          req,
          "setting_updated",
          "setting",
          req.params.key
        );

        res.json({
          ok: true
        });
      } catch {
        res.status(500).json({
          ok: false,
          error: "Could not update setting"
        });
      }
    }
  );

  // ----------------------------------------------------------
  // REGISTRATION FIELDS
  // ----------------------------------------------------------

  app.get(
    "/api/admin/control/registration-fields",
    requireStaff,
    async (req, res) => {
      const result = await pool.query(`
        SELECT *
        FROM registration_fields
        ORDER BY sort_order ASC, id ASC
      `);

      res.json({
        ok: true,
        fields: result.rows
      });
    }
  );

  app.post(
    "/api/admin/control/registration-fields",
    requireStaff,
    async (req, res) => {
      try {
        const fieldKey =
          String(req.body.field_key || "")
            .trim()
            .toLowerCase();

        const label =
          String(req.body.label || fieldKey);

        const result = await pool.query(
          `
          INSERT INTO registration_fields(
            field_key,
            label,
            field_type,
            required,
            enabled,
            placeholder,
            options,
            validation,
            sort_order
          )
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
          RETURNING *
          `,
          [
            fieldKey,
            label,
            req.body.field_type || "text",
            Boolean(req.body.required),
            req.body.enabled !== false,
            req.body.placeholder || null,
            JSON.stringify(req.body.options || []),
            JSON.stringify(req.body.validation || {}),
            Number(req.body.sort_order || 0)
          ]
        );

        await audit(
          req,
          "registration_field_created",
          "registration_field",
          result.rows[0].id
        );

        res.status(201).json({
          ok: true,
          field: result.rows[0]
        });
      } catch (error) {
        res.status(500).json({
          ok: false,
          error: "Could not create registration field"
        });
      }
    }
  );

  // ----------------------------------------------------------
  // AD PLACEMENTS
  // ----------------------------------------------------------

  app.get(
    "/api/admin/control/ad-placements",
    requireStaff,
    async (req, res) => {
      const result = await pool.query(`
        SELECT *
        FROM ad_placements
        ORDER BY id DESC
      `);

      res.json({
        ok: true,
        placements: result.rows
      });
    }
  );

  app.post(
    "/api/admin/control/ad-placements",
    requireStaff,
    async (req, res) => {
      try {
        const result = await pool.query(
          `
          INSERT INTO ad_placements(
            name,
            placement_key,
            provider,
            zone_id,
            ad_type,
            enabled,
            frequency_minutes,
            page_views,
            video_count,
            daily_limit,
            start_at,
            end_at,
            settings
          )
          VALUES(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13
          )
          RETURNING *
          `,
          [
            req.body.name,
            req.body.placement_key,
            req.body.provider || "monetag",
            req.body.zone_id || "11748430",
            req.body.ad_type || "rewarded",
            req.body.enabled !== false,
            req.body.frequency_minutes || null,
            req.body.page_views || null,
            req.body.video_count || null,
            req.body.daily_limit || null,
            req.body.start_at || null,
            req.body.end_at || null,
            JSON.stringify(req.body.settings || {})
          ]
        );

        await audit(
          req,
          "ad_placement_created",
          "ad_placement",
          result.rows[0].id
        );

        res.status(201).json({
          ok: true,
          placement: result.rows[0]
        });
      } catch {
        res.status(500).json({
          ok: false,
          error: "Could not create ad placement"
        });
      }
    }
  );

  // ----------------------------------------------------------
  // AD CREATIVES
  // ----------------------------------------------------------

  app.get(
    "/api/admin/control/ad-creatives",
    requireStaff,
    async (req, res) => {
      const result = await pool.query(`
        SELECT *
        FROM ad_creatives
        ORDER BY id DESC
      `);

      res.json({
        ok: true,
        creatives: result.rows
      });
    }
  );

  app.post(
    "/api/admin/control/ad-creatives",
    requireStaff,
    async (req, res) => {
      try {
        const result = await pool.query(
          `
          INSERT INTO ad_creatives(
            name,
            title,
            subtitle,
            description,
            button_text,
            icon,
            image_url,
            link_url,
            enabled,
            settings
          )
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
          RETURNING *
          `,
          [
            req.body.name,
            req.body.title || null,
            req.body.subtitle || null,
            req.body.description || null,
            req.body.button_text || null,
            req.body.icon || null,
            req.body.image_url || null,
            req.body.link_url || null,
            req.body.enabled !== false,
            JSON.stringify(req.body.settings || {})
          ]
        );

        await audit(
          req,
          "ad_creative_created",
          "ad_creative",
          result.rows[0].id
        );

        res.status(201).json({
          ok: true,
          creative: result.rows[0]
        });
      } catch {
        res.status(500).json({
          ok: false,
          error: "Could not create ad creative"
        });
      }
    }
  );

  // ----------------------------------------------------------
  // PLACEMENT ↔ CREATIVE MAPPING
  // ----------------------------------------------------------

  app.post(
    "/api/admin/control/ad-mapping",
    requireStaff,
    async (req, res) => {
      try {
        await pool.query(
          `
          INSERT INTO ad_placement_creatives(
            placement_id,
            creative_id
          )
          VALUES($1,$2)
          ON CONFLICT DO NOTHING
          `,
          [
            req.body.placement_id,
            req.body.creative_id
          ]
        );

        res.json({
          ok: true
        });
      } catch {
        res.status(500).json({
          ok: false,
          error: "Could not map ad creative"
        });
      }
    }
  );

  // ----------------------------------------------------------
  // CMS
  // ----------------------------------------------------------

  app.get(
    "/api/admin/control/cms",
    requireStaff,
    async (req, res) => {
      const result = await pool.query(`
        SELECT *
        FROM cms_components
        ORDER BY sort_order ASC, id ASC
      `);

      res.json({
        ok: true,
        components: result.rows
      });
    }
  );

  app.post(
    "/api/admin/control/cms",
    requireStaff,
    async (req, res) => {
      try {
        const result = await pool.query(
          `
          INSERT INTO cms_components(
            component_key,
            component_type,
            title,
            subtitle,
            content,
            image_url,
            link_url,
            enabled,
            sort_order,
            settings
          )
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
          RETURNING *
          `,
          [
            req.body.component_key,
            req.body.component_type || "box",
            req.body.title || null,
            req.body.subtitle || null,
            req.body.content || null,
            req.body.image_url || null,
            req.body.link_url || null,
            req.body.enabled !== false,
            Number(req.body.sort_order || 0),
            JSON.stringify(req.body.settings || {})
          ]
        );

        await audit(
          req,
          "cms_component_created",
          "cms",
          result.rows[0].id
        );

        res.status(201).json({
          ok: true,
          component: result.rows[0]
        });
      } catch {
        res.status(500).json({
          ok: false,
          error: "Could not create CMS component"
        });
      }
    }
  );

  // ----------------------------------------------------------
  // SOCIAL SETTINGS
  // ----------------------------------------------------------

  app.get(
    "/api/admin/control/social",
    requireStaff,
    async (req, res) => {
      const result = await pool.query(`
        SELECT *
        FROM social_settings
        ORDER BY platform
      `);

      res.json({
        ok: true,
        social: result.rows
      });
    }
  );

  app.put(
    "/api/admin/control/social/:platform",
    requireStaff,
    async (req, res) => {
      try {
        await pool.query(
          `
          INSERT INTO social_settings(
            platform,
            enabled,
            url,
            chat_id,
            settings,
            updated_at
          )
          VALUES($1,$2,$3,$4,$5,NOW())
          ON CONFLICT(platform)
          DO UPDATE SET
            enabled = EXCLUDED.enabled,
            url = EXCLUDED.url,
            chat_id = EXCLUDED.chat_id,
            settings = EXCLUDED.settings,
            updated_at = NOW()
          `,
          [
            req.params.platform,
            req.body.enabled !== false,
            req.body.url || null,
            req.body.chat_id || null,
            JSON.stringify(req.body.settings || {})
          ]
        );

        res.json({
          ok: true
        });
      } catch {
        res.status(500).json({
          ok: false,
          error: "Could not update social settings"
        });
      }
    }
  );

  // ----------------------------------------------------------
  // AUDIT LOGS
  // ----------------------------------------------------------

  app.get(
    "/api/admin/control/audit",
    requireStaff,
    async (req, res) => {
      try {
        const result = await pool.query(`
          SELECT *
          FROM audit_logs
          ORDER BY id DESC
          LIMIT 2000
        `);

        res.json({
          ok: true,
          logs: result.rows
        });
      } catch {
        res.status(500).json({
          ok: false,
          error: "Could not load audit logs"
        });
      }
    }
  );

  console.log("Admin Control Center routes registered");
}

module.exports = {
  ensureControlCenterDatabase,
  registerAdminControlCenter
};
