const crypto = require("crypto");

// ============================================================
// MAYA DYNAMIC BUILDER BACKEND MODULE
// ============================================================

function registerMayaDynamicBuilder({ app, pool, jwtSecret }) {

  function verifyMayaStaffToken(token, secret) {
    try {
      if (!token || !secret) return null;

      const parts = String(token).split(".");
      if (parts.length !== 3) return null;

      const [header, payload, signature] = parts;
      const unsigned = `${header}.${payload}`;

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

      const body = JSON.parse(
        Buffer.from(payload, "base64url").toString("utf8")
      );

      if (
        body.staff !== true ||
        !body.staffId ||
        !body.exp
      ) {
        return null;
      }

      if (
        Math.floor(Date.now() / 1000) >= Number(body.exp)
      ) {
        return null;
      }

      return body;

    } catch {
      return null;
    }
  }

  let mayaDynamicBuilderReady = null;

  async function ensureMayaDynamicBuilderDatabase() {

    if (mayaDynamicBuilderReady) {
      return mayaDynamicBuilderReady;
    }

    mayaDynamicBuilderReady = (async () => {

      // ========================================================
      // ADVERTISEMENT BUILDER
      // ========================================================

      await pool.query(`
        CREATE TABLE IF NOT EXISTS maya_ad_configs (
          id BIGSERIAL PRIMARY KEY,
          name TEXT NOT NULL,
          provider TEXT NOT NULL,
          ad_type TEXT NOT NULL,
          enabled BOOLEAN NOT NULL DEFAULT TRUE,
          placement TEXT,
          click_url TEXT,
          after_complete_url TEXT,
          config JSONB NOT NULL DEFAULT '{}'::jsonb,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      // ========================================================
      // EXISTING REWARD VIDEO TABLE EXTENSIONS
      // ========================================================

      await pool.query(`
        ALTER TABLE maya_videos
          ADD COLUMN IF NOT EXISTS category TEXT,
          ADD COLUMN IF NOT EXISTS menu_key TEXT,
          ADD COLUMN IF NOT EXISTS page_key TEXT,
          ADD COLUMN IF NOT EXISTS platform TEXT
            NOT NULL DEFAULT 'all',
          ADD COLUMN IF NOT EXISTS unlock_ads INTEGER
            NOT NULL DEFAULT 3,
          ADD COLUMN IF NOT EXISTS access_minutes INTEGER
            NOT NULL DEFAULT 10,
          ADD COLUMN IF NOT EXISTS ad_ids JSONB
            NOT NULL DEFAULT '[]'::jsonb,
          ADD COLUMN IF NOT EXISTS settings JSONB
            NOT NULL DEFAULT '{}'::jsonb
      `);

      // ========================================================
      // PAGE BUILDER
      // ========================================================

      await pool.query(`
        CREATE TABLE IF NOT EXISTS maya_pages (
          id BIGSERIAL PRIMARY KEY,
          page_key TEXT UNIQUE NOT NULL,
          name TEXT NOT NULL,
          parent_menu TEXT,
          route TEXT,
          icon TEXT,
          platform TEXT NOT NULL DEFAULT 'all',
          enabled BOOLEAN NOT NULL DEFAULT TRUE,
          blocks JSONB NOT NULL DEFAULT '[]'::jsonb,
          settings JSONB NOT NULL DEFAULT '{}'::jsonb,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      // ========================================================
      // MENU BUILDER
      // ========================================================

      await pool.query(`
        CREATE TABLE IF NOT EXISTS maya_menus (
          id BIGSERIAL PRIMARY KEY,
          menu_key TEXT UNIQUE NOT NULL,
          name TEXT NOT NULL,
          parent_key TEXT,
          icon TEXT,
          route TEXT,
          position INTEGER NOT NULL DEFAULT 0,
          platform TEXT NOT NULL DEFAULT 'all',
          enabled BOOLEAN NOT NULL DEFAULT TRUE,
          settings JSONB NOT NULL DEFAULT '{}'::jsonb,
          created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      // ========================================================
      // FRONTEND CONFIGURATION
      // ========================================================

      await pool.query(`
        CREATE TABLE IF NOT EXISTS maya_frontend_config (
          key TEXT PRIMARY KEY,
          value JSONB NOT NULL DEFAULT '{}'::jsonb,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
      `);

      // ========================================================
      // DEFAULT CONFIGURATION
      // ========================================================

      await pool.query(`
        INSERT INTO maya_frontend_config(key, value)
        VALUES
          (
            'providers',
            '{"monetag":true,"adsgram":false,"adsterra":true,"adbluemedia":true,"affmine":true}'::jsonb
          ),
          (
            'app',
            '{"name":"Maya","reference":"DDR V18"}'::jsonb
          )
        ON CONFLICT(key) DO NOTHING
      `);

      console.log(
        "Maya Dynamic Builder database ready"
      );

    })().catch(error => {

      mayaDynamicBuilderReady = null;

      throw error;
    });

    return mayaDynamicBuilderReady;
  }

  // ============================================================
  // ADMIN AUTHENTICATION
  // ============================================================

  function mayaDynamicBuilderAuth(req, res, next) {

    const token = String(
      req.headers.authorization || ""
    )
      .replace(/^Bearer\s+/i, "")
      .trim();

    const staff = verifyMayaStaffToken(
      token,
      jwtSecret
    );

    if (!staff) {

      return res.status(401).json({
        ok: false,
        error: "Staff authentication required"
      });

    }

    req.mayaStaff = staff;

    next();
  }

  function mayaBuilderJson(
    value,
    fallback = {}
  ) {

    return (
      value === undefined ||
      value === null
    )
      ? fallback
      : value;
  }

  // ============================================================
  // PROVIDER SCHEMAS
  // ============================================================

  const MAYA_PROVIDER_SCHEMAS = {

    monetag: {
      label: "Monetag",

      supportedTypes: [
        "rewarded_interstitial",
        "rewarded_popup",
        "interstitial",
        "banner",
        "direct_link"
      ],

      fields: [
        "zone_id",
        "sdk_url",
        "sdk_data_attributes",
        "rewarded_call",
        "ymid",
        "request_var",
        "click_url",
        "after_complete_url"
      ]
    },

    adsgram: {
      label: "Adsgram",

      supportedTypes: [
        "rewarded",
        "interstitial",
        "banner"
      ],

      fields: [
        "block_id",
        "sdk_url",
        "init_code",
        "show_code",
        "reward_callback",
        "click_url",
        "after_complete_url"
      ],

      status: "planned"
    },

    adsterra: {
      label: "Adsterra",

      supportedTypes: [
        "banner",
        "social_bar",
        "popunder",
        "native",
        "direct_link"
      ],

      fields: [
        "publisher_id",
        "placement_id",
        "script_code",
        "iframe_code",
        "click_url",
        "after_complete_url"
      ]
    },

    adbluemedia: {
      label: "Adbluemedia",

      supportedTypes: [
        "banner",
        "pop",
        "direct_link",
        "custom"
      ],

      fields: [
        "zone_id",
        "publisher_id",
        "script_code",
        "iframe_code",
        "click_url",
        "after_complete_url"
      ]
    },

    affmine: {
      label: "Affmine",

      supportedTypes: [
        "banner",
        "native",
        "direct_link",
        "custom"
      ],

      fields: [
        "placement_id",
        "publisher_id",
        "script_code",
        "iframe_code",
        "click_url",
        "after_complete_url"
      ]
    },

    custom: {
      label: "Custom",

      supportedTypes: [
        "custom"
      ],

      fields: [
        "script_code",
        "iframe_code",
        "click_url",
        "after_complete_url"
      ]
    }

  };

  // ============================================================
  // PROVIDER SCHEMA API
  // ============================================================

  app.get(
    "/api/maya/builder/provider-schema",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        res.json({
          ok: true,
          schemas: MAYA_PROVIDER_SCHEMAS
        });

      } catch (error) {

        console.error(
          "Maya provider schema error:",
          error
        );

        res.status(500).json({
          ok: false,
          error: "Could not load provider schema"
        });

      }

    }
  );

  // ============================================================
  // LIST ADS
  // ============================================================

  app.get(
    "/api/maya/builder/ads",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const r = await pool.query(`
          SELECT *
          FROM maya_ad_configs
          ORDER BY id DESC
        `);

        res.json({
          ok: true,
          ads: r.rows
        });

      } catch (error) {

        console.error(
          "Maya builder ads list error:",
          error
        );

        res.status(500).json({
          ok: false,
          error: "Could not load ads"
        });

      }

    }
  );

  // ============================================================
  // CREATE AD
  // ============================================================

  app.post(
    "/api/maya/builder/ads",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const b = req.body || {};

        if (
          !b.name ||
          !b.provider ||
          !b.ad_type
        ) {

          return res.status(400).json({
            ok: false,
            error:
              "name, provider and ad_type are required"
          });

        }

        const r = await pool.query(`
          INSERT INTO maya_ad_configs
            (
              name,
              provider,
              ad_type,
              enabled,
              placement,
              click_url,
              after_complete_url,
              config
            )
          VALUES
            (
              $1,
              $2,
              $3,
              $4,
              $5,
              $6,
              $7,
              $8
            )
          RETURNING *
        `, [

          String(b.name).trim(),

          String(b.provider)
            .trim()
            .toLowerCase(),

          String(b.ad_type)
            .trim()
            .toLowerCase(),

          b.enabled !== false,

          b.placement || null,

          b.click_url || null,

          b.after_complete_url || null,

          JSON.stringify(
            mayaBuilderJson(
              b.config,
              {}
            )
          )

        ]);

        res.status(201).json({
          ok: true,
          ad: r.rows[0]
        });

      } catch (error) {

        console.error(
          "Maya builder ad create error:",
          error
        );

        res.status(500).json({
          ok: false,
          error:
            "Could not create advertisement"
        });

      }

    }
  );

  // ============================================================
  // UPDATE AD
  // ============================================================

  app.patch(
    "/api/maya/builder/ads/:id",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const b = req.body || {};

        const r = await pool.query(`
          UPDATE maya_ad_configs
          SET
            name=COALESCE($1,name),
            provider=COALESCE($2,provider),
            ad_type=COALESCE($3,ad_type),
            enabled=COALESCE($4,enabled),
            placement=COALESCE($5,placement),
            click_url=COALESCE($6,click_url),
            after_complete_url=COALESCE($7,after_complete_url),
            config=COALESCE($8,config),
            updated_at=NOW()
          WHERE id=$9
          RETURNING *
        `, [

          b.name ?? null,

          b.provider
            ? String(b.provider)
                .trim()
                .toLowerCase()
            : null,

          b.ad_type
            ? String(b.ad_type)
                .trim()
                .toLowerCase()
            : null,

          typeof b.enabled === "boolean"
            ? b.enabled
            : null,

          b.placement ?? null,

          b.click_url ?? null,

          b.after_complete_url ?? null,

          b.config !== undefined
            ? JSON.stringify(b.config)
            : null,

          Number(req.params.id)

        ]);

        if (!r.rows.length) {

          return res.status(404).json({
            ok: false,
            error: "Advertisement not found"
          });

        }

        res.json({
          ok: true,
          ad: r.rows[0]
        });

      } catch (error) {

        console.error(
          "Maya builder ad update error:",
          error
        );

        res.status(500).json({
          ok: false,
          error:
            "Could not update advertisement"
        });

      }

    }
  );

  // ============================================================
  // DELETE AD
  // ============================================================

  app.delete(
    "/api/maya/builder/ads/:id",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const r = await pool.query(`
          DELETE FROM maya_ad_configs
          WHERE id=$1
          RETURNING id
        `, [
          Number(req.params.id)
        ]);

        if (!r.rows.length) {

          return res.status(404).json({
            ok: false,
            error: "Advertisement not found"
          });

        }

        res.json({
          ok: true
        });

      } catch (error) {

        console.error(
          "Maya builder ad delete error:",
          error
        );

        res.status(500).json({
          ok: false,
          error:
            "Could not delete advertisement"
        });

      }

    }
  );

  // ============================================================
  // LIST VIDEOS
  // ============================================================

  app.get(
    "/api/maya/builder/videos",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const r = await pool.query(`
          SELECT *
          FROM maya_videos
          ORDER BY id DESC
        `);

        res.json({
          ok: true,
          videos: r.rows
        });

      } catch (error) {

        console.error(
          "Maya builder videos list error:",
          error
        );

        res.status(500).json({
          ok: false,
          error:
            "Could not load videos"
        });

      }

    }
  );

  // ============================================================
  // CREATE VIDEO
  // ============================================================

  app.post(
    "/api/maya/builder/videos",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const b = req.body || {};

        if (
          !b.title ||
          !b.video_url
        ) {

          return res.status(400).json({
            ok: false,
            error:
              "title and video_url are required"
          });

        }

        const unlockAds = Math.max(
          0,
          Number(
            b.unlock_ads ??
            b.required_ads ??
            3
          )
        );

        const accessMinutes = Math.max(
          0,
          Number(
            b.access_minutes ??
            10
          )
        );

        const adIds =
          Array.isArray(b.ad_ids)
            ? b.ad_ids
            : [];

        const settings =
          mayaBuilderJson(
            b.settings,
            {}
          );

        const r = await pool.query(`
          INSERT INTO maya_videos
          (
            title,
            video_url,
            thumbnail_url,
            description,
            category,
            menu_key,
            page_key,
            platform,
            unlock_ads,
            access_minutes,
            ad_ids,
            settings
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9,
            $10,
            $11,
            $12
          )
          RETURNING *
        `, [

          String(b.title).trim(),

          String(b.video_url).trim(),

          b.thumbnail_url || null,

          b.description || null,

          b.category || null,

          b.menu_key || null,

          b.page_key || null,

          b.platform || "all",

          unlockAds,

          accessMinutes,

          JSON.stringify(adIds),

          JSON.stringify(settings)

        ]);

        res.status(201).json({
          ok: true,
          video: r.rows[0]
        });

      } catch (error) {

        console.error(
          "Maya builder video create error:",
          error
        );

        res.status(500).json({
          ok: false,
          error:
            "Could not create video"
        });

      }

    }
  );

  // ============================================================
  // UPDATE VIDEO
  // ============================================================

  app.patch(
    "/api/maya/builder/videos/:id",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const b = req.body || {};

        const fields = [];
        const values = [];

        function addField(
          sql,
          value
        ) {

          values.push(value);

          fields.push(
            `${sql}=$${values.length}`
          );

        }

        if (b.title !== undefined) {
          addField(
            "title",
            String(b.title).trim()
          );
        }

        if (b.video_url !== undefined) {
          addField(
            "video_url",
            String(b.video_url).trim()
          );
        }

        if (
          b.thumbnail_url !== undefined
        ) {
          addField(
            "thumbnail_url",
            b.thumbnail_url
          );
        }

        if (
          b.description !== undefined
        ) {
          addField(
            "description",
            b.description
          );
        }

        if (
          b.category !== undefined
        ) {
          addField(
            "category",
            b.category
          );
        }

        if (
          b.menu_key !== undefined
        ) {
          addField(
            "menu_key",
            b.menu_key
          );
        }

        if (
          b.page_key !== undefined
        ) {
          addField(
            "page_key",
            b.page_key
          );
        }

        if (
          b.platform !== undefined
        ) {
          addField(
            "platform",
            b.platform
          );
        }

        if (
          b.unlock_ads !== undefined ||
          b.required_ads !== undefined
        ) {

          addField(
            "unlock_ads",
            Math.max(
              0,
              Number(
                b.unlock_ads ??
                b.required_ads
              )
            )
          );

        }

        if (
          b.access_minutes !== undefined
        ) {

          addField(
            "access_minutes",
            Math.max(
              0,
              Number(
                b.access_minutes
              )
            )
          );

        }

        if (
          b.ad_ids !== undefined
        ) {

          addField(
            "ad_ids",
            JSON.stringify(
              Array.isArray(b.ad_ids)
                ? b.ad_ids
                : []
            )
          );

        }

        if (
          b.settings !== undefined
        ) {

          addField(
            "settings",
            JSON.stringify(
              b.settings || {}
            )
          );

        }

        if (!fields.length) {

          return res.status(400).json({
            ok: false,
            error: "No fields to update"
          });

        }

        values.push(
          Number(req.params.id)
        );

        const r = await pool.query(`
          UPDATE maya_videos
          SET
            ${fields.join(", ")},
            updated_at=NOW()
          WHERE id=$${values.length}
          RETURNING *
        `, values);

        if (!r.rows.length) {

          return res.status(404).json({
            ok: false,
            error: "Video not found"
          });

        }

        res.json({
          ok: true,
          video: r.rows[0]
        });

      } catch (error) {

        console.error(
          "Maya builder video update error:",
          error
        );

        res.status(500).json({
          ok: false,
          error:
            "Could not update video"
        });

      }

    }
  );

  // ============================================================
  // DELETE VIDEO
  // ============================================================

  app.delete(
    "/api/maya/builder/videos/:id",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const r = await pool.query(`
          DELETE FROM maya_videos
          WHERE id=$1
          RETURNING id
        `, [
          Number(req.params.id)
        ]);

        if (!r.rows.length) {

          return res.status(404).json({
            ok: false,
            error: "Video not found"
          });

        }

        res.json({
          ok: true
        });

      } catch (error) {

        console.error(
          "Maya builder video delete error:",
          error
        );

        res.status(500).json({
          ok: false,
          error:
            "Could not delete video"
        });

      }

    }
  );

  // ============================================================
  // PAGE BUILDER - LIST
  // ============================================================

  app.get(
    "/api/maya/builder/pages",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const r = await pool.query(`
          SELECT *
          FROM maya_pages
          ORDER BY id DESC
        `);

        res.json({
          ok: true,
          pages: r.rows
        });

      } catch (error) {

        console.error(
          "Maya builder pages list error:",
          error
        );

        res.status(500).json({
          ok: false,
          error:
            "Could not load pages"
        });

      }

    }
  );

  // ============================================================
  // PAGE BUILDER - CREATE
  // ============================================================

  app.post(
    "/api/maya/builder/pages",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const b = req.body || {};

        if (
          !b.page_key ||
          !b.name
        ) {

          return res.status(400).json({
            ok: false,
            error:
              "page_key and name are required"
          });

        }

        const r = await pool.query(`
          INSERT INTO maya_pages
          (
            page_key,
            name,
            parent_menu,
            route,
            icon,
            platform,
            enabled,
            blocks,
            settings
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9
          )
          RETURNING *
        `, [

          String(
            b.page_key
          ).trim(),

          String(
            b.name
          ).trim(),

          b.parent_menu || null,

          b.route || null,

          b.icon || null,

          b.platform || "all",

          b.enabled !== false,

          JSON.stringify(
            Array.isArray(b.blocks)
              ? b.blocks
              : []
          ),

          JSON.stringify(
            mayaBuilderJson(
              b.settings,
              {}
            )
          )

        ]);

        res.status(201).json({
          ok: true,
          page: r.rows[0]
        });

      } catch (error) {

        console.error(
          "Maya builder page create error:",
          error
        );

        res.status(500).json({
          ok: false,
          error:
            "Could not create page"
        });

      }

    }
  );

  // ============================================================
  // PAGE BUILDER - UPDATE
  // ============================================================

  app.patch(
    "/api/maya/builder/pages/:id",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const b = req.body || {};

        const r = await pool.query(`
          UPDATE maya_pages
          SET
            page_key=COALESCE($1,page_key),
            name=COALESCE($2,name),
            parent_menu=COALESCE($3,parent_menu),
            route=COALESCE($4,route),
            icon=COALESCE($5,icon),
            platform=COALESCE($6,platform),
            enabled=COALESCE($7,enabled),
            blocks=COALESCE($8,blocks),
            settings=COALESCE($9,settings),
            updated_at=NOW()
          WHERE id=$10
          RETURNING *
        `, [

          b.page_key ?? null,

          b.name ?? null,

          b.parent_menu ?? null,

          b.route ?? null,

          b.icon ?? null,

          b.platform ?? null,

          typeof b.enabled === "boolean"
            ? b.enabled
            : null,

          b.blocks !== undefined
            ? JSON.stringify(
                Array.isArray(b.blocks)
                  ? b.blocks
                  : []
              )
            : null,

          b.settings !== undefined
            ? JSON.stringify(
                b.settings || {}
              )
            : null,

          Number(req.params.id)

        ]);

        if (!r.rows.length) {

          return res.status(404).json({
            ok: false,
            error: "Page not found"
          });

        }

        res.json({
          ok: true,
          page: r.rows[0]
        });

      } catch (error) {

        console.error(
          "Maya builder page update error:",
          error
        );

        res.status(500).json({
          ok: false,
          error:
            "Could not update page"
        });

      }

    }
  );

  // ============================================================
  // PAGE BUILDER - DELETE
  // ============================================================

  app.delete(
    "/api/maya/builder/pages/:id",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const r = await pool.query(`
          DELETE FROM maya_pages
          WHERE id=$1
          RETURNING id
        `, [
          Number(req.params.id)
        ]);

        if (!r.rows.length) {

          return res.status(404).json({
            ok: false,
            error: "Page not found"
          });

        }

        res.json({
          ok: true
        });

      } catch (error) {

        console.error(
          "Maya builder page delete error:",
          error
        );

        res.status(500).json({
          ok: false,
          error:
            "Could not delete page"
        });

      }

    }
  );

  // ============================================================
  // MENU BUILDER - LIST
  // ============================================================

  app.get(
    "/api/maya/builder/menus",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const r = await pool.query(`
          SELECT *
          FROM maya_menus
          ORDER BY position ASC, id ASC
        `);

        res.json({
          ok: true,
          menus: r.rows
        });

      } catch (error) {

        console.error(
          "Maya builder menus list error:",
          error
        );

        res.status(500).json({
          ok: false,
          error:
            "Could not load menus"
        });

      }

    }
  );

  // ============================================================
  // MENU BUILDER - CREATE
  // ============================================================

  app.post(
    "/api/maya/builder/menus",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const b = req.body || {};

        if (
          !b.menu_key ||
          !b.name
        ) {

          return res.status(400).json({
            ok: false,
            error:
              "menu_key and name are required"
          });

        }

        const r = await pool.query(`
          INSERT INTO maya_menus
          (
            menu_key,
            name,
            parent_key,
            icon,
            route,
            position,
            platform,
            enabled,
            settings
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8,
            $9
          )
          RETURNING *
        `, [

          String(
            b.menu_key
          ).trim(),

          String(
            b.name
          ).trim(),

          b.parent_key || null,

          b.icon || null,

          b.route || null,

          Number(
            b.position || 0
          ),

          b.platform || "all",

          b.enabled !== false,

          JSON.stringify(
            mayaBuilderJson(
              b.settings,
              {}
            )
          )

        ]);

        res.status(201).json({
          ok: true,
          menu: r.rows[0]
        });

      } catch (error) {

        console.error(
          "Maya builder menu create error:",
          error
        );

        res.status(500).json({
          ok: false,
          error:
            "Could not create menu"
        });

      }

    }
  );

  // ============================================================
  // MENU BUILDER - UPDATE
  // ============================================================

  app.patch(
    "/api/maya/builder/menus/:id",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const b = req.body || {};

        const r = await pool.query(`
          UPDATE maya_menus
          SET
            menu_key=COALESCE($1,menu_key),
            name=COALESCE($2,name),
            parent_key=COALESCE($3,parent_key),
            icon=COALESCE($4,icon),
            route=COALESCE($5,route),
            position=COALESCE($6,position),
            platform=COALESCE($7,platform),
            enabled=COALESCE($8,enabled),
            settings=COALESCE($9,settings),
            updated_at=NOW()
          WHERE id=$10
          RETURNING *
        `, [

          b.menu_key ?? null,

          b.name ?? null,

          b.parent_key ?? null,

          b.icon ?? null,

          b.route ?? null,

          b.position !== undefined
            ? Number(b.position)
            : null,

          b.platform ?? null,

          typeof b.enabled === "boolean"
            ? b.enabled
            : null,

          b.settings !== undefined
            ? JSON.stringify(
                b.settings || {}
              )
            : null,

          Number(req.params.id)

        ]);

        if (!r.rows.length) {

          return res.status(404).json({
            ok: false,
            error: "Menu not found"
          });

        }

        res.json({
          ok: true,
          menu: r.rows[0]
        });

      } catch (error) {

        console.error(
          "Maya builder menu update error:",
          error
        );

        res.status(500).json({
          ok: false,
          error:
            "Could not update menu"
        });

      }

    }
  );

  // ============================================================
  // MENU BUILDER - DELETE
  // ============================================================

  app.delete(
    "/api/maya/builder/menus/:id",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const r = await pool.query(`
          DELETE FROM maya_menus
          WHERE id=$1
          RETURNING id
        `, [
          Number(req.params.id)
        ]);

        if (!r.rows.length) {

          return res.status(404).json({
            ok: false,
            error: "Menu not found"
          });

        }

        res.json({
          ok: true
        });

      } catch (error) {

        console.error(
          "Maya builder menu delete error:",
          error
        );

        res.status(500).json({
          ok: false,
          error:
            "Could not delete menu"
        });

      }

    }
  );

  // ============================================================
  // FRONTEND CONFIG UPDATE
  // ============================================================

  app.put(
    "/api/maya/builder/frontend-config/:key",
    mayaDynamicBuilderAuth,
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const key = String(
          req.params.key
        ).trim();

        if (!key) {

          return res.status(400).json({
            ok: false,
            error: "Config key required"
          });

        }

        const value =
          mayaBuilderJson(
            req.body?.value,
            {}
          );

        const r = await pool.query(`
          INSERT INTO maya_frontend_config
          (
            key,
            value,
            updated_at
          )
          VALUES
          (
            $1,
            $2,
            NOW()
          )
          ON CONFLICT(key)
          DO UPDATE SET
            value=EXCLUDED.value,
            updated_at=NOW()
          RETURNING *
        `, [

          key,

          JSON.stringify(value)

        ]);

        res.json({
          ok: true,
          config: r.rows[0]
        });

      } catch (error) {

        console.error(
          "Maya frontend config update error:",
          error
        );

        res.status(500).json({
          ok: false,
          error:
            "Could not update frontend configuration"
        });

      }

    }
  );

  // ============================================================
  // PUBLIC FRONTEND CONFIG
  // ============================================================

  app.get(
    "/api/maya/public/config",
    async (req, res) => {

      try {

        await ensureMayaDynamicBuilderDatabase();

        const [
          menus,
          pages,
          videos,
          ads,
          config
        ] = await Promise.all([

          pool.query(`
            SELECT *
            FROM maya_menus
            WHERE enabled=TRUE
            ORDER BY position ASC, id ASC
          `),

          pool.query(`
            SELECT *
            FROM maya_pages
            WHERE enabled=TRUE
            ORDER BY id ASC
          `),

          pool.query(`
            SELECT *
            FROM maya_videos
            WHERE COALESCE(enabled, TRUE)=TRUE
            ORDER BY id DESC
          `),

          pool.query(`
            SELECT *
            FROM maya_ad_configs
            WHERE enabled=TRUE
            ORDER BY id DESC
          `),

          pool.query(`
            SELECT key,value
            FROM maya_frontend_config
            ORDER BY key ASC
          `)

        ]);

        const frontendConfig = {};

        for (
          const row of config.rows
        ) {

          frontendConfig[row.key] =
            row.value;

        }

        res.json({
          ok: true,

          menus: menus.rows,

          pages: pages.rows,

          videos: videos.rows,

          ads: ads.rows,

          config: frontendConfig
        });

      } catch (error) {

        console.error(
          "Maya public config error:",
          error
        );

        res.status(500).json({
          ok: false,
          error:
            "Could not load public configuration"
        });

      }

    }
  );

  // ============================================================
  // RETURN MODULE API
  // ============================================================

  return {
    ensureMayaDynamicBuilderDatabase,
    providerSchemas: MAYA_PROVIDER_SCHEMAS
  };
}

// ============================================================
// EXPORTS
// ============================================================

module.exports = {
  registerMayaDynamicBuilder
};

module.exports.registerMayaDynamicBuilder =
  registerMayaDynamicBuilder;

module.exports.default =
  registerMayaDynamicBuilder;