const crypto = require('crypto');

function randomToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString('hex');
}

function registerMayaRewardSystem({ app, pool, botToken, authenticateRequest }) {
  if (!app || !pool) throw new Error('Maya Reward System requires app and pool');

  async function ensureRewardDatabase() {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS maya_videos (
        id BIGSERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        description TEXT,
        telegram_file_id TEXT,
        video_url TEXT,
        thumbnail_url TEXT,
        required_ads INTEGER NOT NULL DEFAULT 3,
        delivery_ttl_seconds INTEGER NOT NULL DEFAULT 600,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CHECK (required_ads BETWEEN 1 AND 20),
        CHECK (delivery_ttl_seconds BETWEEN 60 AND 172800)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS maya_unlock_sessions (
        id BIGSERIAL PRIMARY KEY,
        session_token TEXT NOT NULL UNIQUE,
        user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        video_id BIGINT NOT NULL REFERENCES maya_videos(id) ON DELETE CASCADE,
        required_ads INTEGER NOT NULL,
        verified_ads INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'watching',
        expires_at TIMESTAMPTZ NOT NULL,
        delivered_at TIMESTAMPTZ,
        delivery_message_id BIGINT,
        delivery_expires_at TIMESTAMPTZ,
        revoked_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS maya_ad_events (
        id BIGSERIAL PRIMARY KEY,
        provider TEXT NOT NULL,
        event_id TEXT NOT NULL,
        ymid TEXT,
        user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
        unlock_session_id BIGINT REFERENCES maya_unlock_sessions(id) ON DELETE SET NULL,
        event_type TEXT NOT NULL,
        reward_value NUMERIC(12,2) NOT NULL DEFAULT 0,
        raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(provider, event_id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS maya_reward_tasks (
        id BIGSERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        provider TEXT NOT NULL DEFAULT 'monetag',
        zone_id TEXT,
        ad_type TEXT NOT NULL DEFAULT 'rewarded_interstitial',
        reward_amount NUMERIC(12,2) NOT NULL DEFAULT 1,
        daily_limit INTEGER NOT NULL DEFAULT 20,
        cooldown_seconds INTEGER NOT NULL DEFAULT 30,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS maya_earning_sessions (
        id BIGSERIAL PRIMARY KEY,
        session_token TEXT NOT NULL UNIQUE,
        user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        task_id BIGINT NOT NULL REFERENCES maya_reward_tasks(id) ON DELETE CASCADE,
        ymid TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'watching',
        expires_at TIMESTAMPTZ NOT NULL,
        completed_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS maya_reward_ledger (
        id BIGSERIAL PRIMARY KEY,
        user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        source TEXT NOT NULL,
        source_event_id TEXT NOT NULL,
        amount NUMERIC(12,2) NOT NULL,
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(source, source_event_id)
      )
    `);

    await pool.query(`ALTER TABLE maya_unlock_sessions ADD COLUMN IF NOT EXISTS ymid TEXT`);
    await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS maya_unlock_ymid_unique ON maya_unlock_sessions(ymid) WHERE ymid IS NOT NULL AND ymid <> ''`);
    await pool.query(`CREATE INDEX IF NOT EXISTS maya_unlock_expiry_idx ON maya_unlock_sessions(delivery_expires_at) WHERE delivery_expires_at IS NOT NULL`);
    await pool.query(`CREATE INDEX IF NOT EXISTS maya_earning_user_idx ON maya_earning_sessions(user_id, created_at DESC)`);
  }

  async function telegram(method, body) {
    if (!botToken) throw new Error('TELEGRAM_BOT_TOKEN is not configured');
    const r = await fetch(`https://api.telegram.org/bot${botToken}/${method}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok || !data.ok) throw new Error(data.description || `Telegram ${method} failed`);
    return data.result;
  }

  async function deliverVideo(session) {
    const video = (await pool.query(`SELECT * FROM maya_videos WHERE id=$1 AND enabled=true`, [session.video_id])).rows[0];
    if (!video) throw new Error('Video not found or disabled');
    const user = (await pool.query(`SELECT id,telegram_id,username FROM users WHERE id=$1`, [session.user_id])).rows[0];
    if (!user || !user.telegram_id) throw new Error('User Telegram account is not linked');
    if (!video.telegram_file_id && !video.video_url) throw new Error('Video has no Telegram file ID or video URL');

    const videoInput = video.telegram_file_id || video.video_url;
    const result = await telegram('sendVideo', {
      chat_id: String(user.telegram_id),
      video: videoInput,
      caption: `馃幀 ${video.title}\n\n鈴憋笍 唳忇 唳唳∴唳撪唳� ${video.delivery_ttl_seconds} 唳膏唳曕唳ㄠ唳� 唳Π唰� 唳膏唳唳傕唰嵿Π唳苦唳唳 唳唳涏 唳唳啷,
      supports_streaming: true
    });

    const expires = new Date(Date.now() + Number(video.delivery_ttl_seconds) * 1000);
    await pool.query(`
      UPDATE maya_unlock_sessions
      SET status='delivered', delivered_at=NOW(), delivery_message_id=$1,
          delivery_expires_at=$2, updated_at=NOW()
      WHERE id=$3
    `, [result.message_id, expires, session.id]);

    return { message_id: result.message_id, expires_at: expires };
  }

  // -------------------------
  // ADMIN: video delivery + earning task controls
  // -------------------------
  function adminToken(req) {
    return String(req.headers.authorization || '').replace(/^Bearer\s+/i,'').trim();
  }
  function adminSession(req) {
    try {
      const parts = adminToken(req).split('.');
      if(parts.length !== 3) return null;
      const [h,payload,sig] = parts;
      const unsigned = `${h}.${payload}`;
      const expected = crypto.createHmac('sha256', process.env.JWT_SECRET || '').update(unsigned).digest('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
      const a=Buffer.from(sig), b=Buffer.from(expected);
      if(!a.length || a.length!==b.length || !crypto.timingSafeEqual(a,b)) return null;
      const d=JSON.parse(Buffer.from(payload,'base64url').toString('utf8'));
      if(d.staff!==true || !d.staffId || !d.exp || Math.floor(Date.now()/1000)>=d.exp) return null;
      return d;
    } catch { return null; }
  }
  function adminOnly(req,res,next){
    if(!adminSession(req)) return res.status(401).json({ok:false,error:'Staff authentication required'});
    next();
  }

  app.get('/api/admin/control/reward/videos', adminOnly, async (req,res)=>{
    try{const r=await pool.query(`SELECT * FROM maya_videos ORDER BY id DESC`);res.json({ok:true,videos:r.rows});}
    catch(e){res.status(500).json({ok:false,error:'Could not load reward videos'});}
  });
  app.post('/api/admin/control/reward/videos', adminOnly, async (req,res)=>{
    try{
      const r=await pool.query(`INSERT INTO maya_videos(title,description,telegram_file_id,video_url,thumbnail_url,required_ads,delivery_ttl_seconds,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[
        String(req.body.title||'Untitled Video'), req.body.description||null, req.body.telegram_file_id||null, req.body.video_url||null, req.body.thumbnail_url||null,
        Math.max(1,Math.min(20,Number(req.body.required_ads||3))), Math.max(60,Math.min(172800,Number(req.body.delivery_ttl_seconds||600))), req.body.enabled!==false
      ]);
      res.status(201).json({ok:true,video:r.rows[0]});
    }catch(e){res.status(500).json({ok:false,error:'Could not create reward video'});}
  });
  app.patch('/api/admin/control/reward/videos/:id', adminOnly, async (req,res)=>{
    try{
      const r=await pool.query(`UPDATE maya_videos SET title=COALESCE($1,title),description=COALESCE($2,description),telegram_file_id=COALESCE($3,telegram_file_id),video_url=COALESCE($4,video_url),thumbnail_url=COALESCE($5,thumbnail_url),required_ads=COALESCE($6,required_ads),delivery_ttl_seconds=COALESCE($7,delivery_ttl_seconds),enabled=COALESCE($8,enabled),updated_at=NOW() WHERE id=$9 RETURNING *`,[
        req.body.title||null,req.body.description||null,req.body.telegram_file_id||null,req.body.video_url||null,req.body.thumbnail_url||null,
        req.body.required_ads==null?null:Number(req.body.required_ads),req.body.delivery_ttl_seconds==null?null:Number(req.body.delivery_ttl_seconds),req.body.enabled===undefined?null:!!req.body.enabled,Number(req.params.id)
      ]);
      if(!r.rows[0])return res.status(404).json({ok:false,error:'Reward video not found'});
      res.json({ok:true,video:r.rows[0]});
    }catch(e){res.status(500).json({ok:false,error:'Could not update reward video'});}
  });
  app.delete('/api/admin/control/reward/videos/:id', adminOnly, async (req,res)=>{
    try{const r=await pool.query(`DELETE FROM maya_videos WHERE id=$1 RETURNING id`,[Number(req.params.id)]);if(!r.rows[0])return res.status(404).json({ok:false,error:'Reward video not found'});res.json({ok:true});}
    catch(e){res.status(500).json({ok:false,error:'Could not delete reward video'});}
  });

  app.get('/api/admin/control/reward/tasks', adminOnly, async (req,res)=>{
    try{const r=await pool.query(`SELECT * FROM maya_reward_tasks ORDER BY id DESC`);res.json({ok:true,tasks:r.rows});}
    catch(e){res.status(500).json({ok:false,error:'Could not load earning tasks'});}
  });
  app.post('/api/admin/control/reward/tasks', adminOnly, async (req,res)=>{
    try{
      const r=await pool.query(`INSERT INTO maya_reward_tasks(name,provider,zone_id,ad_type,reward_amount,daily_limit,cooldown_seconds,enabled) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,[
        String(req.body.name||'Watch Ad & Earn'),String(req.body.provider||'monetag'),req.body.zone_id||null,String(req.body.ad_type||'rewarded_interstitial'),Math.max(0,Number(req.body.reward_amount||1)),Math.max(1,Number(req.body.daily_limit||20)),Math.max(0,Number(req.body.cooldown_seconds||30)),req.body.enabled!==false
      ]);res.status(201).json({ok:true,task:r.rows[0]});
    }catch(e){res.status(500).json({ok:false,error:'Could not create earning task'});}
  });
  app.patch('/api/admin/control/reward/tasks/:id', adminOnly, async (req,res)=>{
    try{const r=await pool.query(`UPDATE maya_reward_tasks SET name=COALESCE($1,name),provider=COALESCE($2,provider),zone_id=COALESCE($3,zone_id),ad_type=COALESCE($4,ad_type),reward_amount=COALESCE($5,reward_amount),daily_limit=COALESCE($6,daily_limit),cooldown_seconds=COALESCE($7,cooldown_seconds),enabled=COALESCE($8,enabled),updated_at=NOW() WHERE id=$9 RETURNING *`,[
      req.body.name||null,req.body.provider||null,req.body.zone_id||null,req.body.ad_type||null,req.body.reward_amount==null?null:Number(req.body.reward_amount),req.body.daily_limit==null?null:Number(req.body.daily_limit),req.body.cooldown_seconds==null?null:Number(req.body.cooldown_seconds),req.body.enabled===undefined?null:!!req.body.enabled,Number(req.params.id)
    ]);if(!r.rows[0])return res.status(404).json({ok:false,error:'Earning task not found'});res.json({ok:true,task:r.rows[0]});}
    catch(e){res.status(500).json({ok:false,error:'Could not update earning task'});}
  });
  app.delete('/api/admin/control/reward/tasks/:id', adminOnly, async (req,res)=>{
    try{const r=await pool.query(`DELETE FROM maya_reward_tasks WHERE id=$1 RETURNING id`,[Number(req.params.id)]);if(!r.rows[0])return res.status(404).json({ok:false,error:'Earning task not found'});res.json({ok:true});}
    catch(e){res.status(500).json({ok:false,error:'Could not delete earning task'});}
  });

  // Authenticated video list for the Mini App.
  app.get('/api/reward/videos', authenticateRequest, async (req, res) => {
    try {
      const r = await pool.query(`SELECT id,title,description,thumbnail_url,required_ads,delivery_ttl_seconds FROM maya_videos WHERE enabled=true ORDER BY id DESC`);
      res.json({ ok:true, videos:r.rows });
    } catch (e) {
      res.status(500).json({ ok:false, error:'Could not load reward videos' });
    }
  });

  // Start the unlock flow. This does NOT trust a browser-side ad counter.
  app.post('/api/reward/video/session', authenticateRequest, async (req, res) => {
    try {
      const userId = req.user.id;
      const videoId = Number(req.body.video_id);
      if (!Number.isInteger(videoId) || videoId <= 0) return res.status(400).json({ ok:false, error:'Valid video_id is required' });

      const video = (await pool.query(`SELECT id,title,required_ads,enabled FROM maya_videos WHERE id=$1`, [videoId])).rows[0];
      if (!video || !video.enabled) return res.status(404).json({ ok:false, error:'Video not found' });

      const token = randomToken();
      const ymid = `maya-unlock-${userId}-${Date.now()}-${randomToken(8)}`;
      const expires = new Date(Date.now() + 20 * 60 * 1000);
      const r = await pool.query(`
        INSERT INTO maya_unlock_sessions(session_token,user_id,video_id,required_ads,expires_at)
        VALUES($1,$2,$3,$4,$5) RETURNING id,session_token,video_id,required_ads,verified_ads,status,expires_at
      `, [token,userId,videoId,video.required_ads,expires]);
      res.status(201).json({ok:true,session:r.rows[0]});
    } catch (e) {
      console.error('Maya video session error:', e);
      res.status(500).json({ok:false,error:'Could not start unlock session'});
    }
  });

  app.get('/api/reward/video/session/:token', authenticateRequest, async (req,res) => {
    try {
      const r = await pool.query(`
        SELECT s.id,s.video_id,s.session_token,s.ymid,s.required_ads,s.verified_ads,s.status,s.expires_at,s.delivered_at,s.delivery_expires_at,
               v.title,v.description,v.thumbnail_url
        FROM maya_unlock_sessions s JOIN maya_videos v ON v.id=s.video_id
        WHERE s.session_token=$1 AND s.user_id=$2 LIMIT 1
      `,[req.params.token,req.user.id]);
      if(!r.rows[0]) return res.status(404).json({ok:false,error:'Unlock session not found'});
      res.json({ok:true,session:r.rows[0]});
    } catch(e){ res.status(500).json({ok:false,error:'Could not load unlock session'}); }
  });

  // Provider postback endpoint. Reward is granted only for valued/completed events.
  // For Monetag, configure the postback to send reward_event_type=valued and a unique event identifier.
  app.get('/api/reward/ad/postback', async (req,res) => {
    try {
      const provider = String(req.query.provider || 'monetag').toLowerCase();
      const eventType = String(req.query.reward_event_type || req.query.event_type || '').toLowerCase();
      const eventId = String(req.query.event_id || req.query.transaction_id || req.query.your_parameter || '').trim();
      const ymid = String(req.query.ymid || '').trim();
      const userId = req.query.user_id ? Number(req.query.user_id) : null;
      const unlockToken = String(req.query.session || req.query.unlock_session || '').trim();

      if (eventType !== 'valued') return res.status(200).send('ignored');
      if (!eventId) return res.status(400).send('missing event_id');

      const existing = await pool.query(`SELECT id FROM maya_ad_events WHERE provider=$1 AND event_id=$2 LIMIT 1`,[provider,eventId]);
      if(existing.rows[0]) return res.status(200).send('duplicate');

      let unlock = null;
      if (unlockToken) {
        unlock = (await pool.query(`SELECT * FROM maya_unlock_sessions WHERE session_token=$1 AND status='watching' LIMIT 1`,[unlockToken])).rows[0] || null;
      } else if (ymid) {
        unlock = (await pool.query(`SELECT * FROM maya_unlock_sessions WHERE (session_token=$1 OR ymid=$1) AND status='watching' LIMIT 1`,[ymid])).rows[0] || null;
      }

      if (unlock && unlock.expires_at > new Date()) {
        await pool.query('BEGIN');
        try {
          await pool.query(`INSERT INTO maya_ad_events(provider,event_id,ymid,user_id,unlock_session_id,event_type) VALUES($1,$2,$3,$4,$5,$6)`,[provider,eventId,ymid,unlock.user_id,unlock.id,eventType]);
          const next = await pool.query(`UPDATE maya_unlock_sessions SET verified_ads=verified_ads+1,updated_at=NOW() WHERE id=$1 AND status='watching' AND verified_ads < required_ads RETURNING *`,[unlock.id]);
          const s=next.rows[0];
          await pool.query('COMMIT');
          if(s && s.verified_ads >= s.required_ads) {
            try { await deliverVideo(s); } catch(deliveryError) {
              console.error('Maya Telegram delivery error:',deliveryError);
              await pool.query(`UPDATE maya_unlock_sessions SET status='delivery_failed',updated_at=NOW() WHERE id=$1`,[s.id]);
            }
          }
        } catch(e){ await pool.query('ROLLBACK'); throw e; }
        return res.status(200).send('accepted');
      }

      // Earning-session lookup by ymid.
      if (ymid) {
        const earn = (await pool.query(`
          SELECT es.*,t.reward_amount,t.name task_name,t.daily_limit
          FROM maya_earning_sessions es JOIN maya_reward_tasks t ON t.id=es.task_id
          WHERE es.ymid=$1 AND es.status='watching' AND es.expires_at>NOW() LIMIT 1
        `,[ymid])).rows[0];
        if(earn) {
          await pool.query('BEGIN');
          try {
            await pool.query(`INSERT INTO maya_ad_events(provider,event_id,ymid,user_id,event_type,reward_value) VALUES($1,$2,$3,$4,$5,$6)`,[provider,eventId,ymid,earn.user_id,eventType,earn.reward_amount]);
            const ledger=await pool.query(`
              INSERT INTO maya_reward_ledger(user_id,source,source_event_id,amount,metadata)
              VALUES($1,'earning_ad',$2,$3,$4) ON CONFLICT(source,source_event_id) DO NOTHING RETURNING id
            `,[earn.user_id,eventId,earn.reward_amount,JSON.stringify({provider,ymid,task_id:earn.task_id})]);
            if(ledger.rows[0]) await pool.query(`UPDATE users SET balance=balance+$1,updated_at=NOW() WHERE id=$2`,[earn.reward_amount,earn.user_id]);
            await pool.query(`UPDATE maya_earning_sessions SET status='completed',completed_at=NOW() WHERE id=$1`,[earn.id]);
            await pool.query('COMMIT');
          } catch(e){await pool.query('ROLLBACK');throw e;}
          return res.status(200).send('rewarded');
        }
      }

      // Keep event auditable even when it doesn't map to an active session.
      await pool.query(`INSERT INTO maya_ad_events(provider,event_id,ymid,user_id,event_type) VALUES($1,$2,$3,$4,$5)`,[provider,eventId,ymid,userId,eventType]);
      res.status(200).send('recorded');
    } catch(e){ console.error('Maya ad postback error:',e); res.status(500).send('error'); }
  });

  // Client only asks the server to create an earning session; it cannot grant itself balance.
  app.post('/api/reward/earning/session', authenticateRequest, async (req,res)=>{
    try{
      const taskId=Number(req.body.task_id);
      const task=(await pool.query(`SELECT * FROM maya_reward_tasks WHERE id=$1 AND enabled=true`,[taskId])).rows[0];
      if(!task)return res.status(404).json({ok:false,error:'Reward task not found'});
      const todayCount=(await pool.query(`SELECT COUNT(*)::int AS n FROM maya_earning_sessions WHERE user_id=$1 AND task_id=$2 AND created_at>=CURRENT_DATE`,[req.user.id,taskId])).rows[0].n;
      if(todayCount>=task.daily_limit)return res.status(429).json({ok:false,error:'Daily earning limit reached'});
      const last=(await pool.query(`SELECT created_at FROM maya_earning_sessions WHERE user_id=$1 AND task_id=$2 ORDER BY id DESC LIMIT 1`,[req.user.id,taskId])).rows[0];
      if(last){const elapsed=(Date.now()-new Date(last.created_at).getTime())/1000;if(elapsed<Number(task.cooldown_seconds||0))return res.status(429).json({ok:false,error:`Please wait ${Math.ceil(Number(task.cooldown_seconds)-elapsed)} seconds before the next earning ad`});}
      const ymid=`maya-earn-${req.user.id}-${Date.now()}-${randomToken(8)}`;
      const token=randomToken();
      const expires=new Date(Date.now()+10*60*1000);
      const r=await pool.query(`INSERT INTO maya_earning_sessions(session_token,user_id,task_id,ymid,expires_at) VALUES($1,$2,$3,$4,$5) RETURNING session_token,ymid,expires_at`,[token,req.user.id,taskId,ymid,expires]);
      res.status(201).json({ok:true,session:r.rows[0],task:{id:task.id,name:task.name,provider:task.provider,zone_id:task.zone_id,ad_type:task.ad_type,reward_amount:task.reward_amount}});
    }catch(e){res.status(500).json({ok:false,error:'Could not start reward ad'});}
  });

  app.get('/api/reward/tasks', async (req,res)=>{
    try{
      const r=await pool.query(`SELECT id,name,provider,zone_id,ad_type,reward_amount,daily_limit,cooldown_seconds FROM maya_reward_tasks WHERE enabled=true ORDER BY id`);
      res.json({ok:true,tasks:r.rows});
    }catch(e){res.status(500).json({ok:false,error:'Could not load reward tasks'});}
  });

  // Safe cleanup: expired unlock sessions are revoked and delivered Telegram messages are deleted when possible.
  async function cleanupExpiredDeliveries(){
    try{
      const rows=await pool.query(`SELECT id,delivery_message_id,user_id FROM maya_unlock_sessions WHERE status='delivered' AND delivery_expires_at<=NOW() AND revoked_at IS NULL LIMIT 100`);
      for(const s of rows.rows){
        const u=(await pool.query(`SELECT telegram_id FROM users WHERE id=$1`,[s.user_id])).rows[0];
        if(u?.telegram_id && s.delivery_message_id){
          try{await telegram('deleteMessage',{chat_id:String(u.telegram_id),message_id:Number(s.delivery_message_id)});}catch(e){console.warn('Maya deleteMessage:',e.message);}
        }
        await pool.query(`UPDATE maya_unlock_sessions SET status='expired',revoked_at=NOW(),updated_at=NOW() WHERE id=$1`,[s.id]);
      }
      await pool.query(`UPDATE maya_unlock_sessions SET status='expired',updated_at=NOW() WHERE status='watching' AND expires_at<=NOW()`);
      await pool.query(`DELETE FROM maya_earning_sessions WHERE status IN ('watching','completed') AND expires_at < NOW()-INTERVAL '1 day'`);
    }catch(e){console.error('Maya reward cleanup error:',e);}
  }
  const timer=setInterval(cleanupExpiredDeliveries,60*1000);
  timer.unref?.();

  return { ensureRewardDatabase, cleanupExpiredDeliveries };
}

module.exports = { registerMayaRewardSystem };
module.exports.registerMayaRewardSystem = registerMayaRewardSystem;
module.exports.default = registerMayaRewardSystem;