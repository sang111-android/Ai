import express from 'express';
import pg from 'pg';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const { Pool } = pg;
const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATABASE_URL = process.env.DATABASE_URL || '';
const ENC_SECRET = process.env.APP_ENCRYPTION_KEY || '';
const configErrors = [];
if (!DATABASE_URL) configErrors.push('DATABASE_URL تنظیم نشده است');
if (ENC_SECRET.length < 32) configErrors.push('APP_ENCRYPTION_KEY باید حداقل ۳۲ کاراکتر باشد');
const pool = DATABASE_URL ? new Pool({ connectionString: DATABASE_URL, ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false }) : null;
const encKey = crypto.createHash('sha256').update(ENC_SECRET || 'temporary-unconfigured-key').digest();
let dbReady = false;
let lastDbError = '';
const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

const attempts = new Map();
app.use('/api', (req, res, next) => {
  const key = req.ip, now = Date.now(), row = attempts.get(key) || { n: 0, reset: now + 60000 };
  if (now > row.reset) { row.n = 0; row.reset = now + 60000; }
  row.n++; attempts.set(key, row);
  if (row.n > 120) return res.status(429).json({ error: 'درخواست بیش از حد؛ کمی صبر کنید.' });
  if (configErrors.length) return res.status(503).json({ error: 'تنظیمات Railway کامل نیست: ' + configErrors.join('، ') });
  if (!dbReady) return res.status(503).json({ error: 'دیتابیس هنوز آماده نیست. چند ثانیه دیگر تلاش کنید.', detail: lastDbError });
  next();
});

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, (e, key) => e ? reject(e) : resolve(`${salt}:${key.toString('hex')}`)));
}
async function verifyPassword(password, stored) {
  const [salt, oldHex] = String(stored).split(':');
  const candidate = await hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(candidate.split(':')[1], 'hex'), Buffer.from(oldHex, 'hex'));
}
function encrypt(text) {
  const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', encKey, iv);
  const body = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return `${iv.toString('base64')}.${cipher.getAuthTag().toString('base64')}.${body.toString('base64')}`;
}
function decrypt(payload) {
  const [iv, tag, body] = payload.split('.').map(x => Buffer.from(x, 'base64'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', encKey, iv); decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
}
function cookies(req) { return Object.fromEntries((req.headers.cookie || '').split(';').filter(Boolean).map(v => { const i=v.indexOf('='); return [v.slice(0,i).trim(), decodeURIComponent(v.slice(i+1))]; })); }
function cleanEmail(v) { return String(v || '').trim().toLowerCase(); }
function safeText(v, max=200) { return String(v || '').trim().slice(0,max); }
function randomCode() { return crypto.randomBytes(9).toString('base64url').toUpperCase(); }
function hasAllowedEmailDomain(email) { return /@(gmail\.com|outlook\.com|in2\.kdns\.fr)$/i.test(email); }
function modelImageData(value) {
  if (value === undefined || value === null || value === '') return null;
  const match=String(value).match(/^data:image\/(png|jpeg);base64,([A-Za-z0-9+/=]+)$/);
  if (!match) throw new Error('تصویر مدل باید PNG یا JPEG باشد.');
  const raw=Buffer.from(match[2],'base64');
  if (raw.length > 1024*1024) throw new Error('حجم تصویر مدل نباید بیشتر از ۱ مگابایت باشد.');
  let width=0,height=0;
  if (match[1] === 'png' && raw.length >= 24 && raw.subarray(1,4).toString() === 'PNG') { width=raw.readUInt32BE(16); height=raw.readUInt32BE(20); }
  if (match[1] === 'jpeg' && raw[0] === 0xff && raw[1] === 0xd8) {
    let i=2; while (i < raw.length) { if(raw[i] !== 0xff) {i++; continue;} const marker=raw[i+1], len=raw.readUInt16BE(i+2); if([0xc0,0xc1,0xc2].includes(marker)) { height=raw.readUInt16BE(i+5); width=raw.readUInt16BE(i+7); break; } i += 2 + len; }
  }
  if (width !== 512 || height !== 512) throw new Error('ابعاد تصویر مدل باید دقیقاً ۵۱۲×۵۱۲ پیکسل باشد.');
  return value;
}

async function auth(req, res, next) {
  try {
    const token = cookies(req).sid;
    if (!token) return res.status(401).json({ error: 'ابتدا وارد شوید.' });
    const q = await pool.query(`SELECT u.id,u.email,u.name,u.role,u.plan_id,p.name plan_name,p.slug plan_slug
      FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN plans p ON p.id=u.plan_id
      WHERE s.token_hash=$1 AND s.expires_at>now()`, [crypto.createHash('sha256').update(token).digest('hex')]);
    if (!q.rows[0]) return res.status(401).json({ error: 'نشست منقضی شده است.' });
    req.user=q.rows[0]; next();
  } catch(e) { next(e); }
}
function admin(req,res,next) { if(req.user?.role !== 'admin') return res.status(403).json({error:'دسترسی ادمین لازم است.'}); next(); }
async function createSession(res, userId) {
  const token=crypto.randomBytes(32).toString('base64url');
  await pool.query('INSERT INTO sessions(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval \'30 days\')',[userId,crypto.createHash('sha256').update(token).digest('hex')]);
  res.cookie('sid',token,{httpOnly:true,secure:process.env.NODE_ENV==='production',sameSite:'lax',maxAge:30*86400000,path:'/'});
}

async function migrate() {
  await pool.query(`
  CREATE TABLE IF NOT EXISTS plans(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL,slug TEXT UNIQUE NOT NULL,description TEXT DEFAULT '',created_at TIMESTAMPTZ DEFAULT now());
  CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',plan_id BIGINT REFERENCES plans(id),created_at TIMESTAMPTZ DEFAULT now());
  CREATE TABLE IF NOT EXISTS sessions(id BIGSERIAL PRIMARY KEY,user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,token_hash TEXT UNIQUE NOT NULL,expires_at TIMESTAMPTZ NOT NULL,created_at TIMESTAMPTZ DEFAULT now());
  CREATE TABLE IF NOT EXISTS ai_settings(id INT PRIMARY KEY DEFAULT 1,base_url TEXT NOT NULL DEFAULT '',api_key_encrypted TEXT NOT NULL DEFAULT '',updated_at TIMESTAMPTZ DEFAULT now());
  CREATE TABLE IF NOT EXISTS models(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL,model_key TEXT UNIQUE NOT NULL,description TEXT DEFAULT '',min_plan_id BIGINT REFERENCES plans(id),enabled BOOLEAN DEFAULT true,created_at TIMESTAMPTZ DEFAULT now());
  CREATE TABLE IF NOT EXISTS licenses(id BIGSERIAL PRIMARY KEY,code TEXT UNIQUE NOT NULL,plan_id BIGINT REFERENCES plans(id),max_uses INT NOT NULL DEFAULT 1,used_count INT NOT NULL DEFAULT 0,expires_at TIMESTAMPTZ,active BOOLEAN DEFAULT true,created_at TIMESTAMPTZ DEFAULT now());
  CREATE TABLE IF NOT EXISTS license_redemptions(id BIGSERIAL PRIMARY KEY,license_id BIGINT REFERENCES licenses(id),user_id BIGINT REFERENCES users(id),redeemed_at TIMESTAMPTZ DEFAULT now(),UNIQUE(license_id,user_id));
  CREATE TABLE IF NOT EXISTS chats(id BIGSERIAL PRIMARY KEY,user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,model_id BIGINT REFERENCES models(id),title TEXT NOT NULL DEFAULT 'گفت‌وگوی جدید',created_at TIMESTAMPTZ DEFAULT now(),updated_at TIMESTAMPTZ DEFAULT now());
  CREATE TABLE IF NOT EXISTS messages(id BIGSERIAL PRIMARY KEY,chat_id BIGINT REFERENCES chats(id) ON DELETE CASCADE,role TEXT NOT NULL,content TEXT NOT NULL,created_at TIMESTAMPTZ DEFAULT now());
  ALTER TABLE models ADD COLUMN IF NOT EXISTS image_data TEXT;
  ALTER TABLE models ADD COLUMN IF NOT EXISTS system_prompt TEXT NOT NULL DEFAULT '';
  ALTER TABLE ai_settings ADD COLUMN IF NOT EXISTS header_title TEXT NOT NULL DEFAULT 'Pishi AI';
  ALTER TABLE ai_settings ADD COLUMN IF NOT EXISTS header_subtitle TEXT NOT NULL DEFAULT 'دستیار هوشمند';
  INSERT INTO ai_settings(id) VALUES(1) ON CONFLICT DO NOTHING;
  INSERT INTO plans(name,slug,description) VALUES
    ('رایگان','free','دسترسی به مدل‌های پایه'),
    ('پرو','pro','دسترسی به مدل‌های پیشرفته'),
    ('بیزنس','business','دسترسی کامل برای استفاده حرفه‌ای')
  ON CONFLICT(slug) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description;
  `);
  const free=(await pool.query("SELECT id FROM plans WHERE slug='free'")).rows[0].id;
  await pool.query(`INSERT INTO models(name,model_key,description,min_plan_id) VALUES
    ('مدل سریع','gpt-4o-mini','سریع و مناسب کارهای روزمره',$1),
    ('مدل حرفه‌ای','gpt-4o','قدرت بیشتر برای مسائل پیچیده',(SELECT id FROM plans WHERE slug='pro')) ON CONFLICT(model_key) DO NOTHING`,[free]);
  const email=cleanEmail(process.env.ADMIN_EMAIL), pass=process.env.ADMIN_PASSWORD;
  if(email && pass) {
    const exists=await pool.query('SELECT id FROM users WHERE email=$1',[email]);
    if(!exists.rows[0]) await pool.query('INSERT INTO users(email,name,password_hash,role,plan_id) VALUES($1,$2,$3,\'admin\',$4)',[email,'مدیر سیستم',await hashPassword(pass),free]);
  }
}

app.get('/health', (_req,res)=>res.status(200).json({
  service:'pishi-ai',
  ok:dbReady && configErrors.length===0,
  database:dbReady?'connected':'waiting',
  configuration:configErrors.length?configErrors:'ok',
  lastDatabaseError:lastDbError||undefined
}));
app.post('/api/auth/register', async(req,res,next)=>{try{
  const email=cleanEmail(req.body.email), name=safeText(req.body.name,80), password=String(req.body.password||'');
  if(!hasAllowedEmailDomain(email)||name.length<2||password.length<8) return res.status(400).json({error:'ثبت‌نام فقط با Gmail، Outlook یا دامنه in2.kdns.fr ممکن است؛ رمز هم باید حداقل ۸ کاراکتر باشد.'});
  const free=(await pool.query("SELECT id FROM plans WHERE slug='free'")).rows[0].id;
  const q=await pool.query('INSERT INTO users(email,name,password_hash,plan_id) VALUES($1,$2,$3,$4) RETURNING id',[email,name,await hashPassword(password),free]);
  await createSession(res,q.rows[0].id); res.json({ok:true});
}catch(e){if(e.code==='23505')return res.status(409).json({error:'این ایمیل قبلاً ثبت شده است.'});next(e)}});
app.post('/api/auth/login', async(req,res,next)=>{try{
  const q=await pool.query('SELECT * FROM users WHERE email=$1',[cleanEmail(req.body.email)]), u=q.rows[0];
  if(!u||!(await verifyPassword(String(req.body.password||''),u.password_hash))) return res.status(401).json({error:'ایمیل یا رمز اشتباه است.'});
  await createSession(res,u.id);res.json({ok:true});
}catch(e){next(e)}});
app.post('/api/auth/logout',auth,async(req,res)=>{const t=cookies(req).sid;await pool.query('DELETE FROM sessions WHERE token_hash=$1',[crypto.createHash('sha256').update(t).digest('hex')]);res.clearCookie('sid');res.json({ok:true});});
app.get('/api/me',auth,(req,res)=>res.json({user:req.user}));
app.get('/api/ui-config',auth,async(_req,res)=>res.json({config:(await pool.query('SELECT header_title,header_subtitle FROM ai_settings WHERE id=1')).rows[0]}));
app.patch('/api/me',auth,async(req,res)=>{const name=safeText(req.body.name,80);if(name.length<2)return res.status(400).json({error:'نام باید حداقل ۲ کاراکتر باشد.'});await pool.query('UPDATE users SET name=$1 WHERE id=$2',[name,req.user.id]);res.json({user:{...req.user,name}});});
app.get('/api/plans',auth,async(_req,res)=>res.json({plans:(await pool.query('SELECT id,name,slug,description FROM plans ORDER BY id')).rows}));
app.get('/api/models',auth,async(req,res)=>{const q=await pool.query(`SELECT m.id,m.name,m.model_key,m.description,m.image_data,m.enabled,p.name min_plan,
  (m.min_plan_id IS NULL OR m.min_plan_id=req.plan_id OR req.role='admin' OR EXISTS(SELECT 1 FROM plans up,plans mp WHERE up.id=req.plan_id AND mp.id=m.min_plan_id AND up.id>=mp.id)) unlocked
  FROM models m LEFT JOIN plans p ON p.id=m.min_plan_id CROSS JOIN (SELECT $1::bigint plan_id,$2::text role) req WHERE m.enabled=true ORDER BY m.id`,[req.user.plan_id,req.user.role]);res.json({models:q.rows});});
app.post('/api/licenses/redeem',auth,async(req,res,next)=>{const client=await pool.connect();try{await client.query('BEGIN');
  const q=await client.query('SELECT * FROM licenses WHERE upper(code)=upper($1) FOR UPDATE',[safeText(req.body.code,80)]), lic=q.rows[0];
  if(!lic||!lic.active||(lic.expires_at&&new Date(lic.expires_at)<new Date())||lic.used_count>=lic.max_uses) {await client.query('ROLLBACK');return res.status(400).json({error:'کد نامعتبر، منقضی یا تمام‌شده است.'});}
  await client.query('INSERT INTO license_redemptions(license_id,user_id) VALUES($1,$2)',[lic.id,req.user.id]);
  await client.query('UPDATE licenses SET used_count=used_count+1 WHERE id=$1',[lic.id]);await client.query('UPDATE users SET plan_id=$1 WHERE id=$2',[lic.plan_id,req.user.id]);
  await client.query('COMMIT');res.json({ok:true});
}catch(e){await client.query('ROLLBACK');if(e.code==='23505')return res.status(400).json({error:'این کد قبلاً توسط شما استفاده شده است.'});next(e)}finally{client.release()}});

app.get('/api/chats',auth,async(req,res)=>res.json({chats:(await pool.query('SELECT c.id,c.title,c.updated_at,m.name model_name FROM chats c LEFT JOIN models m ON m.id=c.model_id WHERE c.user_id=$1 ORDER BY c.updated_at DESC',[req.user.id])).rows}));
app.post('/api/chats',auth,async(req,res)=>{const modelId=Number(req.body.modelId);const allowed=await pool.query(`SELECT m.id FROM models m LEFT JOIN plans mp ON mp.id=m.min_plan_id LEFT JOIN plans up ON up.id=$2 WHERE m.id=$1 AND m.enabled=true AND ($3='admin' OR m.min_plan_id IS NULL OR m.min_plan_id=$2 OR up.id>=mp.id)`,[modelId,req.user.plan_id,req.user.role]);if(!allowed.rows[0])return res.status(403).json({error:'این مدل برای پلن شما قفل است.'});const q=await pool.query('INSERT INTO chats(user_id,model_id) VALUES($1,$2) RETURNING *',[req.user.id,modelId]);res.json({chat:q.rows[0]});});
app.get('/api/chats/:id',auth,async(req,res)=>{const c=await pool.query('SELECT c.*,m.name model_name FROM chats c LEFT JOIN models m ON m.id=c.model_id WHERE c.id=$1 AND c.user_id=$2',[req.params.id,req.user.id]);if(!c.rows[0])return res.status(404).json({error:'گفت‌وگو پیدا نشد.'});const messages=(await pool.query('SELECT id,role,content,created_at FROM messages WHERE chat_id=$1 ORDER BY id',[req.params.id])).rows;res.json({chat:c.rows[0],messages});});
app.patch('/api/chats/:id',auth,async(req,res)=>{await pool.query('UPDATE chats SET title=$1,updated_at=now() WHERE id=$2 AND user_id=$3',[safeText(req.body.title,120)||'گفت‌وگو',req.params.id,req.user.id]);res.json({ok:true});});
app.delete('/api/chats/:id',auth,async(req,res)=>{await pool.query('DELETE FROM chats WHERE id=$1 AND user_id=$2',[req.params.id,req.user.id]);res.json({ok:true});});
app.post('/api/chats/:id/messages',auth,async(req,res,next)=>{try{
  const content=safeText(req.body.content,12000);if(!content)return res.status(400).json({error:'پیام خالی است.'});
  const c=(await pool.query(`SELECT c.*,m.model_key,m.enabled,m.min_plan_id,m.system_prompt FROM chats c JOIN models m ON m.id=c.model_id WHERE c.id=$1 AND c.user_id=$2`,[req.params.id,req.user.id])).rows[0];if(!c)return res.status(404).json({error:'گفت‌وگو پیدا نشد.'});
  const allowed=(await pool.query(`SELECT ($3='admin' OR $1 IS NULL OR $1=$2 OR up.id>=mp.id) ok FROM plans up LEFT JOIN plans mp ON mp.id=$1 WHERE up.id=$2`,[c.min_plan_id,req.user.plan_id,req.user.role])).rows[0]?.ok;if(!allowed)return res.status(403).json({error:'مدل برای پلن شما قفل است.'});
  const set=(await pool.query('SELECT * FROM ai_settings WHERE id=1')).rows[0];if(!set.base_url||!set.api_key_encrypted)return res.status(503).json({error:'اتصال مدل هنوز توسط ادمین تنظیم نشده است.'});
  await pool.query('INSERT INTO messages(chat_id,role,content) VALUES($1,\'user\',$2)',[c.id,content]);
  const history=(await pool.query('SELECT role,content FROM messages WHERE chat_id=$1 ORDER BY id DESC LIMIT 30',[c.id])).rows.reverse();
  const modelMessages=c.system_prompt?.trim()?[{role:'system',content:c.system_prompt.trim()},...history]:history;
  const url=set.base_url.trim(); let safeEndpoint='';
  try { const endpoint=new URL(url); safeEndpoint=endpoint.origin+endpoint.pathname; } catch { return res.status(503).json({error:'آدرس endpoint هوش مصنوعی معتبر نیست.'}); }
  let response;
  try { response=await fetch(url,{method:'POST',redirect:'manual',signal:AbortSignal.timeout(90000),headers:{'content-type':'application/json','accept':'text/event-stream, application/json','authorization':`Bearer ${decrypt(set.api_key_encrypted)}`,'user-agent':'Pishi-AI/1.2.0'},body:JSON.stringify({model:c.model_key,messages:modelMessages,temperature:0.7,stream:true})}); }
  catch (upstreamError) { const reason=String(upstreamError?.cause?.message||upstreamError?.message||'خطای شبکه').slice(0,280);console.error('AI upstream connection error',{endpoint:safeEndpoint,reason});return res.status(502).json({error:'اتصال به سرویس هوش مصنوعی برقرار نشد.',detail:`خطای اتصال به ${safeEndpoint}: ${reason}`}); }
  if(!response.ok){const raw=(await response.text()).trim();let detail=raw;try{const parsed=JSON.parse(raw);detail=parsed?.error?.message||parsed?.error||parsed?.message||raw}catch{}detail=String(detail||`سرویس مقصد با وضعیت HTTP ${response.status} پاسخ خالی داد.`).slice(0,700);console.error('AI upstream error',{endpoint:safeEndpoint,status:response.status,detail});return res.status(502).json({error:'خطا در سرویس مدل هوش مصنوعی.',detail:`Endpoint: ${safeEndpoint} | HTTP ${response.status} | ${detail}`});}
  res.status(200);res.setHeader('content-type','text/event-stream; charset=utf-8');res.setHeader('cache-control','no-cache, no-transform');res.setHeader('connection','keep-alive');res.flushHeaders();
  const emit=(event,data)=>res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);let answer='';
  try {
    const contentType=response.headers.get('content-type')||'';
    if(contentType.includes('text/event-stream') && response.body){
      const reader=response.body.getReader(), decoder=new TextDecoder();let buffer='';
      while(true){const {value,done}=await reader.read();if(done)break;buffer+=decoder.decode(value,{stream:true});const packets=buffer.split(/\n\n/);buffer=packets.pop()||'';for(const packet of packets){const dataLine=packet.split(/\r?\n/).find(line=>line.startsWith('data:'));if(!dataLine)continue;const data=dataLine.slice(5).trim();if(data==='[DONE]')continue;try{const delta=JSON.parse(data)?.choices?.[0]?.delta?.content||'';if(delta){answer+=delta;emit('delta',{content:delta});}}catch{}}}
    } else { const raw=await response.text();const data=JSON.parse(raw);answer=data.choices?.[0]?.message?.content||'';if(answer)emit('delta',{content:answer}); }
    if(!answer)throw new Error(`مدل «${c.model_key}» خروجی استاندارد برنگرداند.`);
    await pool.query('INSERT INTO messages(chat_id,role,content) VALUES($1,\'assistant\',$2)',[c.id,answer]);
    const count=(await pool.query('SELECT count(*)::int n FROM messages WHERE chat_id=$1',[c.id])).rows[0].n;if(count===2)await pool.query('UPDATE chats SET title=$1,updated_at=now() WHERE id=$2',[content.slice(0,55),c.id]);else await pool.query('UPDATE chats SET updated_at=now() WHERE id=$1',[c.id]);
    emit('done',{content:answer});res.end();
  } catch(streamError) { console.error('AI stream error',{endpoint:safeEndpoint,error:String(streamError?.message||streamError)});emit('error',{error:'پاسخ مدل کامل نشد.',detail:String(streamError?.message||'خطای نامشخص')});res.end(); }
}catch(e){next(e)}});

app.get('/api/admin/overview',auth,admin,async(_req,res)=>{const [u,c,m,l]=await Promise.all([pool.query('SELECT count(*)::int n FROM users'),pool.query('SELECT count(*)::int n FROM chats'),pool.query('SELECT count(*)::int n FROM messages'),pool.query('SELECT count(*)::int n FROM licenses WHERE active=true')]);res.json({users:u.rows[0].n,chats:c.rows[0].n,messages:m.rows[0].n,licenses:l.rows[0].n});});
app.get('/api/admin/config',auth,admin,async(_req,res)=>{const [s,models,plans,licenses,users]=await Promise.all([pool.query('SELECT base_url,header_title,header_subtitle,(api_key_encrypted<>\'\') has_key,updated_at FROM ai_settings WHERE id=1'),pool.query('SELECT m.*,p.name min_plan FROM models m LEFT JOIN plans p ON p.id=m.min_plan_id ORDER BY m.id'),pool.query('SELECT * FROM plans ORDER BY id'),pool.query('SELECT l.*,p.name plan_name FROM licenses l LEFT JOIN plans p ON p.id=l.plan_id ORDER BY l.id DESC LIMIT 100'),pool.query('SELECT u.id,u.name,u.email,u.role,u.created_at,p.name plan_name FROM users u LEFT JOIN plans p ON p.id=u.plan_id ORDER BY u.id DESC LIMIT 100')]);res.json({settings:s.rows[0],models:models.rows,plans:plans.rows,licenses:licenses.rows,users:users.rows});});
app.put('/api/admin/settings',auth,admin,async(req,res)=>{const base=safeText(req.body.baseUrl,500),headerTitle=safeText(req.body.headerTitle,80)||'Pishi AI',headerSubtitle=safeText(req.body.headerSubtitle,120)||'دستیار هوشمند';if(!/^https?:\/\//.test(base))return res.status(400).json({error:'آدرس معتبر نیست.'});if(req.body.apiKey)await pool.query('UPDATE ai_settings SET base_url=$1,header_title=$2,header_subtitle=$3,api_key_encrypted=$4,updated_at=now() WHERE id=1',[base,headerTitle,headerSubtitle,encrypt(String(req.body.apiKey))]);else await pool.query('UPDATE ai_settings SET base_url=$1,header_title=$2,header_subtitle=$3,updated_at=now() WHERE id=1',[base,headerTitle,headerSubtitle]);res.json({ok:true});});
app.post('/api/admin/plans',auth,admin,async(req,res,next)=>{try{const q=await pool.query('INSERT INTO plans(name,slug,description) VALUES($1,$2,$3) RETURNING *',[safeText(req.body.name,80),safeText(req.body.slug,50).toLowerCase(),safeText(req.body.description,300)]);res.json({plan:q.rows[0]});}catch(e){next(e)}});
app.post('/api/admin/models',auth,admin,async(req,res,next)=>{try{const image=modelImageData(req.body.imageData);const q=await pool.query('INSERT INTO models(name,model_key,description,min_plan_id,image_data,system_prompt,enabled) VALUES($1,$2,$3,$4,$5,$6,true) RETURNING *',[safeText(req.body.name,80),safeText(req.body.modelKey,120),safeText(req.body.description,300),req.body.minPlanId||null,image,safeText(req.body.systemPrompt,6000)]);res.json({model:q.rows[0]});}catch(e){if(e.message?.includes('تصویر')||e.message?.includes('ابعاد')||e.message?.includes('حجم'))return res.status(400).json({error:e.message});next(e)}});
app.patch('/api/admin/models/:id',auth,admin,async(req,res,next)=>{try{const current=(await pool.query('SELECT * FROM models WHERE id=$1',[req.params.id])).rows[0];if(!current)return res.status(404).json({error:'مدل پیدا نشد.'});const has=(key)=>Object.prototype.hasOwnProperty.call(req.body||{},key);const enabled=has('enabled')?Boolean(req.body.enabled):current.enabled;const minPlanId=has('minPlanId')?(req.body.minPlanId||null):current.min_plan_id;const systemPrompt=has('systemPrompt')?safeText(req.body.systemPrompt,6000):current.system_prompt;const image=has('imageData')?modelImageData(req.body.imageData):current.image_data;const q=await pool.query('UPDATE models SET enabled=$1,min_plan_id=$2,system_prompt=$3,image_data=$4 WHERE id=$5 RETURNING *',[enabled,minPlanId,systemPrompt,image,req.params.id]);res.json({ok:true,model:q.rows[0]});}catch(e){if(e.message?.includes('تصویر')||e.message?.includes('ابعاد')||e.message?.includes('حجم'))return res.status(400).json({error:e.message});next(e)}});
app.delete('/api/admin/models/:id',auth,admin,async(req,res,next)=>{const client=await pool.connect();try{const id=Number(req.params.id);if(!Number.isInteger(id)||id<1)return res.status(400).json({error:'شناسه مدل نامعتبر است.'});await client.query('BEGIN');const existing=(await client.query('SELECT id,name FROM models WHERE id=$1 FOR UPDATE',[id])).rows[0];if(!existing){await client.query('ROLLBACK');return res.status(404).json({error:'مدل پیدا نشد.'});}await client.query('UPDATE chats SET model_id=NULL WHERE model_id=$1',[id]);await client.query('DELETE FROM models WHERE id=$1',[id]);await client.query('COMMIT');res.json({ok:true,deleted:existing});}catch(e){await client.query('ROLLBACK');next(e)}finally{client.release()}});
app.patch('/api/admin/users/:id/plan',auth,admin,async(req,res)=>{const planId=Number(req.body.planId);const plan=(await pool.query('SELECT id,name FROM plans WHERE id=$1',[planId])).rows[0];if(!plan)return res.status(400).json({error:'پلن نامعتبر است.'});const user=(await pool.query('UPDATE users SET plan_id=$1 WHERE id=$2 RETURNING id,name,email',[planId,req.params.id])).rows[0];if(!user)return res.status(404).json({error:'کاربر پیدا نشد.'});res.json({ok:true,user,plan});});

app.post('/api/admin/licenses',auth,admin,async(req,res,next)=>{try{const code=safeText(req.body.code,80)||randomCode();const q=await pool.query('INSERT INTO licenses(code,plan_id,max_uses,expires_at) VALUES($1,$2,$3,$4) RETURNING *',[code,req.body.planId,Math.max(1,Number(req.body.maxUses)||1),req.body.expiresAt||null]);res.json({license:q.rows[0]});}catch(e){next(e)}});
app.patch('/api/admin/licenses/:id',auth,admin,async(req,res)=>{await pool.query('UPDATE licenses SET active=$1 WHERE id=$2',[!!req.body.active,req.params.id]);res.json({ok:true});});

app.use((err,req,res,next)=>{console.error(err);if(res.headersSent)return next(err);res.status(500).json({error:'خطای داخلی سرور رخ داد.'});});
app.use((_req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

async function initializeDatabase(attempt=1) {
  if (configErrors.length || !pool) {
    console.error('Configuration error:', configErrors.join(' | '));
    return;
  }
  try {
    await migrate();
    dbReady = true;
    lastDbError = '';
    console.log('Database connected and migrations completed');
  } catch (error) {
    dbReady = false;
    lastDbError = String(error?.message || error).slice(0,300);
    console.error(`Database initialization failed (attempt ${attempt}):`, error);
    const delay = Math.min(30000, 2000 * attempt);
    setTimeout(() => initializeDatabase(attempt + 1), delay);
  }
}

app.listen(PORT,'0.0.0.0',()=>{
  console.log(`Pishi AI listening on ${PORT}`);
  initializeDatabase();
});
