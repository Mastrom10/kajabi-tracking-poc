// Receptor de prueba aislado. Nunca usar como autenticación de alumnos.
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const origin = process.env.ALLOWED_ORIGIN;
const siteId = process.env.ALLOWED_SITE_ID;
const courseId = process.env.ALLOWED_COURSE_ID;
const pagePrefix=process.env.ALLOWED_PAGE_PREFIX || '/products/';
if(!origin || !siteId || !courseId)throw Error('Configurar origen, sitio y curso permitidos');
const adminPassword = process.env.ADMIN_PASSWORD;
if (!adminPassword) throw Error('ADMIN_PASSWORD requerido');
const allowedEvents = new Set(['lesson_viewed','lesson_completion_changed','video_ready','video_play','video_pause','video_seek','video_progress','video_end','page_hidden','page_visible','page_exit']);
const secret = crypto.randomBytes(32);
const limits = new Map();
const base = path.dirname(fileURLToPath(import.meta.url));
const localFile = process.env.LOCAL_EVENT_FILE || path.join(base,'..','private','events.jsonl');
let pool;
let ready = false;
let local = [];

if (process.env.DATABASE_URL) {
  const { default: pg } = await import('pg');
  pool = new pg.Pool({ connectionString:process.env.DATABASE_URL, max:3, connectionTimeoutMillis:10000 });
  pool.on('error', () => console.error('database_pool_error'));
  await pool.query(`CREATE TABLE IF NOT EXISTS tracking_events (
    event_id text PRIMARY KEY, received_at timestamptz NOT NULL DEFAULT now(),
    event_type text NOT NULL, member_id text NOT NULL, course_id text NOT NULL,
    lesson_id text NOT NULL, session_id text NOT NULL, payload jsonb NOT NULL
  )`);
  await pool.query('CREATE INDEX IF NOT EXISTS tracking_member_lesson ON tracking_events(member_id,lesson_id,received_at)');
} else {
  if (process.env.NODE_ENV === 'production') throw Error('DATABASE_URL requerido en Render');
  fs.mkdirSync(path.dirname(localFile),{recursive:true});
  if (fs.existsSync(localFile)) local=fs.readFileSync(localFile,'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
}
ready=true;

function json(res,status,body) {
  res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});
  res.end(JSON.stringify(body));
}
function constantEqual(a,b) {
  const x=Buffer.from(a || ''), y=Buffer.from(b || '');
  return x.length===y.length && crypto.timingSafeEqual(x,y);
}
function signedSession() {
  const data=String(Date.now()+8*3600*1000);
  return data+'.'+crypto.createHmac('sha256',secret).update(data).digest('hex');
}
function isAdmin(req) {
  const token=(req.headers.cookie || '').split(';').map(x=>x.trim()).find(x=>x.startsWith('kajabi_admin='))?.slice(13);
  if(!token) return false;
  const [expires,sig]=token.split('.');
  return Number(expires)>Date.now() && constantEqual(sig,crypto.createHmac('sha256',secret).update(expires).digest('hex'));
}
async function body(req,max=65536) {
  let size=0; const parts=[];
  for await(const chunk of req) { size+=chunk.length; if(size>max) throw Error('body_too_large'); parts.push(chunk); }
  return Buffer.concat(parts).toString('utf8');
}
function permitRate(req) {
  const ip=(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  const now=Date.now(); let entry=limits.get(ip);
  if(!entry || entry.until<now) {entry={count:0,until:now+60000};limits.set(ip,entry);}
  if(limits.size>10000) for(const [k,v] of limits) if(v.until<now) limits.delete(k);
  return ++entry.count<=240;
}
export function validateEvent(e) {
  if(!e || typeof e!=='object' || Array.isArray(e)) throw Error('invalid_event');
  if(!/^[a-zA-Z0-9_-]{8,100}$/.test(e.event_id || '') || !allowedEvents.has(e.event)) throw Error('invalid_event_id_or_type');
  if(e.site_id!==siteId || e.course_id!==courseId || !/^\d{1,20}$/.test(e.lesson_id || '') || !/^\d{1,20}$/.test(e.member_id || '')) throw Error('outside_test_scope_or_missing_identity');
  if(!/^[a-zA-Z0-9_-]{8,100}$/.test(e.session_id || '') || !Number.isFinite(Date.parse(e.occurred_at))) throw Error('invalid_session_or_time');
  const occurred=Date.parse(e.occurred_at);
  if(occurred>Date.now()+300000 || occurred<Date.now()-7*86400000) throw Error('event_time_outside_window');
  if(e.page_path && (!e.page_path.startsWith(pagePrefix) || e.page_path.includes('?'))) throw Error('invalid_page_path');
  const cleaned={event_id:e.event_id,event:e.event,occurred_at:e.occurred_at,session_id:e.session_id,site_id:e.site_id,course_id:e.course_id,lesson_id:e.lesson_id,member_id:e.member_id,module_id:String(e.module_id || ''),page_path:String(e.page_path || ''),source:'browser_poc',identity_verified:false,context:'test_preview_or_member_unverified',tracker_version:'0.2.0'};
  if(e.lesson_completed!==undefined) {
    if(typeof e.lesson_completed!=='boolean') throw Error('invalid_event');
    cleaned.lesson_completed=e.lesson_completed;
  }
  if(e.course_progress && typeof e.course_progress==='object') {
    const {completed,total,percent}=e.course_progress;
    if(![completed,total,percent].every(Number.isFinite) || completed<0 || total<completed || percent<0 || percent>100) throw Error('invalid_event');
    cleaned.course_progress={completed,total,percent};
    cleaned.course_progress_source='liquid_snapshot_at_page_load';
  }
  if(e.video && typeof e.video==='object') {
    cleaned.video={id:String(e.video.id || '').slice(0,100)};
    for(const k of ['position_seconds','duration_seconds','position_percent','watched_percent','unique_watched_seconds','from_seconds']) {
      const value=e.video[k];
      if(value!==undefined && value!==null) {
        if(typeof value!=='number' || !Number.isFinite(value) || value<0 || value>86400) throw Error('invalid_video_measure');
        if(k.endsWith('percent') && value>100) throw Error('invalid_video_percent');
        cleaned.video[k]=value;
      }
    }
    if(e.video.watched_ranges_seconds!==undefined){
      const ranges=e.video.watched_ranges_seconds;
      if(!Array.isArray(ranges) || ranges.length>200 || ranges.some(r=>!Array.isArray(r) || r.length!==2 || !r.every(Number.isFinite) || r[0]<0 || r[1]<=r[0] || r[1]>86400))throw Error('invalid_video_measure');
      cleaned.video.watched_ranges_seconds=ranges;cleaned.video.ranges_truncated=Boolean(e.video.ranges_truncated);
    }
  }
  return cleaned;
}
async function insert(e) {
  const stamped={...e,received_at:new Date().toISOString()};
  if(pool) {
    const r=await pool.query('INSERT INTO tracking_events(event_id,event_type,member_id,course_id,lesson_id,session_id,payload) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(event_id) DO NOTHING RETURNING event_id',[e.event_id,e.event,e.member_id,e.course_id,e.lesson_id,e.session_id,e]);
    return r.rowCount===1;
  }
  if(local.some(v=>v.event_id===e.event_id)) return false;
  fs.appendFileSync(localFile,JSON.stringify(stamped)+'\n');local.push(stamped); return true;
}
async function events(member,lesson,exportAll=false) {
  if(pool) {
    const r=await pool.query('SELECT payload,received_at FROM tracking_events WHERE ($1::text IS NULL OR member_id=$1) AND ($2::text IS NULL OR lesson_id=$2) ORDER BY received_at DESC LIMIT $3',[member || null,lesson || null,exportAll?10000:300]);
    return r.rows.map(v=>({...v.payload,received_at:v.received_at}));
  }
  return local.filter(v=>(!member || v.member_id===member)&&(!lesson || v.lesson_id===lesson)).slice().reverse().slice(0,exportAll?10000:300);
}
const loginHtml=`<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Tracking Kajabi · Pruebas</title><style>body{font:16px system-ui;background:#f3f4f6;color:#1c2631;max-width:520px;margin:12vh auto;padding:24px}input,button{font:inherit;padding:12px;margin-top:12px;width:100%;box-sizing:border-box}button{background:#243a50;color:white;border:0}small{display:block;margin-top:24px;color:#536170}</style><h1>Registro de eventos Kajabi</h1><p>Entorno de prueba aislado. Acceso de revisión.</p><form method="POST" action="/login"><label>Contraseña de revisión<input type="password" name="password" required autocomplete="current-password"></label><button>Entrar</button></form><small>La captura proviene del navegador. La identidad de alumno aún no está verificada.</small></html>`;
const dashboardHtml=`<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Eventos Kajabi · Pruebas</title><style>body{font:15px system-ui;background:#f5f6f8;color:#1c2631;margin:0}main{max-width:1250px;margin:auto;padding:28px}h1{font-size:26px;margin-bottom:8px}p{line-height:1.5}.toolbar{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}input,button,a{font:inherit;padding:10px}button{cursor:pointer;background:#243a50;color:white;border:0}a{color:#243a50}table{width:100%;border-collapse:collapse;background:white}th,td{padding:10px;text-align:left;border-bottom:1px solid #d8dde3;font-size:13px}th{background:#e9edf2}pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0;font:12px ui-monospace}details{max-width:400px}.note{color:#586572}.status{font-weight:600}#summary{margin:14px 0}.scroll{overflow:auto}</style></head><body><main><h1>Eventos de tracking Kajabi</h1><p class="note">Pruebas Mastria · eventos persistidos en el backend. Identidad informada por el navegador, pendiente de verificación.</p><div class="toolbar"><input id="member" placeholder="ID de usuario"><input id="lesson" placeholder="ID de lección"><button id="refresh">Actualizar</button><a id="export" href="/api/export">Exportar JSON</a><button id="logout">Salir</button></div><p id="summary" class="status">Cargando eventos...</p><p class="note">Posición indica dónde está el reproductor. Visto indica segundos únicos reproducidos según el player; saltar no equivale a mirar. Pausa o última señal no prueban abandono definitivo.</p><div class="scroll"><table><thead><tr><th>Recepción UTC</th><th>Evento</th><th>Usuario</th><th>Lección</th><th>Posición / duración</th><th>Visto</th><th>Metadata</th></tr></thead><tbody id="rows"></tbody></table></div></main><script>
const $=id=>document.getElementById(id);
async function load(){try{const q=new URLSearchParams({member:$('member').value,lesson:$('lesson').value});const res=await fetch('/api/events?'+q);if(res.status===401){location.reload();return;}if(!res.ok)throw Error('No se pudieron leer eventos');const data=await res.json();$('summary').textContent=data.total+' eventos mostrados · almacenamiento '+data.storage;const tbody=$('rows');tbody.replaceChildren();for(const e of data.events){const tr=document.createElement('tr');const values=[new Date(e.received_at).toISOString(),e.event,e.member_id,e.lesson_id,e.video?(e.video.position_seconds??'—')+' / '+(e.video.duration_seconds??'—')+' s':'—',e.video?(e.video.watched_percent??'—')+' %':'—'];for(const value of values){const td=document.createElement('td');td.textContent=value;tr.append(td);}const td=document.createElement('td'),details=document.createElement('details'),summary=document.createElement('summary'),pre=document.createElement('pre');summary.textContent='Ver evento';pre.textContent=JSON.stringify(e,null,2);details.append(summary,pre);td.append(details);tr.append(td);tbody.append(tr);} $('export').href='/api/export?'+q;}catch(err){$('summary').textContent=err.message;}}
$('refresh').onclick=load;$('logout').onclick=async()=>{await fetch('/logout',{method:'POST'});location.reload();};load();setInterval(load,5000);
</script></body></html>`;

const server=http.createServer(async(req,res)=>{
  res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Cache-Control','no-store');
  const url=new URL(req.url,'http://localhost');
  try {
    if(url.pathname==='/health') return json(res,ready?200:503,{ok:ready,storage:pool?'postgres':'local_jsonl',scope:'test_only'});
    if(url.pathname==='/events') {
      if(req.headers.origin!==origin) return json(res,403,{error:'origin_not_allowed'});
      res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');
      if(req.method==='OPTIONS') {res.setHeader('Access-Control-Allow-Methods','POST, OPTIONS');res.setHeader('Access-Control-Allow-Headers','Content-Type');res.writeHead(204);return res.end();}
      if(req.method!=='POST') return json(res,405,{error:'method_not_allowed'});
      if(!permitRate(req)) return json(res,429,{error:'rate_limit'});
      if(!(req.headers['content-type'] || '').startsWith('application/json')) return json(res,415,{error:'json_required'});
      const input=JSON.parse(await body(req)); const batch=input.events;
      if(!Array.isArray(batch) || !batch.length || batch.length>40) return json(res,400,{error:'invalid_batch'});
      const checked=batch.map(validateEvent); let inserted=0;
      for(const e of checked) if(await insert(e)) inserted++;
      return json(res,200,{accepted:checked.length,inserted,duplicates:checked.length-inserted});
    }
    if(url.pathname==='/login' && req.method==='POST') {
      if(!permitRate(req)) return json(res,429,{error:'rate_limit'});
      if(!constantEqual(new URLSearchParams(await body(req,4096)).get('password'),adminPassword)) return json(res,401,{error:'invalid_password'});
      res.setHeader('Set-Cookie','kajabi_admin='+signedSession()+'; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800'+(process.env.NODE_ENV==='production'?'; Secure':''));
      res.writeHead(303,{Location:'/'});return res.end();
    }
    if(url.pathname==='/logout' && req.method==='POST'){res.setHeader('Set-Cookie','kajabi_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');res.writeHead(204);return res.end();}
    if(url.pathname==='/api/events' || url.pathname==='/api/export') {
      if(!isAdmin(req)) return json(res,401,{error:'admin_login_required'});
      const data=await events(url.searchParams.get('member'),url.searchParams.get('lesson'),url.pathname.endsWith('export'));
      if(url.pathname.endsWith('export')) res.setHeader('Content-Disposition','attachment; filename="kajabi-events.json"');
      return json(res,200,{total:data.length,storage:pool?'postgres':'local_jsonl',events:data});
    }
    if(url.pathname==='/' && req.method==='GET') {res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});return res.end(isAdmin(req)?dashboardHtml:loginHtml);}
    json(res,404,{error:'not_found'});
  } catch(error) {
    const inputErrors=['invalid_event','invalid_event_id_or_type','outside_test_scope_or_missing_identity','invalid_session_or_time','event_time_outside_window','invalid_page_path','invalid_video_measure','invalid_video_percent','body_too_large'];
    if(error instanceof SyntaxError || inputErrors.includes(error.message)) return json(res,400,{error:inputErrors.includes(error.message)?error.message:'invalid_json'});
    console.error('request_failed');json(res,503,{error:'temporarily_unavailable_retry_same_event_id'});
  }
});
server.listen(Number(process.env.PORT || 8787),'0.0.0.0',()=>console.log('tracking_receiver_ready'));
process.on('SIGTERM',()=>server.close(async()=>{if(pool)await pool.end();process.exit(0);}));
