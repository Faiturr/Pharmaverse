// Pharmacy Life - Worker (Cloudflare D1)
// Fitur: leaderboard + sistem kode redeem + panel admin (semua dilindungi secret ADMIN_KEY)
// Binding: D1 dengan nama variabel DB, Static Assets dengan nama ASSETS.
// Secret yang dibutuhkan untuk admin: ADMIN_KEY (Settings > Variables and Secrets > tipe Secret).
// + Siaran developer & event global (/live.json, /broadcast, /broadcast/delete) -- ditandatangani kunci developer, tanpa token.
// Tabel dibuat otomatis. Script klien redeem disisipkan otomatis ke index.html oleh Worker ini.
const MAX_SHOW = 100;
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};
const json = (d, s = 200) =>
  new Response(JSON.stringify(d), { status: s, headers: { "Content-Type": "application/json", ...CORS } });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const CODE_RE = /^[A-Z0-9-]{4,24}$/;
const ID_RE = /^[A-Za-z0-9_-]{1,40}$/;
const LB_ID_RE = /^[A-Za-z0-9_-]{8,64}$/;
const START_CAP = 20000;   // skor maks. yang diterima saat ID baru pertama kali muncul
const BURST = 3000;        // lonjakan skor wajar per kiriman
const RATE_PER_MIN = 1500; // kenaikan skor maks. per menit (kelebihannya dikejar bertahap, bukan ditolak)
const MIN_GAP = 15000;     // jarak minimal antar kiriman per ID (ms)
const cleanName = (v) => String(v ?? "").replace(/[\u0000-\u001f\u007f<>&"'`]/g, "").trim().slice(0, 14) || "Apoteker";
const clientIp = (req) => req.headers.get("CF-Connecting-IP") || "0";
// Batas laju (jendela tetap) di D1. true = sudah melewati batas.
async function limited(env, key, max, windowMs) {
  const now = Date.now(), w = Math.floor(now / windowMs);
  const r = await env.DB.prepare("INSERT INTO rl (k, n, exp) VALUES (?1, 1, ?2) ON CONFLICT(k) DO UPDATE SET n = n + 1 RETURNING n")
    .bind(key + ":" + w, (w + 1) * windowMs).first();
  if (Math.random() < 0.02) await env.DB.prepare("DELETE FROM rl WHERE exp < ?").bind(now).run();
  return !r || r.n > max;
}
// Tolak POST dari situs lain (browser mengirim Origin). Klien game selalu satu origin.
const badOrigin = (req, url) => { const o = req.headers.get("Origin"); return !!o && o !== url.origin; };
const clampInt = (v, max) => Math.min(Math.max(Math.floor(Number(v)) || 0, 0), max);


// ===== Siaran developer & event global =====
// Hanya siaran yang ditandatangani kunci developer (ECDSA P-256) yang diterima. Tidak ada token yang perlu dijaga.
const LIVE_PUB = { kty: "EC", crv: "P-256", x: "5KzP_YO5lKrbP3Cb136R9QlXknULf4MZPcsPyLKUMZQ", y: "Hc-rlggVe8tY-UWbI4tBfP5J2EYURrtIvZIGVxUbsQ8", ext: true };
const LIVE_ID_RE = /^[A-Za-z0-9_-]{4,40}$/;
const liveJson = (d, s = 200) =>
  new Response(JSON.stringify(d), { status: s, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...CORS } });
const liveB64 = (s) => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const b = atob(s), u = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
  return u;
};
async function liveVerify(msg, sig) {
  try {
    const k = await crypto.subtle.importKey("jwk", LIVE_PUB, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, k, liveB64(sig), new TextEncoder().encode(msg));
  } catch (e) { return false; }
}
async function handleLive(req, env, p) {
  if (p === "/live.json" && req.method === "GET") {
    const r = await env.DB.prepare("SELECT p, s FROM live_items WHERE t1 > ? AND (id NOT LIKE 'ch%' OR t1 > ?) ORDER BY t1 DESC LIMIT 60").bind(Date.now() - 7 * 864e5, Date.now()).all();
    return liveJson({ items: r.results || [] });
  }
  if (p === "/broadcast" && req.method === "POST") {
    const b = await readJson(req);
    if (!b || typeof b.p !== "string" || typeof b.s !== "string" || b.p.length > 4000) return liveJson({ error: "Format tidak valid" }, 400);
    if (!(await liveVerify("plife-live|" + b.p, b.s))) { await sleep(400); return liveJson({ error: "Tanda tangan tidak valid" }, 403); }
    let d; try { d = JSON.parse(b.p); } catch (e) { return liveJson({ error: "Payload tidak valid" }, 400); }
    if (!LIVE_ID_RE.test(String((d && d.id) || "")) || !(+d.t1 > 0)) return liveJson({ error: "Payload tidak valid" }, 400);
    await env.DB.prepare("INSERT INTO live_items (id, p, s, t1) VALUES (?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET p = excluded.p, s = excluded.s, t1 = excluded.t1")
      .bind(d.id, b.p, b.s, +d.t1).run();
    await env.DB.prepare("DELETE FROM live_items WHERE t1 < ?").bind(Date.now() - 30 * 864e5).run();
    await env.DB.prepare("DELETE FROM live_items WHERE id LIKE 'ch%' AND t1 < ?").bind(Date.now() - 600000).run();
    return liveJson({ ok: true, id: d.id });
  }
  if (p === "/broadcast/delete" && req.method === "POST") {
    const b = await readJson(req);
    if (!b || !LIVE_ID_RE.test(String(b.id || "")) || typeof b.s !== "string") return liveJson({ error: "Format tidak valid" }, 400);
    if (!(await liveVerify("plife-live-del|" + b.id, b.s))) { await sleep(400); return liveJson({ error: "Tanda tangan tidak valid" }, 403); }
    await env.DB.prepare("DELETE FROM live_items WHERE id = ?").bind(b.id).run();
    return liveJson({ ok: true });
  }
  return null;
}

// Cache singkat khusus chat (per isolate) agar polling 2 detik dari banyak pemain tidak menghantam D1 terus
let CHAT_CACHE = { t: 0, items: [] };
let ready = false;
async function init(env) {
  if (ready) return;
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS leaderboard (id TEXT PRIMARY KEY, name TEXT NOT NULL, score INTEGER NOT NULL, lv INTEGER NOT NULL DEFAULT 1, updated INTEGER NOT NULL)"
  ).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_lb_score ON leaderboard (score DESC)").run();
  for (const c of ["dev TEXT", "ip TEXT", "created INTEGER"]) {
    try { await env.DB.prepare("ALTER TABLE leaderboard ADD COLUMN " + c).run(); } catch (e) { /* sudah ada */ }
  }
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS rl (k TEXT PRIMARY KEY, n INTEGER NOT NULL, exp INTEGER NOT NULL)").run();
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS redeem_codes (code TEXT PRIMARY KEY, money INTEGER NOT NULL DEFAULT 0, xp INTEGER NOT NULL DEFAULT 0, item TEXT NOT NULL DEFAULT '', qty INTEGER NOT NULL DEFAULT 0, cos TEXT NOT NULL DEFAULT '', max INTEGER NOT NULL DEFAULT 0, exp INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL)"
  ).run();
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS redeem_claims (pid TEXT NOT NULL, code TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (pid, code))"
  ).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_claims_code ON redeem_claims (code)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS live_items (id TEXT PRIMARY KEY, p TEXT NOT NULL, s TEXT NOT NULL, t1 INTEGER NOT NULL)").run();
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS app_secrets (name TEXT PRIMARY KEY, value TEXT NOT NULL)").run();
  ready = true;
}

async function sha(s) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(b)).map((x) => x.toString(16).padStart(2, "0")).join("");
}
// Sumber kunci admin: (1) Secret Cloudflare ADMIN_KEY, (2) cadangan: tabel D1 app_secrets (name = 'ADMIN_KEY')
async function getAdminKey(env) {
  const fromEnv = String(env.ADMIN_KEY ?? "").trim();
  if (fromEnv) return { key: fromEnv, src: "secret" };
  if (env.DB) {
    try {
      const row = await env.DB.prepare("SELECT value FROM app_secrets WHERE name = 'ADMIN_KEY'").first();
      const v = row ? String(row.value ?? "").trim() : "";
      if (v) return { key: v, src: "d1" };
    } catch (e) { /* tabel belum ada */ }
  }
  return { key: "", src: "" };
}
async function isAdmin(env, key) {
  const real = (await getAdminKey(env)).key;
  if (!real || typeof key !== "string" || !key.trim()) return false;
  const [a, b] = await Promise.all([sha(key.trim()), sha(real)]);
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
async function readJson(req) {
  try { return await req.json(); } catch { return null; }
}
const countClaims = async (env, code) =>
  (await env.DB.prepare("SELECT COUNT(*) AS n FROM redeem_claims WHERE code = ?").bind(code).first()).n;

async function handleRedeem(req, env) {
  if (await limited(env, "rd:" + (await sha(clientIp(req))), 30, 600000)) return json({ error: "Terlalu banyak percobaan, coba lagi nanti" }, 429);
  const b = await readJson(req);
  if (!b) return json({ error: "JSON tidak valid" }, 400);
  const pid = String(b.id ?? "");
  if (!LB_ID_RE.test(pid)) return json({ error: "ID tidak valid" }, 400);
  const code = String(b.code ?? "").trim().toUpperCase();
  if (!CODE_RE.test(code)) return json({ error: "Kode tidak valid" }, 400);

  const row = await env.DB.prepare("SELECT * FROM redeem_codes WHERE code = ?").bind(code).first();
  if (!row) return json({ error: "Kode tidak valid" }, 404);
  if (row.exp && Date.now() > row.exp) return json({ error: "Kode sudah kedaluwarsa" }, 410);

  const had = await env.DB.prepare("SELECT 1 AS x FROM redeem_claims WHERE pid = ? AND code = ?").bind(pid, code).first();
  if (had) return json({ error: "Kode ini sudah kamu pakai" }, 409);
  if (row.max && (await countClaims(env, code)) >= row.max) return json({ error: "Kuota kode sudah habis" }, 410);

  const ins = await env.DB.prepare("INSERT OR IGNORE INTO redeem_claims (pid, code, at) VALUES (?, ?, ?)")
    .bind(pid, code, Date.now()).run();
  if (!ins.meta || ins.meta.changes === 0) return json({ error: "Kode ini sudah kamu pakai" }, 409);

  // Cek ulang kuota setelah klaim (menutup celah balapan dua pemain bersamaan)
  if (row.max && (await countClaims(env, code)) > row.max) {
    await env.DB.prepare("DELETE FROM redeem_claims WHERE pid = ? AND code = ?").bind(pid, code).run();
    return json({ error: "Kuota kode sudah habis" }, 410);
  }
  return json({ ok: true, reward: { money: row.money, xp: row.xp, item: row.item, qty: row.qty, cos: row.cos } });
}

async function handleAdmin(req, env) {
  if (!(await getAdminKey(env)).key) return json({ error: "ADMIN_KEY belum dipasang (Secret Cloudflare atau tabel app_secrets)" }, 503);
  if (await limited(env, "adm:" + (await sha(clientIp(req))), 60, 600000)) return json({ error: "Terlalu banyak percobaan, coba lagi nanti" }, 429);
  const b = await readJson(req);
  if (!b) return json({ error: "JSON tidak valid" }, 400);
  if (!(await isAdmin(env, b.key))) {
    await sleep(600);
    return json({ error: "Kunci admin salah" }, 401);
  }

  if (b.action === "check") return json({ ok: true });

  // Pembersihan leaderboard: lihat 100 teratas (lengkap dengan id/dev) dan hapus entri curang / ganda
  if (b.action === "lb_list") {
    const { results } = await env.DB.prepare("SELECT id, name, score, lv, dev, updated, created FROM leaderboard ORDER BY score DESC LIMIT 100").all();
    return json({ ok: true, rows: results });
  }
  if (b.action === "lb_delete") {
    const id = String(b.id ?? "");
    if (!LB_ID_RE.test(id)) return json({ error: "ID tidak valid" }, 400);
    await env.DB.prepare("DELETE FROM leaderboard WHERE id = ?").bind(id).run();
    return json({ ok: true });
  }

  if (b.action === "create") {
    const code = String(b.code ?? "").trim().toUpperCase();
    if (!CODE_RE.test(code)) return json({ error: "Format kode tidak valid" }, 400);
    const money = clampInt(b.money, 1e9), xp = clampInt(b.xp, 1e9), qty = clampInt(b.qty, 9999);
    const item = ID_RE.test(String(b.item ?? "")) ? String(b.item) : "";
    const cos = ID_RE.test(String(b.cos ?? "")) ? String(b.cos) : "";
    const max = clampInt(b.max, 1e6), days = clampInt(b.days, 3650);
    if (!money && !xp && !(item && qty) && !cos) return json({ error: "Isi minimal satu hadiah" }, 400);
    const exp = days > 0 ? Date.now() + days * 86400000 : 0;
    const r = await env.DB.prepare(
      "INSERT OR IGNORE INTO redeem_codes (code, money, xp, item, qty, cos, max, exp, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(code, money, xp, item, item ? qty : 0, cos, max, exp, Date.now()).run();
    if (!r.meta || r.meta.changes === 0) return json({ error: "Kode itu sudah ada" }, 409);
    return json({ ok: true });
  }

  if (b.action === "list") {
    const { results } = await env.DB.prepare(
      "SELECT c.code, c.money, c.xp, c.item, c.qty, c.cos, c.max, c.exp, (SELECT COUNT(*) FROM redeem_claims r WHERE r.code = c.code) AS used FROM redeem_codes c ORDER BY c.created DESC LIMIT 200"
    ).all();
    return json({ ok: true, codes: results });
  }

  if (b.action === "delete") {
    const code = String(b.code ?? "").trim().toUpperCase();
    if (!CODE_RE.test(code)) return json({ error: "Kode tidak valid" }, 400);
    await env.DB.prepare("DELETE FROM redeem_codes WHERE code = ?").bind(code).run();
    await env.DB.prepare("DELETE FROM redeem_claims WHERE code = ?").bind(code).run();
    return json({ ok: true });
  }
  return json({ error: "Aksi tidak dikenal" }, 400);
}

// ===== Script klien redeem (dikirim ke browser) =====
const CLIENT_JS = String.raw`/* Redeem client (disisipkan otomatis oleh worker.js). Menggantikan rdUI bawaan. */
(function(){
var LS=window.localStorage;
var IDR=/^[A-Za-z0-9-]{16,64}$/;
function gen(){return (window.crypto&&crypto.randomUUID)?crypto.randomUUID():Array.prototype.map.call(crypto.getRandomValues(new Uint8Array(16)),function(b){return ('0'+b.toString(16)).slice(-2)}).join('')}
/* Sama persis dengan pid() leaderboard: ID menempel pada SAVE (S.lid), bukan perangkat. */
function pid(){var d=null;try{d=LS.getItem('plLbId')}catch(e){}
 if(typeof S!=='undefined'&&S){
  if(!IDR.test(S.lid||''))S.lid=IDR.test(d||'')?d:gen();
  if(!IDR.test(d||'')){try{LS.setItem('plLbId',S.lid)}catch(e){}}
  return S.lid}
 if(IDR.test(d||''))return d;var n=gen();try{LS.setItem('plLbId',n)}catch(e){}return n}
function say(m){try{toast(m)}catch(e){}}
function getKey(){try{return LS.getItem('plAdminKey')||''}catch(e){return ''}}
function setKey(k){try{if(k)LS.setItem('plAdminKey',k);else LS.removeItem('plAdminKey')}catch(e){}}
async function api(path,body){
 var c=new AbortController(),to=setTimeout(function(){c.abort()},10000);
 try{
  var r=await fetch(location.origin+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:c.signal});
  var j={};try{j=await r.json()}catch(e){}
  return {s:r.status,j:j};
 }finally{clearTimeout(to)}
}
function sum(d){var r=[];
 if(d.money)r.push('Rp'+Math.round(d.money).toLocaleString('id-ID'));
 if(d.xp)r.push(d.xp+' XP');
 if(d.item&&window.MEDS&&MEDS[d.item]&&d.qty)r.push(d.qty+' '+MEDS[d.item].n);
 if(d.cos&&window.COS){var cc=COS.filter(function(i){return i.id==d.cos})[0];if(cc)r.push('Kosmetik: '+cc.n)}
 return r.join(', ')||'(kosong)'}
var FI='style="width:100%;box-sizing:border-box;padding:6px;border:2px solid #a28669;border-radius:6px;background:#fcfbf8;color:#474239" onkeydown="event.stopPropagation()"';
var IN='<input id="rd-in" autocomplete="off" autocapitalize="characters" onkeydown="event.stopPropagation()" style="width:100%;box-sizing:border-box;padding:8px;font-size:16px;text-transform:uppercase;border:2px solid #a28669;border-radius:6px;background:#fcfbf8;color:#474239">';

window.rdUI=function(){
 var b=[{t:'Tukar kode',fn:redeem}];
 if(getKey())b.push({t:'Kelola kode (admin)',fn:adminUI});
 b.push({t:'Tutup'});
 modal('Kode Redeem','Masukkan kode untuk mendapat hadiah. Tiap kode hanya bisa dipakai sekali per pemain.<br><br>'+IN,b);
};

async function redeem(){
 var v=(($('rd-in')||{}).value||'').trim();
 if(v.toLowerCase()==='/admin'){adminLogin();return}
 if(v.length<4){say('Masukkan kode');return}
 try{
  var r=await api('/redeem',{id:pid(),code:v.toUpperCase()});
  if(r.s!==200||!r.j.ok){say(r.j.error||'Gagal memproses kode');return}
  var d=r.j.reward||{};
  if(d.money)S.money+=d.money;
  if(d.xp)addXP(d.xp);
  if(d.cos&&window.cosGive)cosGive(d.cos);
  if(d.item&&MEDS[d.item]&&d.qty>0){S.stock[d.item]=(S.stock[d.item]||0)+d.qty;try{addB(d.item,d.qty)}catch(e){}}
  try{hud()}catch(e){}
  try{save()}catch(e){}
  modal('Redeem berhasil','Hadiah diterima: <b>'+sum(d)+'</b>',[{t:'Tutup'}]);
 }catch(e){say('Gagal terhubung ke server')}
}

function adminLogin(){
 modal('Masuk admin','Masukkan kunci admin.<br><br><input id="ad-k" type="password" autocomplete="off" '+FI+'>',
  [{t:'Masuk',fn:doLogin},{t:'Batal',fn:rdUI}]);
}
async function doLogin(){
 var k=(($('ad-k')||{}).value||'');
 if(!k){say('Isi kunci admin');return}
 try{
  var r=await api('/redeem/admin',{key:k,action:'check'});
  if(r.s===200&&r.j.ok){setKey(k);say('Admin aktif');adminUI()}
  else say(r.j.error||'Kunci admin salah');
 }catch(e){say('Gagal terhubung ke server')}
}
function authFail(r){
 if(r.s===401||r.s===503){if(r.s===401)setKey('');say(r.j.error||'Tidak diizinkan');return true}
 return false}
function rnd(){var A='ABCDEFGHJKLMNPQRSTUVWXYZ23456789',s='';for(var i=0;i<10;i++)s+=A[Math.floor(Math.random()*A.length)];return s.slice(0,5)+'-'+s.slice(5)}

function adminUI(code){
 var opt='<option value="">— tidak ada —</option>'+Object.keys(MEDS).map(function(k){return'<option value="'+k+'">'+MEDS[k].n+'</option>'}).join('');
 var copt='<option value="">— tidak ada —</option>'+(window.COS||[]).map(function(i){return'<option value="'+i.id+'">'+i.n+'</option>'}).join('');
 var f=function(id,l,v){return'<label>'+l+'<input id="'+id+'" type="number" min="0" value="'+v+'" '+FI+'></label>'};
 modal('Buat kode redeem','<label>Kode (4-24 huruf/angka/tanda -)<input id="rc-c" value="'+(typeof code=='string'?code:'')+'" '+FI+'></label>'
  +f('rc-m','Uang (Rp)',0)+f('rc-x','XP',0)
  +'<label>Obat<select id="rc-i" '+FI+'>'+opt+'</select></label>'+f('rc-q','Jumlah obat',0)
  +'<label>Kosmetik<select id="rc-k" '+FI+'>'+copt+'</select></label>'
  +f('rc-u','Maks. pemakaian (0 = tak terbatas)',0)+f('rc-e','Berlaku (hari, 0 = tanpa batas)',0),
  [{t:'Kode acak',fn:function(){adminUI(rnd())}},{t:'Buat kode',fn:create},{t:'Daftar kode',fn:list},{t:'Keluar admin',fn:function(){setKey('');rdUI()}},{t:'Kembali',fn:rdUI}]);
}
async function create(){
 var g=function(i){return($(i)||{}).value||''},c=g('rc-c').trim().toUpperCase();
 if(!/^[A-Z0-9-]{4,24}$/.test(c)){say('Format kode tidak valid');return}
 var d={action:'create',key:getKey(),code:c,money:+g('rc-m')||0,xp:+g('rc-x')||0,item:g('rc-i'),qty:+g('rc-q')||0,cos:g('rc-k'),max:+g('rc-u')||0,days:+g('rc-e')||0};
 if(!d.money&&!d.xp&&!(d.item&&d.qty)&&!d.cos){say('Isi minimal satu hadiah');return}
 try{
  var r=await api('/redeem/admin',d);
  if(authFail(r))return;
  if(!r.j.ok){say(r.j.error||'Gagal menyimpan');return}
  modal('Kode dibuat','Kode: <b>'+c+'</b><br>Hadiah: '+sum(d)+'<br>Catat kode ini.',[{t:'Buat lagi',fn:adminUI},{t:'Daftar kode',fn:list}]);
 }catch(e){say('Gagal terhubung ke server')}
}
async function list(){
 try{
  var r=await api('/redeem/admin',{action:'list',key:getKey()});
  if(authFail(r))return;
  if(!r.j.ok){say(r.j.error||'Gagal memuat daftar');return}
  var b=(r.j.codes||[]).map(function(a){
   return{t:'Hapus '+a.code+' — '+sum(a)+' — dipakai '+a.used+(a.max?'/'+a.max:'')+(a.exp&&Date.now()>a.exp?' (kedaluwarsa)':''),
    fn:async function(){
     try{var x=await api('/redeem/admin',{action:'delete',key:getKey(),code:a.code});
      if(authFail(x))return;say(x.j.ok?'Kode dihapus':(x.j.error||'Gagal menghapus'));list()}
     catch(e){say('Gagal menghapus')}}};
  });
  b.push({t:'Kembali',fn:adminUI});
  modal('Daftar kode',b.length>1?'Ketuk untuk menghapus kode.':'Belum ada kode.',b);
 }catch(e){say('Gagal memuat daftar')}
}

/* Pembuka panel admin: ketuk kotak status 5x dalam 3 detik. Panel dikirim server hanya bila kunci benar. */
var panelBusy=false,taps=[];
function keyBox(msg){
 return new Promise(function(res){
  var ov=document.createElement('div');
  ov.style.cssText='position:fixed;inset:0;z-index:1000;background:#000a;display:flex;align-items:center;justify-content:center;touch-action:manipulation;user-select:text;-webkit-user-select:text';
  ov.innerHTML='<div style="background:#f6f4ee;color:#474239;border:3px solid #a28669;border-radius:10px;padding:12px;width:min(88vw,360px);font:14px sans-serif"><b style="font-size:16px">Kunci admin</b><div id="pk-m" style="min-height:18px;color:#b03030;margin:4px 0"></div><input id="pk-i" type="password" autocomplete="off" style="width:100%;box-sizing:border-box;padding:8px;font-size:16px;border:2px solid #a28669;border-radius:6px;background:#fcfbf8;color:#474239"><div style="margin-top:10px;display:flex;gap:8px;justify-content:flex-end"><button id="pk-c" style="padding:8px 12px;border:2px solid #a28669;border-radius:8px;background:#f6f4ee;color:#474239">Batal</button><button id="pk-o" style="padding:8px 14px;border:2px solid #4c6d5c;border-radius:8px;background:#6d907c;color:#fff">Buka</button></div></div>';
  document.body.appendChild(ov);
  var i=ov.querySelector('#pk-i');ov.querySelector('#pk-m').textContent=msg||'';
  function done(v){ov.remove();res(v)}
  i.onkeydown=function(e){e.stopPropagation();if(e.key==='Enter')done(i.value.trim())};
  ov.querySelector('#pk-o').onclick=function(){done(i.value.trim())};
  ov.querySelector('#pk-c').onclick=function(){done(null)};
  setTimeout(function(){try{i.focus()}catch(e){}},50);
 });
}
async function fetchPanel(k){
 var c=new AbortController(),to=setTimeout(function(){c.abort()},10000);
 try{return await fetch(location.origin+'/admin/panel',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:k}),signal:c.signal})}
 finally{clearTimeout(to)}
}
async function openPanel(){
 if(panelBusy)return;panelBusy=true;
 try{
  var k=getKey(),msg='';
  for(;;){
   if(!k){k=await keyBox(msg);if(!k)return}
   var r=null;
   try{r=await fetchPanel(k)}catch(e){msg='Gagal terhubung ke server';k='';continue}
   if(r.status===401){setKey('');msg='Kunci salah';k='';continue}
   if(!r.ok){var m='';try{m=(JSON.parse(await r.text())||{}).error||''}catch(e){}msg=(m||'Panel tidak tersedia')+' (kode '+r.status+')';k='';continue}
   var js=await r.text();
   if(!window.__plOpenPanel){var s=document.createElement('script');s.textContent=js;document.head.appendChild(s)}
   setKey(k);
   if(window.__plOpenPanel)window.__plOpenPanel();
   return;
  }
 }finally{panelBusy=false}
}
document.addEventListener('pointerdown',function(e){
 var st=document.getElementById('st');if(!st)return;
 var r=st.getBoundingClientRect();
 if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)return;
 var n=Date.now();taps=taps.filter(function(t){return n-t<3000});taps.push(n);
 if(taps.length>=5){taps=[];say('Membuka panel admin...');openPanel()}
},true);
})();
`;

// ===== Panel admin (HANYA dikirim ke pemilik yang memegang ADMIN_KEY) =====
const PANEL_JS = String.raw`(function(){
  var opener=null;
  function mount(){
    var ov=document.createElement('div');
    ov.hidden=true;
    ov.style.cssText='position:fixed;inset:0;z-index:30;background:#000a;display:flex;align-items:center;justify-content:center;touch-action:manipulation;user-select:text;-webkit-user-select:text';
    ov.innerHTML='<div id="adm" style="background:#f6f4ee;color:#474239;border:3px solid #a28669;border-radius:10px;padding:10px 12px;width:min(92vw,560px);max-height:90vh;overflow:auto;font-size:13px"></div>';
    document.body.appendChild(ov);
    var box=ov.firstChild;
    var FIELDS=[['money','Uang (Rp)'],['xp','XP'],['rep','Reputasi'],['en','Energi (0-100)'],['t','Waktu (menit, 480 = 08:00)']];
    function inp(id,v){return '<input id="'+id+'" type="number" value="'+v+'" style="width:100%;box-sizing:border-box;padding:5px;border:2px solid #a28669;border-radius:6px;background:#fcfbf8;color:#474239">'}
    function btnH(id,t){return '<button id="'+id+'" style="padding:6px 9px;margin:2px;border:2px solid #4c6d5c;border-radius:8px;background:#6d907c;color:#ffffff">'+t+'</button>'}
    function render(){
      if(typeof S==='undefined'||!S){box.innerHTML='<b>Game belum dimulai.</b> Tekan Mulai dulu.<br>'+btnH('a-x','Tutup');box.querySelector('#a-x').onclick=close;return}
      var h='<div style="display:flex;justify-content:space-between;align-items:center"><b style="font-size:16px">\u2699 Panel Admin</b>'+btnH('a-x','Tutup')+'</div>';
      h+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:6px">';
      FIELDS.forEach(function(f){h+='<label>'+f[1]+inp('f-'+f[0],S[f[0]])+'</label>'});
      h+='</div><b style="display:block;margin-top:8px">Stok obat</b><div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:6px">';
      Object.keys(S.stock||{}).forEach(function(k){h+='<label>'+k+inp('s-'+k,S.stock[k])+'</label>'});
      h+='</div><div style="margin-top:8px">'+btnH('a-apply','Terapkan & simpan')+btnH('a-money','+Rp 1 juta')+btnH('a-en','Energi penuh')+btnH('a-stock','Semua stok +20')+btnH('a-cos','Buka semua kosmetik')+'</div>';
      h+='<b style="display:block;margin-top:8px">Data save (JSON)</b><textarea id="a-json" rows="4" style="width:100%;box-sizing:border-box;font-size:11px;border:2px solid #a28669;border-radius:6px"></textarea>';
      h+='<div>'+btnH('a-exp','Ekspor')+btnH('a-imp','Impor')+btnH('a-rst','Hapus save & mulai ulang')+btnH('a-lb','Kelola leaderboard')+'</div><div id="lb-box" style="margin-top:8px"></div>';
      box.innerHTML=h;
      var q=function(id){return box.querySelector(id)};
      q('#a-x').onclick=close;
      q('#a-apply').onclick=function(){apply();note('Tersimpan')};
      q('#a-money').onclick=function(){S.money+=1000000;refresh()};
      q('#a-en').onclick=function(){S.en=100;refresh()};
      q('#a-stock').onclick=function(){Object.keys(S.stock).forEach(function(k){S.stock[k]+=20});refresh()};q('#a-cos').onclick=function(){cosAll();note('Semua kosmetik terbuka')};
      q('#a-exp').onclick=function(){q('#a-json').value=JSON.stringify(S)};
      q('#a-imp').onclick=function(){try{var o=JSON.parse(q('#a-json').value);if(!o||typeof o!=='object')throw 0;S=o;done();note('Diimpor')}catch(e){note('JSON tidak valid')}};
      q('#a-lb').onclick=lbLoad;
      q('#a-rst').onclick=function(){if(confirm('Hapus semua progres?')){try{localStorage.removeItem('plsave')}catch(e){}location.reload()}};
    }
    function lbLoad(){
      var bx=box.querySelector('#lb-box'),k='';
      try{k=localStorage.getItem('plAdminKey')||''}catch(e){}
      bx.textContent='Memuat leaderboard...';
      function call(b){b.key=k;return fetch('/redeem/admin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).then(function(r){return r.json()})}
      call({action:'lb_list'}).then(function(j){
        if(!j.ok){bx.textContent=j.error||'Gagal memuat';return}
        var rows=j.rows||[],cnt={};
        rows.forEach(function(r){var c=r.name+'|'+r.score;cnt[c]=(cnt[c]||0)+1});
        bx.innerHTML='';
        var hd=document.createElement('b');hd.textContent='Leaderboard (100 teratas). Ketuk Hapus untuk membuang entri. "kembar" = nama dan skor sama.';
        bx.appendChild(hd);
        rows.forEach(function(r,i){
          var d=document.createElement('div');
          d.style.cssText='display:flex;gap:6px;align-items:center;justify-content:space-between;padding:4px 0;border-bottom:1px solid #d8cfc0';
          var t=document.createElement('span');
          var twin=cnt[r.name+'|'+r.score]>1;
          t.textContent='#'+(i+1)+' '+r.name+' \u2022 '+r.score+' \u2022 id '+String(r.id).slice(0,6)+(twin?' \u2022 kembar':'');
          if(twin)t.style.color='#b03030';
          var b=document.createElement('button');
          b.textContent='Hapus';
          b.style.cssText='padding:4px 8px;border:2px solid #995548;border-radius:8px;background:#d2887a;color:#fff';
          b.onclick=function(){
            if(!confirm('Hapus '+r.name+' (skor '+r.score+') dari leaderboard?'))return;
            call({action:'lb_delete',id:r.id}).then(function(x){note(x.ok?'Entri dihapus':(x.error||'Gagal menghapus'));lbLoad()}).catch(function(){note('Gagal terhubung')});
          };
          d.appendChild(t);d.appendChild(b);bx.appendChild(d);
        });
        if(!rows.length)bx.textContent='Leaderboard kosong.';
      }).catch(function(){bx.textContent='Gagal terhubung ke server'});
    }
    function apply(){
      FIELDS.forEach(function(f){var v=parseFloat(box.querySelector('#f-'+f[0]).value);if(!isNaN(v))S[f[0]]=v});
      Object.keys(S.stock||{}).forEach(function(k){var v=parseInt(box.querySelector('#s-'+k).value,10);if(!isNaN(v))S.stock[k]=Math.max(0,v)});
      done();
    }
    function done(){try{if(typeof hud==='function')hud()}catch(e){}try{if(typeof save==='function')save()}catch(e){}}
    function refresh(){done();render()}
    function note(m){try{toast(m)}catch(e){}}
    function close(){ov.hidden=true}
    opener=function(){render();ov.hidden=false};
  }
  window.__plOpenPanel=function(){if(!opener)mount();opener()};
})();
`;

const ICON_192 = "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";
const ICON_512 = "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";

// Service worker: game bisa dibuka tanpa internet setelah dimuat sekali. API (skor, redeem, chat, siaran) tidak pernah di-cache.
const SW_JS = String.raw`var V='pl-v1',RT='pl-rt-v1';
var CORE=['/','/redeem-client.js','/manifest.webmanifest','/icon-192.png','/icon-512.png'];
var CDN=['https://cdnjs.cloudflare.com/ajax/libs/phaser/3.60.0/phaser.min.js'];
var API=/^\/(scores?|chat|live\.json|broadcast|redeem|admin)(\/|$)/;
var noop=function(){};
self.addEventListener('install',function(e){
  e.waitUntil(caches.open(V).then(function(c){
    return Promise.all(CORE.map(function(u){return c.add(new Request(u,{cache:'reload'})).catch(noop)})
      .concat(CDN.map(function(u){return fetch(u,{mode:'no-cors'}).then(function(r){return c.put(u,r)}).catch(noop)})));
  }).then(function(){return self.skipWaiting()}));
});
self.addEventListener('activate',function(e){
  e.waitUntil(caches.keys().then(function(ks){return Promise.all(ks.filter(function(k){return k!==V&&k!==RT}).map(function(k){return caches.delete(k)}))}).then(function(){return self.clients.claim()}));
});
function notify(){self.clients.matchAll({type:'window'}).then(function(l){l.forEach(function(c){c.postMessage({type:'upd'})})})}
function refresh(c){
  return fetch('/',{cache:'no-cache'}).then(function(res){
    if(!res||!res.ok)return res;
    return c.match('/').then(function(old){
      if(!old){c.put('/',res.clone());return res}
      return Promise.all([old.arrayBuffer(),res.clone().arrayBuffer()]).then(function(b){
        var eo=old.headers.get('etag'),en=res.headers.get('etag');
        var diff=b[0].byteLength!==b[1].byteLength||(eo&&en&&eo!==en);
        return c.put('/',res.clone()).then(function(){if(diff)notify();return res});
      });
    });
  });
}
function nav(e){
  return caches.open(V).then(function(c){
    return c.match('/').then(function(hit){
      if(hit){e.waitUntil(refresh(c).catch(noop));return hit}
      return refresh(c).catch(function(){return new Response('Kamu sedang offline. Buka game sekali dengan internet agar bisa dimainkan tanpa sinyal.',{status:503,headers:{'Content-Type':'text/plain; charset=utf-8'}})});
    });
  });
}
function swr(r,name){
  return caches.open(name).then(function(c){
    return c.match(r).then(function(hit){
      var net=fetch(r).then(function(res){if(res&&(res.ok||res.type==='opaque'))c.put(r,res.clone());return res}).catch(function(){return hit});
      return hit||net;
    });
  });
}
self.addEventListener('fetch',function(e){
  var r=e.request;if(r.method!=='GET')return;
  var u=new URL(r.url);
  if(u.origin===location.origin){
    if(API.test(u.pathname)||u.pathname==='/sw.js')return;
    if(r.mode==='navigate'){e.respondWith(nav(e));return}
    e.respondWith(swr(r,V));return;
  }
  if(/(^|\.)(cdnjs\.cloudflare\.com|fonts\.googleapis\.com|fonts\.gstatic\.com)$/.test(u.hostname))e.respondWith(swr(r,RT));
});
`;

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const p = url.pathname;

    // ===== PWA: manifest, ikon, service worker (offline), assetlinks (untuk APK/TWA) =====
    if (p === "/manifest.webmanifest") {
      return new Response(JSON.stringify({
        id: "/", name: "Pharmacy Life: The Pharmacist", short_name: "Pharmacy Life", lang: "id",
        description: "Simulasi apotek: layani pasien, kelola stok, dan naik karier jadi apoteker.",
        start_url: "/", scope: "/", display: "fullscreen", display_override: ["fullscreen", "standalone"],
        orientation: "landscape", background_color: "#372619", theme_color: "#372619", categories: ["games"],
        icons: [
          { src: "/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
          { src: "/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any" },
          { src: "/icon-512.png", sizes: "512x512", type: "image/png", purpose: "maskable" },
        ],
      }), { headers: { "Content-Type": "application/manifest+json", "Cache-Control": "public, max-age=3600" } });
    }
    if (p === "/icon-192.png" || p === "/icon-512.png") {
      const raw = atob(p === "/icon-192.png" ? ICON_192 : ICON_512);
      const u = new Uint8Array(raw.length);
      for (let i = 0; i < raw.length; i++) u[i] = raw.charCodeAt(i);
      return new Response(u, { headers: { "Content-Type": "image/png", "Cache-Control": "public, max-age=86400" } });
    }
    if (p === "/sw.js") {
      return new Response(SW_JS, { headers: { "Content-Type": "application/javascript; charset=utf-8", "Cache-Control": "no-cache", "Service-Worker-Allowed": "/" } });
    }
    // Digital Asset Links untuk APK (TWA): isi variabel ASSETLINKS (teks JSON dari PWABuilder/Bubblewrap) di Settings > Variables
    if (p === "/.well-known/assetlinks.json") {
      if (!env.ASSETLINKS) return json({ error: "ASSETLINKS belum diisi" }, 404);
      return new Response(String(env.ASSETLINKS), { headers: { "Content-Type": "application/json", ...CORS } });
    }

    // Script klien redeem
    if (p === "/redeem-client.js") {
      return new Response(CLIENT_JS, {
        headers: { "Content-Type": "application/javascript; charset=utf-8", "Cache-Control": "no-cache" },
      });
    }

    const isApi = p === "/scores" || p === "/score" || p === "/redeem" || p === "/redeem/admin" || p === "/admin/panel" || p === "/admin/status" || p === "/live.json" || p === "/broadcast" || p === "/broadcast/delete" || p === "/chat";

    if (!isApi) {
      if (!env.ASSETS) return json({ error: "Not found" }, 404);
      const res = await env.ASSETS.fetch(req);
      const ct = res.headers.get("content-type") || "";
      // Sisipkan script redeem ke halaman game (index.html)
      if (req.method === "GET" && res.status === 200 && ct.includes("text/html")) {
        // Buang panel admin LAMA (yang hash sandinya tertanam di HTML) bila index.html versi lama masih terpasang
        let decided = false, drop = false, buf = "";
        return new HTMLRewriter()
          .on("script", {
            element() { decided = false; drop = false; buf = ""; },
            text(t) {
              if (decided) { if (drop) t.remove(); return; }
              buf += t.text;
              if (buf.length >= 400 || t.lastInTextNode) {
                decided = true;
                drop = buf.includes("PANEL ADMIN =====");
                if (drop) t.remove(); else t.replace(buf, { html: true });
              } else t.remove();
            },
          })
          .on("body", { element(el) { el.append('<script src="/redeem-client.js"></script>', { html: true }); } })
          .transform(res);
      }
      return res;
    }
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });

    // Cek status: apakah ADMIN_KEY terbaca Worker (tanpa menampilkan isinya)
    if (p === "/admin/status") {
      let ak = { key: "", src: "" };
      try { if (env.DB) await init(env); ak = await getAdminKey(env); } catch (e) {}
      const raw = env.ADMIN_KEY == null ? null : String(env.ADMIN_KEY);
      return json({ adminKeyTerpasang: !!ak.key, sumber: ak.src || "tidak ada", adaSpasiDiUjung: raw !== null && raw !== raw.trim(), dbTerpasang: !!env.DB, versi: "panel-v4" });
    }

    // Panel admin: kodenya hanya dikirim bila ADMIN_KEY benar (tidak ada di index.html)
    if (p === "/admin/panel") {
      if (req.method !== "POST") return json({ error: "Method tidak didukung" }, 405);
      try { if (env.DB) await init(env); } catch (e) {}
      if (!(await getAdminKey(env)).key) return json({ error: "ADMIN_KEY belum dipasang (Secret Cloudflare atau tabel app_secrets)" }, 503);
      try { if (env.DB && (await limited(env, "adm:" + (await sha(clientIp(req))), 60, 600000))) return json({ error: "Terlalu banyak percobaan, coba lagi nanti" }, 429); } catch (e) {}
      const b = await readJson(req);
      if (!b || !(await isAdmin(env, b.key))) { await sleep(600); return json({ error: "Kunci admin salah" }, 401); }
      return new Response(PANEL_JS, {
        headers: { "Content-Type": "application/javascript; charset=utf-8", "Cache-Control": "no-store" },
      });
    }

    try {
      if (!env.DB) return json({ error: "Binding DB belum dipasang" }, 500);
      await init(env);

      if (p === "/chat" && req.method === "GET") {
        const n = Date.now();
        if (n - CHAT_CACHE.t > 1500) {
          const r = await env.DB.prepare("SELECT p, s FROM live_items WHERE id LIKE 'ch%' AND t1 > ? ORDER BY t1 DESC LIMIT 5").bind(n).all();
          CHAT_CACHE = { t: n, items: r.results || [] };
        }
        return liveJson({ items: CHAT_CACHE.items });
      }
      if (p === "/live.json" || p === "/broadcast" || p === "/broadcast/delete") {
        if (p !== "/live.json") CHAT_CACHE = { t: 0, items: [] };
        const lr = await handleLive(req, env, p);
        return lr || json({ error: "Method tidak didukung" }, 405);
      }

      if (p === "/redeem") {
        if (req.method !== "POST") return json({ error: "Method tidak didukung" }, 405);
        return await handleRedeem(req, env);
      }
      if (p === "/redeem/admin") {
        if (req.method !== "POST") return json({ error: "Method tidak didukung" }, 405);
        return await handleAdmin(req, env);
      }

      // GET /scores?limit=10&me=<id>
      if (p === "/scores" && req.method === "GET") {
        const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit")) || 10, 1), MAX_SHOW);
        const me = url.searchParams.get("me") || "";
        const { results } = await env.DB.prepare(
          "SELECT id, name, score, lv FROM leaderboard ORDER BY score DESC, updated ASC LIMIT ?"
        ).bind(limit).all();
        return json(results.map((r) => ({ name: r.name, score: r.score, lv: r.lv, me: !!me && r.id === me })));
      }

      // POST /score  { id, dev, name, score, lv }
      if (p === "/score" && req.method === "POST") {
        if (badOrigin(req, url)) return json({ error: "Origin tidak diizinkan" }, 403);
        let b;
        try { b = await req.json(); } catch { return json({ error: "JSON tidak valid" }, 400); }
        if (!b || typeof b !== "object") return json({ error: "JSON tidak valid" }, 400);

        const id = String(b.id ?? "");
        const dev = LB_ID_RE.test(String(b.dev ?? "")) ? String(b.dev) : null;
        const name = cleanName(b.name);
        const raw = Math.floor(Number(b.score));
        const lv = Math.min(Math.max(1, Math.floor(Number(b.lv)) || 1), 99);
        if (!LB_ID_RE.test(id)) return json({ error: "ID tidak valid" }, 400);
        if (!Number.isFinite(raw) || raw < 0 || raw > 1e8) return json({ error: "Skor tidak valid" }, 400);

        const now = Date.now(), ipH = await sha(clientIp(req));
        if (await limited(env, "sc:" + ipH, 120, 600000)) return json({ error: "Terlalu banyak permintaan" }, 429);

        const prev = await env.DB.prepare("SELECT score, updated FROM leaderboard WHERE id = ?").bind(id).first();
        let score;
        if (!prev) {
          // ID baru: batasi pembuatan ID per IP (anti banjir entri ganda) dan batasi skor awal
          if (await limited(env, "new:" + ipH, 5, 86400000)) return json({ error: "Terlalu banyak pemain baru dari jaringan ini" }, 429);
          score = Math.min(raw, START_CAP);
        } else {
          if (now - prev.updated < MIN_GAP) return json({ ok: true, throttled: true });
          const mins = Math.min((now - prev.updated) / 60000, 1440);
          // Naik paling cepat BURST + RATE_PER_MIN * menit; selisihnya dikejar di kiriman berikutnya (tidak terkunci).
          score = Math.max(prev.score, Math.min(raw, prev.score + BURST + Math.floor(RATE_PER_MIN * mins)));
        }

        await env.DB.prepare(
          `INSERT INTO leaderboard (id, name, score, lv, updated, dev, ip, created) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?5)
           ON CONFLICT(id) DO UPDATE SET
             name = excluded.name,
             lv = excluded.lv,
             score = MAX(leaderboard.score, excluded.score),
             updated = excluded.updated,
             dev = COALESCE(excluded.dev, leaderboard.dev)`
        ).bind(id, name, score, lv, now, dev, ipH).run();

        const row = await env.DB.prepare(
          "SELECT COUNT(*) + 1 AS rank FROM leaderboard WHERE score > (SELECT score FROM leaderboard WHERE id = ?)"
        ).bind(id).first();
        return json({ ok: true, rank: row ? row.rank : null });
      }

      return json({ error: "Method tidak didukung" }, 405);
    } catch (e) {
      return json({ error: "Server error" }, 500);
    }
  },
};
