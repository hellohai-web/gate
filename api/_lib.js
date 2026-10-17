'use strict';
// Shared helpers for the license API. Files starting with "_" are NOT public routes on Vercel.
const crypto = require('crypto');

const env = (k) => (process.env[k] || '').trim();
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
function safeEq(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

/* ---------- Redis (Upstash REST; works with the Vercel Marketplace integration) ---------- */
function redisConf() {
  let url = env('UPSTASH_REDIS_REST_URL') || env('KV_REST_API_URL');
  let token = env('UPSTASH_REDIS_REST_TOKEN') || env('KV_REST_API_TOKEN');
  if (!url || !token) {
    for (const k of Object.keys(process.env)) {
      if (!url && /(REST_API_URL|REDIS_REST_URL)$/.test(k)) url = process.env[k];
      if (!token && /(REST_API_TOKEN|REDIS_REST_TOKEN)$/.test(k) && !/READ_ONLY/.test(k)) token = process.env[k];
    }
  }
  return url && token ? { url: url.trim().replace(/\/+$/, ''), token: token.trim() } : null;
}
async function rfetch(path, body) {
  const c = redisConf();
  if (!c) throw new Error('REDIS_NOT_SET');
  const r = await fetch(c.url + path, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + c.token, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => null);
  if (!r.ok || !j) throw new Error('REDIS_HTTP_' + r.status + (j && j.error ? ': ' + j.error : ''));
  return j;
}
async function rcmd(...args) {
  const j = await rfetch('', args);
  if (j.error) throw new Error('REDIS: ' + j.error);
  return j.result;
}
async function rpipe(cmds) {
  const j = await rfetch('/pipeline', cmds);
  if (!Array.isArray(j)) throw new Error('REDIS_PIPELINE_BAD');
  return j.map((x) => { if (x.error) throw new Error('REDIS: ' + x.error); return x.result; });
}
const toObj = (arr) => {
  const o = {};
  if (Array.isArray(arr)) for (let i = 0; i + 1 < arr.length; i += 2) o[arr[i]] = arr[i + 1];
  return o;
};

/* ---------- license keys: STATUS-0001-XXXX-XXXX-XXXX-XXXX ---------- */
function keySecret() {
  const s = env('KEY_SECRET');
  if (s.length < 16) throw new Error('KEY_SECRET_NOT_SET');
  return s;
}
function tag(serial) {
  return crypto.createHmac('sha256', keySecret()).update('status-' + serial).digest('hex').slice(0, 16).toUpperCase();
}
function makeKey(serial) {
  const s = String(serial).padStart(4, '0');
  const t = tag(s);
  return 'STATUS-' + s + '-' + t.slice(0, 4) + '-' + t.slice(4, 8) + '-' + t.slice(8, 12) + '-' + t.slice(12, 16);
}
function parseKey(input) {
  const raw = String(input || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  const m = /^STATUS(\d{4})([0-9A-F]{16})$/.exec(raw);
  if (!m || m[1] === '0000') return null;
  if (!safeEq(tag(m[1]), m[2])) return null;
  return { serial: m[1], key: makeKey(m[1]) };
}

/* ---------- device fingerprint (soft second factor next to the device token) ---------- */
function normFp(fp) {
  if (!fp || typeof fp !== 'object' || !Array.isArray(fp.s)) return null;
  return [
    String(Number(fp.s[0]) || 0), String(Number(fp.s[1]) || 0),
    String(Number(fp.c) || 0), String(Number(fp.t) || 0),
    String(fp.g || '').toLowerCase().slice(0, 80),
  ];
}
function fpMatch(storedJson, fp) {
  let a; try { a = JSON.parse(storedJson); } catch (e) { return false; }
  const b = normFp(fp);
  if (!Array.isArray(a) || !b) return false;
  let same = 0;
  for (let i = 0; i < 5; i++) if (a[i] === b[i]) same++;
  return same >= 3; // tolerates a moved window / zoom / browser update, rejects another device
}

/* ---------- request helpers ---------- */
function noStore(res) {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('X-Robots-Tag', 'noindex, nofollow');
}
function send(res, code, obj) {
  res.statusCode = code;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(obj));
}
function originOk(req) {
  const o = req.headers.origin;
  if (!o || o === 'null') return false; // a downloaded/offline copy (file://) sends Origin: null
  let h; try { h = new URL(o).host; } catch (e) { return false; }
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  if (h === host) return true;
  return env('ALLOWED_HOSTS').split(',').map((s) => s.trim()).filter(Boolean).includes(h);
}
async function readBody(req) {
  if (req.body && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) return req.body;
  let raw = typeof req.body === 'string' ? req.body : '';
  if (!raw) {
    raw = await new Promise((resolve) => {
      let d = '';
      req.on('data', (c) => { d += c; if (d.length > 20000) req.destroy(); });
      req.on('end', () => resolve(d));
      req.on('error', () => resolve(''));
    });
  }
  try { return JSON.parse(raw || '{}'); } catch (e) { return {}; }
}
function cookies(req) {
  const o = {};
  String(req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return o;
}
function setTokenCookie(res, token) {
  res.setHeader('Set-Cookie', 'sdt=' + encodeURIComponent(token) + '; Path=/; Max-Age=31536000; HttpOnly; Secure; SameSite=Strict');
}
function clientIp(req) {
  return String(req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || (req.socket && req.socket.remoteAddress) || 'x').split(',')[0].trim();
}
const LIMIT = 30, WINDOW = 900; // 30 failed tries / 15 min / IP
async function blocked(scope, ip) {
  return Number((await rcmd('GET', 'rl:' + scope + ':' + sha256(ip).slice(0, 16))) || 0) >= LIMIT;
}
async function noteFail(scope, ip) {
  const k = 'rl:' + scope + ':' + sha256(ip).slice(0, 16);
  const n = await rcmd('INCR', k);
  if (n === 1) await rcmd('EXPIRE', k, WINDOW);
}
function missingConfig(need) {
  const miss = [];
  if (need.includes('SITE_PASSWORD') && !env('SITE_PASSWORD')) miss.push('SITE_PASSWORD');
  if (need.includes('KEY_SECRET') && env('KEY_SECRET').length < 16) miss.push('KEY_SECRET');
  if (need.includes('ADMIN_SECRET') && env('ADMIN_SECRET').length < 12) miss.push('ADMIN_SECRET');
  if (need.includes('REDIS') && !redisConf()) miss.push('REDIS (Upstash)');
  return miss;
}
function appKey() {
  const k = env('APP_KEY');
  try { return Buffer.from(k, 'base64').length === 32 ? k : null; } catch (e) { return null; }
}

module.exports = {
  env, sha256, safeEq, redisConf, rcmd, rpipe, toObj, makeKey, parseKey, normFp, fpMatch,
  noStore, send, originOk, readBody, cookies, setTokenCookie, clientIp, blocked, noteFail,
  missingConfig, appKey,
};
