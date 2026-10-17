'use strict';
const L = require('./_lib');

function serialOf(b) {
  if (b.serial && /^\d{1,4}$/.test(String(b.serial))) return String(b.serial).padStart(4, '0');
  const p = L.parseKey(b.key);
  return p ? p.serial : null;
}

module.exports = async (req, res) => {
  L.noStore(res);
  if (req.method !== 'POST') return L.send(res, 405, { ok: false, err: 'method' });
  if (!L.originOk(req)) return L.send(res, 403, { ok: false, err: 'origin' });
  const miss = L.missingConfig(['ADMIN_SECRET', 'KEY_SECRET', 'REDIS']);
  if (miss.length) return L.send(res, 500, { ok: false, err: 'config', miss });
  try {
    const b = await L.readBody(req);
    const ip = L.clientIp(req);
    if (await L.blocked('adm', ip)) return L.send(res, 429, { ok: false, err: 'rate' });
    if (!L.safeEq(L.sha256(b.secret || ''), L.sha256(L.env('ADMIN_SECRET')))) {
      await L.noteFail('adm', ip);
      return L.send(res, 401, { ok: false, err: 'auth' });
    }

    if (b.a === 'list') {
      const seq = Math.min(Number((await L.rcmd('GET', 'lic:seq')) || 5), 400);
      const cmds = [];
      for (let i = 1; i <= seq; i++) cmds.push(['HGETALL', 'lic:' + String(i).padStart(4, '0')]);
      const out = await L.rpipe(cmds);
      const rows = out.map((a, i) => {
        const r = L.toObj(a), s = String(i + 1).padStart(4, '0');
        return { serial: s, key: L.makeKey(s), bound: !!r.th, rev: !!r.rev,
          at: r.at ? Number(r.at) : null, last: r.last ? Number(r.last) : null, ua: r.ua || '' };
      });
      return L.send(res, 200, { ok: true, rows });
    }
    if (b.a === 'gen') {
      const n = Math.max(1, Math.min(Number(b.n) || 1, 50));
      const cmds = [['SETNX', 'lic:seq', '5']];
      for (let i = 0; i < n; i++) cmds.push(['INCR', 'lic:seq']);
      const out = await L.rpipe(cmds);
      const keys = out.slice(1).map((s) => L.makeKey(String(s).padStart(4, '0')));
      return L.send(res, 200, { ok: true, keys });
    }
    if (b.a === 'reset' || b.a === 'revoke' || b.a === 'unrevoke') {
      const s = serialOf(b);
      if (!s || s === '0000') return L.send(res, 400, { ok: false, err: 'key' });
      const k = 'lic:' + s;
      if (b.a === 'reset') await L.rcmd('HDEL', k, 'th', 'fp', 'at', 'last', 'ua');
      else if (b.a === 'revoke') await L.rcmd('HSET', k, 'rev', '1');
      else await L.rcmd('HDEL', k, 'rev');
      return L.send(res, 200, { ok: true, serial: s });
    }
    return L.send(res, 400, { ok: false, err: 'bad' });
  } catch (e) {
    console.error('admin error', e && e.message);
    return L.send(res, 500, { ok: false, err: 'server', msg: String((e && e.message) || e).slice(0, 120) });
  }
};
