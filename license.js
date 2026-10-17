'use strict';
const L = require('./_lib');

async function getRec(serial) {
  return L.toObj(await L.rcmd('HGETALL', 'lic:' + serial));
}
// Is this token the one bound to its key, from the same kind of device?
async function verifyToken(tok, fp) {
  tok = String(tok || '');
  const serial = tok.split('.')[0];
  if (!/^\d{4}$/.test(serial)) return { ok: false, err: 'none' };
  const rec = await getRec(serial);
  if (!rec.th) return { ok: false, err: 'none' };
  if (rec.rev) return { ok: false, err: 'revoked' };
  if (!L.safeEq(L.sha256(tok), rec.th)) return { ok: false, err: 'device' };
  if (!L.fpMatch(rec.fp, fp)) return { ok: false, err: 'device' };
  await L.rcmd('HSET', 'lic:' + serial, 'last', String(Date.now()));
  return { ok: true, serial, tok };
}
async function checkAny(req, body) {
  const seen = new Set();
  let last = { ok: false, err: 'none' };
  for (const t of [body.t, L.cookies(req).sdt]) {
    if (!t || seen.has(t)) continue;
    seen.add(t);
    const r = await verifyToken(t, body.fp);
    if (r.ok) return r;
    if (r.err !== 'none') last = r;
  }
  return last;
}
function granted(res, tok, serial) {
  L.setTokenCookie(res, tok);
  L.send(res, 200, { ok: true, k: L.appKey(), t: tok, s: serial });
}

module.exports = async (req, res) => {
  L.noStore(res);
  if (req.method !== 'POST') return L.send(res, 405, { ok: false, err: 'method' });
  if (!L.originOk(req)) return L.send(res, 403, { ok: false, err: 'origin' });
  const miss = L.missingConfig(['SITE_PASSWORD', 'KEY_SECRET', 'REDIS']);
  if (miss.length) return L.send(res, 500, { ok: false, err: 'config', miss });
  try {
    const body = await L.readBody(req);
    const ip = L.clientIp(req);
    if (!L.normFp(body.fp)) return L.send(res, 400, { ok: false, err: 'bad' });

    if (body.a === 'check') {
      const r = await checkAny(req, body);
      if (r.ok) return granted(res, r.tok, r.serial);
      return L.send(res, 200, { ok: false, err: r.err });
    }

    if (body.a === 'activate') {
      if (await L.blocked('lic', ip)) return L.send(res, 429, { ok: false, err: 'rate' });
      if (!L.safeEq(L.sha256(body.pw || ''), L.sha256(L.env('SITE_PASSWORD')))) {
        await L.noteFail('lic', ip);
        return L.send(res, 401, { ok: false, err: 'pw' });
      }
      const pk = L.parseKey(body.key);
      if (!pk) { await L.noteFail('lic', ip); return L.send(res, 401, { ok: false, err: 'key' }); }
      const rec = await getRec(pk.serial);
      if (rec.rev) return L.send(res, 403, { ok: false, err: 'revoked' });

      if (rec.th) {
        // already bound: only the same device may enter it again
        const r = await checkAny(req, body);
        if (r.ok && r.serial === pk.serial) return granted(res, r.tok, r.serial);
        return L.send(res, 403, { ok: false, err: 'used' });
      }
      const tok = pk.serial + '.' + require('crypto').randomBytes(24).toString('base64url');
      const won = await L.rcmd('HSETNX', 'lic:' + pk.serial, 'th', L.sha256(tok));
      if (won !== 1) return L.send(res, 403, { ok: false, err: 'used' }); // someone else bound it first
      await L.rcmd('HSET', 'lic:' + pk.serial,
        'fp', JSON.stringify(L.normFp(body.fp)), 'at', String(Date.now()), 'last', String(Date.now()),
        'ua', String(req.headers['user-agent'] || '').slice(0, 120));
      return granted(res, tok, pk.serial);
    }
    return L.send(res, 400, { ok: false, err: 'bad' });
  } catch (e) {
    console.error('license error', e && e.message);
    return L.send(res, 500, { ok: false, err: 'server', msg: String((e && e.message) || e).slice(0, 120) });
  }
};
