'use strict';
// Open https://YOUR-SITE/api/ping in a browser to see whether the API is alive and configured.
const L = require('./_lib');
module.exports = async (req, res) => {
  L.noStore(res);
  const env = {
    SITE_PASSWORD: !!L.env('SITE_PASSWORD'),
    KEY_SECRET: L.env('KEY_SECRET').length >= 16,
    APP_KEY: !!L.appKey(),
    ADMIN_SECRET: L.env('ADMIN_SECRET').length >= 12,
    REDIS_VARS: !!L.redisConf(),
  };
  let redis = 'belum disambung';
  if (env.REDIS_VARS) {
    try { redis = (await L.rcmd('PING')) === 'PONG' ? 'ok' : 'jawapan pelik'; }
    catch (e) { redis = 'ralat: ' + String(e.message).slice(0, 100); }
  }
  L.send(res, 200, { ok: true, api: 'aktif', node: process.version, time: new Date().toISOString(), env, redis });
};
