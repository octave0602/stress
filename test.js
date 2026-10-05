// Smoke test: node test.js
const { spawn } = require('node:child_process');
const assert = require('node:assert');
const PORT = 3999;
// 127.0.0.1 and ::1 show up as two different client IPs, enough to test the per-IP limit
const V4 = `http://127.0.0.1:${PORT}`, V6 = `http://[::1]:${PORT}`;
const srv = spawn(process.execPath, ['server.js'], { cwd: __dirname, env: { ...process.env, PORT, DB: ':memory:' } });
let out = '';
srv.stdout.on('data', d => out += d);

const call = (method, url, body, cookie, base = V4) => fetch(base + url, {
  method, headers: { 'Content-Type': 'application/json', ...(cookie && { cookie }) }, body: body && JSON.stringify(body),
}).then(async r => ({ status: r.status, body: await r.json(), cookie: r.headers.get('set-cookie')?.split(';')[0] }));

(async () => {
  while (!out.includes('VANISH')) await new Promise(r => setTimeout(r, 50));

  const adminTok = (await call('POST', '/api/signup')).body.token;
  assert.equal((await call('POST', '/api/signup')).status, 429, 'one token per IP');
  const token = (await call('POST', '/api/signup', null, null, V6)).body.token;
  assert.match(token, /^VNSH-[0-9A-F]{32}$/);

  assert.equal((await call('POST', '/api/login', { token: 'VNSH-nope' })).status, 401);
  const a = await call('POST', '/api/login', { token: adminTok });
  assert.equal(a.body.role, 'admin', 'first account is admin');
  const u = await call('POST', '/api/login', { token });
  assert.equal(u.body.role, 'user');
  assert.equal((await call('GET', '/api/accounts', null, u.cookie)).status, 403, 'user cannot list');

  assert.equal((await call('GET', '/api/stats')).status, 401, 'stats need login');
  assert.equal((await call('GET', '/api/crypto/deposits', null, u.cookie)).status, 200, 'deposit history is private');
  assert.equal((await call('POST', '/api/crypto/deposits', { asset: 'USDT_TRC20', amount: '10' }, u.cookie)).status, 503, 'unconfigured wallets cannot accept deposits');
  assert.equal((await call('POST', '/api/crypto/deposits', { asset: 'DOGE', amount: '10' }, u.cookie)).status, 503, 'only configured supported assets are accepted');
  const stats = (await call('GET', '/api/stats', null, a.cookie)).body;
  assert.equal(stats.users, 2);
  assert.ok(stats.requests > 0 && typeof stats.storageBytes === 'number');

  const list = (await call('GET', '/api/accounts', null, a.cookie)).body;
  assert.equal(list.length, 2);
  assert.ok(!JSON.stringify(list).includes(token), 'raw token never listed');
  assert.equal((await call('DELETE', '/api/accounts', { id: a.body.id }, a.cookie)).status, 400, 'no self-delete');

  await call('DELETE', '/api/accounts', { id: u.body.id }, a.cookie);
  assert.equal((await call('GET', '/api/me', null, u.cookie)).status, 401, 'deleted account session dies');
  assert.equal((await call('POST', '/api/login', { token })).status, 401, 'deleted token cannot log in');
  assert.equal((await call('POST', '/api/signup', null, null, V6)).status, 429, 'IP stays used after deletion');
  console.log('ok');
})().catch(e => { console.error(e); process.exitCode = 1; }).finally(() => srv.kill());
