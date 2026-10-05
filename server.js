// VANISH panel — zero deps. Run: node server.js
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

// Optional local configuration without adding a dependency. Shell environment wins over .env.
const envFile = path.join(__dirname, '.env');
if (fs.existsSync(envFile)) for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
  const match = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line);
  if (match && process.env[match[1]] === undefined) process.env[match[1]] = match[2].replace(/^['"]|['"]$/g, '');
}
const PORT = process.env.PORT || 3000;
const db = new DatabaseSync(process.env.DB || path.join(__dirname, 'vanish.db'));
const CRYPTO_CONFIRMATIONS = Math.max(1, Number(process.env.CRYPTO_CONFIRMATIONS || 12));
const CRYPTO_ORDER_TTL_MIN = Math.max(5, Number(process.env.CRYPTO_ORDER_TTL_MIN || 30));
const TRON_RECEIVE_ADDRESS = process.env.TRON_RECEIVE_ADDRESS || '';
const LTC_RECEIVE_ADDRESS = process.env.LTC_RECEIVE_ADDRESS || '';
const TRONGRID_API_KEY = process.env.TRONGRID_API_KEY || '';
const USDT_TRC20_CONTRACT = process.env.USDT_TRC20_CONTRACT || 'TXLAQ63Xg1NAzckPwKHvzw7CSEmLMEqcdj';
const TRX_USD_RATE = Number(process.env.TRX_USD_RATE || 0);
const LTC_USD_RATE = Number(process.env.LTC_USD_RATE || 0);
// A token IS the account. Only its sha256 is stored; the raw token is shown once at creation.
db.exec(`
  CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY, hash TEXT UNIQUE NOT NULL, prefix TEXT NOT NULL, label TEXT NOT NULL,
    role TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, last_login TEXT);
  CREATE TABLE IF NOT EXISTS signup_ips (ip TEXT PRIMARY KEY, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS balances (
    account_id INTEGER PRIMARY KEY, usdt_micros INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS crypto_balances (
    account_id INTEGER NOT NULL, asset TEXT NOT NULL, units INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(account_id, asset));
  CREATE TABLE IF NOT EXISTS account_credit (
    account_id INTEGER PRIMARY KEY, usd_cents INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS crypto_deposits (
    id TEXT PRIMARY KEY, account_id INTEGER NOT NULL, asset TEXT NOT NULL, expected_units INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', tx_hash TEXT UNIQUE, block_number INTEGER, usd_cents INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, credited_at TEXT);
  CREATE INDEX IF NOT EXISTS crypto_deposits_pending ON crypto_deposits(status, asset, expected_units, expires_at);
  CREATE TABLE IF NOT EXISTS update_logs (
    id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);
if (db.prepare('SELECT count(*) n FROM update_logs').get().n === 0) {
  db.prepare('INSERT INTO update_logs(title, body, created_at) VALUES (?, ?, ?), (?, ?, ?)').run(
    '실시간 대시보드 공개', '통계 카드와 실시간 그래프가 추가되었습니다.', '2026-10-04 09:00:00',
    '플랜 관리 개편', '사이드바에서 플랜과 잔액을 바로 확인할 수 있습니다.', '2026-09-28 09:00:00');
}
const depositColumns = db.prepare('PRAGMA table_info(crypto_deposits)').all().map(c => c.name);
if (depositColumns.includes('expected_micros') && !depositColumns.includes('asset')) {
  db.exec("ALTER TABLE crypto_deposits ADD COLUMN asset TEXT NOT NULL DEFAULT 'USDT_TRC20'; ALTER TABLE crypto_deposits ADD COLUMN expected_units INTEGER NOT NULL DEFAULT 0;");
  db.exec('UPDATE crypto_deposits SET expected_units=expected_micros WHERE expected_units=0');
}
if (!depositColumns.includes('usd_cents')) db.exec('ALTER TABLE crypto_deposits ADD COLUMN usd_cents INTEGER NOT NULL DEFAULT 0');

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const createAccount = role => {
  const token = 'VNSH-' + crypto.randomBytes(16).toString('hex').toUpperCase();
  // label = public token prefix, so accounts are still tellable apart without a nickname
  db.prepare('INSERT INTO accounts (hash, prefix, label, role) VALUES (?, ?, ?, ?)')
    .run(sha(token), token.slice(0, 11), token.slice(0, 11), role);
  return token;
};

// ponytail: first account ever becomes admin; create yours before exposing the panel
const isEmpty = () => !db.prepare('SELECT 1 FROM accounts').get();

// One token per IP, ever (survives restarts and account deletion).
// ponytail: uses the socket address; behind a reverse proxy read X-Forwarded-For instead
const claimIp = ip => db.prepare('INSERT OR IGNORE INTO signup_ips (ip) VALUES (?)').run(ip).changes === 1;

// ponytail: in-memory sessions, everyone logs out on restart; move to a table if that matters
const sessions = new Map();
const sidOf = req => /(?:^|;\s*)sid=([a-f0-9]+)/.exec(req.headers.cookie || '')?.[1];

const send = (res, code, body, headers = {}) => {
  res.writeHead(code, { 'Content-Type': 'application/json', ...headers });
  res.end(JSON.stringify(body));
};
const readJson = req => new Promise((ok, fail) => {
  let s = '';
  req.on('data', c => { s += c; if (s.length > 1e4) req.destroy(); });
  req.on('end', () => { try { ok(JSON.parse(s || '{}')); } catch { fail(new Error('bad json')); } });
});
const currentUser = req => {
  const id = sessions.get(sidOf(req));
  return id ? db.prepare('SELECT id, label, role, created_at FROM accounts WHERE id=?').get(id) : null;
};
const cookie = (sid, maxAge) => ({ 'Set-Cookie': `sid=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}` });
const adminOnly = fn => (req, res, u) => u?.role === 'admin' ? fn(req, res, u) : send(res, 403, { error: '권한 없음' });

const ASSETS = {
  USDT_TRC20: { decimals: 6, address: TRON_RECEIVE_ADDRESS },
  TRX: { decimals: 6, address: TRON_RECEIVE_ADDRESS },
  LTC: { decimals: 8, address: LTC_RECEIVE_ADDRESS },
};
const cryptoConfigured = asset => Boolean(ASSETS[asset]?.address);
const unitsFor = (amount, asset) => {
  const n = Number(amount), cfg = ASSETS[asset];
  if (!cfg || !Number.isFinite(n) || n <= 0 || n > 1000000) return null;
  const units = Math.round(n * 10 ** cfg.decimals);
  return Math.abs(n - units / 10 ** cfg.decimals) < 1e-10 ? units : null;
};
const amountOf = (units, asset) => Number(units) / 10 ** ASSETS[asset].decimals;
const usdRate = async asset => {
  if (asset === 'USDT_TRC20') return 1;
  const configured = asset === 'TRX' ? TRX_USD_RATE : LTC_USD_RATE;
  if (configured > 0) return configured;
  const id = asset === 'TRX' ? 'tron' : 'litecoin';
  const quote = await json(`https://api.coingecko.com/api/v3/simple/price?ids=${id}&vs_currencies=usd`);
  const rate = Number(quote[id]?.usd);
  if (!Number.isFinite(rate) || rate <= 0) throw new Error('USD 환율을 가져오지 못했습니다. TRX_USD_RATE 또는 LTC_USD_RATE를 설정하세요.');
  return rate;
};
const usdCentsFor = async (units, asset) => Math.round(amountOf(units, asset) * await usdRate(asset) * 100);
const expireCryptoOrders = () => db.prepare("UPDATE crypto_deposits SET status='expired' WHERE status='pending' AND expires_at <= CURRENT_TIMESTAMP").run();
const pendingDeposits = () => db.prepare("SELECT * FROM crypto_deposits WHERE status='pending' AND expires_at > CURRENT_TIMESTAMP").all();
const creditDeposit = deposit => {
  db.exec('BEGIN IMMEDIATE');
  try {
    const fresh = db.prepare("SELECT * FROM crypto_deposits WHERE id=? AND status='pending'").get(deposit.id);
    if (!fresh) { db.exec('COMMIT'); return false; }
    db.prepare("UPDATE crypto_deposits SET status='credited', tx_hash=?, block_number=?, credited_at=CURRENT_TIMESTAMP WHERE id=?")
      .run(deposit.txHash, deposit.blockNumber || null, deposit.id);
    db.prepare("INSERT INTO crypto_balances(account_id, asset, units, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP) ON CONFLICT(account_id, asset) DO UPDATE SET units=units+excluded.units, updated_at=CURRENT_TIMESTAMP")
      .run(deposit.account_id, deposit.asset, deposit.expected_units);
    db.prepare("INSERT INTO account_credit(account_id, usd_cents, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(account_id) DO UPDATE SET usd_cents=usd_cents+excluded.usd_cents, updated_at=CURRENT_TIMESTAMP")
      .run(deposit.account_id, fresh.usd_cents);
    db.exec('COMMIT');
    return true;
  } catch (e) { db.exec('ROLLBACK'); throw e; }
};
const tronHeaders = () => TRONGRID_API_KEY ? { 'TRON-PRO-API-KEY': TRONGRID_API_KEY } : {};
const json = async (url, headers = {}) => { const r = await fetch(url, { headers }); if (!r.ok) throw new Error('blockchain provider unavailable'); return r.json(); };
const scanTron = async (asset, deposits) => {
  if (!TRON_RECEIVE_ADDRESS || !deposits.length) return;
  const url = asset === 'USDT_TRC20'
    ? `https://api.trongrid.io/v1/accounts/${TRON_RECEIVE_ADDRESS}/transactions/trc20?only_confirmed=true&limit=200&contract_address=${USDT_TRC20_CONTRACT}`
    : `https://api.trongrid.io/v1/accounts/${TRON_RECEIVE_ADDRESS}/transactions?only_confirmed=true&only_to=true&limit=200`;
  const body = await json(url, tronHeaders());
  const wanted = new Map(deposits.map(d => [String(d.expected_units), d]));
  for (const tx of body.data || []) {
    const units = asset === 'USDT_TRC20' ? String(tx.value) : String(tx.raw_data?.contract?.[0]?.parameter?.value?.amount ?? '');
    const deposit = wanted.get(units);
    if (deposit) creditDeposit({ ...deposit, txHash: (tx.transaction_id || tx.txID || '').toLowerCase(), blockNumber: tx.blockNumber });
  }
};
const scanLtc = async deposits => {
  if (!LTC_RECEIVE_ADDRESS || !deposits.length) return;
  const body = await json(`https://api.blockcypher.com/v1/ltc/main/addrs/${LTC_RECEIVE_ADDRESS}/full?limit=50`);
  const wanted = new Map(deposits.map(d => [String(d.expected_units), d]));
  for (const tx of body.txs || []) for (const output of tx.outputs || []) {
    if (!output.addresses?.includes(LTC_RECEIVE_ADDRESS)) continue;
    const deposit = wanted.get(String(output.value));
    if (deposit) creditDeposit({ ...deposit, txHash: String(tx.hash).toLowerCase(), blockNumber: tx.block_height });
  }
};
let cryptoScan = Promise.resolve();
const scanCryptoDeposits = () => {
  cryptoScan = cryptoScan.catch(() => {}).then(async () => {
    expireCryptoOrders();
    const pending = pendingDeposits();
    await Promise.all([
      scanTron('USDT_TRC20', pending.filter(d => d.asset === 'USDT_TRC20')),
      scanTron('TRX', pending.filter(d => d.asset === 'TRX')),
      scanLtc(pending.filter(d => d.asset === 'LTC')),
    ].map(p => p.catch(e => console.error('crypto scan:', e.message))));
  });
  return cryptoScan;
};
const depositView = d => ({ id: d.id, asset: d.asset, amount: amountOf(d.expected_units, d.asset), usdAmount: d.usd_cents / 100, status: d.status, address: ASSETS[d.asset]?.address || '', expiresAt: d.expires_at, txHash: d.tx_hash });

// real server metrics
const startedAt = Date.now();
let requests = 0; // counts API hits since boot
const dbBytes = () => { try { return fs.statSync(process.env.DB || path.join(__dirname, 'vanish.db')).size; } catch { return 0; } };

const routes = {
  'POST /api/signup': (req, res) => {
    if (!claimIp(req.socket.remoteAddress)) return send(res, 429, { error: '이 IP에서는 이미 토큰을 생성했습니다' });
    send(res, 200, { token: createAccount(isEmpty() ? 'admin' : 'user') });
  },
  'POST /api/login': async (req, res) => {
    const { token } = await readJson(req);
    const a = typeof token === 'string' && db.prepare('SELECT id, label, role FROM accounts WHERE hash=?').get(sha(token.trim()));
    if (!a) return send(res, 401, { error: '유효하지 않은 토큰' });
    db.prepare('UPDATE accounts SET last_login=CURRENT_TIMESTAMP WHERE id=?').run(a.id);
    const sid = crypto.randomBytes(32).toString('hex');
    sessions.set(sid, a.id);
    send(res, 200, a, cookie(sid, 604800));
  },
  'POST /api/logout': (req, res) => {
    sessions.delete(sidOf(req));
    send(res, 200, {}, cookie('', 0));
  },
  'GET /api/me': (req, res, u) => u ? send(res, 200, u) : send(res, 401, { error: 'login' }),
  'GET /api/stats': (req, res, u) => {
    if (!u) return send(res, 401, { error: 'login' });
    send(res, 200, {
      users: db.prepare('SELECT count(*) n FROM accounts').get().n,
      sessions: sessions.size,
      requests,
      storageBytes: dbBytes(),
      uptimeSec: Math.floor((Date.now() - startedAt) / 1000),
    });
  },
  'GET /api/updates': (req, res, u) => {
    if (!u) return send(res, 401, { error: 'login' });
    send(res, 200, db.prepare('SELECT id, title, body, created_at FROM update_logs ORDER BY created_at DESC, id DESC').all());
  },
  'POST /api/updates': adminOnly(async (req, res) => {
    const { title, body } = await readJson(req);
    if (typeof title !== 'string' || typeof body !== 'string' || !title.trim() || !body.trim() || title.length > 100 || body.length > 1000) return send(res, 400, { error: '제목과 내용을 확인하세요.' });
    const result = db.prepare('INSERT INTO update_logs(title, body) VALUES (?, ?)').run(title.trim(), body.trim());
    send(res, 201, db.prepare('SELECT id, title, body, created_at FROM update_logs WHERE id=?').get(result.lastInsertRowid));
  }),
  'DELETE /api/updates': adminOnly(async (req, res) => {
    const { id } = await readJson(req);
    db.prepare('DELETE FROM update_logs WHERE id=?').run(Number(id));
    send(res, 200, {});
  }),
  'GET /api/crypto/deposits': async (req, res, u) => {
    if (!u) return send(res, 401, { error: 'login' });
    await scanCryptoDeposits();
    const deposits = db.prepare('SELECT * FROM crypto_deposits WHERE account_id=? ORDER BY created_at DESC LIMIT 20').all(u.id).map(depositView);
    const balances = db.prepare('SELECT asset, units FROM crypto_balances WHERE account_id=?').all(u.id)
      .map(b => ({ asset: b.asset, amount: amountOf(b.units, b.asset) }));
    const credit = db.prepare('SELECT usd_cents FROM account_credit WHERE account_id=?').get(u.id);
    send(res, 200, { configured: Object.fromEntries(Object.keys(ASSETS).map(a => [a, cryptoConfigured(a)])), deposits, balances, balanceUsd: (credit?.usd_cents || 0) / 100 });
  },
  'POST /api/crypto/deposits': async (req, res, u) => {
    if (!u) return send(res, 401, { error: 'login' });
    expireCryptoOrders();
    const { asset, amount } = await readJson(req);
    if (!cryptoConfigured(asset)) return send(res, 503, { error: '해당 코인 충전 주소가 아직 설정되지 않았습니다.' });
    let units = unitsFor(amount, asset);
    if (!units || units < 1) return send(res, 400, { error: '올바른 충전 금액을 입력하세요.' });
    // A one-unit nonce makes deposits to a shared address safely identifiable.
    const occupied = new Set(db.prepare("SELECT expected_units FROM crypto_deposits WHERE asset=? AND status='pending' AND expires_at>CURRENT_TIMESTAMP").all(asset).map(d => d.expected_units));
    while (occupied.has(units)) units++;
    let usdCents;
    try { usdCents = await usdCentsFor(units, asset); }
    catch (e) { return send(res, 503, { error: e.message }); }
    if (usdCents < 1) return send(res, 400, { error: '최소 충전 금액은 $0.01입니다.' });
    const id = crypto.randomUUID();
    db.prepare("INSERT INTO crypto_deposits(id, account_id, asset, expected_units, usd_cents, expires_at) VALUES (?, ?, ?, ?, ?, datetime('now', ?))")
      .run(id, u.id, asset, units, usdCents, `+${CRYPTO_ORDER_TTL_MIN} minutes`);
    send(res, 201, depositView(db.prepare('SELECT * FROM crypto_deposits WHERE id=?').get(id)));
  },
  'GET /api/accounts': adminOnly((req, res) =>
    send(res, 200, db.prepare('SELECT id, prefix, label, role, created_at, last_login FROM accounts ORDER BY id DESC').all())),
  'DELETE /api/accounts': adminOnly(async (req, res, u) => {
    const { id } = await readJson(req);
    if (id === u.id) return send(res, 400, { error: '자기 자신은 삭제할 수 없습니다' });
    db.prepare('DELETE FROM accounts WHERE id=?').run(Number(id));
    for (const [sid, aid] of sessions) if (aid === id) sessions.delete(sid);
    send(res, 200, {});
  }),
  'PATCH /api/accounts': adminOnly(async (req, res, u) => {
    const { id, role } = await readJson(req);
    if (!['user', 'admin'].includes(role) || Number(id) === u.id) return send(res, 400, { error: '자신의 권한은 변경할 수 없습니다.' });
    db.prepare('UPDATE accounts SET role=? WHERE id=?').run(role, Number(id));
    send(res, 200, {});
  }),
};

const html = fs.readFileSync(path.join(__dirname, 'index.html'));
setInterval(() => { scanCryptoDeposits(); }, 30000).unref();
http.createServer(async (req, res) => {
  const route = routes[`${req.method} ${req.url.split('?')[0]}`];
  if (route) requests++;
  if (!route) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(html);
  }
  try { await route(req, res, currentUser(req)); }
  catch (e) { console.error(e); if (!res.headersSent) send(res, 400, { error: '잘못된 요청' }); }
}).listen(PORT, () => console.log(`VANISH → http://localhost:${PORT}`));
