// doubao-context.js — 豆包工作平台(DoubaoWork) 本机凭证只读模块（开源版）。
// 开源版仅保留只读查询（读取本机登录态 + 账号有效性/额度探测）；注入/设备身份/上下文/重置不在开源范围。
// 契约来源（09-22 逆向 DoubaoWork CEF 客户端 v1.57.0，DoubaoWork.dll 字符串）：
//   · 登录态 = .doubao.com Passport cookie，落盘 %LOCALAPPDATA%\DoubaoWork\User Data\Default\Network\Cookies
//     （Chromium SQLite，v10 = DPAPI 主密钥 + AES-256-GCM，与扣子同构）。
//   · 校验 GET www.doubao.com/passport/account/info/v2/；额度 POST /commerce/benefit_supply/credit/get_credit_num_optional_tasks + GET /v1/shopping/subscriptions（防御式扫描）。

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const DOUBAO_API_BASE = 'https://www.doubao.com';
const DOUBAO_ACCOUNT_INFO_PATH = '/passport/account/info/v2/';
const DOUBAO_CREDIT_PATH = '/commerce/benefit_supply/credit/get_credit_num_optional_tasks';
const DOUBAO_SUBSCRIPTION_PATH = '/v1/shopping/subscriptions';
const DOUBAO_CLIENT_VERSION = '1.57.0';
const DOUBAO_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) DoubaoWork/1.57.0 Chrome/147.0.0.0 Safari/537.36';

const DOUBAO_AUTH_COOKIE_NAMES = [
	'is_staff_user', 'n_mh', 'sessionid', 'sessionid_ss', 'session_tlb_tag', 'sid_guard', 'sid_tt',
	'sid_ucp_v1', 'uid_tt', 'uid_tt_ss', 'ssid_ucp_v1', 'passport_csrf_token', 'passport_csrf_token_default',
	'passport_auth_status', 'passport_auth_status_ss', 'ttwid', 'odin_tt', 'has_biz_token',
];
const DOUBAO_REQUIRED_COOKIE_NAMES = ['sessionid', 'sid_guard', 'sid_tt', 'uid_tt'];

function doubaoUserDataDir() {
	const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local');
	return path.join(localAppData, 'DoubaoWork', 'User Data');
}

function doubaoAppDataDir() {
	const appdata = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
	return path.join(appdata, 'Doubao');
}

function doubaoCookiesDbPath() {
	return path.join(doubaoUserDataDir(), 'Default', 'Network', 'Cookies');
}

function doubaoUserId() {
	try {
		const obj = JSON.parse(fs.readFileSync(path.join(doubaoAppDataDir(), 'public_config.json'), 'utf8'));
		const u = obj && obj.text_picker && (obj.text_picker.current_user || (obj.text_picker.users || [])[0]);
		return u && typeof u.user_id === 'string' ? u.user_id.trim() : '';
	} catch { return ''; }
}

function normalizeDoubaoCookie(raw) {
	const t = typeof raw === 'string' ? raw.trim() : '';
	if (!t) return '';
	if (t.startsWith('{')) {
		try {
			const obj = JSON.parse(t);
			if (!obj || typeof obj !== 'object') return '';
			return Object.entries(obj).filter(([k, v]) => k && typeof v === 'string' && v).map(([k, v]) => `${k}=${v}`).join('; ');
		} catch { return ''; }
	}
	return t.replace(/\r?\n\s*/g, '; ').replace(/;\s*;+/g, ';').replace(/\s{2,}/g, ' ').replace(/;\s*$/, '');
}

function parseDoubaoCookieHeader(cookieHeader) {
	const out = [];
	for (const seg of normalizeDoubaoCookie(cookieHeader).split(';')) {
		const s = seg.trim();
		if (!s || s.indexOf('=') <= 0) continue;
		out.push({ name: s.slice(0, s.indexOf('=')).trim(), value: s.slice(s.indexOf('=') + 1).trim() });
	}
	return out;
}

function decryptV10(masterKey, data) {
	const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
	if (buf.slice(0, 3).toString('ascii') !== 'v10') throw new Error('cookie 值前缀不是 v10');
	const nonce = buf.slice(3, 15);
	const tag = buf.slice(buf.length - 16);
	const ct = buf.slice(15, buf.length - 16);
	const d = crypto.createDecipheriv('aes-256-gcm', masterKey, nonce);
	d.setAuthTag(tag);
	return Buffer.concat([d.update(ct), d.final()]).toString('utf8');
}

function doubaoMasterKey() {
	let Dpapi = null; try { Dpapi = require('@primno/dpapi'); } catch { Dpapi = null; }
	if (!Dpapi) throw new Error('缺少 @primno/dpapi，无法解密豆包 cookie');
	const localState = JSON.parse(fs.readFileSync(path.join(doubaoUserDataDir(), 'Local State'), 'utf8'));
	const b64 = localState && localState.os_crypt && localState.os_crypt.encrypted_key;
	if (!b64) throw new Error('Local State 中无 os_crypt.encrypted_key');
	const buf = Buffer.from(b64, 'base64');
	if (buf.slice(0, 5).toString('ascii') !== 'DPAPI') throw new Error('encrypted_key 前缀不是 DPAPI');
	const key = Buffer.from(Dpapi.unprotectData(buf.slice(5), null, 'CurrentUser'));
	if (key.length !== 32) throw new Error(`主密钥长度异常: ${key.length}`);
	return key;
}

let _SQL = null;
async function getSqlJs() {
	if (_SQL) return _SQL;
	const initSqlJs = require('sql.js');
	const wasmPath = require.resolve('sql.js/dist/sql-wasm.wasm');
	_SQL = await initSqlJs({ wasmBinary: new Uint8Array(fs.readFileSync(wasmPath)) });
	return _SQL;
}

async function readDoubaoCookies() {
	const dbPath = doubaoCookiesDbPath();
	const result = { dbPath, cookies: [], missing: [], warnings: [] };
	if (!fs.existsSync(dbPath)) { result.warnings.push('未找到 cookie 库（豆包工作平台尚未登录或未安装）: ' + dbPath); return result; }
	let dbBytes;
	try { dbBytes = fs.readFileSync(dbPath); } catch (e) {
		if (e && (e.code === 'EBUSY' || e.code === 'EPERM')) throw new Error('豆包工作平台正在运行，cookie 库被独占无法读取。请先退出豆包客户端后重试。');
		throw e;
	}
	const SQL = await getSqlJs();
	const db = new SQL.Database(dbBytes);
	try {
		const stmt = db.prepare("SELECT name, value, encrypted_value FROM cookies WHERE host_key LIKE '%doubao.com'");
		let masterKey = null;
		while (stmt.step()) {
			const [name, value, encryptedValue] = stmt.get();
			let plain = typeof value === 'string' && value ? value : '';
			if (!plain && encryptedValue) {
				try { if (!masterKey) masterKey = doubaoMasterKey(); plain = decryptV10(masterKey, encryptedValue); }
				catch (e) { result.warnings.push(`cookie ${name} 解密失败: ${e.message}`); continue; }
			}
			if (plain) result.cookies.push({ name: String(name), value: plain });
		}
		stmt.free();
	} finally { db.close(); }
	const have = new Set(result.cookies.map((c) => c.name));
	result.missing = DOUBAO_REQUIRED_COOKIE_NAMES.filter((n) => !have.has(n));
	return result;
}

async function readDoubaoCredentials() {
	const r = await readDoubaoCookies();
	if (!r.cookies.length || r.missing.length) return null;
	const header = r.cookies.filter((c) => DOUBAO_AUTH_COOKIE_NAMES.includes(c.name)).map((c) => `${c.name}=${c.value}`).join('; ');
	if (!header) return null;
	const userId = doubaoUserId();
	return { token: header, refresh_token: '', user_data: JSON.stringify({ ...(userId ? { device_id: userId } : {}) }) };
}

async function doubaoFetch(url, options) {
	const { netRequest } = require('./net-helper');
	return netRequest(url, options);
}

async function verifyDoubaoLogin(cookieHeader) {
	const cookie = normalizeDoubaoCookie(cookieHeader);
	if (!cookie) return { ok: false, status: 0 };
	try {
		const resp = await doubaoFetch(DOUBAO_API_BASE + DOUBAO_ACCOUNT_INFO_PATH, {
			headers: { 'Cookie': cookie, 'Accept': 'application/json', 'Referer': DOUBAO_API_BASE + '/', 'User-Agent': DOUBAO_UA },
			timeout: 15000,
		});
		if (!resp || !resp.ok) return { ok: false, status: resp ? resp.status : 0 };
		const body = await resp.json().catch(() => null);
		const bags = [body, body && body.data, body && body.data && body.data.data];
		let userId = '';
		for (const bag of bags) {
			if (!bag || typeof bag !== 'object') continue;
			for (const k of ['user_id_str', 'user_id', 'userId', 'uid']) {
				const v = bag[k];
				if (typeof v === 'string' && v.trim()) { userId = v.trim(); break; }
				if (typeof v === 'number' && Number.isFinite(v)) { userId = String(v); break; }
			}
			if (userId) break;
		}
		return { ok: !!userId, userId, status: resp.status };
	} catch (err) { return { ok: false, status: 0, error: err && err.message }; }
}

function scanDoubaoQuotaFields(body) {
	const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
	const found = { total: undefined, used: undefined, remaining: undefined, plan_name: '' };
	const remainKeys = ['remaining', 'remaining_num', 'remaining_quota', 'remaining_points', 'left', 'left_num', 'balance', 'available', 'credits', 'credit_num', 'remaining_credits'];
	const totalKeys = ['total', 'total_num', 'total_quota', 'total_points', 'quota', 'limit', 'total_credits', 'credit_total', 'credit_limit'];
	const usedKeys = ['used', 'used_num', 'used_quota', 'used_points', 'used_credits', 'consumed', 'consumed_num', 'consume'];
	const planKeys = ['plan_name', 'planName', 'plan', 'level', 'product_name', 'subscription_type'];
	const walk = (node, depth) => {
		if (!node || typeof node !== 'object' || depth > 3) return;
		if (Array.isArray(node)) { for (const it of node.slice(0, 20)) walk(it, depth + 1); return; }
		for (const [k, v] of Object.entries(node)) {
			if (v && typeof v === 'object') { walk(v, depth + 1); continue; }
			const lk = k.toLowerCase();
			if (found.remaining === undefined && remainKeys.includes(lk)) { const n = num(v); if (n !== undefined) { found.remaining = n; continue; } }
			if (found.total === undefined && totalKeys.includes(lk)) { const n = num(v); if (n !== undefined) { found.total = n; continue; } }
			if (found.used === undefined && usedKeys.includes(lk)) { const n = num(v); if (n !== undefined) { found.used = n; continue; } }
			if (!found.plan_name && planKeys.includes(lk) && typeof v === 'string' && v.trim()) found.plan_name = v.trim();
		}
	};
	walk(body, 0);
	return found;
}

async function fetchDoubaoQuota(cookieHeader) {
	const cookie = normalizeDoubaoCookie(cookieHeader);
	const headers = { 'Cookie': cookie, 'Content-Type': 'application/json', 'Accept': 'application/json', 'Origin': DOUBAO_API_BASE, 'Referer': DOUBAO_API_BASE + '/', 'User-Agent': DOUBAO_UA };
	try {
		const resp = await doubaoFetch(DOUBAO_API_BASE + DOUBAO_CREDIT_PATH, { method: 'POST', headers, body: '{}', timeout: 15000 });
		if (resp && resp.ok) {
			const data = await resp.json().catch(() => null);
			if (data && typeof data === 'object') {
				const f = scanDoubaoQuotaFields(data);
				if (f.remaining !== undefined || f.total !== undefined || f.used !== undefined) {
					const total = f.total !== undefined ? f.total : (f.remaining !== undefined && f.used !== undefined ? f.remaining + f.used : undefined);
					const used = f.used !== undefined ? f.used : (total !== undefined && f.remaining !== undefined ? Math.max(0, total - f.remaining) : 0);
					const remaining = f.remaining !== undefined ? f.remaining : (total !== undefined ? Math.max(0, total - used) : null);
					return { total: total ?? null, used, remaining, ...(f.plan_name ? { plan_name: f.plan_name } : {}) };
				}
			}
		}
	} catch {}
	try {
		const resp = await doubaoFetch(DOUBAO_API_BASE + DOUBAO_SUBSCRIPTION_PATH, { headers: { 'Cookie': cookie, 'Accept': 'application/json', 'Referer': DOUBAO_API_BASE + '/', 'User-Agent': DOUBAO_UA }, timeout: 15000 });
		if (resp && resp.ok) {
			const data = await resp.json().catch(() => null);
			if (data && typeof data === 'object') {
				const f = scanDoubaoQuotaFields(data);
				if (f.remaining !== undefined || f.total !== undefined) {
					const total = f.total ?? f.remaining; const remaining = f.remaining ?? total;
					return { total: total ?? null, used: 0, remaining, ...(f.plan_name ? { plan_name: f.plan_name } : {}) };
				}
				return { remaining: null, quota_unavailable_reason: 'no_quota_field', ...(f.plan_name ? { plan_name: f.plan_name } : {}) };
			}
		}
	} catch {}
	return { remaining: null, quota_unavailable_reason: 'no_quota_field' };
}

module.exports = {
	DOUBAO_API_BASE,
	DOUBAO_AUTH_COOKIE_NAMES,
	DOUBAO_REQUIRED_COOKIE_NAMES,
	doubaoUserDataDir,
	doubaoAppDataDir,
	doubaoCookiesDbPath,
	doubaoUserId,
	normalizeDoubaoCookie,
	parseDoubaoCookieHeader,
	decryptV10,
	doubaoMasterKey,
	readDoubaoCookies,
	readDoubaoCredentials,
	verifyDoubaoLogin,
	scanDoubaoQuotaFields,
	fetchDoubaoQuota,
};
