// coze-context.js — 扣子（Coze）桌面版本机凭证只读模块（开源版）。
//
// 开源版仅保留**只读查询**能力（读取本机登录态 + 账号有效性/额度探测）；
// 凭证注入 / 设备身份轮换 / 上下文清理 / 全新重置不在开源范围内（见桌面端商业版）。
//
// 契约来源（09-21 逆向 Coze 桌面版 1.1.43，Electron 39.2.7）：
//   · 登录态 = `.coze.cn` 域下的字节跳动 Passport cookie，落盘 %APPDATA%\Coze\Network\Cookies
//     （Chromium SQLite；值为 v10 = DPAPI 主密钥 + AES-256-GCM）。
//   · 有效性端点 GET https://www.coze.cn/passport/account/info/v2/（官方 verifyLoginSession 同款）。
//   · 额度 POST /api/coze_claw/user/pc_client_usage_status（生成式 SDK 无响应 schema → 防御式扫描）。

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const COZE_API_BASE = 'https://www.coze.cn';
const COZE_ACCOUNT_INFO_PATH = '/passport/account/info/v2/';
const COZE_USAGE_STATUS_PATH = '/api/coze_claw/user/pc_client_usage_status';
const COZE_CLIENT_VERSION = '1.1.43';
const COZE_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Coze/1.1.43 Chrome/142.0.0.0 Electron/39.2.7 Safari/537.36';

/** 应用认定的凭证 cookie 名单（app.asar AUTH_COOKIE_NAMES 原样搬运） */
const COZE_AUTH_COOKIE_NAMES = [
	'is_staff_user', 'n_mh', 'sessionid', 'sessionid_ss', 'session_tlb_tag', 'sid_guard', 'sid_tt',
	'sid_ucp_v1', 'uid_tt', 'uid_tt_ss', 'ssid_ucp_v1', 'passport_csrf_token', 'passport_csrf_token_default',
	'passport_auth_status', 'passport_auth_status_ss', 'ttwid', 'odin_tt', 'has_biz_token',
];
const COZE_REQUIRED_COOKIE_NAMES = ['sessionid', 'sid_guard', 'sid_tt', 'uid_tt'];

function cozeUserDataDir() {
	const appdata = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
	return path.join(appdata, 'Coze');
}

function cozeDataDir() {
	return path.join(os.homedir(), '.coze');
}

function cozeCookiesDbPath() {
	return path.join(cozeUserDataDir(), 'Network', 'Cookies');
}

/** 本机设备标识（~/.coze/desktop/device.json） */
function cozeDeviceId() {
	try {
		const obj = JSON.parse(fs.readFileSync(path.join(cozeDataDir(), 'desktop', 'device.json'), 'utf8'));
		return typeof obj.deviceId === 'string' ? obj.deviceId.trim() : '';
	} catch {
		return '';
	}
}

/** 归一 cookie 串（`k=v; k=v` / 换行分隔 / JSON 对象三形态） */
function normalizeCozeCookie(raw) {
	const t = typeof raw === 'string' ? raw.trim() : '';
	if (!t) return '';
	if (t.startsWith('{')) {
		try {
			const obj = JSON.parse(t);
			if (!obj || typeof obj !== 'object') return '';
			return Object.entries(obj)
				.filter(([k, v]) => k && typeof v === 'string' && v)
				.map(([k, v]) => `${k}=${v}`)
				.join('; ');
		} catch {
			return '';
		}
	}
	return t.replace(/\r?\n\s*/g, '; ').replace(/;\s*;+/g, ';').replace(/\s{2,}/g, ' ').replace(/;\s*$/, '');
}

/** cookie 串 → [{name, value}] */
function parseCozeCookieHeader(cookieHeader) {
	const out = [];
	for (const seg of normalizeCozeCookie(cookieHeader).split(';')) {
		const s = seg.trim();
		if (!s) continue;
		const eq = s.indexOf('=');
		if (eq <= 0) continue;
		out.push({ name: s.slice(0, eq).trim(), value: s.slice(eq + 1).trim() });
	}
	return out;
}

/** 会话标识（uid_tt → uid_tt_ss → sessionid，与桌面端同优先级） */
function cozeCookieSessionKey(cookieHeader) {
	const map = new Map(parseCozeCookieHeader(cookieHeader).map((c) => [c.name, c.value]));
	return map.get('uid_tt') || map.get('uid_tt_ss') || map.get('sessionid') || '';
}

/**
 * 读取 os_crypt 主密钥（%APPDATA%\Coze\Local State 的 os_crypt.encrypted_key → DPAPI）。
 * @primno/dpapi 为可选依赖：缺失时抛出可读错误（仅明文 cookie 可读）。
 */
function cozeMasterKey() {
	let Dpapi = null;
	try { Dpapi = require('@primno/dpapi'); } catch { Dpapi = null; }
	if (!Dpapi) throw new Error('缺少 @primno/dpapi，无法解密本机 cookie（可 npm i @primno/dpapi 后重试）');
	const localState = JSON.parse(fs.readFileSync(path.join(cozeUserDataDir(), 'Local State'), 'utf8'));
	const b64 = localState && localState.os_crypt && localState.os_crypt.encrypted_key;
	if (!b64) throw new Error('Local State 中无 os_crypt.encrypted_key');
	const buf = Buffer.from(b64, 'base64');
	if (buf.slice(0, 5).toString('ascii') !== 'DPAPI') throw new Error('encrypted_key 前缀不是 DPAPI');
	const key = Buffer.from(Dpapi.unprotectData(buf.slice(5), null, 'CurrentUser'));
	if (key.length !== 32) throw new Error(`主密钥长度异常: ${key.length}（期望 32）`);
	return key;
}

/** 解密 v10（AES-256-GCM：nonce 12 + ct + tag 16） */
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

/** 惰性加载 sql.js（开源版依赖内已有） */
let _SQL = null;
async function getSqlJs() {
	if (_SQL) return _SQL;
	const initSqlJs = require('sql.js');
	const wasmPath = require.resolve('sql.js/dist/sql-wasm.wasm');
	const wasmBinary = new Uint8Array(fs.readFileSync(wasmPath));
	_SQL = await initSqlJs({ wasmBinary });
	return _SQL;
}

/**
 * 读取本机扣子登录 cookie（只读）。客户端运行中时 cookie 库被独占（EBUSY）→ 需先退出客户端。
 * @returns {Promise<{dbPath:string, cookies:Array<{name:string,value:string}>, missing:string[], warnings:string[]}>}
 */
async function readCozeCookies() {
	const dbPath = cozeCookiesDbPath();
	const result = { dbPath, cookies: [], missing: [], warnings: [] };
	if (!fs.existsSync(dbPath)) {
		result.warnings.push('未找到 cookie 库（扣子桌面版尚未登录或未安装）: ' + dbPath);
		return result;
	}
	const SQL = await getSqlJs();
	const db = new SQL.Database(fs.readFileSync(dbPath));
	try {
		const stmt = db.prepare("SELECT name, value, encrypted_value FROM cookies WHERE host_key LIKE '%coze.cn'");
		let masterKey = null;
		while (stmt.step()) {
			const [name, value, encryptedValue] = stmt.get();
			let plain = typeof value === 'string' && value ? value : '';
			if (!plain && encryptedValue) {
				try {
					if (!masterKey) masterKey = cozeMasterKey();
					plain = decryptV10(masterKey, encryptedValue);
				} catch (e) {
					result.warnings.push(`cookie ${name} 解密失败: ${e.message}`);
					continue;
				}
			}
			if (plain) result.cookies.push({ name: String(name), value: plain });
		}
		stmt.free();
	} finally {
		db.close();
	}
	const have = new Set(result.cookies.map((c) => c.name));
	result.missing = COZE_REQUIRED_COOKIE_NAMES.filter((n) => !have.has(n));
	return result;
}

/** 本机凭证（cookie 串 + device_id）；未登录/缺字段返回 null */
async function readCozeCredentials() {
	const r = await readCozeCookies();
	if (!r.cookies.length || r.missing.length) return null;
	const header = r.cookies.filter((c) => COZE_AUTH_COOKIE_NAMES.includes(c.name)).map((c) => `${c.name}=${c.value}`).join('; ');
	if (!header) return null;
	const deviceId = cozeDeviceId();
	return { token: header, refresh_token: '', user_data: JSON.stringify({ ...(deviceId ? { device_id: deviceId } : {}) }) };
}

async function cozeFetch(url, options) {
	const { netRequest } = require('./net-helper');
	return netRequest(url, options);
}

/** 登录态在线校验（200 且含 user_id_str = 有效） */
async function verifyCozeLogin(cookieHeader) {
	const cookie = normalizeCozeCookie(cookieHeader);
	if (!cookie) return { ok: false, status: 0 };
	try {
		const resp = await cozeFetch(COZE_API_BASE + COZE_ACCOUNT_INFO_PATH, {
			headers: { 'Cookie': cookie, 'Accept': 'application/json', 'Referer': COZE_API_BASE + '/', 'User-Agent': COZE_UA },
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
	} catch (err) {
		return { ok: false, status: 0, error: err && err.message };
	}
}

/** 防御式扫描额度数值（字段名随版本漂移） */
function scanCozeQuotaFields(body) {
	const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
	const found = { total: undefined, used: undefined, remaining: undefined, plan_name: '' };
	const remainKeys = ['remaining', 'remaining_quota', 'remaining_points', 'remaining_credits', 'left', 'balance', 'available', 'credits'];
	const totalKeys = ['total', 'total_quota', 'total_points', 'total_credits', 'quota', 'limit'];
	const usedKeys = ['used', 'used_quota', 'used_points', 'used_credits', 'consumed'];
	const planKeys = ['plan_name', 'planName', 'plan', 'level', 'product_name'];
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

/** 额度探测（best-effort；不可读时 remaining=null，仅报有效性） */
async function fetchCozeQuota(cookieHeader, deviceId) {
	const cookie = normalizeCozeCookie(cookieHeader);
	const headers = {
		'Cookie': cookie,
		'Content-Type': 'application/json',
		'Accept': 'application/json',
		'x-space-client': 'pc',
		'x-coze-version': '3.5',
		'x-coze-version-name': COZE_CLIENT_VERSION,
		'Origin': COZE_API_BASE,
		'Referer': COZE_API_BASE + '/',
		'User-Agent': COZE_UA,
	};
	const did = deviceId || cozeDeviceId();
	if (did) headers['x-coze-desktop'] = did;
	try {
		const resp = await cozeFetch(COZE_API_BASE + COZE_USAGE_STATUS_PATH, { method: 'POST', headers, body: '{}', timeout: 15000 });
		if (!resp || !resp.ok) return { remaining: null, quota_unavailable_reason: 'usage_status_http_' + (resp ? resp.status : 0) };
		const data = await resp.json().catch(() => null);
		if (!data || typeof data !== 'object') return { remaining: null, quota_unavailable_reason: 'usage_status_unparsable' };
		const f = scanCozeQuotaFields(data);
		if (f.remaining === undefined && f.total === undefined && f.used === undefined) {
			return { remaining: null, quota_unavailable_reason: 'no_quota_field', ...(f.plan_name ? { plan_name: f.plan_name } : {}) };
		}
		const total = f.total !== undefined ? f.total : (f.remaining !== undefined && f.used !== undefined ? f.remaining + f.used : undefined);
		const used = f.used !== undefined ? f.used : (total !== undefined && f.remaining !== undefined ? Math.max(0, total - f.remaining) : 0);
		const remaining = f.remaining !== undefined ? f.remaining : (total !== undefined ? Math.max(0, total - used) : null);
		return { total: total ?? null, used, remaining, ...(f.plan_name ? { plan_name: f.plan_name } : {}) };
	} catch (err) {
		return { remaining: null, quota_unavailable_reason: 'usage_status_error', error: err && err.message };
	}
}

module.exports = {
	COZE_API_BASE,
	COZE_ACCOUNT_INFO_PATH,
	COZE_USAGE_STATUS_PATH,
	COZE_AUTH_COOKIE_NAMES,
	COZE_REQUIRED_COOKIE_NAMES,
	cozeUserDataDir,
	cozeDataDir,
	cozeCookiesDbPath,
	cozeDeviceId,
	normalizeCozeCookie,
	parseCozeCookieHeader,
	cozeCookieSessionKey,
	cozeMasterKey,
	decryptV10,
	readCozeCookies,
	readCozeCredentials,
	verifyCozeLogin,
	scanCozeQuotaFields,
	fetchCozeQuota,
};
