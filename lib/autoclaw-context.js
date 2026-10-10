// autoclaw-context.js — AutoClaw（智谱 AutoGLM 系 OpenClaw 换牌发行版）本机凭证只读模块（开源版）。
//
// 开源版仅保留**只读查询**能力（读取本机注入凭据 + 账号有效性/额度探测）；
// 凭据注入 / 设备身份轮换 / 上下文清理 / 全新重置不在开源范围内（见桌面端商业版）。
//
// 契约来源（09-21 逆向 F:\rhhj\AutoClaw\resources\gateway\openclaw 可读编译产物）：
//   · 状态目录：OPENCLAW_STATE_DIR 覆盖优先，否则 %USERPROFILE%\.openclaw-autoclaw
//   · 凭据形态：`<apiKeyId>.<secret>`（客户签名凭据，经 autoglm-proxy 中转，上游 provider 固定 zai）
//   · 本机落点：<stateDir>\request-headers.json 的 X-Authorization（运行时实时读取）；
//     备用：agents/<id>/agent/openclaw-agent.sqlite 的 auth_profile_store（doctor 迁移后的权威存储）
//   · 额度/有效性：GET https://api.z.ai/api/monitor/usage/quota/limit（Authorization: Bearer <key>）
//     —— 与 ZCode 的 BigModel monitor 通道同口径（limits[].{usage,remaining,percentage}）

const fs = require('fs');
const os = require('os');
const path = require('path');

const AUTOCLAW_QUOTA_BASE = 'https://api.z.ai';
const AUTOCLAW_QUOTA_PATH = '/api/monitor/usage/quota/limit';
const AUTOCLAW_UA = 'AutoClaw/1.19.0';
const AUTOCLAW_DEFAULT_MODEL = 'zai/glm-4.6';
const AUTOCLAW_STATE_DIRNAME = '.openclaw-autoclaw';

function autoclawStateDir() {
	const fromEnv = (process.env.OPENCLAW_STATE_DIR || '').trim();
	if (fromEnv) return path.resolve(fromEnv);
	return path.join(os.homedir(), AUTOCLAW_STATE_DIRNAME);
}

function autoclawRequestHeadersPath() {
	return path.join(autoclawStateDir(), 'request-headers.json');
}

function autoclawAgentDir(agentId = 'main') {
	return path.join(autoclawStateDir(), 'agents', agentId, 'agent');
}

/** 归一 API Key（去空白；容忍 "Bearer xxx" 前缀） */
function normalizeAutoclawKey(raw) {
	const t = typeof raw === 'string' ? raw.trim() : '';
	return t ? t.replace(/^Bearer\s+/i, '').trim() : '';
}

/** 读取 request-headers.json 里的 X-Authorization（本机当前注入值） */
function readInjectedAutoclawKey() {
	try {
		const obj = JSON.parse(fs.readFileSync(autoclawRequestHeadersPath(), 'utf8'));
		const headers = obj && typeof obj === 'object' && obj.headers && typeof obj.headers === 'object' ? obj.headers : {};
		for (const [k, v] of Object.entries(headers)) {
			if (k.toLowerCase() === 'x-authorization') return normalizeAutoclawKey(v);
		}
	} catch { /* 文件不存在/损坏 */ }
	return '';
}

/**
 * 读取本机 AutoClaw 凭据（只读）。
 * 顺序：request-headers.json → agents/<id>/agent/openclaw-agent.sqlite（auth_profile_store 单行 JSON）
 *      → 环境变量 ZAI_API_KEY / Z_AI_API_KEY。
 * @returns {Promise<{token:string, refresh_token:string, user_data:string, source:string}|null>}
 */
async function readAutoclawCredentials() {
	const stateDir = autoclawStateDir();
	const injected = readInjectedAutoclawKey();
	if (injected) return { token: injected, refresh_token: '', user_data: autoclawUserData(stateDir), source: 'request-headers.json' };

	const dbPath = path.join(autoclawAgentDir(), 'openclaw-agent.sqlite');
	if (fs.existsSync(dbPath)) {
		try {
			const initSqlJs = require('sql.js');
			const wasmPath = require.resolve('sql.js/dist/sql-wasm.wasm');
			const SQL = await initSqlJs({ wasmBinary: new Uint8Array(fs.readFileSync(wasmPath)) });
			const db = new SQL.Database(fs.readFileSync(dbPath));
			let storeJson = null;
			try {
				const stmt = db.prepare("SELECT store_json FROM auth_profile_store WHERE store_key = 'primary'");
				if (stmt.step()) storeJson = stmt.get()[0];
				stmt.free();
			} finally {
				db.close();
			}
			if (storeJson) {
				const store = JSON.parse(String(storeJson));
				const profiles = store && store.profiles && typeof store.profiles === 'object' ? store.profiles : {};
				const entries = Object.entries(profiles);
				const pick = entries.find(([id, p]) => /^zai(:|$)/i.test(id) && p && p.key)
					|| entries.find(([, p]) => p && p.type === 'api_key' && p.key);
				if (pick) {
					const key = normalizeAutoclawKey(pick[1].key);
					if (key) return { token: key, refresh_token: '', user_data: autoclawUserData(stateDir), source: 'auth_profile_store:' + pick[0] };
				}
			}
		} catch { /* 库不可读 → 继续兜底 */ }
	}
	for (const envKey of ['ZAI_API_KEY', 'Z_AI_API_KEY']) {
		const key = normalizeAutoclawKey(process.env[envKey]);
		if (key) return { token: key, refresh_token: '', user_data: autoclawUserData(stateDir), source: 'env:' + envKey };
	}
	return null;
}

/** user_data（中转基址 + 默认模型；仅注入端使用，只读场景留作库存元数据） */
function autoclawUserData(stateDir) {
	return JSON.stringify({ base_url: AUTOCLAW_QUOTA_BASE, model: AUTOCLAW_DEFAULT_MODEL, state_dir: stateDir });
}

/** monitor 口径 limits 归一：取剩余最大项；仅百分比时按 usage 折算 */
function pickMonitorQuota(limits) {
	const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
	if (!Array.isArray(limits) || limits.length === 0) return null;
	let best = null;
	for (const item of limits) {
		if (!item || typeof item !== 'object') continue;
		const usage = num(item.usage) ?? num(item.total) ?? num(item.currentValue);
		let remaining = num(item.remaining);
		if (remaining === undefined) {
			const pct = num(item.percentage);
			if (pct !== undefined && usage !== undefined) remaining = Math.max(0, Math.round(usage * (100 - pct) / 100));
		}
		if (remaining === undefined) continue;
		const total = usage ?? remaining;
		const cand = { total, used: Math.max(0, total - remaining), remaining };
		if (!best || cand.remaining > best.remaining) best = cand;
	}
	return best;
}

/**
 * 额度/有效性探测（api.z.ai monitor，Bearer <key>）。
 * @returns {Promise<{ok:boolean, status?:number, total?:number|null, used?:number|null,
 *   remaining?:number|null, plan_name?:string, error?:string, quota_unavailable_reason?:string}>}
 */
async function fetchAutoclawQuota(token) {
	const key = normalizeAutoclawKey(token);
	if (!key) return { ok: false, error: 'AutoClaw 凭证为空' };
	// OAuth 登录产生的 JWT（eyJ 开头）只对 autoclaw-proxy 中转有效，api.z.ai monitor 只认 GLM API Key
	// → 用 JWT 探 monitor 必 401，会被误判死号。短路为「有效但额度不可查」。
	if (key.startsWith('eyJ') && key.split('.').length === 3) {
		return { ok: true, remaining: null, total: null, used: null, quota_unavailable_reason: 'oauth_jwt_no_monitor' };
	}
	try {
		const { netRequest } = require('./net-helper');
		const resp = await netRequest(AUTOCLAW_QUOTA_BASE + AUTOCLAW_QUOTA_PATH, {
			headers: { 'Authorization': `Bearer ${key}`, 'Accept': 'application/json', 'User-Agent': AUTOCLAW_UA },
			timeout: 15000,
		});
		const status = resp ? resp.status : 0;
		if (!resp || !resp.ok) return { ok: false, status, error: `额度接口不可用(状态码 ${status})` };
		const data = await resp.json().catch(() => null);
		if (!data || typeof data !== 'object') return { ok: true, remaining: null, quota_unavailable_reason: 'unparsable' };
		const code = typeof data.code === 'number' ? data.code : undefined;
		if (data.success === false || (code !== undefined && code !== 200 && code !== 0)) {
			const msg = String(data.msg || data.message || '');
			const authFailed = code === 401 || /unauthorized|invalid[ _-]?(token|key|api)|认证失败|凭证无效/i.test(msg);
			return { ok: false, status, error: authFailed ? `凭证无效（${msg || 'HTTP 401'}）` : `额度查询失败: ${msg || '业务码 ' + code}` };
		}
		const limits = data.data && Array.isArray(data.data.limits) ? data.data.limits : null;
		const picked = pickMonitorQuota(limits);
		if (!picked) return { ok: true, total: null, used: null, remaining: null, quota_unavailable_reason: 'no_quota_field' };
		const out = { ok: true, ...picked };
		const planName = typeof data?.data?.planName === 'string' ? data.data.planName.trim() : '';
		if (planName) out.plan_name = planName;
		return out;
	} catch (err) {
		return { ok: false, error: `额度查询异常: ${err && err.message}` };
	}
}

module.exports = {
	AUTOCLAW_QUOTA_BASE,
	AUTOCLAW_QUOTA_PATH,
	AUTOCLAW_DEFAULT_MODEL,
	autoclawStateDir,
	autoclawRequestHeadersPath,
	autoclawAgentDir,
	normalizeAutoclawKey,
	readInjectedAutoclawKey,
	readAutoclawCredentials,
	autoclawUserData,
	pickMonitorQuota,
	fetchAutoclawQuota,
};
