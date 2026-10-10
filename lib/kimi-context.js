// kimi-context.js — Kimi Code（月之暗面 Kimi for Coding，Kimi Code CLI）额度查询支持。
//
// 逆向实证（kimi.exe 0.40.1 内置 bundle）：
//   数据目录：$KIMI_CODE_HOME 优先，缺省 ~/.kimi-code；OAuth 凭证存于 <data>/oauth/kimi-code.json
//   （键位 access_token / refresh_token / expires_at）。
//   额度接口：GET <coding base>/usages —— 国内 https://api.kimi.com/coding/v1，
//   国际 https://api.kimi.ai/coding/v1；响应 {usage:{used,limit,resetTime,name},
//   limits:[{name,window:{duration,timeUnit},detail:{used,limit,resetTime}}],
//   boosterWallet:{balance:{type,amount,amountLeft},monthlyChargeLimit,monthlyUsed}}；
//   usage 为汇总窗口（缺 window 视为 1 周），limits 为 5h/周分窗口。
//   刷新：POST https://auth.kimi.com/api/oauth/token（grant_type=refresh_token，
//   client_id=17e5f671-d194-4dfb-9706-5516cb48c098）——refresh token 由上游轮换。
//
// 计价口径：取「额度最大的窗口」（周窗口上限；5h 窗口是瞬时速率限制，不代表周期可售额度）。

const fs = require('fs');
const path = require('path');
const os = require('os');

const KIMI_API_BASE = 'https://api.kimi.com/coding/v1';
const KIMI_INTL_API_BASE = 'https://api.kimi.ai/coding/v1';
const KIMI_OAUTH_BASE = 'https://auth.kimi.com';
const KIMI_OAUTH_TOKEN_PATH = '/api/oauth/token';
const KIMI_OAUTH_CLIENT_ID = '17e5f671-d194-4dfb-9706-5516cb48c098';
const KIMI_UA = 'kimi-code-cli/0.40.1';
const KIMI_WEB_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

/** Kimi Code CLI 数据目录（KIMI_CODE_HOME 可重定位，官方同语义） */
function kimiHomeDir() {
	if (process.env.KIMI_CODE_HOME && path.isAbsolute(process.env.KIMI_CODE_HOME)) return process.env.KIMI_CODE_HOME;
	return path.join(os.homedir(), '.kimi-code');
}

/** 区域 → coding base（user_data.region='intl' 走 api.kimi.ai；缺省国内） */
function kimiApiBase(region) {
	return region === 'intl' ? KIMI_INTL_API_BASE : KIMI_API_BASE;
}

/**
 * 读取本机 Kimi Code CLI 凭证（本地检测「从本机导入」用），两条来源：
 *   ① <data>/oauth/*.json —— `kimi login` 设备码登录写的 OAuth 凭证（access_token/refresh_token）。
 *   ② <data>/config.toml —— 手工/中转配置里的 api_key（[providers."kimi-for-coding"].api_key 或
 *      type="kimi" 的 provider；等价于环境变量 KIMI_API_KEY，两者对 /coding/v1 同权）。
 * 注意（09-21 实测）：Kimi 桌面端（%APPDATA%\kimi-desktop）的登录 token 只对 www.kimi.com 网页
 * 接口有效，调 api.kimi.com/coding/v1 恒 401 invalid_authentication_error → 不能作为 Kimi Code 凭证。
 * @returns {{access_token:string, refresh_token:string, file:string, source:'oauth'|'config'} | null}
 */
function readKimiCredentials(homeDir) {
	const base = homeDir || kimiHomeDir();
	// 0.40.1 起官方槽位在 <home>/credentials/<name>.json（oauth/ 为旧版式锁目录，仍兼容扫描）
	for (const sub of ['credentials', 'oauth']) {
		const dir = path.join(base, sub);
		let files = [];
		try {
			files = fs.readdirSync(dir).filter((f) => f.endsWith('.json'));
		} catch { continue; }
		for (const f of files) {
			try {
				const data = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
				if (data && typeof data === 'object' && typeof data.access_token === 'string' && data.access_token) {
					return {
						access_token: data.access_token,
						refresh_token: typeof data.refresh_token === 'string' ? data.refresh_token : '',
						expires_at: typeof data.expires_at === 'number' ? data.expires_at : 0,
						file: path.join(dir, f),
						source: sub,
					};
				}
			} catch { /* 单个文件损坏跳过 */ }
		}
	}
	// config.toml：api_key（简化 TOML 解析——只取 [providers.*] 段内的 api_key/type，够用且无依赖）
	try {
		const toml = fs.readFileSync(path.join(base, 'config.toml'), 'utf8');
		let current = null;
		const sections = [];
		for (const line of toml.split(/\r?\n/)) {
			const sec = /^\s*\[providers\.(?:"([^"]+)"|'([^']+)'|([^\]]+))\]\s*$/.exec(line);
			if (sec) {
				current = { name: sec[1] || sec[2] || sec[3], type: '', api_key: '' };
				sections.push(current);
				continue;
			}
			if (/^\s*\[/.test(line)) { current = null; continue; }
			if (!current) continue;
			const kv = /^\s*([A-Za-z_][\w-]*)\s*=\s*"([^"]*)"/.exec(line);
			if (!kv) continue;
			if (kv[1] === 'type') current.type = kv[2];
			if (kv[1] === 'api_key') current.api_key = kv[2];
		}
		// 跳过占位/测试值（如中转联调时的 cb-testkey-placeholder），避免把假 key 当凭证导入
		const isRealKey = (v) => typeof v === 'string' && v.length >= 16 && !/placeholder|testkey|^cb-test|^your[_-]?/i.test(v);
		const pick = (sections.find((s) => isRealKey(s.api_key) && s.type === 'kimi')
			|| sections.find((s) => isRealKey(s.api_key) && /kimi/i.test(s.name)));
		if (pick && pick.api_key) {
			return { access_token: pick.api_key, refresh_token: '', file: path.join(base, 'config.toml'), source: 'config' };
		}
	} catch { /* 无 config.toml */ }
	return null;
}

/**
 * 读取 Kimi 桌面端登录凭证（本机导入用）：%APPDATA%\kimi-desktop Local Storage leveldb 中的明文 JWT
 * （键 access_token / refresh_token；09-21 实测为明文，access 15 分钟有效、由桌面端自动续期）。
 * @returns {{access_token:string, refresh_token:string, expires_at:number|null} | null}
 */
function readKimiDesktopCredentials(appDataDir) {
	const appData = appDataDir || process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
	const dir = path.join(appData, 'kimi-desktop', 'Local Storage', 'leveldb');
	let files = [];
	try {
		files = fs.readdirSync(dir).filter((f) => /\.(log|ldb)$/i.test(f));
	} catch {
		return null;
	}
	const pick = { access_token: '', refresh_token: '' };
	for (const f of files) {
		let text;
		try { text = fs.readFileSync(path.join(dir, f), 'latin1'); } catch { continue; }
		for (const key of ['access_token', 'refresh_token']) {
			let idx = -1;
			let last = '';
			while ((idx = text.indexOf(key, idx + 1)) !== -1) {
				const m = /eyJ[\w-]+\.[\w-]+\.[\w-]+/.exec(text.slice(idx, idx + 4000));
				if (m) last = m[0];
			}
			if (last) pick[key] = last;
		}
	}
	if (!pick.access_token) return null;
	let expires = null;
	try {
		const pl = JSON.parse(Buffer.from(pick.access_token.split('.')[1], 'base64url').toString('utf8'));
		if (Number.isFinite(pl.exp)) expires = pl.exp * 1000;
	} catch { /* 非 JWT 或解析失败：仅回传 token */ }
	return { access_token: pick.access_token, refresh_token: pick.refresh_token, expires_at: expires };
}

/** usages 请求（CLI packages/kosong/src/usage.ts 同款端点） */
async function fetchKimiUsage(token, region, opts = {}) {
	const doFetch = opts._fetchImpl || (async (url, options) => {
		const { netRequest } = require('./net-helper');
		return netRequest(url, options);
	});
	return doFetch(kimiApiBase(region) + '/usages', {
		headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json', 'User-Agent': KIMI_UA },
		timeout: 20000,
	});
}

/** 网页 apiv2 RPC（Connect 协议：POST JSON + Connect-Protocol-Version: 1） */
async function fetchKimiWebRpc(path, token, opts = {}) {
	const doFetch = opts._fetchImpl || (async (url, options) => {
		const { netRequest } = require('./net-helper');
		return netRequest(url, options);
	});
	return doFetch('https://www.kimi.com/apiv2' + path, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Connect-Protocol-Version': '1',
			'Accept': 'application/json',
			'Authorization': `Bearer ${token}`,
			'Origin': 'https://www.kimi.com',
			'Referer': 'https://www.kimi.com/',
			'User-Agent': KIMI_WEB_UA,
		},
		body: '{}',
		timeout: 20000,
	});
}

/**
 * Kimi 桌面端账号兜底校验（网页 apiv2 会员/用量口径；与服务端 probeKimiDesktopSubscription 同构）。
 * 桌面端登录 token 调 coding 网关恒 401，但网页 apiv2 认 → 判定账号有效并回传套餐/计费周期与用量比例
 * （amountUsedRatio 无量纲）→ usage.remaining=null（额度不可查，渲染端按订阅口径展示）。
 * @returns {Promise<object|null>}
 */
async function probeKimiDesktopSubscription(token, opts = {}) {
	try {
		const statsResp = await fetchKimiWebRpc('/kimi.gateway.membership.v2.MembershipService/GetSubscriptionStats', token, opts);
		if (statsResp.status === 401 || statsResp.status === 403 || !statsResp.ok) return null;
		const stats = await statsResp.json().catch(() => null);
		const balance = stats && stats.subscriptionBalance && typeof stats.subscriptionBalance === 'object' ? stats.subscriptionBalance : null;
		if (!balance) return null;
		let goodsTitle = '';
		let membershipLevel = '';
		try {
			const subResp = await fetchKimiWebRpc('/kimi.gateway.membership.v2.MembershipService/GetSubscription', token, opts);
			if (subResp.ok) {
				const sub = await subResp.json().catch(() => null);
				const s = sub && sub.subscription && typeof sub.subscription === 'object' ? sub.subscription : null;
				if (s && s.goods && typeof s.goods === 'object') {
					if (typeof s.goods.title === 'string') goodsTitle = s.goods.title;
					if (typeof s.goods.membershipLevel === 'string') membershipLevel = s.goods.membershipLevel;
				}
			}
		} catch { /* 套餐详情失败不影响有效性判定 */ }
		const levelName = membershipLevel ? membershipLevel.replace(/^LEVEL_/, '').replace(/_/g, ' ') : '';
		const planName = [goodsTitle, levelName].filter(Boolean).join(' · ') || 'Kimi';
		const usage = {
			used: null,
			remaining: null,
			total: null,
			percentage: typeof balance.amountUsedRatio === 'number' ? Math.round(balance.amountUsedRatio * 100) : null,
			unit: 'credits',
			plan_tier_name: `Kimi ${planName}`,
		};
		if (typeof balance.expireTime === 'string' && balance.expireTime) {
			const ts = Date.parse(balance.expireTime);
			if (Number.isFinite(ts)) usage.next_reset_at = ts;
		}
		return { success: true, usage };
	} catch {
		return null;
	}
}

/** OAuth 续期（RT 轮换；明确拒绝 4xx → 永久失败，5xx/网络 → 临时故障） */
async function refreshKimiToken(refreshToken, region, opts = {}) {
	const doFetch = opts._fetchImpl || (async (url, options) => {
		const { netRequest } = require('./net-helper');
		return netRequest(url, options);
	});
	try {
		const base = region === 'intl' ? 'https://auth.kimi.ai' : KIMI_OAUTH_BASE;
		const resp = await doFetch(base + KIMI_OAUTH_TOKEN_PATH, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'Accept': 'application/json',
				'User-Agent': KIMI_UA,
			},
			body: new URLSearchParams({
				grant_type: 'refresh_token',
				refresh_token: refreshToken,
				client_id: KIMI_OAUTH_CLIENT_ID,
			}).toString(),
			timeout: 20000,
		});
		if (!resp.ok) {
			if (resp.status === 400 || resp.status === 401 || resp.status === 403) return { success: false, error: `HTTP ${resp.status}` };
			return { success: false, error: `刷新通道不可用(HTTP ${resp.status})，稍后重试` };
		}
		const data = await resp.json().catch(() => null);
		if (!data || !data.access_token) return { success: false, error: '刷新响应无 access_token 字段' };
		return { success: true, token: data.access_token, refresh_token: data.refresh_token || refreshToken };
	} catch (err) {
		return { success: false, error: `Token 刷新异常: ${err.message}` };
	}
}

/**
 * usages 响应 → 渲染端口径 usage（CLI parseManagedUsagePayload 同口径）。
 * 取额度最大的窗口（周窗口上限）作为计价与展示口径。
 * @returns {{usage: {used, remaining, total, percentage, unit, plan_tier_name}} | {error: string}}
 */
function parseKimiUsageData(data) {
	if (!data || typeof data !== 'object') return { error: '响应为空或格式错误' };
	const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
	const rows = [];
	const pushRow = (raw, extra = {}) => {
		if (!raw || typeof raw !== 'object') return;
		const used = num(raw.used);
		const limit = num(raw.limit);
		if (used === undefined && limit === undefined) return;
		rows.push({
			name: extra.name || (typeof raw.name === 'string' ? raw.name : 'usage'),
			used: used ?? 0,
			limit: limit ?? 0,
			resetAt: typeof raw.resetTime === 'string' ? raw.resetTime : undefined,
		});
	};
	pushRow(data.usage);
	if (Array.isArray(data.limits)) {
		for (const item of data.limits) {
			if (!item || typeof item !== 'object') continue;
			const detail = item.detail && typeof item.detail === 'object' ? item.detail : item;
			pushRow(detail, { name: typeof item.name === 'string' ? item.name : undefined });
		}
	}
	if (rows.length === 0) return { error: '缺少 usage/limits 额度字段（malformed 或套餐未开通）' };
	let best = rows[0];
	for (const r of rows) if (r.limit > best.limit) best = r;
	const remaining = Math.max(0, best.limit - best.used);
	const usage = {
		used: best.used,
		remaining,
		total: best.limit,
		percentage: best.limit > 0 ? Math.round((best.used / best.limit) * 100) : 0,
		unit: 'credits',
		plan_tier_name: best.name && best.name !== 'usage' ? `Kimi ${best.name}` : null,
	};
	const resetMs = best.resetAt ? Date.parse(best.resetAt) : NaN;
	if (Number.isFinite(resetMs)) usage.next_reset_at = resetMs;
	return { usage };
}

module.exports = {
	KIMI_API_BASE,
	KIMI_INTL_API_BASE,
	KIMI_OAUTH_BASE,
	KIMI_OAUTH_CLIENT_ID,
	kimiHomeDir,
	kimiApiBase,
	readKimiCredentials,
	readKimiDesktopCredentials,
	fetchKimiUsage,
	fetchKimiWebRpc,
	probeKimiDesktopSubscription,
	refreshKimiToken,
	parseKimiUsageData,
};
