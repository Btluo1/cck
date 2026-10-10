// zcode-context.js — ZCode（智谱 Z.ai 编程套餐 IDE）额度查询与本地凭证支持。
//
// 逆向实证（ZCode 3.10.x Electron 客户端 out/host/index.js）：
//   本地凭证 ~/.zcode/v2/credentials.json，值形如 enc:v1:<iv>.<tag>.<ct>（AES-256-GCM，
//   base64url 分段，密钥 = sha256(`zcode-credential-fallback:${platform}:${homedir}:${username}`)）；
//   关键键位：zcodejwttoken（会话 JWT）、oauth:zai:access_token（智谱 MaaS/套餐授权 token）、
//   oauth:zai:user_info。
//   额度接口：GET https://zcode.z.ai/api/v1/mcp/usage —— 需双 Bearer
//   （Authorization: Bearer <zcode jwt> + X-Bigmodel-Authorization: Bearer <套餐 token>），
//   响应 {code,msg,data:{used,limit,remaining,next_refresh_at,server_time,level}}（时间戳单位秒）；
//   客户端聚合口径 remaining = min(max(0,remaining), limit)。
//   兜底：GET https://api.z.ai/api/monitor/usage/quota/limit（BigModel monitor，仅需套餐 token）。
//
// 说明：ZCode 无对外 OAuth 刷新通道（会话 JWT 由客户端自行登录/续期），本模块一律只读。

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const ZCODE_API_BASE = 'https://zcode.z.ai';
const ZCODE_USAGE_PATH = '/api/v1/mcp/usage';
const ZCODE_MONITOR_BASE = 'https://api.z.ai';
const ZCODE_MONITOR_QUOTA_PATH = '/api/monitor/usage/quota/limit';
const ZCODE_CLIENT_HEADER = 'X-Bigmodel-Authorization';
const ZCODE_UA = 'zcode/3.10.1';

/** ZCode 数据目录（~/.zcode；客户端固定路径，无环境变量重定位） */
function zcodeHomeDir() {
	return path.join(os.homedir(), '.zcode');
}

/** 本地凭证文件路径（v2 版式；客户端升级换版式时此处同步） */
function zcodeCredentialsPath(homeDir) {
	return path.join(homeDir || zcodeHomeDir(), 'v2', 'credentials.json');
}

/** 解密 enc:v1 段（AES-256-GCM；非 enc:v1 前缀原样返回）。密钥派生与客户端一致，失败返回 null */
function decryptZcodeValue(value) {
	if (typeof value !== 'string') return null;
	if (!value.startsWith('enc:v1:')) return value;
	try {
		const secret = `zcode-credential-fallback:${os.platform()}:${os.homedir()}:${os.userInfo().username}`;
		const key = crypto.createHash('sha256').update(secret).digest();
		const [ivB64, tagB64, ctB64] = value.slice('enc:v1:'.length).split('.');
		if (!ivB64 || !tagB64 || !ctB64) return null;
		const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64url'));
		decipher.setAuthTag(Buffer.from(tagB64, 'base64url'));
		return Buffer.concat([decipher.update(Buffer.from(ctB64, 'base64url')), decipher.final()]).toString('utf8');
	} catch {
		return null;
	}
}

/**
 * 读取本机 ZCode 登录凭证（本地检测「从本机导入」用）。
 * 09-21 实测：登录后 credentials.json 键位为 zcodejwttoken + oauth:<active_provider>:access_token
 * （active_provider=bigmodel 时为 oauth:bigmodel:access_token，早期版本为 oauth:zai:access_token）
 * → 以 oauth:active_provider 为准取套餐 token，并兼容两种历史键位。
 * @returns {{jwt:string, zaiAccessToken:string, userInfo:string|null, provider:string} | null}
 */
function readZcodeCredentials(homeDir) {
	let raw;
	try {
		raw = JSON.parse(fs.readFileSync(zcodeCredentialsPath(homeDir), 'utf8'));
	} catch {
		return null;
	}
	if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
	const provider = String(decryptZcodeValue(raw['oauth:active_provider']) || '').trim();
	const jwt = decryptZcodeValue(raw['zcodejwttoken']);
	const planKeys = [
		...(provider ? [`oauth:${provider}:access_token`] : []),
		'oauth:bigmodel:access_token',
		'oauth:zai:access_token',
	];
	let zai = '';
	let usedProvider = provider;
	for (const k of planKeys) {
		if (!raw[k]) continue;
		const v = decryptZcodeValue(raw[k]);
		if (typeof v === 'string' && v) {
			zai = v;
			if (!usedProvider) usedProvider = k.slice('oauth:'.length, -':access_token'.length);
			break;
		}
	}
	const userInfoKey = provider ? `oauth:${provider}:user_info` : 'oauth:zai:user_info';
	return {
		jwt: typeof jwt === 'string' ? jwt : '',
		zaiAccessToken: zai,
		userInfo: decryptZcodeValue(raw[userInfoKey]) || decryptZcodeValue(raw['oauth:zai:user_info']) || null,
		provider: usedProvider,
	};
}

/** ZCode 套餐档位 → 展示名（统一加 ZCode 前缀，避免与服务端「Pro 双倍定价」约定撞名） */
function zcodePlanName(level) {
	const v = String(level || '').toLowerCase();
	if (!v) return '';
	if (v.includes('max')) return 'ZCode Max';
	if (v.includes('pro')) return 'ZCode Pro';
	if (v.includes('start') || v.includes('lite') || v.includes('basic')) return 'ZCode Start';
	return `ZCode ${level}`;
}

/** mcp/usage 请求（客户端 buildOfficialMcpAuthHeaders 同款：双 Bearer + 团队域头） */
async function fetchZcodeUsage(token, planToken, opts = {}) {
	const doFetch = opts._fetchImpl || (async (url, options) => {
		const { netRequest } = require('./net-helper');
		return netRequest(url, options);
	});
	const headers = {
		'Authorization': `Bearer ${token}`,
		'Accept': 'application/json',
		'User-Agent': ZCODE_UA,
	};
	if (planToken) headers[ZCODE_CLIENT_HEADER] = `Bearer ${planToken}`;
	const ud = opts.userData && typeof opts.userData === 'object' ? opts.userData : {};
	if (ud.target_type === 'TEAM' || (ud.organization_id && ud.project_id)) {
		headers['Bigmodel-Target-Type'] = 'TEAM';
		if (ud.organization_id) headers['Bigmodel-Organization'] = ud.organization_id;
		if (ud.project_id) headers['Bigmodel-Project'] = ud.project_id;
	}
	return doFetch(ZCODE_API_BASE + ZCODE_USAGE_PATH, { headers, timeout: 20000 });
}

/** monitor 额度接口（仅需套餐授权 token；mcp 通道 400/未开通时回退） */
async function fetchZcodeMonitorQuota(planToken, opts = {}) {
	const doFetch = opts._fetchImpl || (async (url, options) => {
		const { netRequest } = require('./net-helper');
		return netRequest(url, options);
	});
	return doFetch(ZCODE_MONITOR_BASE + ZCODE_MONITOR_QUOTA_PATH, {
		headers: { 'Authorization': `Bearer ${planToken}`, 'Accept': 'application/json', 'User-Agent': ZCODE_UA },
		timeout: 20000,
	});
}

/**
 * mcp/usage 响应 → 渲染端口径 usage。
 * @returns {{usage: {used, remaining, total, percentage, unit, plan_tier_name}} | {error: string}}
 */
function parseZcodeUsageData(data) {
	if (!data || typeof data !== 'object') return { error: '响应为空或格式错误' };
	if (typeof data.code === 'number' && data.code !== 0) {
		// 3101 coding plan is required（09-21 真机实测）：账号已登录但无 z.ai 编程套餐订阅
		if (data.code === 3101 || /coding plan/i.test(String(data.msg || ''))) {
			return { error: '该账号无编程套餐（coding plan is required）' };
		}
		return { error: `业务码 ${data.code}${data.msg ? `: ${data.msg}` : ''}` };
	}
	const d = data.data;
	if (!d || typeof d !== 'object') return { error: '响应缺少 data（无编程套餐授权或未登录套餐账号）' };
	const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
	// 10-04 对齐客户端 3.10.1 schema：额度在 data.total_usage.{used,limit,remaining}（嵌套），
	// 旧版/网关直出为顶层平铺 → 嵌套优先、缺失回落（与服务端 parseZcodeUsage 同口径）
	const src = d.total_usage && typeof d.total_usage === 'object' ? d.total_usage : d;
	const limit = num(src.limit);
	const used = num(src.used);
	let remaining = num(src.remaining);
	if (remaining === undefined && limit !== undefined && used !== undefined) remaining = limit - used;
	if (remaining === undefined) return { error: '响应缺少额度字段（malformed）' };
	remaining = Math.max(0, limit !== undefined ? Math.min(remaining, limit) : remaining);
	const total = limit ?? remaining;
	const usedVal = used ?? Math.max(0, total - remaining);
	return {
		usage: {
			used: usedVal,
			remaining,
			total,
			percentage: total > 0 ? Math.round((usedVal / total) * 100) : 0,
			unit: 'credits',
			plan_tier_name: zcodePlanName(d.level) || null,
			...(num(d.next_refresh_at) !== undefined ? { next_reset_at: num(d.next_refresh_at) * 1000 } : {}),
		},
	};
}

/**
 * monitor 额度响应 → 渲染端口径 usage（取剩余最大的窗口：周窗口为主计费周期，
 * 避免 5h 瞬时窗口低估可售额度）；解析不出返回 {error}。
 */
function parseZcodeMonitorQuotaData(data) {
	const limits = data && data.data && Array.isArray(data.data.limits) ? data.data.limits : null;
	if (!limits || limits.length === 0) return { error: '响应缺少 limits 字段' };
	const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
	let best = null;
	for (const item of limits) {
		if (!item || typeof item !== 'object') continue;
		const remaining = num(item.remaining);
		if (remaining === undefined) continue;
		const total = num(item.usage) ?? num(item.total) ?? num(item.currentValue) ?? remaining;
		if (!best || remaining > best.remaining) best = { remaining, total, used: Math.max(0, total - remaining) };
	}
	if (!best) return { error: 'limits 中无可用剩余额度字段' };
	return {
		usage: {
			used: best.used,
			remaining: best.remaining,
			total: best.total,
			percentage: best.total > 0 ? Math.round((best.used / best.total) * 100) : 0,
			unit: 'credits',
			plan_tier_name: zcodePlanName(data?.data?.level) || null,
		},
	};
}

module.exports = {
	ZCODE_API_BASE,
	ZCODE_USAGE_PATH,
	ZCODE_MONITOR_BASE,
	ZCODE_MONITOR_QUOTA_PATH,
	ZCODE_CLIENT_HEADER,
	zcodeHomeDir,
	zcodeCredentialsPath,
	decryptZcodeValue,
	readZcodeCredentials,
	zcodePlanName,
	fetchZcodeUsage,
	fetchZcodeMonitorQuota,
	parseZcodeUsageData,
	parseZcodeMonitorQuotaData,
};
