// qwenwork-context.js — 千问办公(QwenWork CN) 额度查询支持：账号上下文获取 + deviceToken 续期 + 解析。
// 开源版仅保留只读查询链路（登录注入/设备身份/上下文清理不在开源范围内）。

const QWENWORK_GATEWAY = 'https://gateway.qwenwork.cn';
const QWENWORK_CONTEXT_PATH = '/api/v1/adapter/user/account-context?include=user,plan,quota';
// 官方客户端 refreshDeviceToken: POST openApiBase + /api/v1/deviceToken/refresh
// （个人 target='c'，企业 target='biz'+team_id；响应 device_token??token + refresh_token）
const QWENWORK_REFRESH_PATH = '/api/v1/deviceToken/refresh';
const QWENWORK_UA = 'qoderwork/1.0.1';

/**
 * 查询千问办公账号上下文（官方客户端 fetchUserInfo/fetchQuotaUsage 同端点同口径）。
 * 401/403 → {success:false, status}（调用方决定是否用 refreshToken 续期）。
 * @returns {Promise<{success: boolean, user?: object, plan?: object, quota?: object, error?: string, status?: number}>}
 */
async function fetchQwenworkAccountContext(token, _fetchImpl) {
	const doFetch = _fetchImpl || (async (url, opts) => {
		const { netRequest } = require('./net-helper');
		return netRequest(url, opts);
	});
	try {
		const resp = await doFetch(QWENWORK_GATEWAY + QWENWORK_CONTEXT_PATH, {
			headers: {
				'Authorization': `Bearer ${token}`,
				'Accept': 'application/json',
				'User-Agent': QWENWORK_UA,
				'X-QwenWork-Version': '1.0.1',
				'X-QwenWork-Platform': 'win32',
			},
			timeout: 15000,
		});
		if (resp.status === 401 || resp.status === 403) {
			return { success: false, status: resp.status, error: `HTTP ${resp.status}` };
		}
		if (!resp.ok) {
			return { success: false, status: resp.status, error: `HTTP ${resp.status}` };
		}
		const data = await resp.json();
		// adapter 包裹 {data:{user,plan,quota,...}}（客户端 normalizeAccountContext 同款解包）
		const ctx = data && typeof data.data === 'object' && data.data !== null && !Array.isArray(data.data) ? data.data : data;
		const user = (ctx && typeof ctx.user === 'object' && ctx.user !== null) ? ctx.user : {};
		if (!user.id || typeof user.id !== 'string') {
			return { success: false, error: 'account-context 缺少 user.id' };
		}
		return {
			success: true,
			ctx,
			user,
			plan: (ctx && typeof ctx.plan === 'object' && ctx.plan !== null) ? ctx.plan : {},
			quota: (ctx && typeof ctx.quota === 'object' && ctx.quota !== null) ? ctx.quota : null,
		};
	} catch (e) {
		return { success: false, error: e && e.message ? e.message : String(e) };
	}
}

/**
 * 千问办公 deviceToken 续期（个人账号 target='c'，官方客户端 refreshDeviceToken 同款；
 * 企业账号需 target='biz'+team_id，不适用本链路）。
 * 响应 token/device_token 二选一字段，refresh_token 缺省时回退原值。
 * @returns {Promise<{success: boolean, token?: string, refresh_token?: string, error?: string}>}
 */
async function refreshQwenworkToken(refreshToken, _fetchImpl) {
	const doFetch = _fetchImpl || (async (url, opts) => {
		const { netRequest } = require('./net-helper');
		return netRequest(url, opts);
	});
	try {
		const resp = await doFetch(QWENWORK_GATEWAY + QWENWORK_REFRESH_PATH, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'Accept': 'application/json',
				'User-Agent': QWENWORK_UA,
			},
			body: JSON.stringify({ refresh_token: refreshToken, target: 'c' }),
			timeout: 15000,
		});
		if (!resp.ok) {
			const data = await resp.json().catch(() => ({}));
			return { success: false, error: data.errorMessage || data.message || `HTTP ${resp.status}` };
		}
		const data = await resp.json();
		const newToken = data.token || data.device_token;
		if (!newToken) return { success: false, error: '刷新响应无 token 字段' };
		return { success: true, token: newToken, refresh_token: data.refresh_token || refreshToken };
	} catch (e) {
		return { success: false, error: e && e.message ? e.message : String(e) };
	}
}

/**
 * 解析 account-context 为渲染端口径 usage。
 * remaining 取 quota.remaining，缺省回退 user_quota+add_on_quota 分项之和；
 * plan_name 取 plan.name，企业版（pid=qwen-office-enterprise / is_biz）兜底。
 * @returns {{usage: {used, remaining, total, percentage, unit, plan_tier_name}, plan_expires_at?: string}}
 *         | {{error: string}} malformed 时
 */
function parseQwenworkQuotaContext(ctx) {
	const user = ctx && typeof ctx.user === 'object' && ctx.user !== null ? ctx.user : {};
	const plan = ctx && typeof ctx.plan === 'object' && ctx.plan !== null ? ctx.plan : {};
	const quota = ctx && typeof ctx.quota === 'object' && ctx.quota !== null ? ctx.quota : null;
	if (!quota) return { error: '千问办公响应缺少 quota 字段' };
	const num = (v) => (typeof v === 'number' && Number.isFinite(v)) ? v : undefined;
	const userQuota = quota.user_quota || quota.userQuota || {};
	const addOnQuota = quota.add_on_quota || quota.addOnQuota || {};
	let remaining = num(quota.remaining);
	if (remaining === undefined) {
		const uq = num(userQuota.remaining);
		const aq = num(addOnQuota.remaining);
		if (uq === undefined && aq === undefined) {
			return { error: '千问办公 quota 缺少 remaining/user_quota 字段（malformed）' };
		}
		remaining = (uq ?? 0) + (aq ?? 0);
	}
	// 分项汇总：仅当分项确实带总量/用量时才采用（Free 套餐网关返回 total/used 均为 null，
	// 且无 user_quota/add_on_quota 分项 → 保持 null，渲染端只显示剩余，不再误显示 0/0）
	const subTotal = (num(userQuota.total) ?? 0) + (num(addOnQuota.total) ?? 0);
	const subUsed = (num(userQuota.used) ?? 0) + (num(addOnQuota.used) ?? 0);
	const total = num(quota.total) ?? (subTotal > 0 ? subTotal : null);
	const used = num(quota.used) ?? (subUsed > 0 ? subUsed : null);
	const planId = typeof plan.pid === 'string' ? plan.pid : '';
	const isEnterprise = planId === 'qwen-office-enterprise' || user.is_biz === true || user.isBiz === true;
	const usage = {
		used,
		remaining,
		total,
		percentage: (num(total) != null && total > 0 && num(used) != null) ? Math.round((used / total) * 100) : 0,
		unit: '积分',
		plan_tier_name: (typeof plan.name === 'string' && plan.name) || (isEnterprise ? '企业版' : '个人版'),
	};
	const result = { usage };
	if (typeof plan.next_due_date === 'string' && plan.next_due_date) {
		result.plan_expires_at = plan.next_due_date;
	}
	return result;
}

module.exports = {
	QWENWORK_GATEWAY,
	QWENWORK_CONTEXT_PATH,
	QWENWORK_REFRESH_PATH,
	fetchQwenworkAccountContext,
	refreshQwenworkToken,
	parseQwenworkQuotaContext,
};
