// minimax-context.js — MiniMax Code（MiniMax Agent 桌面端 mcode / 编程套餐）额度查询支持。
//
// 逆向实证（MiniMax Agent 3.0.73 Electron 包 @mavis/oauth-core + openplatform 客户端）：
//   账号体系：account.minimax.cn（国内）/ account.minimax.io（国际），OAuth 设备码流程
//   （/oauth2/device/code、/oauth2/token、/oauth2/revoke；client_id=mcode-public，
//    scope=agent.default，audience=agent-backend）。
//   本地凭证：<userData>/auth/<buildEnv>/<region>/<clientId>/auth.json（旧版式 <userData>/auth/auth.json），
//   内容 {schemaVersion:1, records:{"<service>\0<account>": {access_token, refresh_token, ...}}}。
//   额度接口（开放平台）：
//     GET {platform}/v1/api/openplatform/coding_plan/remains
//       → {model_remains:[{model_name,end_time,current_interval_total_count,
//          current_interval_used_count,current_interval_status,weekly_end_time,
//          current_weekly_total_count,current_weekly_used_count,current_weekly_status}]}
//       （current_interval_status/weekly_status = 3 表示该窗口不限量）
//     GET {platform}/backend/account/token_plan/remains_percent → 百分比口径（无量纲，不用于计价）
//   平台域名：platform.minimaxi.com（国内）/ platform.minimax.io（国际）。

const fs = require('fs');
const path = require('path');
const os = require('os');

const MINIMAX_API_BASE = 'https://platform.minimaxi.com';
const MINIMAX_INTL_API_BASE = 'https://platform.minimax.io';
// 主通道：网页后端 token plan 积分（09-21 实测；Origin/Referer 必填）
const MINIMAX_WEB_BASE = 'https://www.minimaxi.com';
const MINIMAX_WEB_INTL_BASE = 'https://www.minimax.io';
const MINIMAX_TOKEN_PLAN_CREDIT_PATH = '/backend/account/token_plan_credit';
const MINIMAX_REMAINS_PATH = '/v1/api/openplatform/coding_plan/remains';
const MINIMAX_REMAINS_PERCENT_PATH = '/backend/account/token_plan/remains_percent';
const MINIMAX_OAUTH_BASE = 'https://account.minimax.cn';
const MINIMAX_OAUTH_INTL_BASE = 'https://account.minimax.io';
const MINIMAX_OAUTH_TOKEN_PATH = '/oauth2/token';
const MINIMAX_OAUTH_CLIENT_ID = 'mcode-public';
const MINIMAX_UA = 'MiniMax-Agent/3.0.73';

/** 区域 → 开放平台 base */
function minimaxApiBase(region) {
	return region === 'intl' ? MINIMAX_INTL_API_BASE : MINIMAX_API_BASE;
}

/**
 * MiniMax 凭证数据目录候选。
 * 09-21 实测：OAuth 凭证落在本地运行时数据目录 `~/.minimax/auth/<env>/<region>/mcode-public/auth.json`
 * （dataDir 由 resolveLocalRuntimeDataDir() 解析：MINIMAX_DATA_DIR/MAVIS_DATA_DIR 环境变量优先，
 *  缺省 ~/.minimax，与 Electron userData 无关）；Electron userData 候选保留作历史版式兜底。
 */
function minimaxUserDataDirs() {
	const appData = process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming');
	const envDir = (process.env.MINIMAX_DATA_DIR || process.env.MAVIS_DATA_DIR || '').trim();
	return [
		...(envDir && path.isAbsolute(envDir) ? [envDir] : []),
		path.join(os.homedir(), '.minimax'),
		path.join(appData, '@mmx-agent', 'electron'),
		path.join(appData, '@mmx-agent'),
		path.join(appData, 'MiniMax Agent'),
		path.join(appData, 'mmx-agent'),
	].filter((p) => {
		try { return fs.statSync(p).isDirectory(); } catch { return false; }
	});
}

/** 递归收集 <dir>/auth 下的 auth.json（新版式在 auth/<env>/<region>/<clientId>/ 深层） */
function collectMinimaxAuthFiles(root, out = [], depth = 0) {
	if (depth > 5) return out;
	let entries;
	try {
		entries = fs.readdirSync(root, { withFileTypes: true });
	} catch {
		return out;
	}
	for (const e of entries) {
		const full = path.join(root, e.name);
		if (e.isDirectory()) collectMinimaxAuthFiles(full, out, depth + 1);
		else if (e.name === 'auth.json') out.push(full);
	}
	return out;
}

/**
 * 读取本机 MiniMax 登录凭证（本地检测「从本机导入」用）。
 * auth.json 的 records 以 "<service>\0<account>" 为键；09-21 实测记录为 camelCase
 * （{schemaVersion,accessToken,refreshToken,tokenType,clientId,scopes,audience,expiresAtMs,generation,...}），
 * 旧版式可能为 snake_case → 两种键位都取。
 * @returns {{access_token:string, refresh_token:string, expires_at:number|null, file:string} | null}
 */
function readMinimaxCredentials(userDataDirs) {
	const roots = Array.isArray(userDataDirs) && userDataDirs.length > 0 ? userDataDirs : minimaxUserDataDirs();
	for (const root of roots) {
		for (const file of collectMinimaxAuthFiles(path.join(root, 'auth'))) {
			try {
				const data = JSON.parse(fs.readFileSync(file, 'utf8'));
				const records = data && typeof data.records === 'object' && data.records !== null ? data.records : null;
				if (!records) continue;
				for (const rec of Object.values(records)) {
					if (!rec || typeof rec !== 'object') continue;
					const at = rec.accessToken || rec.access_token;
					const rt = rec.refreshToken || rec.refresh_token;
					if (typeof at === 'string' && at) {
						return {
							access_token: at,
							refresh_token: typeof rt === 'string' ? rt : '',
							expires_at: Number.isFinite(rec.expiresAtMs) ? rec.expiresAtMs : null,
							file,
						};
					}
				}
			} catch { /* 单文件损坏跳过 */ }
		}
	}
	return null;
}

/**
 * 编程套餐积分请求（主通道，09-21 真机实测 200）。
 * 必须带 Origin/Referer（www 域），否则服务端按未登录返回 401 {base_resp:{status_code:1004}}。
 */
async function fetchMinimaxTokenPlanCredit(token, region, opts = {}) {
	const doFetch = opts._fetchImpl || (async (url, options) => {
		const { netRequest } = require('./net-helper');
		return netRequest(url, options);
	});
	const base = region === 'intl' ? 'https://www.minimax.io' : 'https://www.minimaxi.com';
	return doFetch(base + MINIMAX_TOKEN_PLAN_CREDIT_PATH, {
		headers: {
			'Authorization': `Bearer ${token}`,
			'Accept': 'application/json',
			'User-Agent': MINIMAX_UA,
			'Origin': base,
			'Referer': `${base}/`,
		},
		timeout: 20000,
	});
}

/**
 * token_plan_credit 响应 → 渲染端口径 usage（09-21 真机实测形状）。
 * {total_credits,used_credits,remaining_credits,api_key,balance_breakdown,base_resp}
 */
function parseMinimaxTokenPlanCreditData(data) {
	if (!data || typeof data !== 'object') return { error: '响应为空或格式错误' };
	const br = data.base_resp && typeof data.base_resp === 'object' ? data.base_resp : null;
	if (br && typeof br.status_code === 'number' && br.status_code !== 0) {
		return { error: `业务码 ${br.status_code}${br.status_msg ? `: ${br.status_msg}` : ''}` };
	}
	const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
	const total = num(data.total_credits);
	const used = num(data.used_credits);
	let remaining = num(data.remaining_credits);
	if (remaining === undefined && total !== undefined && used !== undefined) remaining = total - used;
	if (remaining === undefined) return { error: '响应缺少 credits 字段（malformed）' };
	const totalVal = total ?? remaining;
	const usedVal = used ?? Math.max(0, totalVal - remaining);
	return {
		usage: {
			used: usedVal,
			remaining: Math.max(0, remaining),
			total: totalVal,
			percentage: totalVal > 0 ? Math.round((usedVal / totalVal) * 100) : 0,
			unit: 'credits',
			plan_tier_name: 'MiniMax Code',
		},
	};
}

/** 编程套餐余量请求（旧版式回退；企业账号带 GroupId 头） */
async function fetchMinimaxRemains(token, region, groupId, opts = {}) {
	const doFetch = opts._fetchImpl || (async (url, options) => {
		const { netRequest } = require('./net-helper');
		return netRequest(url, options);
	});
	const base = minimaxApiBase(region);
	return doFetch(base + MINIMAX_REMAINS_PATH, {
		headers: {
			'Authorization': `Bearer ${token}`,
			'Accept': 'application/json',
			'User-Agent': MINIMAX_UA,
			'Origin': base,
			'Referer': `${base}/`,
			...(groupId ? { 'GroupId': groupId } : {}),
		},
		timeout: 20000,
	});
}

/** 百分比口径余量（仅用于「额度不可查」时的有效性佐证，不参与计价） */
async function fetchMinimaxRemainsPercent(token, region, opts = {}) {
	const doFetch = opts._fetchImpl || (async (url, options) => {
		const { netRequest } = require('./net-helper');
		return netRequest(url, options);
	});
	return doFetch(minimaxApiBase(region) + MINIMAX_REMAINS_PERCENT_PATH, {
		headers: { 'Authorization': `Bearer ${token}`, 'Accept': 'application/json', 'User-Agent': MINIMAX_UA },
		timeout: 20000,
	});
}

/** OAuth 续期（RT 轮换；明确拒绝 4xx → 永久失败，5xx/网络 → 临时故障） */
async function refreshMinimaxToken(refreshToken, region, opts = {}) {
	const doFetch = opts._fetchImpl || (async (url, options) => {
		const { netRequest } = require('./net-helper');
		return netRequest(url, options);
	});
	try {
		const base = region === 'intl' ? MINIMAX_OAUTH_INTL_BASE : MINIMAX_OAUTH_BASE;
		const resp = await doFetch(base + MINIMAX_OAUTH_TOKEN_PATH, {
			method: 'POST',
			headers: {
				'Content-Type': 'application/x-www-form-urlencoded',
				'Accept': 'application/json',
				'User-Agent': MINIMAX_UA,
			},
			body: new URLSearchParams({
				grant_type: 'refresh_token',
				refresh_token: refreshToken,
				client_id: MINIMAX_OAUTH_CLIENT_ID,
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
 * coding_plan/remains 响应 → 渲染端口径 usage（客户端 queryPercent 同口径）。
 * 取 general 模型项（客户端同优先级：general → 无名通用项 → 首项）；status=3 视为不限量；
 * 仅百分比口径（无次数）→ remaining/null（额度不可查：只校验有效性，由管理员手动定价）。
 * @returns {{usage: object} | {error: string}}
 */
function parseMinimaxRemainsData(data) {
	if (!data || typeof data !== 'object') return { error: '响应为空或格式错误' };
	const list = Array.isArray(data.model_remains) ? data.model_remains : null;
	if (!list || list.length === 0) return { error: '响应缺少 model_remains（套餐未开通或无余量数据）' };
	const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
	const pick = list.find((m) => m && m.model_name === 'general')
		|| list.find((m) => m && !m.model_name)
		|| list[0];
	if (!pick || typeof pick !== 'object') return { error: '余量项格式错误（malformed）' };
	const model = typeof pick.model_name === 'string' && pick.model_name ? pick.model_name : 'general';
	const planName = `MiniMax ${model}`;
	if (pick.current_interval_status === 3) {
		return { usage: { used: 0, remaining: Infinity, total: 999999, percentage: 0, unit: 'credits', plan_tier_name: planName } };
	}
	let total = num(pick.current_interval_total_count);
	let used = num(pick.current_interval_used_count);
	if (total === undefined) {
		total = num(pick.current_weekly_total_count);
		used = num(pick.current_weekly_used_count);
	}
	if (total === undefined || total <= 0) {
		// 仅百分比口径 → 额度不可查（渲染端展示「订阅套餐/按窗口限额」口径，管理员手动定价）
		return { usage: { used: null, remaining: null, total: null, percentage: num(pick.current_interval_used_percent) ?? null, unit: 'credits', plan_tier_name: planName } };
	}
	const usedVal = used ?? 0;
	const usage = {
		used: usedVal,
		remaining: Math.max(0, total - usedVal),
		total,
		percentage: total > 0 ? Math.round((usedVal / total) * 100) : 0,
		unit: 'credits',
		plan_tier_name: planName,
	};
	const end = pick.end_time || pick.weekly_end_time;
	if (typeof end === 'string' && end) {
		const ts = Date.parse(end);
		if (Number.isFinite(ts)) usage.next_reset_at = ts;
	}
	return { usage };
}

module.exports = {
	MINIMAX_API_BASE,
	MINIMAX_INTL_API_BASE,
	MINIMAX_WEB_BASE,
	MINIMAX_WEB_INTL_BASE,
	MINIMAX_TOKEN_PLAN_CREDIT_PATH,
	MINIMAX_REMAINS_PATH,
	MINIMAX_REMAINS_PERCENT_PATH,
	MINIMAX_OAUTH_BASE,
	MINIMAX_OAUTH_CLIENT_ID,
	minimaxApiBase,
	minimaxUserDataDirs,
	readMinimaxCredentials,
	fetchMinimaxTokenPlanCredit,
	parseMinimaxTokenPlanCreditData,
	fetchMinimaxRemains,
	fetchMinimaxRemainsPercent,
	refreshMinimaxToken,
	parseMinimaxRemainsData,
};
