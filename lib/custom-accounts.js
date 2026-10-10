// 自定义账号（用户自有凭证）本地管理：验证 / 增 / 删 / 查。
// 凭证只存本机（local-store safeStorage/DPAPI 加密），不上传后端；启动走 client-launcher 既有链路。
// store 依赖注入（{ get, set, delete }），便于无 Electron 环境单测。

const CATEGORY_LABELS = {
	qoder: 'Qoder Work CN',
	qodercn: 'Qoder IDE CN',
	qoderapp: 'Qoder CN App',
	qoder_intl: 'Qoder 国际版',
	trae_cn: 'TRAE CN',
	trae_solo: 'TRAE CN (SOLO)',
	trae_intl: 'Trae 国际版',
	codebuddy_cn: 'CodeBuddy/WorkBuddy CN',
	workbuddy: 'CodeBuddy/WorkBuddy CN',
	codebuddy_intl: 'CodeBuddy 国际版',
	qwenwork: '千问办公',
	codex: 'Codex CLI',
	cursor: 'Cursor IDE',
	kiro: 'Kiro IDE',
	zcode: 'ZCode (智谱)',
	kimi: 'Kimi Code',
	minimax: 'MiniMax Code',
	coze: '扣子 (Coze)',
	autoclaw: 'AutoClaw (智谱)',
	doubao: '豆包工作平台 (Doubao)',
};
const QODER_CATS = ['qoder', 'qodercn', 'qoderapp', 'qoder_intl'];
const CB_CATS = ['codebuddy_cn', 'workbuddy', 'codebuddy_intl'];
const QWENWORK_CATS = ['qwenwork'];
const CODEX_CATS = ['codex'];
const CURSOR_CATS = ['cursor'];
const KIRO_CATS = ['kiro'];
const ZCODE_CATS = ['zcode'];
const KIMI_CATS = ['kimi'];
const MINIMAX_CATS = ['minimax'];
const COZE_CATS = ['coze'];
const AUTOCLAW_CATS = ['autoclaw'];
const DOUBAO_CATS = ['doubao'];
// 无刷新通道分类 → refresh_token 可空：
//   zcode = 会话 JWT；coze = 登录 cookie（过期只能重新登录）；autoclaw = GLM/AutoClaw API Key（不可刷新）
const REFRESH_OPTIONAL_CATS = ['zcode', 'coze', 'autoclaw', 'doubao'];
// 他家族 JWT 签发域（新分类误投拦截共用；09-21 追加字节系 bytedance/coze）
const FOREIGN_ISS_MARKERS = ['openai.com', 'cursor.com', 'anysphere', 'codebuddy', 'workbuddy', 'tencent', 'qoder', 'qwenwork', 'trae', 'marscode', 'aliyun', 'authing', 'kiro.dev', 'bytedance', 'coze'];
/** 扣子凭证形态判定：登录 cookie 串（含 = 且带 Passport 会话字段） */
function looksLikeCozeCookie(token) {
	const t = typeof token === 'string' ? token.trim() : '';
	if (!t || !t.includes('=')) return false;
	return /(^|[;\s])(sessionid|sid_guard|sid_tt|uid_tt|sessionid_ss|uid_tt_ss)=/.test(t);
}

/** 解析 JWT payload（不验签，读 iss；非三段式 JWT 返回 null） */
function parseJwt(token) {
	if (!token || typeof token !== 'string' || !token.startsWith('eyJ')) return null;
	try {
		const parts = token.split('.');
		if (parts.length !== 3) return null;
		const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
		return payload && typeof payload === 'object' ? payload : null;
	} catch {
		return null;
	}
}

/** 按 JWT iss 识别 CB 家族签发域（与服务端 detectCbCategory 同口径） */
function detectCbCategory(token) {
	const iss = typeof parseJwt(token)?.iss === 'string' ? parseJwt(token).iss : '';
	if (iss.includes('workbuddy.cn')) return 'workbuddy';
	if (iss.includes('codebuddy.cn')) return 'codebuddy_cn';
	if (iss.includes('codebuddy.ai')) return 'codebuddy_intl';
	return null;
}

/** 按 JWT iss 识别 Codex 凭证（auth.openai.com 签发；与服务端 validateCodexCredential 同口径） */
function detectCodexCategory(token) {
	const iss = typeof parseJwt(token)?.iss === 'string' ? parseJwt(token).iss : '';
	return iss.includes('auth.openai.com') ? 'codex' : null;
}

/**
 * 识别 Cursor 凭证（Auth0/WorkOS 签发三段式 JWT；与服务端 validateCursorCredential 同口径）：
 * sub 去 provider 前缀（| 分隔）后 user_ 开头，或 payload 含 https://api.cursor.com 命名空间声明。
 */
function detectCursorCategory(token) {
	const jwt = parseJwt(token);
	if (!jwt) return null;
	const sub = typeof jwt.sub === 'string' ? jwt.sub : '';
	if (!sub) return null;
	const norm = sub.split('|').pop() || '';
	const hasCursorClaim = Object.keys(jwt).some((k) => k.includes('api.cursor.com'));
	return (norm.startsWith('user_') || hasCursorClaim) ? 'cursor' : null;
}

/**
 * 识别 Kiro 凭证（AWS auth.desktop.kiro.dev 签发 JWT；iss 含 kiro.dev）。
 * Kiro 签发域形态无法穷举 → 仅做正向识别（iss 含 kiro.dev），不做强校验；
 * 与服务端 validateKiroCredential 互补：服务端用 KIRO_FOREIGN_ISS_MARKERS 拦截他家族误投。
 */
function detectKiroCategory(token) {
	const jwt = parseJwt(token);
	if (!jwt) return null;
	const iss = typeof jwt.iss === 'string' ? jwt.iss : '';
	if (iss.includes('kiro.dev')) return 'kiro';
	return null;
}

/**
 * 识别 ZCode 凭证（智谱 Z.ai 编程套餐，客户端会话 JWT；与服务端 validateZcodeCredential 同口径）：
 * 三段式 JWT、无固定 iss（客户端自签），只做「是 JWT 且非他家族签发」的形态判定，真实性靠在线验证。
 */
function detectZcodeCategory(token) {
	const jwt = parseJwt(token);
	if (!jwt) return null;
	const iss = typeof jwt.iss === 'string' ? jwt.iss.toLowerCase() : '';
	if (iss && FOREIGN_ISS_MARKERS.some((m) => iss.includes(m))) return null;
	return 'zcode';
}

/** 判断 token 是否为已知他家族凭证（新分类误投拦截共用；未知 iss 返回 null 交由在线验证判定） */
function foreignFamilyOf(token) {
	const jwt = parseJwt(token);
	if (!jwt) return null;
	const iss = typeof jwt.iss === 'string' ? jwt.iss.toLowerCase() : '';
	if (!iss) return null;
	if (iss.includes('openai.com')) return 'Codex CLI';
	if (iss.includes('cursor')) return 'Cursor IDE';
	if (iss.includes('kiro.dev')) return 'Kiro IDE';
	if (iss.includes('trae') || iss.includes('marscode')) return 'Trae 系';
	if (iss.includes('qoder')) return 'Qoder 系';
	if (iss.includes('qwenwork')) return '千问办公';
	const cb = detectCbCategory(token);
	if (cb != null) return CATEGORY_LABELS[cb];
	return null;
}

/**
 * 校验并归一化自定义账号输入。
 * @param {{category, token, refresh_token, label?, user_data?}} input
 * @returns {{ok: true, account: {id, category, token, refresh_token, label, user_data, created_at}}}
 *          | {{ok: false, error: string, category?: string}}
 *   - Qoder 家族：dt-/drt- 前缀强校验；误投 JWT 拒绝并提示切换分类
 *   - Trae/CB 家族：token 须为 eyJ 三段式；CB 家族按 iss 自动归类（workbuddy→codebuddy_cn 统一归类，
 *     codebuddy.ai→codebuddy_intl），跨家族误投拒绝（与服务端批量导入口径一致）
 *   - 千问办公：OAuth 凭证无固定前缀，仅拦截 Qoder/CB/Codex/Cursor 跨家族误投，真实性靠在线验证
 *   - Codex：access_token 须为 auth.openai.com 签发 JWT（iss 识别），其余家族误投拒绝
 *   - Cursor：access_token 须为 Cursor Auth0/WorkOS 签发 JWT（sub 形如 google-oauth2|user_xxx
 *     或含 https://api.cursor.com 声明），其余家族误投拒绝
 *   - Kiro：access_token 须为 Kiro 签发 JWT（iss 含 kiro.dev 或未知 iss 放行），他家族误投拒绝
 *   - user_data 可选（Trae 设备密钥对等）；填写时必须是合法 JSON 对象
 */
function validateCustomAccount(input, existing = []) {
	if (!input || typeof input !== 'object') return { ok: false, error: '无效的输入' };
	const category = String(input.category || '').trim();
	if (!Object.prototype.hasOwnProperty.call(CATEGORY_LABELS, category)) {
		return { ok: false, error: '请选择账号类型' };
	}
	const token = String(input.token || '').trim().slice(0, 4096);
	const refreshToken = String(input.refresh_token || '').trim().slice(0, 4096);
	if (!token) return { ok: false, error: 'token 必填' };
	if (!refreshToken && !REFRESH_OPTIONAL_CATS.includes(category)) return { ok: false, error: 'token 与 refresh_token 均必填' };

	let finalCategory = category;
	if (QODER_CATS.includes(category)) {
		if (!token.startsWith('dt-') || !refreshToken.startsWith('drt-')) {
			if (token.startsWith('eyJ')) {
				return { ok: false, error: '检测到 JWT 凭证（eyJ 开头）：请将账号类型切换为 Trae 系 / CodeBuddy 系 / Codex / Cursor / Kiro 后重试' };
			}
			return { ok: false, error: 'Qoder 系凭证应为 dt-/drt- 前缀（如 dt-xxx / drt-xxx），请核对凭证' };
		}
	} else if (QWENWORK_CATS.includes(category)) {
		// 千问办公 token 为 OAuth 凭证（无固定前缀）：本地仅拦截已知跨家族误投，真实性靠在线验证
		if (token.startsWith('dt-') || refreshToken.startsWith('drt-')) {
			return { ok: false, error: '检测到 Qoder 凭证（dt-/drt- 开头）：请将账号类型切换为 Qoder 系后重试' };
		}
		const cb = detectCbCategory(token);
		if (cb != null) {
			return { ok: false, error: '检测到 CodeBuddy 家族凭证（JWT 签发域识别为 ' + CATEGORY_LABELS[cb] + '）：请将账号类型切换为 CodeBuddy 系后重试' };
		}
		if (detectCodexCategory(token)) {
			return { ok: false, error: '检测到 Codex 凭证（JWT 签发域 auth.openai.com）：请将账号类型切换为 Codex CLI 后重试' };
		}
		if (detectKiroCategory(token)) {
			return { ok: false, error: '检测到 Kiro 凭证（JWT 签发域 kiro.dev）：请将账号类型切换为 Kiro IDE 后重试' };
		}
		if (detectCursorCategory(token)) {
			return { ok: false, error: '检测到 Cursor 凭证（JWT 用户 ID 形态识别）：请将账号类型切换为 Cursor IDE 后重试' };
		}
	} else if (CODEX_CATS.includes(category)) {
		if (!token.startsWith('eyJ') || token.split('.').length !== 3) {
			if (token.startsWith('dt-')) {
				return { ok: false, error: '检测到 Qoder 凭证（dt- 开头）：请将账号类型切换为 Qoder 系后重试' };
			}
			return { ok: false, error: 'Codex 的 access_token 应为 eyJ 开头的 JWT（auth.openai.com 签发），请核对凭证' };
		}
		const cb = detectCbCategory(token);
		if (cb != null) {
			return { ok: false, error: '检测到 CodeBuddy 家族凭证（JWT 签发域识别为 ' + CATEGORY_LABELS[cb] + '）：请将账号类型切换为 CodeBuddy 系后重试' };
		}
		if (detectKiroCategory(token)) {
			return { ok: false, error: '检测到 Kiro 凭证（JWT 签发域 kiro.dev）：请将账号类型切换为 Kiro IDE 后重试' };
		}
		if (detectCursorCategory(token)) {
			return { ok: false, error: '检测到 Cursor 凭证（JWT 用户 ID 形态识别）：请将账号类型切换为 Cursor IDE 后重试' };
		}
		if (!detectCodexCategory(token)) {
			return { ok: false, error: 'JWT 签发方非 auth.openai.com，非 Codex 凭证：请核对凭证与账号类型' };
		}
	} else if (CURSOR_CATS.includes(category)) {
		if (!token.startsWith('eyJ') || token.split('.').length !== 3) {
			if (token.startsWith('dt-')) {
				return { ok: false, error: '检测到 Qoder 凭证（dt- 开头）：请将账号类型切换为 Qoder 系后重试' };
			}
			return { ok: false, error: 'Cursor 的 access_token 应为 eyJ 开头的 JWT（Cursor 官方 Auth0/WorkOS 签发），请核对凭证' };
		}
		const cb = detectCbCategory(token);
		if (cb != null) {
			return { ok: false, error: '检测到 CodeBuddy 家族凭证（JWT 签发域识别为 ' + CATEGORY_LABELS[cb] + '）：请将账号类型切换为 CodeBuddy 系后重试' };
		}
		if (detectCodexCategory(token)) {
			return { ok: false, error: '检测到 Codex 凭证（JWT 签发域 auth.openai.com）：请将账号类型切换为 Codex CLI 后重试' };
		}
		if (detectKiroCategory(token)) {
			return { ok: false, error: '检测到 Kiro 凭证（JWT 签发域 kiro.dev）：请将账号类型切换为 Kiro IDE 后重试' };
		}
		if (!detectCursorCategory(token)) {
			return { ok: false, error: 'JWT 非 Cursor 签发形态（sub 应形如 google-oauth2|user_xxx 或含 api.cursor.com 声明）：请核对凭证与账号类型' };
		}
	} else if (KIRO_CATS.includes(category)) {
		if (!token.startsWith('eyJ') || token.split('.').length !== 3) {
			if (token.startsWith('dt-')) {
				return { ok: false, error: '检测到 Qoder 凭证（dt- 开头）：请将账号类型切换为 Qoder 系后重试' };
			}
			return { ok: false, error: 'Kiro 的 access_token 应为 eyJ 开头的 JWT（auth.desktop.kiro.dev 签发），请核对凭证' };
		}
		const cb = detectCbCategory(token);
		if (cb != null) {
			return { ok: false, error: '检测到 CodeBuddy 家族凭证（JWT 签发域识别为 ' + CATEGORY_LABELS[cb] + '）：请将账号类型切换为 CodeBuddy 系后重试' };
		}
		if (detectCodexCategory(token)) {
			return { ok: false, error: '检测到 Codex 凭证（JWT 签发域 auth.openai.com）：请将账号类型切换为 Codex CLI 后重试' };
		}
		// Kiro 与 Cursor 均使用 google-oauth2|user_xxx 形态 sub，sub 维度无法区分；
		// 用 iss 域区分：kiro.dev → 确认 Kiro；cursor.sh → 误投 Cursor；其余放行
		const _jwt = parseJwt(token);
		const _iss = typeof _jwt?.iss === 'string' ? _jwt.iss : '';
		if (_iss.includes('cursor.sh')) {
			return { ok: false, error: '检测到 Cursor 凭证（JWT 签发域 cursor.sh）：请将账号类型切换为 Cursor IDE 后重试' };
		}
		// kiro.dev → 确认；未知 iss → 放行（真实性靠在线验证）
	} else if (ZCODE_CATS.includes(category)) {
		// ZCode 会话 JWT（refresh_token 可空；套餐授权 token 走 user_data.zai_access_token，选填）
		const foreign = foreignFamilyOf(token);
		if (foreign != null) {
			return { ok: false, error: `检测到 ${foreign} 凭证：请将账号类型切换为「${foreign}」后重试` };
		}
		if (!token.startsWith('eyJ') || token.split('.').length !== 3) {
			if (token.startsWith('dt-')) {
				return { ok: false, error: '检测到 Qoder 凭证（dt- 开头）：请将账号类型切换为 Qoder 系后重试' };
			}
			return { ok: false, error: 'ZCode 的会话凭证应为 eyJ 开头的 JWT（zcodejwttoken），请核对凭证' };
		}
	} else if (KIMI_CATS.includes(category) || MINIMAX_CATS.includes(category)) {
		const label = KIMI_CATS.includes(category) ? 'Kimi Code' : 'MiniMax Code';
		if (token.startsWith('dt-') || refreshToken.startsWith('drt-')) {
			return { ok: false, error: '检测到 Qoder 凭证（dt-/drt- 开头）：请将账号类型切换为 Qoder 系后重试' };
		}
		// OAuth access_token 无统一前缀（可能为不透明串）：仅拦截已知他家族凭证，真实性靠在线验证
		const foreign = foreignFamilyOf(token);
		if (foreign != null) {
			return { ok: false, error: `检测到 ${foreign} 凭证：请将账号类型切换为「${foreign}」后重试` };
		}
		if (/\s/.test(token)) {
			return { ok: false, error: `${label} 的 access_token 不能含空白字符（需为单行凭证）` };
		}
	} else if (COZE_CATS.includes(category)) {
		// 扣子：凭证 = 登录 cookie 串（Passport 会话 cookie；refresh_token 可空）
		if (token.startsWith('dt-') || refreshToken.startsWith('drt-')) {
			return { ok: false, error: '检测到 Qoder 凭证（dt-/drt- 开头）：请将账号类型切换为 Qoder 系后重试' };
		}
		if (!looksLikeCozeCookie(token)) {
			if (token.startsWith('eyJ')) {
				return { ok: false, error: '扣子的凭证应为登录 cookie 串（形如 sessionid=...; sid_guard=...），不是 JWT：请从已登录客户端复制 cookie' };
			}
			return { ok: false, error: '未识别为扣子登录 cookie（需含 sessionid / sid_guard / sid_tt / uid_tt 之一）' };
		}
	} else if (DOUBAO_CATS.includes(category)) {
		// 豆包：凭证 = 登录 cookie 串（.doubao.com Passport；refresh_token 可空，与扣子同 SSO）
		if (token.startsWith('dt-') || refreshToken.startsWith('drt-')) {
			return { ok: false, error: '检测到 Qoder 凭证（dt-/drt- 开头）：请将账号类型切换为 Qoder 系后重试' };
		}
		if (!looksLikeCozeCookie(token)) {
			if (token.startsWith('eyJ')) {
				return { ok: false, error: '豆包的凭证应为登录 cookie 串（形如 sessionid=...; sid_guard=...），不是 JWT：请从已登录豆包客户端复制 cookie' };
			}
			return { ok: false, error: '未识别为豆包登录 cookie（需含 sessionid / sid_guard / sid_tt / uid_tt 之一）' };
		}
	} else if (AUTOCLAW_CATS.includes(category)) {
		// AutoClaw：凭证 = GLM/AutoClaw API Key（<apiKeyId>.<secret>；refresh_token 可空）
		if (looksLikeCozeCookie(token)) {
			return { ok: false, error: '检测到 cookie 串凭证：AutoClaw 需要 GLM/AutoClaw API Key（形如 <apiKeyId>.<secret>），请核对账号类型' };
		}
		const foreign = foreignFamilyOf(token);
		if (foreign != null) {
			return { ok: false, error: `检测到 ${foreign} 凭证：请将账号类型切换为「${foreign}」后重试` };
		}
		if (token.startsWith('dt-') || refreshToken.startsWith('drt-')) {
			return { ok: false, error: '检测到 Qoder 凭证（dt-/drt- 开头）：请将账号类型切换为 Qoder 系后重试' };
		}
		if (/\s/.test(token)) {
			return { ok: false, error: 'AutoClaw 的 API Key 不能含空白字符（需为单行凭证）' };
		}
	} else {
		if (!token.startsWith('eyJ') || token.split('.').length !== 3) {
			if (token.startsWith('dt-')) {
				return { ok: false, error: '检测到 Qoder 凭证（dt- 开头）：请将账号类型切换为 Qoder 系后重试' };
			}
			return { ok: false, error: '该账号类型的 token 应为 eyJ 开头的 JWT，请核对凭证' };
		}
		if (detectCodexCategory(token)) {
			return { ok: false, error: '检测到 Codex 凭证（JWT 签发域 auth.openai.com）：请将账号类型切换为 Codex CLI 后重试' };
		}
		if (detectCursorCategory(token)) {
			return { ok: false, error: '检测到 Cursor 凭证（JWT 用户 ID 形态识别）：请将账号类型切换为 Cursor IDE 后重试' };
		}
		if (detectKiroCategory(token)) {
			return { ok: false, error: '检测到 Kiro 凭证（JWT 签发域 kiro.dev）：请将账号类型切换为 Kiro IDE 后重试' };
		}
		if (CB_CATS.includes(category)) {
			const detected = detectCbCategory(token);
			if (detected == null) {
				return { ok: false, error: '无法识别该 JWT 的 CodeBuddy 签发域（非 CB 家族凭证）：请核对凭证，或切换到 Trae 系' };
			}
			finalCategory = detected === 'workbuddy' ? 'codebuddy_cn' : detected;
		} else {
			// Trae 系分类收 CB 家族 JWT → 误投（不拦会走到在线验证 401 → 被当成「账号已封禁」误导用户）
			const cb = detectCbCategory(token);
			if (cb != null) {
				return { ok: false, error: '检测到 CodeBuddy 家族凭证（JWT 签发域识别为 ' + CATEGORY_LABELS[cb] + '）：请将账号类型切换为 CodeBuddy 系后重试' };
			}
		}
	}

	let userData = null;
	if (input.user_data != null && String(input.user_data).trim() !== '') {
		try {
			const ud = JSON.parse(String(input.user_data));
			if (!ud || typeof ud !== 'object' || Array.isArray(ud)) {
				return { ok: false, error: 'user_data 必须是 JSON 对象（如 Trae 设备密钥对 {"device_id":...}）' };
			}
			userData = JSON.stringify(ud).slice(0, 10240);
		} catch {
			return { ok: false, error: 'user_data 不是合法的 JSON，请核对（不需要可留空）' };
		}
	}

	// 同 token 去重（本地清单内）
	if (existing.some((a) => a.token === token)) {
		return { ok: false, error: '该 token 已存在于自定义账号列表中' };
	}

	const label = input.label ? String(input.label).trim().slice(0, 256) : null;
	return {
		ok: true,
		account: {
			id: 'c' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
			category: finalCategory,
			token,
			refresh_token: refreshToken,
			label,
			user_data: userData,
			created_at: new Date().toISOString().replace('T', ' ').slice(0, 16),
		},
	};
}

/** 读取自定义账号列表（store 解密返回 JSON 字符串；异常回退空数组） */
function loadCustomAccounts(store) {
	const raw = store.get('customAccounts', '[]');
	if (typeof raw !== 'string') return Array.isArray(raw) ? raw : [];
	try {
		const list = JSON.parse(raw);
		return Array.isArray(list) ? list : [];
	} catch {
		return [];
	}
}

/** 添加自定义账号（校验 + 去重），返回 {ok, account|error} */
function addCustomAccount(store, input) {
	const existing = loadCustomAccounts(store);
	const r = validateCustomAccount(input, existing);
	if (!r.ok) return r;
	existing.push(r.account);
	store.set('customAccounts', JSON.stringify(existing));
	return r;
}

/** 删除自定义账号（按 id），返回 {ok, removed} */
function removeCustomAccount(store, id) {
	const existing = loadCustomAccounts(store);
	const next = existing.filter((a) => a.id !== id);
	if (next.length === existing.length) return { ok: false, error: '未找到该自定义账号' };
	store.set('customAccounts', JSON.stringify(next));
	return { ok: true, removed: id };
}

module.exports = {
	CATEGORY_LABELS,
	QODER_CATS,
	CB_CATS,
	QWENWORK_CATS,
	CODEX_CATS,
	CURSOR_CATS,
	parseJwt,
	detectCbCategory,
	detectCodexCategory,
	detectCursorCategory,
	validateCustomAccount,
	loadCustomAccounts,
	addCustomAccount,
	removeCustomAccount,
};
