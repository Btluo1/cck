// 自定义账号单元测试：凭证校验/家族识别（纯函数）+ 增删查（mock store）+ 全链路接线（源码断言）
// 另含开源版剥离防护断言（客户端启动/设备重置/环境清理不得回流入库）。
// 运行: npm test（或 node test/test-custom-accounts.js）

let pass = 0, fail = 0;
const assertEq = (actual, expected, name) => {
	const ok = JSON.stringify(actual) === JSON.stringify(expected);
	if (ok) { pass++; console.log('  PASS ' + name); }
	else { fail++; console.log('  FAIL ' + name + ': expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual)); }
};
const assert = (cond, name) => {
	if (cond) { pass++; console.log('  PASS ' + name); }
	else { fail++; console.log('  FAIL ' + name); }
};
const D = (f) => require('path').join(__dirname, '..', f);
const readSrc = (f) => require('fs').readFileSync(f, 'utf8');

const { parseJwt, detectCbCategory, detectCodexCategory, validateCustomAccount, loadCustomAccounts, addCustomAccount, removeCustomAccount, CATEGORY_LABELS } = require(D('lib/custom-accounts'));

/** 构造测试用 JWT（三段式，payload 指定 iss） */
const makeJwt = (iss) => 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from(JSON.stringify({ iss, iat: 1, exp: 9e12 })).toString('base64url') + '.sig';
const TRAE_JWT = makeJwt('https://api.trae.cn');
const WB_JWT = makeJwt('https://passport.workbuddy.cn');
const CB_CN_JWT = makeJwt('https://passport.codebuddy.cn');
const CB_INTL_JWT = makeJwt('https://www.codebuddy.ai');
const CODEX_JWT = makeJwt('https://auth.openai.com/');

// ---------- 纯函数：parseJwt / detectCbCategory / detectCodexCategory ----------
function testJwt() {
	console.log('== parseJwt / detectCbCategory / detectCodexCategory ==');
	assertEq(parseJwt('dt-abc'), null, 'parseJwt: 非 JWT 前缀 → null');
	assertEq(parseJwt('eyJx'), null, 'parseJwt: 非三段式 → null');
	assertEq(parseJwt('eyJh.eyJb.!!not-base64!!'), null, 'parseJwt: 非法 base64 → null');
	assertEq(parseJwt(TRAE_JWT).iss, 'https://api.trae.cn', 'parseJwt: 合法 JWT → 解出 payload');
	assertEq(parseJwt(null), null, 'parseJwt: null → null');
	assertEq(detectCbCategory(WB_JWT), 'workbuddy', 'detectCbCategory: workbuddy.cn → workbuddy');
	assertEq(detectCbCategory(CB_CN_JWT), 'codebuddy_cn', 'detectCbCategory: codebuddy.cn → codebuddy_cn');
	assertEq(detectCbCategory(CB_INTL_JWT), 'codebuddy_intl', 'detectCbCategory: codebuddy.ai → codebuddy_intl');
	assertEq(detectCbCategory(TRAE_JWT), null, 'detectCbCategory: Trae iss → null（非 CB 家族）');
	assertEq(detectCbCategory('dt-xxx'), null, 'detectCbCategory: 非 JWT → null');
	assertEq(detectCodexCategory(CODEX_JWT), 'codex', 'detectCodexCategory: auth.openai.com → codex');
	assertEq(detectCodexCategory(TRAE_JWT), null, 'detectCodexCategory: Trae iss → null（非 Codex）');
	assertEq(detectCodexCategory(CB_INTL_JWT), null, 'detectCodexCategory: CB iss → null（非 Codex）');
	assertEq(detectCodexCategory('dt-xxx'), null, 'detectCodexCategory: 非 JWT → null');
}

// ---------- 纯函数：validateCustomAccount ----------
function testValidate() {
	console.log('== validateCustomAccount 输入校验 ==');
	assertEq(validateCustomAccount(null).ok, false, 'null 输入 → 拒绝');
	assertEq(validateCustomAccount({}).error, '请选择账号类型', '未知分类 → 提示选择类型');
	assertEq(validateCustomAccount({ category: 'qoder' }).error, 'token 必填', '缺凭证 → 必填提示');
	assertEq(validateCustomAccount({ category: 'qoder', token: 'dt-a' }).error, 'token 与 refresh_token 均必填', '缺 refresh_token（非 ZCode）→ 必填提示');
	assertEq(validateCustomAccount({ category: 'workbuddy_x' }).error, '请选择账号类型', '不存在的分类 → 拒绝');

	// Qoder 家族
	assert(validateCustomAccount({ category: 'qoder', token: 'dt-abc', refresh_token: 'drt-abc' }).ok, 'qoder + dt-/drt- → 通过');
	assert(validateCustomAccount({ category: 'qodercn', token: 'dt-abc', refresh_token: 'drt-abc' }).ok, 'qodercn → 通过');
	assert(validateCustomAccount({ category: 'qoderapp', token: 'dt-abc', refresh_token: 'drt-abc' }).ok, 'qoderapp → 通过');
	assert(validateCustomAccount({ category: 'qoder_intl', token: 'dt-abc', refresh_token: 'drt-abc' }).ok, 'qoder_intl → 通过');
	assert(!validateCustomAccount({ category: 'qoder', token: 'dt-abc', refresh_token: 'bad' }).ok, 'refresh 无 drt- 前缀 → 拒绝');
	assert(validateCustomAccount({ category: 'qoder', token: TRAE_JWT, refresh_token: 'drt-x' }).error.includes('切换为 Trae'), 'Qoder 分类收 JWT → 提示切换分类');
	assert(validateCustomAccount({ category: 'qodercn', token: 'abc', refresh_token: 'drt-x' }).error.includes('dt-/drt-'), 'Qoder 分类收随机串 → 前缀提示');

	// Trae 家族
	assert(validateCustomAccount({ category: 'trae_cn', token: TRAE_JWT, refresh_token: 'r' }).ok, 'trae_cn + JWT → 通过');
	assert(validateCustomAccount({ category: 'trae_solo', token: TRAE_JWT, refresh_token: 'r' }).ok, 'trae_solo → 通过');
	assert(validateCustomAccount({ category: 'trae_intl', token: TRAE_JWT, refresh_token: 'r' }).ok, 'trae_intl → 通过');
	assert(validateCustomAccount({ category: 'trae_cn', token: 'dt-abc', refresh_token: 'drt-x' }).error.includes('切换为 Qoder'), 'Trae 分类收 dt- → 提示切换分类');
	assert(validateCustomAccount({ category: 'trae_cn', token: 'notajwt', refresh_token: 'r' }).error.includes('eyJ'), 'Trae 分类收非 JWT → eyJ 提示');

	// CB 家族：按 iss 自动归类
	assertEq(validateCustomAccount({ category: 'codebuddy_cn', token: WB_JWT, refresh_token: 'r' }).account.category, 'codebuddy_cn', 'CB 分类 + workbuddy.cn iss → codebuddy_cn（归一化）');
	assertEq(validateCustomAccount({ category: 'workbuddy', token: CB_CN_JWT, refresh_token: 'r' }).account.category, 'codebuddy_cn', 'workbuddy 分类 + codebuddy.cn iss → codebuddy_cn');
	assertEq(validateCustomAccount({ category: 'codebuddy_intl', token: CB_INTL_JWT, refresh_token: 'r' }).account.category, 'codebuddy_intl', 'CB intl 分类 + codebuddy.ai iss → codebuddy_intl');
	assertEq(validateCustomAccount({ category: 'codebuddy_cn', token: CB_INTL_JWT, refresh_token: 'r' }).account.category, 'codebuddy_intl', 'CB CN 分类 + codebuddy.ai iss → 自动纠正为 codebuddy_intl');
	assert(validateCustomAccount({ category: 'codebuddy_cn', token: TRAE_JWT, refresh_token: 'r' }).error.includes('无法识别'), 'CB 分类收 Trae JWT → 无法识别提示');
	assert(validateCustomAccount({ category: 'codebuddy_cn', token: CODEX_JWT, refresh_token: 'r' }).error.includes('切换为 Codex'), 'CB 分类收 Codex JWT → 提示切换 Codex');
	// Trae 系分类收 CB 家族 JWT → 拦截（漏拦会走到在线验证 401 被当成「账号已封禁」误导用户）
	assert(validateCustomAccount({ category: 'trae_cn', token: CB_CN_JWT, refresh_token: 'r' }).error.includes('切换为 CodeBuddy'), 'trae_cn 分类收 CB JWT → 提示切换 CB');
	assert(validateCustomAccount({ category: 'trae_solo', token: WB_JWT, refresh_token: 'r' }).error.includes('切换为 CodeBuddy'), 'trae_solo 分类收 WB JWT → 提示切换 CB');
	assert(validateCustomAccount({ category: 'trae_intl', token: CB_INTL_JWT, refresh_token: 'r' }).error.includes('CodeBuddy 国际版'), 'trae_intl 分类收 CB intl JWT → 提示含具体归类');

	// Codex 家族：iss 须为 auth.openai.com，跨家族误投拒绝
	assert(validateCustomAccount({ category: 'codex', token: CODEX_JWT, refresh_token: 'rt-cx' }).ok, 'codex + auth.openai.com JWT → 通过');
	assert(validateCustomAccount({ category: 'codex', token: 'dt-abc', refresh_token: 'drt-x' }).error.includes('切换为 Qoder'), 'codex 分类收 dt- → 提示切换 Qoder');
	assert(validateCustomAccount({ category: 'codex', token: 'notajwt', refresh_token: 'r' }).error.includes('eyJ'), 'codex 分类收非 JWT → eyJ 提示');
	assert(validateCustomAccount({ category: 'codex', token: CB_INTL_JWT, refresh_token: 'r' }).error.includes('CodeBuddy'), 'codex 分类收 CB JWT → 提示切换 CB');
	assert(validateCustomAccount({ category: 'codex', token: TRAE_JWT, refresh_token: 'r' }).error.includes('非 auth.openai.com'), 'codex 分类收 Trae JWT → 签发方报错');
	assert(validateCustomAccount({ category: 'qwenwork', token: CODEX_JWT, refresh_token: 'r' }).error.includes('切换为 Codex'), 'qwenwork 分类收 Codex JWT → 提示切换 Codex');
	assert(validateCustomAccount({ category: 'trae_cn', token: CODEX_JWT, refresh_token: 'r' }).error.includes('切换为 Codex'), 'trae 分类收 Codex JWT → 提示切换 Codex');

	// user_data
	assert(validateCustomAccount({ category: 'trae_cn', token: TRAE_JWT, refresh_token: 'r', user_data: '{bad json' }).error.includes('JSON'), 'user_data 非法 JSON → 拒绝');
	assert(validateCustomAccount({ category: 'trae_cn', token: TRAE_JWT, refresh_token: 'r', user_data: '[1,2]' }).error.includes('JSON 对象'), 'user_data 数组 → 拒绝');
	assert(validateCustomAccount({ category: 'trae_cn', token: TRAE_JWT, refresh_token: 'r', user_data: '123' }).error.includes('JSON 对象'), 'user_data 数字 → 拒绝');
	assertEq(validateCustomAccount({ category: 'trae_cn', token: TRAE_JWT, refresh_token: 'r', user_data: '{ "device_id": "x" }' }).account.user_data, '{"device_id":"x"}', 'user_data 合法对象 → 紧凑 JSON 存储');
	assertEq(validateCustomAccount({ category: 'trae_cn', token: TRAE_JWT, refresh_token: 'r', user_data: '  ' }).account.user_data, null, 'user_data 空白 → 视为未填');
	assertEq(validateCustomAccount({ category: 'trae_cn', token: TRAE_JWT, refresh_token: 'r', user_data: null }).account.user_data, null, 'user_data null → 未填');

	// label / 长度上限
	assertEq(validateCustomAccount({ category: 'qoder', token: 'dt-a', refresh_token: 'drt-a', label: '  测试号  ' }).account.label, '测试号', 'label 去两端空白');
	assertEq(validateCustomAccount({ category: 'qoder', token: 'dt-a', refresh_token: 'drt-a', label: 'x'.repeat(300) }).account.label.length, 256, 'label 截断 256');
	assertEq(validateCustomAccount({ category: 'qoder', token: 'dt-' + 'x'.repeat(5000), refresh_token: 'drt-a' }).account.token.length, 4096, 'token 截断 4096');

	// 去重
	const one = validateCustomAccount({ category: 'qoder', token: 'dt-dup', refresh_token: 'drt-a' }).account;
	assert(validateCustomAccount({ category: 'qodercn', token: 'dt-dup', refresh_token: 'drt-b' }, [one]).error.includes('已存在'), '同 token 去重（跨分类）');
	assert(validateCustomAccount({ category: 'qodercn', token: 'dt-dup2', refresh_token: 'drt-b' }, [one]).ok, '不同 token 不受影响');

	// id 格式与创建时间
	const acc = validateCustomAccount({ category: 'trae_cn', token: TRAE_JWT, refresh_token: 'r' }).account;
	assert(/^c[0-9a-z]+$/.test(acc.id), 'id 为 c 前缀字符串（与平台数字 id 区分）');
	assert(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/.test(acc.created_at), 'created_at 为 YYYY-MM-DD HH:mm');
	assertEq(Object.keys(CATEGORY_LABELS).length, 20, 'CATEGORY_LABELS 覆盖 20 个分类（含千问办公/Codex/Cursor/Kiro/qoderapp/ZCode/Kimi/MiniMax/扣子/AutoClaw/豆包）');
}

// ---------- 纯函数：09-21 新增三分类（ZCode / Kimi Code / MiniMax Code）----------
function testValidateNewPlatforms() {
	console.log('== validateCustomAccount 新分类（zcode/kimi/minimax） ==');
	const ZCODE_JWT = makeJwt('https://zcode.z.ai');
	const KIMI_TOKEN = 'oauth-kimi-access-token-abcdefghijklmnop';

	// ZCode：会话 JWT（refresh_token 可空；套餐授权 token 走 user_data）
	assert(validateCustomAccount({ category: 'zcode', token: ZCODE_JWT, refresh_token: '' }).ok, 'zcode：仅会话 JWT（无 refresh）→ 通过');
	assertEq(validateCustomAccount({ category: 'zcode', token: ZCODE_JWT, refresh_token: '' }).account.refresh_token, '', 'zcode：refresh_token 允许为空');
	assert(validateCustomAccount({ category: 'zcode', token: 'notajwt', refresh_token: '' }).error.includes('zcodejwttoken'), 'zcode：非 JWT → 形态提示');
	assert(validateCustomAccount({ category: 'zcode', token: 'dt-abc', refresh_token: 'drt-x' }).error.includes('切换为 Qoder'), 'zcode：收 Qoder 凭证 → 提示切换');
	assert(validateCustomAccount({ category: 'zcode', token: CODEX_JWT, refresh_token: '' }).error.includes('Codex CLI'), 'zcode：收 Codex JWT → 误投拦截');
	assert(validateCustomAccount({ category: 'zcode', token: TRAE_JWT, refresh_token: '' }).error.includes('Trae'), 'zcode：收 Trae JWT → 误投拦截');
	assert(validateCustomAccount({ category: 'zcode', token: CB_INTL_JWT, refresh_token: '' }).error.includes('CodeBuddy'), 'zcode：收 CB JWT → 误投拦截');

	// Kimi Code：OAuth 双凭证（无固定前缀，refresh 必填）
	assert(validateCustomAccount({ category: 'kimi', token: KIMI_TOKEN, refresh_token: 'rt-kimi' }).ok, 'kimi：OAuth access_token + refresh → 通过');
	assert(validateCustomAccount({ category: 'kimi', token: KIMI_TOKEN }).error.includes('均必填'), 'kimi：缺 refresh_token → 拒绝');
	assert(validateCustomAccount({ category: 'kimi', token: 'dt-abc', refresh_token: 'drt-x' }).error.includes('切换为 Qoder'), 'kimi：收 Qoder 凭证 → 提示切换');
	assert(validateCustomAccount({ category: 'kimi', token: CODEX_JWT, refresh_token: 'r' }).error.includes('Codex CLI'), 'kimi：收 Codex JWT → 误投拦截');

	// MiniMax Code：同 Kimi 口径
	assert(validateCustomAccount({ category: 'minimax', token: KIMI_TOKEN, refresh_token: 'rt-mm' }).ok, 'minimax：OAuth 双凭证 → 通过');
	assert(validateCustomAccount({ category: 'minimax', token: 'has space token', refresh_token: 'r' }).error.includes('空白'), 'minimax：token 含空白 → 拒绝');
	assert(validateCustomAccount({ category: 'minimax', token: CB_CN_JWT, refresh_token: 'r' }).error.includes('CodeBuddy'), 'minimax：收 CB JWT → 误投拦截');
}

// ---------- 增删查：mock store ----------
function mockStore() {
	const map = {};
	return {
		get: (k, d) => (k in map ? map[k] : d),
		set: (k, v) => { map[k] = v; },
		delete: (k) => { delete map[k]; },
		_dump: () => map,
	};
}

function testStoreOps() {
	console.log('== addCustomAccount / removeCustomAccount / loadCustomAccounts ==');
	const store = mockStore();
	assertEq(loadCustomAccounts(store), [], '空 store → 空数组');
	assertEq(loadCustomAccounts(store).length, 0, '默认值兜底不写入');

	const r1 = addCustomAccount(store, { category: 'qoder', token: 'dt-a1', refresh_token: 'drt-a1', label: '号1' });
	assert(r1.ok, 'add: Qoder 凭证入库');
	const r2 = addCustomAccount(store, { category: 'trae_cn', token: TRAE_JWT, refresh_token: 'tr1' });
	assert(r2.ok, 'add: Trae JWT 入库');
	assertEq(typeof store._dump().customAccounts, 'string', 'store 中为 JSON 字符串（供 local-store 敏感键加密直通）');
	assertEq(loadCustomAccounts(store).length, 2, 'load: 两条账号');

	const r3 = addCustomAccount(store, { category: 'qodercn', token: 'dt-a1', refresh_token: 'drt-x' });
	assert(!r3.ok && r3.error.includes('已存在'), 'add: 同 token 拒绝');
	assertEq(loadCustomAccounts(store).length, 2, 'add 拒绝后数量不变');

	const r4 = removeCustomAccount(store, r1.account.id);
	assert(r4.ok, 'remove: 按 id 删除');
	assertEq(loadCustomAccounts(store).length, 1, 'remove: 剩 1 条');
	assert(!removeCustomAccount(store, r1.account.id).ok, 'remove: 重复删除 → 未找到');
	assert(loadCustomAccounts(store)[0].token === TRAE_JWT, '剩余为 Trae 账号');

	// 异常回退路径
	assertEq(loadCustomAccounts({ get: () => '{corrupted', set: () => {} }), [], '损坏 JSON → 空数组');
	assertEq(loadCustomAccounts({ get: (k, d) => [{ id: 'cx' }], set: () => {} })[0].id, 'cx', '非字符串（数组）→ 直通返回');
	assertEq(loadCustomAccounts({ get: (k, d) => 'notarray', set: () => {} }), [], 'JSON 非数组 → 空数组');
}

// ---------- 接线：local-store 加密 / main IPC / preload / 渲染端 ----------
function testWiring() {
	console.log('== 全链路接线（源码断言） ==');
	const ls = readSrc(D('lib/local-store.js'));
	assert(ls.includes("new Set(['sessionToken', 'customAccounts'])"), 'local-store: customAccounts 纳入敏感键加密');
	assert(ls.includes('typeof value === \'string\' ? value : JSON.stringify(value)'), 'local-store: 非字符串值序列化后加密');
	assert(ls.includes('decryptValue(store[key]) ?? defaultValue'), 'local-store: get 解密失败回落默认值');

	const main = readSrc(D('main.js'));
	assert(main.includes("'accounts:custom-list'") && main.includes("'accounts:custom-add'") && main.includes("'accounts:custom-remove'"), 'main: 3 个自定义账号 IPC handler');
	assert(main.includes('customAccounts.addCustomAccount(store'), 'main: custom-add 走校验入库');
	assert(main.includes("if (verify !== false)"), 'main: custom-add 默认在线验证');
	assert(main.includes('customAccounts.removeCustomAccount(store, r.account.id)'), 'main: 验证失败自动回滚不入库');
	assert(main.includes('checkQuota(r.account.token, r.account.refresh_token, r.account.category)'), 'main: 验证复用 checkQuota 额度链路');
	assert(!/customAccounts[^;]*api\.(post|get)/.test(main), 'main: 自定义账号不过后端 API');

	const preload = readSrc(D('preload.js'));
	assert(preload.includes('customList') && preload.includes('customAdd') && preload.includes('customRemove'), 'preload: 暴露 customList/customAdd/customRemove');

	const html = readSrc(D('renderer/index.html'));
	assert(html.includes('id="add-custom-btn"'), 'index.html: 添加按钮存在');
	assert(html.includes('app.js?v=30'), 'index.html: app.js 缓存版本一致（v30 = 09-22 新增豆包工作平台）');

	const app = readSrc(D('renderer/js/app.js'));
	assert(app.includes('function showAddCustomAccountModal'), 'app.js: 添加弹窗函数');
	assert(app.includes('function renderCustomAccountCard'), 'app.js: 自定义账号卡片渲染');
	assert(app.includes('function findAccountById'), 'app.js: 平台+自定义统一 id 查找');
	assert(app.includes('customAccounts.map(renderCustomAccountCard)'), 'app.js: 我的账号页合并渲染自定义账号');
	assert(app.includes('bindMyAccountEvents()'), 'app.js: 事件绑定统一入口');
	assert(app.includes('custom-remove-btn'), 'app.js: 删除按钮绑定');
	assert(app.includes("API.accounts.customAdd(input)"), 'app.js: 弹窗提交调用 customAdd');
	assert(app.includes("API.accounts.customList()"), 'app.js: 加载调用 customList');
	assert(app.includes("API.accounts.customRemove(id)"), 'app.js: 删除调用 customRemove');
	assert(app.includes('function findAccountById(accountId)') || app.includes('function findAccountById(id)'), 'app.js: 凭证/额度查询走统一查找');
	assert(app.includes('function updateQuotaDisplay(accountId, quota, banned, isCustom)'), 'app.js: 额度显示区分自定义账号');
	assert(app.includes('⛔ 凭证已失效（被平台拒绝）'), 'app.js: 自定义账号封禁无退款入口提示');
	assert(!app.includes("showCredentials(parseInt"), 'app.js: 不再对 id 做 parseInt（自定义 id 为字符串）');
	assert(app.includes('const customPromises = customAccounts.map'), 'app.js: 批量额度查询含自定义账号');
	assert(app.includes("document.getElementById('add-custom-btn').addEventListener"), 'app.js: 添加按钮事件绑定');

	// 双域名容灾接线
	const apic = readSrc(D('lib/api-client.js'));
	assert(apic.includes("'https://cck.bteai.top', 'https://cck.btluo.com'"), 'api-client: 双域名清单');
	assert(main.includes("api.get('/api/version', { timeout: 8000 })"), 'main: 更新检查走 api-client（容灾）');
	assert(main.includes("'https://cck.btluo.com' + data.download_url"), 'main: 下载链接固定官方下载站 cck.btluo.com');
	assert(html.includes('https://cck.btluo.com'), 'index.html: CSP 含备用域名');
}

// ---------- 开源版剥离防护：敏感链路不得回流 ----------
function testStripGuards() {
	console.log('== 开源版剥离防护（客户端启动/设备指纹/环境清理不得回流） ==');
	const main = readSrc(D('main.js'));
	const preload = readSrc(D('preload.js'));
	const app = readSrc(D('renderer/js/app.js'));
	const html = readSrc(D('renderer/index.html'));

	for (const [src, label] of [[main, 'main.js'], [preload, 'preload.js'], [app, 'app.js']]) {
		assert(!/launchClient|launch-qoderwork|launch-by-category/.test(src), label + ': 不含客户端启动链路');
		assert(!/reset-device|resetDevice|wipe-fresh|wipeFresh|switchIp|getMyIp|checkRiskLogout/.test(src), label + ': 不含设备重置/环境清理/换 IP 链路');
		assert(!/hardware-fingerprint|device-restriction-fix|updateHardwareFingerprint|finalizeDeviceFix/.test(src), label + ': 不含硬件指纹模块引用');
	}
	assert(!/data-view="fix"|fix-view|fix-list|device-risk-banner/.test(html), 'index.html: 不含「解决问题」页与设备风控横幅');
	assert(!/client-launcher|auth-v2|ip-switch/.test(main + preload + app), '主进程/渲染端: 不引用剥离的 lib 模块');

	const libDir = require('path').join(__dirname, '..', 'lib');
	const libFiles = require('fs').readdirSync(libDir).filter((f) => f.endsWith('.js'));
	const allowed = ['api-client.js', 'autoclaw-context.js', 'cck-logger.js', 'codex-context.js', 'coze-context.js', 'cursor-context.js', 'custom-accounts.js', 'doubao-context.js', 'kimi-context.js', 'kiro-context.js', 'local-store.js', 'minimax-context.js', 'net-helper.js', 'quota-checker.js', 'qwenwork-context.js', 'vscdb-secret.js', 'zcode-context.js'];
	assertEq(libFiles.sort().join(','), [...allowed].sort().join(','), 'lib/ 仅含白名单 16 个模块（含 09-21 新增 coze/autoclaw-context 只读模块，无 client-launcher/auth-v2/ip-switch 等）');
}

// ---------- API 双域名容灾（注入 mock net-helper/local-store 到 require.cache 后加载 api-client） ----------
async function testApiFailover() {
	console.log('== API 双域名容灾 ==');
	const netPath = require.resolve(D('lib/net-helper'));
	const storePath = require.resolve(D('lib/local-store'));
	const apiPath = require.resolve(D('lib/api-client'));
	const PRIMARY = 'https://cck.bteai.top';
	const BACKUP = 'https://cck.btluo.com';

	// 每个场景重载 api-client（重置会话内域名粘滞状态），并替换 mock 实现
	function freshApi(netImpl) {
		delete require.cache[apiPath];
		require.cache[netPath] = { exports: { netRequest: netImpl } };
		require.cache[storePath] = { exports: { get: () => null, set: () => {}, delete: () => {}, getAll: () => ({}) } };
		return require(apiPath);
	}
	const okResp = (obj) => ({ ok: true, status: 200, json: async () => obj });
	const netErr = () => ({ ok: false, status: 0, json: async () => ({}) });

	// 场景1: 主域名正常 → 单请求、不切换
	{
		const calls = [];
		const api = freshApi(async (url) => { calls.push(url); return okResp({ latest: '9.9.9' }); });
		const r = await api.get('/api/version');
		assertEq(calls, [PRIMARY + '/api/version'], '主域名正常: 仅请求主域名');
		assertEq(r.httpStatus, 200, '主域名正常: 状态透传');
		assertEq(api.getActiveBase(), PRIMARY, '主域名正常: 活跃域名=主');
		assertEq(api.API_BASES, [PRIMARY, BACKUP], 'API_BASES 双域名清单');
	}

	// 场景2: 主域名网络层挂（status=0）→ 自动切备用 + 会话粘滞
	{
		const calls = [];
		const api = freshApi(async (url) => { calls.push(url); return url.startsWith(BACKUP) ? okResp({ via: 'backup' }) : netErr(); });
		const r = await api.get('/api/me');
		assertEq(r.via, 'backup', '主域名挂: 采用备用域名响应');
		assertEq(calls, [PRIMARY + '/api/me', BACKUP + '/api/me'], '主域名挂: 先主后备用');
		assertEq(api.getActiveBase(), BACKUP, '主域名挂: 活跃域名=备用');
		calls.length = 0;
		await api.get('/api/accounts?category=qoder');
		assertEq(calls, [BACKUP + '/api/accounts?category=qoder'], '会话粘滞: 后续请求直连备用');
	}

	// 场景3: 双域名均挂 → 网络错误
	{
		const api = freshApi(async () => netErr());
		const r = await api.get('/api/me');
		assertEq(r.success, false, '双域名挂: 失败返回');
		assert(r.error.includes('网络连接失败'), '双域名挂: 网络错误文案');
		assertEq(r.httpStatus, 0, '双域名挂: httpStatus=0');
	}

	// 场景4: 主域名 HTTP 5xx（域名可达）→ 不切换
	{
		const calls = [];
		const api = freshApi(async (url) => { calls.push(url); return { ok: false, status: 500, json: async () => ({ error: 'server' }) }; });
		const r = await api.get('/api/me');
		assertEq(calls.length, 1, 'HTTP 500: 不触发域名切换');
		assertEq(r.httpStatus, 500, 'HTTP 500: 状态透传');
	}

	// 场景5: 备用粘滞后备用挂、主恢复 → 自动切回
	{
		const calls = [];
		const state = { backupUp: true, primaryUp: false };
		const api = freshApi(async (url) => {
			calls.push(url);
			if (url.startsWith(BACKUP)) return state.backupUp ? okResp({ via: 'backup' }) : netErr();
			return state.primaryUp ? okResp({ via: 'primary' }) : netErr();
		});
		await api.get('/api/me'); // 主挂 → 切备用
		assertEq(api.getActiveBase(), BACKUP, '切回前置: 粘滞备用');
		state.backupUp = false; state.primaryUp = true;
		calls.length = 0;
		const r = await api.get('/api/me'); // 备用挂 → 切回主
		assertEq(r.via, 'primary', '备用挂主恢复: 响应来自主域名');
		assertEq(calls, [BACKUP + '/api/me', PRIMARY + '/api/me'], '备用挂主恢复: 先备用后主');
		assertEq(api.getActiveBase(), PRIMARY, '备用挂主恢复: 活跃域名切回主');
	}
}

async function main() {
	testJwt();
	testValidate();
	testValidateNewPlatforms();
	testStoreOps();
	testWiring();
	testStripGuards();
	await testApiFailover();
	console.log(`\n结果: ${pass} 通过, ${fail} 失败`);
	process.exit(fail === 0 ? 0 : 1);
}
main().catch(e => { console.error('测试异常:', e); process.exit(1); });
