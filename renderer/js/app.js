// 渲染进程主逻辑：登录/注册 + 主界面 + 账号管理
// 开源版仅保留账号管理与额度查询（客户端启动/设备指纹/环境清理不在开源范围内）。

const API = window.electronAPI;

// ========== Toast 提示 ==========
function toast(msg, type = 'info') {
	const t = document.getElementById('toast');
	t.textContent = msg;
	t.className = `toast ${type} show`;
	setTimeout(() => t.classList.remove('show'), 3000);
}

/** HTML 转义，防止 XSS（含双引号，属性上下文安全） */
function escapeHtml(str) {
	const div = document.createElement('div');
	div.textContent = String(str ?? '');
	return div.innerHTML.replace(/"/g, '&quot;');
}

// ========== 登录/注册页 ==========
let authMode = 'login';

async function initLoginPage() {
	// Tab 切换
	document.querySelectorAll('.tab-btn').forEach((btn) => {
		btn.addEventListener('click', async () => {
			document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
			btn.classList.add('active');
			authMode = btn.dataset.tab;
			const isRegister = authMode === 'register';
			document.getElementById('auth-submit').textContent = isRegister ? '注册' : '登录';
			document.getElementById('auth-error').textContent = '';
			document.getElementById('confirm-password-group').style.display = isRegister ? 'block' : 'none';
		});
	});

	// 提交
	document.getElementById('auth-submit').addEventListener('click', doAuth);
	document.getElementById('auth-password').addEventListener('keydown', (e) => {
		if (e.key === 'Enter') doAuth();
	});
}

async function doAuth() {
	const username = document.getElementById('auth-username').value.trim();
	const password = document.getElementById('auth-password').value;
	const errorEl = document.getElementById('auth-error');

	if (!username || !password) {
		errorEl.textContent = '请输入用户名和密码';
		return;
	}
	errorEl.textContent = '';

	const submitBtn = document.getElementById('auth-submit');
	submitBtn.disabled = true;
	submitBtn.textContent = '处理中...';

	let resp;
	try {
		if (authMode === 'login') {
			resp = await API.auth.login(username, password);
		} else {
			const confirmPassword = document.getElementById('auth-confirm-password').value;
			if (confirmPassword !== password) {
				errorEl.textContent = '两次输入的密码不一致';
				submitBtn.disabled = false;
				submitBtn.textContent = '注册';
				return;
			}
			resp = await API.auth.register(username, password, confirmPassword);
		}
	} catch (e) {
		errorEl.textContent = '请求失败: ' + e.message;
		submitBtn.disabled = false;
		submitBtn.textContent = authMode === 'login' ? '登录' : '注册';
		return;
	}

	if (resp.success) {
		showMainView(resp.user);
	} else {
		errorEl.textContent = resp.error || '操作失败';
		submitBtn.disabled = false;
		submitBtn.textContent = authMode === 'login' ? '登录' : '注册';
	}
}

// ========== 主界面 ==========
let currentUser = null;

function showMainView(user) {
	currentUser = user;
	document.getElementById('login-view').style.display = 'none';
	document.getElementById('main-view').style.display = 'flex';
	updateUserInfo(user);
	initMainViewEvents();
	loadShop();
	checkUpdateBanner(); // 启动静默检查：非最新版则顶部横幅提示（不阻塞，失败静默）
}

function updateUserInfo(user) {
	if (user) {
		document.getElementById('user-badge').textContent = user.username;
		document.getElementById('credits-display').innerHTML = `余额: <b>${Number(user.credits)}</b>`;
	}
}

async function refreshBalance() {
	const resp = await API.auth.getSession();
	if (resp.success) {
		currentUser = resp.user;
		updateUserInfo(resp.user);
		toast('余额已刷新', 'success');
	} else {
		toast('刷新失败: ' + (resp.error || ''), 'error');
	}
}

function showRedeemModal() {
	const overlay = document.createElement('div');
	overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);display:flex;justify-content:center;align-items:center;z-index:1000';
	overlay.innerHTML = `
		<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px;width:420px;max-width:90vw">
			<h2 style="margin-bottom:16px;font-size:18px">兑换码充值</h2>
			<div class="form-group">
				<label>兑换码</label>
				<input type="text" id="redeem-code" placeholder="输入兑换码" style="font-family:Consolas,monospace" autocomplete="off">
			</div>
			<div id="redeem-result" style="font-size:13px;min-height:18px;margin-bottom:12px"></div>
			<button class="btn btn-primary btn-block" id="redeem-submit">兑换</button>
		</div>`;
	document.body.appendChild(overlay);

	const close = () => overlay.remove();
	overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });

	overlay.querySelector('#redeem-submit').addEventListener('click', async () => {
		const code = overlay.querySelector('#redeem-code').value.trim();
		const resultEl = overlay.querySelector('#redeem-result');
		if (!code) { resultEl.innerHTML = '<span class="text-danger">请输入兑换码</span>'; return; }
		const btn = overlay.querySelector('#redeem-submit');
		btn.disabled = true;
		btn.textContent = '兑换中...';
		const resp = await API.credits.redeem(code);
		if (resp.success) {
			toast(`兑换成功，+${resp.credits} 余额`, 'success');
			currentUser.credits = resp.new_balance;
			updateUserInfo(currentUser);
			close();
		} else {
			resultEl.innerHTML = `<span class="text-danger">${escapeHtml(resp.error || '兑换失败')}</span>`;
			btn.disabled = false;
			btn.textContent = '兑换';
		}
	});
}

let mainViewEventsBound = false;
function initMainViewEvents() {
	if (mainViewEventsBound) return;
	mainViewEventsBound = true;
	// Tab 切换
	document.querySelectorAll('.main-tab').forEach((tab) => {
		tab.addEventListener('click', () => {
			document.querySelectorAll('.main-tab').forEach((t) => t.classList.remove('active'));
			tab.classList.add('active');
			document.querySelectorAll('.view-section').forEach((s) => s.classList.remove('active'));
			document.getElementById(tab.dataset.view + '-view').classList.add('active');
			if (tab.dataset.view === 'my') loadMyAccounts();
		});
	});

	// 退出
	document.getElementById('update-btn').addEventListener('click', async () => {
		const btn = document.getElementById('update-btn');
		btn.disabled = true; btn.textContent = '检查中...';
		try {
			const result = await window.electronAPI.checkUpdate();
			if (result.error) { toast('检查更新失败: ' + result.error, 'error'); return; }
			if (result.hasUpdate) {
				showUpdateModal(result);
			} else {
				toast('已是最新版本 (' + result.current + ')', 'success');
			}
		} catch (e) {
			toast('检查更新失败: ' + (e && e.message ? e.message : '未知错误'), 'error');
		} finally {
			btn.disabled = false; btn.textContent = '检查更新';
		}
	});

	document.getElementById('logout-btn').addEventListener('click', async () => {
		await API.auth.logout();
		document.getElementById('main-view').style.display = 'none';
		document.getElementById('login-view').style.display = 'flex';
		toast('已退出登录', 'info');
	});

	// 刷新余额
	document.getElementById('refresh-balance').addEventListener('click', refreshBalance);
	// 兑换码充值
	document.getElementById('redeem-btn').addEventListener('click', showRedeemModal);

	// 刷新商城
	document.getElementById('refresh-shop').addEventListener('click', loadShop);

	// 刷新我的账号
	document.getElementById('refresh-my').addEventListener('click', loadMyAccounts);

	// 添加自定义账号（自有凭证，仅存本机）
	document.getElementById('add-custom-btn').addEventListener('click', showAddCustomAccountModal);

	// 代理商页签：淘宝购买兑换卡（点链接系统浏览器打开，复制按钮写剪贴板并提示在淘宝 App 打开）
	document.querySelectorAll('.agent-taobao-link').forEach((a) => {
		a.addEventListener('click', (e) => {
			e.preventDefault();
			window.electronAPI.openExternal(a.dataset.url);
		});
	});
	document.querySelectorAll('.agent-copy-btn').forEach((btn) => {
		btn.addEventListener('click', async () => {
			const url = btn.dataset.url;
			let ok = false;
			try { await navigator.clipboard.writeText(url); ok = true; } catch {}
			if (!ok) {
				try {
					const ta = document.createElement('textarea');
					ta.value = url;
					ta.style.cssText = 'position:fixed;opacity:0';
					document.body.appendChild(ta);
					ta.select();
					ok = document.execCommand('copy');
					ta.remove();
				} catch {}
			}
			if (ok) toast('链接已复制，请在淘宝 App 中打开', 'success');
			else toast('复制失败，请手动选中链接复制', 'error');
		});
	});
}

// ========== 账号分类 ==========
// 2026-10: Trae 官方把 TraeCode CN 与 TraeWork CN 合并为统一 TRAE CN 客户端 ——
// trae_cn / trae_solo 两个账号分类对买家统一展示为 TRAE CN, 商城合并为一个 Tab
const CATEGORY_NAMES = { qoder: 'Qoder Work CN', qodercn: 'Qoder IDE CN', qoderapp: 'Qoder CN', qoder_intl: 'Qoder 国际版', trae_cn: 'TRAE CN', trae_solo: 'TRAE CN', trae_intl: 'Trae 国际版', codebuddy_cn: 'CodeBuddy/WorkBuddy CN', workbuddy: 'CodeBuddy/WorkBuddy CN', codebuddy_intl: 'CodeBuddy 国际版', qwenwork: '千问办公', codex: 'Codex CLI', cursor: 'Cursor IDE', kiro: 'Kiro IDE', zcode: 'ZCode (智谱)', kimi: 'Kimi Code', minimax: 'MiniMax Code', coze: '扣子 (Coze)', autoclaw: 'AutoClaw (智谱)', doubao: '豆包工作平台 (Doubao)' };
// 商城 Tab 家族分组与配色（仅前端视觉，按四家族着色：Qoder=蓝 / Trae=琥珀 / CodeBuddy=绿 / 独立=紫）
const TAB_FAMILY = {
	qoder: 'fam-qoder', qodercn: 'fam-qoder', qoderapp: 'fam-qoder', qoder_intl: 'fam-qoder',
	trae_cn: 'fam-trae', trae_solo: 'fam-trae', trae_intl: 'fam-trae',
	codebuddy_cn: 'fam-cb', codebuddy_intl: 'fam-cb',
	qwenwork: 'fam-indep', codex: 'fam-indep', cursor: 'fam-indep', kiro: 'fam-indep',
	zcode: 'fam-indep', kimi: 'fam-indep', minimax: 'fam-indep',
	coze: 'fam-indep', autoclaw: 'fam-indep',
	doubao: 'fam-indep',
};
// Tab 短标签（节省宽度，避免 12 个按钮拥挤；鼠标悬停 tooltip 显示全名）
const TAB_SHORT = {
	qoder: 'Qoder Work CN', qodercn: 'Qoder IDE CN', qoderapp: 'Qoder CN', qoder_intl: 'Qoder 国际',
	trae_cn: 'TRAE CN', trae_solo: 'TRAE CN', trae_intl: 'Trae 国际',
	codebuddy_cn: 'CodeBuddy/WorkBuddy CN', codebuddy_intl: 'CB 国际',
	qwenwork: '千问办公', codex: 'Codex', cursor: 'Cursor', kiro: 'Kiro',
	zcode: 'ZCode', kimi: 'Kimi', minimax: 'MiniMax',
	coze: '扣子', autoclaw: 'AutoClaw',
	doubao: '豆包',
};
// CodeBuddy 与 WorkBuddy 凭证互通、积分通用(同一账号体系): 商城统一一个分类
const isBuddyCat = (c) => c === 'codebuddy_cn' || c === 'workbuddy';
// 积分制分类: CB/WB 共用积分体系 + CodeBuddy 国际版(独立账号体系, 同为积分制, www.codebuddy.ai)
// + 千问办公(阿里 QwenWork, qwenwork.cn, 积分制月度套餐刷新)
// + Codex(OpenAI Codex CLI, chatgpt 账号体系, credits 积分/订阅双形态)
// + Cursor(Anysphere IDE, api2.cursor.sh planUsage 美分额度, 月度计费周期重置)
// + ZCode(智谱 Z.ai 编程套餐, 5h/周窗口滚动刷新) / Kimi Code(周窗口) / MiniMax Code(周期额度)
// + 扣子(Coze 积分/资源点) / AutoClaw(智谱 GLM 编程套餐周期额度)
const isCreditsCat = (c) => isBuddyCat(c) || c === 'codebuddy_intl' || c === 'qwenwork' || c === 'codex' || c === 'cursor' || c === 'kiro'
	|| c === 'zcode' || c === 'kimi' || c === 'minimax'
	|| c === 'coze' || c === 'autoclaw' || c === 'doubao';
// Trae 国际版额度口径为 fast requests (非 credits)
const isTraeIntlCat = (c) => c === 'trae_intl';
const quotaUnit = (c) => (isCreditsCat(c) ? '积分' : isTraeIntlCat(c) ? 'fast requests' : 'credits');
// 商城合并 Tab: Tab 分类 → 实际拉取的账号分类列表（10-10 Trae 官方合并客户端后, trae_solo 并入
// 「TRAE CN」Tab 展示; 购买/额度仍按卡片各自分类走后端）
const SHOP_TAB_AGGREGATION = { trae_cn: ['trae_cn', 'trae_solo'] };
let currentShopCategory = 'qoder';

// ========== 账号商城 ==========
async function loadShop() {
	const listEl = document.getElementById('shop-list');
	listEl.innerHTML = '<div class="loading">加载中...</div>';

	// 渲染分类 Tab
	const tabContainer = document.getElementById('shop-category-tabs');
	if (tabContainer) {
		// 商城 Tab: CB/WB 凭证互通、积分通用, 统一一个「CodeBuddy/WorkBuddy」入口
		// 10-04: 下架国际版/海外平台分类——qoder_intl / trae_intl / codebuddy_intl / codex / cursor / kimi
		//        （用户指令：商城不再销售这些分类；「添加自定义账号」弹窗仍保留，自有凭证可继续添加管理）
		// 10-10: Trae 官方合并 TraeCode CN / TraeWork CN 为统一 TRAE CN 客户端 ——
		//        商城只留一个「TRAE CN」Tab, 聚合 trae_cn + trae_solo 两个分类的库存
			const SHOP_TABS = ['qoder', 'qodercn', 'qoderapp', 'trae_cn', 'codebuddy_cn', 'qwenwork', 'zcode', 'minimax', 'coze', 'autoclaw', 'doubao'];
		// 紧凑药丸 chip + 家族配色：自动换行避免拥挤；激活态用家族色填充，未激活用家族色描边+色点，视觉上一眼分四组
		tabContainer.innerHTML = SHOP_TABS.map(cat => {
			const fam = TAB_FAMILY[cat] || 'fam-indep';
			const active = cat === currentShopCategory;
			return `<button class="shop-tab ${fam}${active ? ' active' : ''}" data-cat="${cat}" title="${CATEGORY_NAMES[cat]}"><span class="dot"></span><span class="lbl">${TAB_SHORT[cat] || CATEGORY_NAMES[cat]}</span></button>`;
		}).join('');
		tabContainer.querySelectorAll('button').forEach(btn => {
			btn.addEventListener('click', () => {
				currentShopCategory = btn.dataset.cat;
				loadShop();
			});
		});
	}

	// 合并 Tab(如 TRAE CN = trae_cn + trae_solo)并行拉取各分类库存; 单分类失败不阻断其余展示
	const fetchCats = SHOP_TAB_AGGREGATION[currentShopCategory] || [currentShopCategory];
	const responses = await Promise.all(fetchCats.map((c) => API.accounts.list(c).catch(() => ({ success: false, error: '请求异常' }))));
	if (!responses.some((r) => r.success)) {
		const firstError = (responses.find((r) => !r.success) || {}).error || '加载失败';
		listEl.innerHTML = `<div class="empty-state"><div class="icon">⚠</div>${escapeHtml(firstError)}</div>`;
		return;
	}

	// 聚合各分类卡片并标记来源分类(购买按钮携带, 后端按原分类结算), 按额度升序+价格升序排列
	const accounts = [];
	responses.forEach((resp, i) => {
		if (!resp.success) return;
		for (const a of resp.accounts || []) accounts.push(Object.assign({}, a, { _shopCat: fetchCats[i] }));
	});
	if (accounts.length === 0) {
		listEl.innerHTML = '<div class="empty-state"><div class="icon">◈</div>暂无可购买账号</div>';
		return;
	}
	accounts.sort((x, y) => (Number(x.plan_quota) - Number(y.plan_quota)) || (Number(x.price) - Number(y.price)));

	listEl.innerHTML = accounts
		.map(
			(a) => `
		<div class="account-card">
			<div class="plan-name">${escapeHtml(a.plan_name || (a.plan_quota + '额度套餐'))}</div>
			${currentShopCategory === 'qoder' && a.label ? `<div class="plan-label">${escapeHtml(a.label)}</div>` : ''}
			<div class="plan-meta">
					<span><span class="meta-label">${isCreditsCat(a._shopCat) ? '积分' : '额度'}:</span> ${Number(a.plan_quota)} ${quotaUnit(a._shopCat)}</span>
				</div>
			<div class="plan-price"><span class="unit">售价 </span>${a.discount && Number(a.original_price) > Number(a.price) ? `<s class="price-strike">${Number(a.original_price)}</s> ` : ''}${Number(a.price)}${a.discount ? ` <span class="promo-badge">${escapeHtml(String(a.discount_label || '促销'))}</span>` : ''}</div>
			<button class="btn btn-primary btn-block purchase-btn" data-quota="${Number(a.plan_quota)}" data-name="${escapeHtml(a.plan_name || (a.plan_quota + '额度'))}" data-category="${a._shopCat}">购买</button>
		</div>`,
		)
		.join('');

	document.querySelectorAll('.purchase-btn').forEach((btn) => {
		btn.addEventListener('click', () => purchaseAccount(parseInt(btn.dataset.quota, 10), btn.dataset.name, btn, btn.dataset.category));
	});
}

/** 自定义确认弹窗（替代原生 confirm，避免 sandbox 闪退） */
function showConfirm(message) {
	return new Promise((resolve) => {
		const overlay = document.createElement('div');
		overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);display:flex;justify-content:center;align-items:center;z-index:1000';
		overlay.innerHTML = `
			<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px;width:380px;max-width:90vw">
				<p style="margin-bottom:20px;font-size:14px;line-height:1.6">${escapeHtml(message).replace(/\n/g, '<br>')}</p>
				<div style="display:flex;justify-content:flex-end;gap:8px">
					<button class="btn btn-sm btn-secondary" id="cf-cancel">取消</button>
					<button class="btn btn-sm btn-primary" id="cf-ok">确定</button>
				</div>
			</div>`;
		document.body.appendChild(overlay);
		overlay.querySelector('#cf-ok').addEventListener('click', () => { overlay.remove(); resolve(true); });
		overlay.querySelector('#cf-cancel').addEventListener('click', () => { overlay.remove(); resolve(false); });
		overlay.addEventListener('click', (e) => { if (e.target === overlay) { overlay.remove(); resolve(false); } });
	});
}

/** 启动静默更新检查：非最新版则在 topbar 下方常驻横幅提示（不阻塞，失败静默，不弹 toast）。
 *  同一最新版本号本次会话忽略后不再重复提示（sessionStorage 记录，下次启动仍会检查）。 */
async function checkUpdateBanner() {
	const banner = document.getElementById('update-banner');
	if (!banner) return;
	try {
		const r = await window.electronAPI.checkUpdate();
		if (!r || r.error || !r.hasUpdate || !r.latest) return; // 已最新或检查失败 → 不打扰
		if (sessionStorage.getItem('cck_update_dismiss_' + r.latest) === '1') return; // 本次会话已忽略
		banner.innerHTML = `
			<span class="ub-icon">▲</span>
			<span class="ub-text">发现新版本 <b>v${escapeHtml(r.latest)}</b>（当前 v${escapeHtml(r.current || '')}），更新以获取最新功能与修复</span>
			<span class="ub-actions">
				<button class="btn btn-sm btn-primary" id="ub-update">立即更新</button>
				<button class="ub-close" id="ub-close" title="本次会话不再提示">×</button>
			</span>`;
		banner.style.display = 'flex';
		banner.querySelector('#ub-update').addEventListener('click', () => {
			if (r.downloadUrl) window.electronAPI.openExternal(r.downloadUrl);
		});
		banner.querySelector('#ub-close').addEventListener('click', () => {
			sessionStorage.setItem('cck_update_dismiss_' + r.latest, '1');
			banner.style.display = 'none';
		});
	} catch (e) { /* 静默：网络/代理异常不打扰用户 */ }
}

/** 更新窗口：展示当前/最新版本，确认后打开下载页 */
function showUpdateModal({ current, latest, downloadUrl }) {
	const overlay = document.createElement('div');
	overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);display:flex;justify-content:center;align-items:center;z-index:1000';
	overlay.innerHTML = `
		<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px;width:400px;max-width:90vw;text-align:center">
			<div style="font-size:30px;margin-bottom:8px">▲</div>
			<h3 style="font-size:17px;margin-bottom:14px">发现新版本 ${escapeHtml(latest || '')}</h3>
			<p style="font-size:13px;color:var(--text-dim);margin-bottom:6px">当前版本: ${escapeHtml(current || '')}</p>
			<p style="font-size:13px;color:var(--text-dim);margin-bottom:20px">更新后体验最新功能与问题修复</p>
			<div style="display:flex;justify-content:center;gap:10px">
				<button class="btn btn-sm btn-secondary" id="upd-later">稍后再说</button>
				<button class="btn btn-sm btn-primary" id="upd-now">立即更新</button>
			</div>
		</div>`;
	document.body.appendChild(overlay);
	const close = () => overlay.remove();
	overlay.querySelector('#upd-later').addEventListener('click', close);
	overlay.querySelector('#upd-now').addEventListener('click', () => { close(); window.electronAPI.openExternal(downloadUrl); });
	overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
}

async function purchaseAccount(planQuota, name, btn) {
	if (!await showConfirm(`确定购买「${name}」吗？将扣除对应余额。`)) return;

	if (btn) { btn.disabled = true; btn.textContent = '购买中...'; }

	const resp = await API.accounts.purchase(planQuota, currentShopCategory);
	if (resp.success) {
		toast(`购买成功，剩余余额: ${resp.new_balance}`, 'success');
		currentUser.credits = resp.new_balance;
		updateUserInfo(currentUser);
		await loadShop();
		// 如果在我的账号页，也刷新
		if (document.getElementById('my-view').classList.contains('active')) {
			await loadMyAccounts();
		}
	} else {
		toast(resp.error || '购买失败', 'error');
		if (btn) { btn.disabled = false; btn.textContent = '购买'; }
	}
}

// ========== 我的账号 ==========
let myAccounts = [];
let customAccounts = [];

/** 平台账号 + 自定义账号统一查找（自定义 id 为 c 前缀字符串，平台 id 为数字） */
function findAccountById(id) {
	return myAccounts.find((a) => String(a.id) === String(id)) || customAccounts.find((a) => String(a.id) === String(id));
}

/** 自定义账号卡片：与本机凭证绑定，无平台购买记录（不参与封禁退款） */
function renderCustomAccountCard(a) {
	const quotaHtml = `<div class="account-quota" id="quota-${a.id}">额度: <span class="text-dim">查询中...</span></div>`;
	const actionsHtml = `<button class="btn btn-sm btn-secondary credentials-btn" data-id="${a.id}">查看凭证</button>
		<button class="btn btn-sm btn-secondary quota-btn" data-id="${a.id}">刷新额度</button>
		<button class="btn btn-sm btn-danger custom-remove-btn" data-id="${a.id}">删除</button>`;
	const name = a.label || ('自定义' + (CATEGORY_NAMES[a.category] ? ' ' + CATEGORY_NAMES[a.category] : ''));
	return `
	<div class="my-account-card">
		<div class="account-info">
			<div class="account-name">${escapeHtml(name)} <span class="badge badge-info">自定义</span></div>
			<div class="account-meta">
				<span>类型: ${escapeHtml(CATEGORY_NAMES[a.category] || a.category)}</span>
				<span>来源: 本机凭证（不上传服务器）</span>
				<span>添加于: ${escapeHtml(a.created_at || '')}</span>
			</div>
			${quotaHtml}
		</div>
		<div class="account-actions">${actionsHtml}</div>
	</div>`;
}

async function loadMyAccounts() {
	const listEl = document.getElementById('my-list');
	listEl.innerHTML = '<div class="loading">加载中...</div>';

	// 平台账号与自定义账号并行加载：平台请求失败不阻断本机自定义账号展示
	const [myResp, customResp] = await Promise.all([
		API.accounts.my().catch(() => ({ success: false, error: '请求异常' })),
		API.accounts.customList().catch(() => ({ success: false, accounts: [] })),
	]);

	customAccounts = customResp.success ? (customResp.accounts || []) : [];

	if (!myResp.success) {
		const customHtml = customAccounts.map(renderCustomAccountCard).join('');
		listEl.innerHTML = customAccounts.length === 0
			? `<div class="empty-state"><div class="icon">⚠</div>${escapeHtml(myResp.error || '加载失败')}</div>`
			: `<div class="empty-state"><div class="icon">⚠</div>平台账号加载失败：${escapeHtml(myResp.error || '')}（下方自定义账号不受影响）</div>${customHtml}`;
		bindMyAccountEvents();
		refreshAllQuotas();
		return;
	}

	myAccounts = myResp.accounts || [];
	if (myAccounts.length === 0 && customAccounts.length === 0) {
		listEl.innerHTML = '<div class="empty-state"><div class="icon">◉</div>您还没有账号，请到商城购买，或点击右上角「+ 添加自定义账号」</div>';
		return;
	}

	listEl.innerHTML = myAccounts
		.map((a) => {
			const quotaHtml = `<div class="account-quota" id="quota-${a.id}">额度: <span class="text-dim">查询中...</span></div>`;
			// 已退款: 保留卡片+徽标，只留「查看凭证」；manual（09-03 全自动退款后服务端不再产生，仅停用期遗留）: 提示自动结算中
			const isRefunded = a.status === 'refunded';
			const statusBadge = isRefunded
				? `<span class="badge badge-danger">已退款 ${Number(a.refund_amount || 0)} 积分</span>`
				: (a.status === 'manual' ? '<span class="badge badge-warning" title="系统每小时自动核查结算：死号自动退款到余额，健康则恢复正常，无需联系客服">自动结算中</span>' : '');
			const actionsHtml = isRefunded
				? `<button class="btn btn-sm btn-secondary credentials-btn" data-id="${a.id}">查看凭证</button>`
				: `<button class="btn btn-sm btn-secondary credentials-btn" data-id="${a.id}">查看凭证</button>
				<button class="btn btn-sm btn-secondary quota-btn" data-id="${a.id}">刷新额度</button>`;
			return `
		<div class="my-account-card">
			<div class="account-info">
				<div class="account-name">${escapeHtml(a.plan_name) || '未命名'} ${a.label ? '<span class="text-dim">(' + escapeHtml(a.label) + ')</span>' : ''} ${statusBadge}</div>
				<div class="account-meta">
					<span>${isCreditsCat(a.category) ? '积分' : '额度'}: ${a.plan_quota != null ? Number(a.plan_quota) : '-'}${isTraeIntlCat(a.category) ? ' fast requests' : ''}</span>
					<span>购买价: ${Number(a.price_paid)}</span>
					<span>${escapeHtml(a.purchased_at || '')}</span>
				</div>
				${quotaHtml}
			</div>
			<div class="account-actions">${actionsHtml}</div>
		</div>`;
		})
		.join('') + customAccounts.map(renderCustomAccountCard).join('');

	bindMyAccountEvents();

	// 自动查询所有账号额度
	refreshAllQuotas();
}

/** 「我的账号」卡片事件绑定（平台账号 + 自定义账号共用；自定义 id 为字符串，不做 parseInt） */
function bindMyAccountEvents() {
	document.querySelectorAll('.credentials-btn').forEach((btn) => {
		btn.addEventListener('click', () => showCredentials(btn.dataset.id));
	});
	document.querySelectorAll('.quota-btn').forEach((btn) => {
		btn.addEventListener('click', () => checkQuota(btn.dataset.id));
	});
	document.querySelectorAll('.custom-remove-btn').forEach((btn) => {
		btn.addEventListener('click', () => removeCustomAccountById(btn.dataset.id));
	});
}

function showCredentials(accountId) {
	const account = findAccountById(accountId);
	if (!account) return;
	const isCustom = customAccounts.some((a) => String(a.id) === String(accountId));
	// Qoder 系凭证为 dt-/drt- 前缀，Trae/CodeBuddy 系为 JWT，千问办公为 OAuth token（无固定前缀）
	const isQoderCred = (account.token || '').startsWith('dt-');
	const isQwCred = account.category === 'qwenwork';
	const tokenLabel = isQoderCred ? 'Device Token (dt-xxx)' : isQwCred ? 'Access Token' : 'Access Token (JWT)';
	const refreshLabel = isQoderCred ? 'Refresh Token (drt-xxx)' : 'Refresh Token';
	const title = isCustom
		? escapeHtml(account.label || ('自定义 ' + (CATEGORY_NAMES[account.category] || account.category)))
		: (escapeHtml(account.plan_name) || '#' + accountId);
	const desc = isCustom
		? '本机保存的自定义账号凭证（未上传服务器），请妥善保管。'
		: '以下凭证用于登录 CCK 账号管理器和对应客户端，请妥善保管。';

	const overlay = document.createElement('div');
	overlay.className = 'modal-overlay show';
	overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);display:flex;justify-content:center;align-items:center;z-index:1000';
	overlay.innerHTML = `
		<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px;width:520px;max-width:90vw">
			<h2 style="margin-bottom:16px;font-size:18px">账号凭证 - ${title}</h2>
			<p style="font-size:13px;color:var(--text-dim);margin-bottom:16px">${desc}</p>
			<div class="form-group">
				<label>${tokenLabel}</label>
				<input type="text" id="cred-token" value="${escapeHtml(account.token || '')}" readonly style="font-family:Consolas,monospace;font-size:12px">
			</div>
			<div class="form-group">
				<label>${refreshLabel}</label>
				<input type="text" id="cred-refresh" value="${escapeHtml(account.refresh_token || '')}" readonly style="font-family:Consolas,monospace;font-size:12px">
			</div>
			<div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
				<button class="btn btn-sm btn-secondary" id="cred-copy-token">复制 Token</button>
				<button class="btn btn-sm btn-secondary" id="cred-copy-refresh">复制 Refresh</button>
				<button class="btn btn-sm btn-primary" id="cred-close">关闭</button>
			</div>
		</div>`;
	document.body.appendChild(overlay);

	const close = () => overlay.remove();
	overlay.querySelector('#cred-close').addEventListener('click', close);
	overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });

	overlay.querySelector('#cred-copy-token').addEventListener('click', async () => {
		await copyToClipboard(account.token || '');
		toast('Device Token 已复制', 'success');
	});
	overlay.querySelector('#cred-copy-refresh').addEventListener('click', async () => {
		await copyToClipboard(account.refresh_token || '');
		toast('Refresh Token 已复制', 'success');
	});
}

/** 更新单个账号的额度显示（quota 为空且 banned=true → 平台封禁，红色醒目提示；自定义账号无退款入口） */
function updateQuotaDisplay(accountId, quota, banned, isCustom) {
	const el = document.getElementById(`quota-${accountId}`);
	if (!el) return;
	if (!quota) {
		if (banned) {
			if (isCustom) {
				// 自定义账号凭证被平台明确拒绝 → 死号，仅提示（无平台购买记录，不走封禁退款）
				el.innerHTML = '额度: <span class="text-danger">⛔ 凭证已失效（被平台拒绝）</span>';
				markAccountBanned(accountId);
				return;
			}
			// 凭证被平台明确拒绝（吊销/白名单未过/死 token）→ 死号，告知用户已封禁不可用 + 退款入口
			el.innerHTML = `额度: <span class="text-danger">⛔ 账号已被平台封禁，无法使用</span>
				<button class="btn btn-sm btn-danger ban-refund-btn" data-id="${accountId}" style="margin-left:8px">封禁退款</button>`;
			const btn = el.querySelector('.ban-refund-btn');
			if (btn) btn.addEventListener('click', () => requestBanRefund(btn.dataset.id));
			markAccountBanned(accountId);
			return;
		}
		el.innerHTML = '额度: <span class="text-dim">查询失败（网络异常，请稍后重试）</span>';
		return;
	}
	// CodeBuddy 系（CN/WB/国际版，积分制）：凭证校验通过即显示有效，无额度统计
	if (quota.valid_only) {
		el.innerHTML = '额度: <b>积分制</b> <span class="text-dim">凭证有效（无额度统计）</span>';
		return;
	}
	const pct = Number(quota.percentage) || 0;
	const danger = pct > 80;
	const fmt = (v) => Number.isFinite(v) ? Number(v) : '无限';
	// 套餐徽标（Qoder 系实测: plan_tier_name=Free/Pro; Pro 绿色、其他灰色）
	const isPro = String(quota.plan_tier || '').toLowerCase() === 'pro';
	const planHtml = quota.plan_tier_name
		? `<span style="background:${isPro ? 'rgba(16,185,129,.15)' : 'rgba(161,161,161,.18)'};color:${isPro ? 'var(--primary)' : 'var(--text-dim)'};border-radius:4px;padding:1px 8px;font-size:12px;font-weight:600;margin-right:6px">${escapeHtml(quota.plan_tier_name)}</span>`
		: '';
	// Codex 订阅账号（Plus/Pro 等）：wham/usage 仅 5 小时/周百分比窗口，无剩余数值 → 只展示套餐
	if (quota.remaining == null && quota.total == null) {
		el.innerHTML = `${planHtml}额度: <b>订阅套餐</b> <span class="text-dim">按 5 小时/周窗口限额（无剩余数值）</span>`;
		return;
	}
	// 只有剩余、无总量口径（千问办公 Free 套餐网关返回 total/used 均为 null；Cursor 企业账号同理）
	// → 只展示剩余，不渲染 used/total 与进度条（fmt(null) 会误显示「无限」，0/0 又与剩余自相矛盾）
	// 判定须显式排除 null：Number(null)===0 且 isFinite(0)===true，用 isFinite 判会漏掉 null；
	// total=Infinity（不限量账号）仍走下方完整展示分支（fmt 渲染为「无限」）
	if (quota.remaining != null && (quota.total == null || Number.isNaN(Number(quota.total)))) {
		el.innerHTML = `${planHtml}额度: <b>剩余 ${fmt(quota.remaining)}</b> ${escapeHtml(quota.unit || 'credits')}
			<span class="text-dim">（平台未返回总量口径）</span>`;
		return;
	}
	el.innerHTML = `${planHtml}额度: <b>${fmt(quota.used)}</b>/<b>${fmt(quota.total)}</b> ${escapeHtml(quota.unit || 'credits')}
		<span class="text-dim">剩余 ${fmt(quota.remaining)}</span>
		<span class="quota-bar"><span class="quota-bar-fill" style="width:${pct}%"></span></span>
		<span class="${danger ? 'text-danger' : ''}">${pct}%</span>`;
}

/** 账号卡片追加「已封禁」红色徽标（额度检测判定平台封禁时；幂等，已存在不重复加） */
function markAccountBanned(accountId) {
	const quotaEl = document.getElementById(`quota-${accountId}`);
	const card = quotaEl ? quotaEl.closest('.my-account-card') : null;
	const nameEl = card ? card.querySelector('.account-name') : null;
	if (!nameEl || nameEl.querySelector('.cck-banned-badge')) return;
	const badge = document.createElement('span');
	badge.className = 'badge badge-danger cck-banned-badge';
	badge.style.marginLeft = '6px';
	badge.textContent = '已封禁';
	nameEl.appendChild(badge);
}

/** 封禁退款（v1.2.11）：服务端复核死号定论后按剩余额度比例退到余额（仅平台购买账号） */
async function requestBanRefund(accountId) {
	const account = myAccounts.find((a) => String(a.id) === String(accountId));
	if (!account) return;

	const confirmed = await showConfirm(
		`确认对「${account.plan_name || '该账号'}」发起封禁退款？\n\n` +
		'退款金额按账号剩余额度比例计算，将退回到您的 CCK 余额。\n' +
		'退款后该账号不可继续使用，且无法撤销。');
	if (!confirmed) return;

	const btn = document.querySelector(`.ban-refund-btn[data-id="${accountId}"]`);
	if (btn) { btn.disabled = true; btn.textContent = '退款中...'; }

	const resp = await API.accounts.banRefund(accountId);
	if (resp.success && resp.status === 'refunded') {
		toast(`退款成功，+${Number(resp.refund_amount || 0)} 余额已到账`, 'success');
	} else if (resp.success && resp.status === 'token_refreshed') {
		toast('经复核该账号凭证已自动续期恢复可用，无需退款', 'success');
	} else if (resp.success && resp.status === 'healthy') {
		toast('经复核该账号状态正常，不符合退款条件', 'info');
	} else if (resp.success && resp.status === 'manual') {
		// 09-03 全自动退款后服务端不再返回 manual（保留分支兼容旧响应）：遗留订单由每小时巡检自动结算
		toast('该账号正在自动结算中，稍后会自动退款到您的余额，无需联系客服', 'info');
	} else if (resp.success && resp.status === 'out_of_scope') {
		// legacy 历史订单等不适用自动退款：服务端已给出明确文案
		toast(resp.error || '该订单不在自动退款范围内', 'info');
	} else if (resp.success && resp.status === 'out_of_window') {
		// 09-04 起服务端超期改返 out_of_scope + error 文案（走上面 out_of_scope 分支），此分支仅兼容旧响应。
		toast(resp.error || '已超过 31 天保障期，该账号已到期并回收再售，不在自动退款范围', 'info');
	} else if (resp.success && resp.status === 'not_found') {
		toast('未找到该账号记录', 'error');
	} else {
		toast(resp.error || '暂时无法确认封禁状态，请稍后重试', 'error');
	}

	// 刷新余额与账号列表（退款→已退款徽标；续期→新 token 生效）
	try {
		const sess = await API.auth.getSession();
		if (sess.success) { currentUser = sess.user; updateUserInfo(sess.user); }
	} catch (e) { /* 余额刷新失败不阻断 */ }
	await loadMyAccounts();
}

/** 并发查询所有账号额度（平台 + 自定义），逐个更新 DOM */
async function refreshAllQuotas() {
	// 跳过已退款账号（死号，额度查询必然失败）
	const platformPromises = myAccounts.filter((a) => a.status !== 'refunded').map(async (a) => {
		const resp = await API.quota.check(a.token, a.refresh_token, a.category || 'qoder');
		if (resp.success) {
			a._quota = resp.usage;
			a._banned = false;
			updateQuotaDisplay(a.id, resp.usage);
		} else {
			a._banned = !!resp.banned;
			updateQuotaDisplay(a.id, null, resp.banned);
		}
	});
	// 自定义账号：额度失败不参与封禁计数（非平台资产）
	const customPromises = customAccounts.map(async (a) => {
		const resp = await API.quota.check(a.token, a.refresh_token, a.category || 'qoder');
		if (resp.success) {
			a._quota = resp.usage;
			a._banned = false;
			updateQuotaDisplay(a.id, resp.usage, undefined, true);
		} else {
			a._banned = !!resp.banned;
			updateQuotaDisplay(a.id, null, resp.banned, true);
		}
	});
	await Promise.all(platformPromises.concat(customPromises));
}

/** 查询单个账号额度 */
async function checkQuota(accountId) {
	const account = findAccountById(accountId);
	if (!account) return;
	const isCustom = customAccounts.some((a) => String(a.id) === String(accountId));

	const btn = document.querySelector(`.quota-btn[data-id="${accountId}"]`);
	if (btn) { btn.disabled = true; btn.textContent = '查询中...'; }

	const resp = await API.quota.check(account.token, account.refresh_token, account.category || 'qoder');
	if (resp.success) {
		account._quota = resp.usage;
		account._banned = false;
		updateQuotaDisplay(accountId, resp.usage, undefined, isCustom);
		toast('额度已更新', 'success');
	} else {
		account._banned = !!resp.banned;
		updateQuotaDisplay(accountId, null, resp.banned, isCustom);
		toast(resp.banned
			? '该账号已被平台封禁，无法使用。如仍在使用有效期内，请凭购买记录联系卖家更换'
			: (resp.error || '额度查询失败'), 'error');
	}
	if (btn) { btn.disabled = false; btn.textContent = '刷新额度'; }
}

// ========== 自定义账号（用户自有凭证，仅存本机 DPAPI 加密，不过后端/不占平台库存） ==========

/** 添加自定义账号弹窗：选类型 + 输入凭证 + 可选在线验证（CodeBuddy 家族按 JWT iss 自动归类） */
function showAddCustomAccountModal() {
	const CATS = [
		['qoder', 'Qoder Work CN'],
		['qodercn', 'Qoder IDE CN'],
		['qoderapp', 'Qoder CN App'],
		['qoder_intl', 'Qoder 国际版'],
		['trae_cn', 'TRAE CN'],
		['trae_solo', 'TRAE CN (SOLO)'],
		['trae_intl', 'Trae 国际版'],
		['codebuddy_cn', 'CodeBuddy/WorkBuddy CN'],
		['codebuddy_intl', 'CodeBuddy 国际版'],
		['qwenwork', '千问办公'],
		['codex', 'Codex CLI'],
		['cursor', 'Cursor IDE'],
		['kiro', 'Kiro IDE'],
		['zcode', 'ZCode (智谱)'],
		['kimi', 'Kimi Code'],
		['coze', '扣子 (Coze)'],
		['autoclaw', 'AutoClaw (智谱)'],
		['doubao', '豆包工作平台 (Doubao)'],
		['minimax', 'MiniMax Code'],
	];
	const overlay = document.createElement('div');
	overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);display:flex;justify-content:center;align-items:center;z-index:1000';
	overlay.innerHTML = `
		<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:24px;width:520px;max-width:92vw;max-height:90vh;overflow-y:auto">
			<h2 style="margin-bottom:6px;font-size:18px">添加自定义账号</h2>
			<p style="font-size:12px;color:var(--text-dim);margin-bottom:16px;line-height:1.7">凭证仅保存在本机（系统级加密），不会上传服务器，与平台购买账号互不影响。</p>
			<div class="form-group">
				<label>账号类型</label>
				<select id="cac-category" style="width:100%">${CATS.map(([v, n]) => `<option value="${v}">${n}</option>`).join('')}</select>
			</div>
			<div class="form-group">
				<label id="cac-token-label">Device Token (dt-xxx)</label>
				<textarea id="cac-token" rows="3" placeholder="dt-..." style="width:100%;font-family:Consolas,monospace;font-size:12px" autocomplete="off" spellcheck="false"></textarea>
			</div>
			<div class="form-group">
				<label id="cac-refresh-label">Refresh Token (drt-xxx)</label>
				<input type="text" id="cac-refresh" placeholder="drt-..." style="width:100%;font-family:Consolas,monospace;font-size:12px" autocomplete="off" spellcheck="false">
			</div>
			<div class="form-group">
				<label>备注名称（选填）</label>
				<input type="text" id="cac-label" placeholder="如：工作号-1" maxlength="64" autocomplete="off">
			</div>
			<div class="form-group">
				<label>user_data（选填，JSON 对象）</label>
				<textarea id="cac-userdata" rows="2" placeholder='如 Trae 设备密钥对 {"device_id":"...","device_private_key":"..."}' style="width:100%;font-family:Consolas,monospace;font-size:12px" autocomplete="off" spellcheck="false"></textarea>
			</div>
			<label style="display:flex;align-items:center;gap:8px;font-size:13px;margin-bottom:12px">
				<input type="checkbox" id="cac-verify" checked> 添加时在线验证凭证（推荐；离线时可取消勾选跳过）
			</label>
			<div id="cac-result" style="font-size:13px;min-height:18px;margin-bottom:12px"></div>
			<div style="display:flex;justify-content:flex-end;gap:8px">
				<button class="btn btn-sm btn-secondary" id="cac-cancel">取消</button>
				<button class="btn btn-sm btn-secondary" id="cac-add-noverify" title="不做在线验证直接保存">跳过验证添加</button>
				<button class="btn btn-sm btn-primary" id="cac-add">验证并添加</button>
			</div>
		</div>`;
	document.body.appendChild(overlay);
	const close = () => overlay.remove();
	overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
	overlay.querySelector('#cac-cancel').addEventListener('click', close);

	// 账号类型切换时同步凭证提示（Qoder 系 dt-/drt- 前缀，千问办公无固定前缀，其余为 JWT）
	const syncLabels = () => {
		const cat = overlay.querySelector('#cac-category').value;
		const isQoder = cat === 'qoder' || cat === 'qodercn' || cat === 'qoderapp' || cat === 'qoder_intl';
		const isQw = cat === 'qwenwork';
		overlay.querySelector('#cac-token-label').textContent = isQoder ? 'Device Token (dt-xxx)' : isQw ? 'Access Token' : 'Access Token (JWT，eyJ 开头)';
		overlay.querySelector('#cac-refresh-label').textContent = isQoder ? 'Refresh Token (drt-xxx)' : 'Refresh Token';
		overlay.querySelector('#cac-token').placeholder = isQoder ? 'dt-...' : isQw ? '登录凭证 token（无固定前缀）' : 'eyJ...';
		overlay.querySelector('#cac-refresh').placeholder = isQoder ? 'drt-...' : '';
	};
	overlay.querySelector('#cac-category').addEventListener('change', syncLabels);
	syncLabels();

	const doAdd = async (verify) => {
		const resultEl = overlay.querySelector('#cac-result');
		const input = {
			category: overlay.querySelector('#cac-category').value,
			token: overlay.querySelector('#cac-token').value.trim(),
			refresh_token: overlay.querySelector('#cac-refresh').value.trim(),
			label: overlay.querySelector('#cac-label').value.trim(),
			user_data: overlay.querySelector('#cac-userdata').value.trim(),
			verify,
		};
		if (!input.token || !input.refresh_token) {
			resultEl.innerHTML = '<span class="text-danger">请填写 Token 与 Refresh Token</span>';
			return;
		}
		const btns = overlay.querySelectorAll('#cac-add, #cac-add-noverify');
		btns.forEach((b) => { b.disabled = true; });
		resultEl.innerHTML = verify ? '<span class="text-dim">正在验证凭证并保存...</span>' : '<span class="text-dim">正在保存...</span>';
		try {
			const resp = await API.accounts.customAdd(input);
			if (resp.success) {
				const catName = CATEGORY_NAMES[resp.account.category] || resp.account.category;
				close();
				toast(`自定义账号已添加${catName !== CATEGORY_NAMES[input.category] ? '（已识别为 ' + catName + '）' : ''}`, 'success');
				await loadMyAccounts();
			} else {
				resultEl.innerHTML = `<span class="text-danger">${escapeHtml(resp.error || '添加失败')}</span>`;
				btns.forEach((b) => { b.disabled = false; });
			}
		} catch (e) {
			resultEl.innerHTML = `<span class="text-danger">请求异常: ${escapeHtml(e.message)}</span>`;
			btns.forEach((b) => { b.disabled = false; });
		}
	};
	overlay.querySelector('#cac-add').addEventListener('click', () => doAdd(overlay.querySelector('#cac-verify').checked));
	overlay.querySelector('#cac-add-noverify').addEventListener('click', () => doAdd(false));
}

/** 删除自定义账号：仅移除本机保存的凭证，不影响客户端内已登录状态 */
async function removeCustomAccountById(id) {
	const account = customAccounts.find((a) => String(a.id) === String(id));
	if (!account) return;
	const name = account.label || CATEGORY_NAMES[account.category] || '未命名';
	const confirmed = await showConfirm(`确定删除自定义账号「${name}」吗？\n\n仅从本机移除保存的凭证；客户端内已登录的账号不受影响。`);
	if (!confirmed) return;
	const resp = await API.accounts.customRemove(id);
	if (resp.success) {
		toast('自定义账号已删除', 'success');
		await loadMyAccounts();
	} else {
		toast(resp.error || '删除失败', 'error');
	}
}

// ========== 初始化 ==========
async function copyToClipboard(text) {
	try {
		await navigator.clipboard.writeText(text);
		toast('已复制', 'success');
	} catch {
		const ta = document.createElement('textarea');
		ta.value = text;
		ta.style.position = 'fixed';
		ta.style.opacity = '0';
		document.body.appendChild(ta);
		ta.select();
		try { document.execCommand('copy'); toast('已复制', 'success'); } catch { toast('复制失败', 'error'); }
		document.body.removeChild(ta);
	}
}

async function init() {
	await initLoginPage();

	// 检查已有会话
	const session = await API.auth.getSession();
	if (session.success) {
		showMainView(session.user);
	} else {
		document.getElementById('login-view').style.display = 'flex';
	}
}

// 添加 text-dim 工具类
const style = document.createElement('style');
style.textContent = '.text-dim{color:var(--text-dim);}.text-danger{color:var(--danger)!important;}';
document.head.appendChild(style);

init().catch((e) => {
	console.error('初始化失败:', e);
	toast('初始化失败: ' + e.message, 'error');
});
