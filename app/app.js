/* ==========================================================================
   CxScope · Checkmarx One 漏洞看板
   纯前端单页应用：通过本地代理（proxy.py）调用 Checkmarx One REST API。

   登录流程（与 IDEA 插件 / ast-cli 一致）：
     1. API Key 是 JWT；解码其 payload，取 aud（形如 https://<region>.iam.checkmarx.net/auth/realms/<tenant>）
        作为 IAM realm，取 azp 作为 client_id（默认 ast-app）；
     2. POST <realm>/protocol/openid-connect/token
          grant_type=refresh_token&client_id=<azp>&refresh_token=<API Key>
        换取 access_token；
     3. access_token 的 ast-base-url 声明即 AST API 地址（不可用时按 IAM -> AST 域名替换兜底）；
     4. 之后所有 API 调用携带 Authorization: Bearer <access_token>。
   ========================================================================== */
(function () {
  'use strict';

  /* ---------------------------------------------------------------------- */
  var PROXY_FILE_URL = 'http://127.0.0.1:8787';   // file:// 打开时使用的本地代理地址
  var LS_CFG = 'cxs_config_v1';
  var LS_FILTER = 'cxs_filter_v1';   // 筛选记忆：项目/分支/严重级别（按 租户+API 地址 隔离，仅存本机）
  var LS_SCAN_MEMORY = 'cxs_scan_memory_v1';   // 本地扫描记忆：文件夹路径 + Checkmarx One 项目名（按 租户+API 地址 隔离，仅存本机）
  var SCAN_MEMORY_ROWS_MAX = 8;        // 记忆最多恢复的文件夹行数
  var SCAN_MEMORY_RECENT_MAX = 8;      // 「最近扫描」最多保留的「路径 + 项目名」条数
  var SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  var SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  var SEV_LABEL = { CRITICAL: '严重', HIGH: '高危', MEDIUM: '中危', LOW: '低危', INFO: '信息' };
  var STATE_LABEL = {
    TO_VERIFY: '待确认', CONFIRMED: '已确认', IGNORED: '已忽略', URGENT: '紧急',
    NOT_EXPLOITABLE: '不可利用', PROPOSED_NOT_EXPLOITABLE: '建议不可利用', FIXED: '已修复'
  };
  var STATUS_LABEL = { NEW: '新增', RECURRENT: '复现', FIXED: '已修复' };
  var RESULT_PAGE = 500;
  var SCAN_PAGE = 100;
  /* 详情抽屉宽度：默认 520px，最小 420px，最大为浏览器可视宽度的 70% */
  var DRAWER_DEFAULT_WIDTH = 520;
  var DRAWER_MIN_WIDTH = 420;
  var DRAWER_MAX_RATIO = 0.7;
  var LS_DRAWER_WIDTH = 'cxs_drawer_width_v1';
  var drawerDesiredWidth = null;
  var KB = window.CX_KB || { cwes: {}, generic: { attackVector: '', remediation: {} }, resolveCwe: function () { return 0; }, lookup: function () { return { cwe: 0, entry: null }; }, cweUrl: function () { return ''; } };

  /* ---------------------------------------------------------------------- */
  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function pad(n) { return n < 10 ? '0' + n : '' + n; }
  function fmtDate(v) {
    if (!v) return '—';
    var d = new Date(v);
    if (isNaN(d.getTime())) return String(v);
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }
  function relTime(v) {
    if (!v) return '—';
    var t = new Date(v).getTime();
    if (isNaN(t)) return '—';
    var diff = Date.now() - t;
    if (diff < 60e3) return '刚刚';
    if (diff < 3600e3) return Math.round(diff / 60e3) + ' 分钟前';
    if (diff < 86400e3) return Math.round(diff / 3600e3) + ' 小时前';
    var days = Math.round(diff / 86400e3);
    if (days < 30) return days + ' 天前';
    return fmtDate(v).slice(0, 10);
  }
  function debounce(fn, ms) { var t; return function () { var a = arguments, self = this; clearTimeout(t); t = setTimeout(function () { fn.apply(self, a); }, ms); }; }
  function setBusy(btn, busy, text) {
    if (!btn) return;
    if (busy) { btn.dataset._html = btn.innerHTML; btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> ' + (text || '处理中…'); }
    else { btn.disabled = false; btn.innerHTML = btn.dataset._html || text || btn.innerHTML; }
  }
  function toast(msg, type, ms) {
    var stack = $('#toastStack');
    if (!stack) { stack = document.createElement('div'); stack.className = 'toast-stack'; stack.id = 'toastStack'; document.body.appendChild(stack); }
    var el = document.createElement('div');
    el.className = 'toast ' + (type || 'info');
    el.innerHTML = (type === 'ok' ? '✓ ' : type === 'err' ? '⚠ ' : 'ℹ️ ') + esc(msg);
    stack.appendChild(el);
    setTimeout(function () {
      el.classList.add('leaving');
      setTimeout(function () { el.remove(); }, 220);
    }, ms || 2800);
  }

  /* ---------------------------------------------------------------------- */
  /* 详情抽屉宽度（拖拽调整 + 记忆）                                          */
  /* ---------------------------------------------------------------------- */
  function drawerMaxWidth() {
    var vw = window.innerWidth || document.documentElement.clientWidth || 1280;
    return Math.max(DRAWER_MIN_WIDTH, Math.floor(vw * DRAWER_MAX_RATIO));
  }
  function clampDrawerWidth(w) {
    var n = Number(w);
    if (isNaN(n)) n = DRAWER_DEFAULT_WIDTH;
    return Math.max(DRAWER_MIN_WIDTH, Math.min(Math.round(n), drawerMaxWidth()));
  }
  function loadDrawerWidth() {
    try {
      var v = parseInt(localStorage.getItem(LS_DRAWER_WIDTH) || '', 10);
      if (!isNaN(v)) return clampDrawerWidth(v);
    } catch (e) { /* ignore */ }
    return DRAWER_DEFAULT_WIDTH;
  }
  function persistDrawerWidth() {
    try { localStorage.setItem(LS_DRAWER_WIDTH, String(drawerDesiredWidth)); } catch (e) { /* ignore */ }
  }
  /** 应用抽屉宽度：desired 为期望宽度（可大于当前视口上限），实际宽度会 clamp。 */
  function applyDrawerWidth(desired, persist) {
    var drawer = $('#detailDrawer');
    if (!drawer) return;
    var n = Number(desired);
    if (isNaN(n)) n = DRAWER_DEFAULT_WIDTH;
    drawerDesiredWidth = Math.max(DRAWER_MIN_WIDTH, Math.round(n));
    var actual = clampDrawerWidth(drawerDesiredWidth);
    drawer.style.width = actual + 'px';
    if (persist) persistDrawerWidth();
  }
  function initDrawerResize() {
    var drawer = $('#detailDrawer');
    var handle = $('#drawerResizer');
    if (!drawer || !handle) return;
    var dragging = false;
    var startX = 0;
    var startW = 0;

    function onDown(e) {
      if (e.button != null && e.button !== 0) return;
      dragging = true;
      startX = e.clientX;
      startW = drawer.getBoundingClientRect().width;
      handle.classList.add('dragging');
      document.body.classList.add('drawer-resizing');
      try { handle.setPointerCapture(e.pointerId); } catch (err) { /* ignore */ }
      e.preventDefault();
    }
    function onMove(e) {
      if (!dragging) return;
      // 向左拖拽 => 变宽
      applyDrawerWidth(startW + (startX - e.clientX), false);
      e.preventDefault();
    }
    function onUp(e) {
      if (!dragging) return;
      dragging = false;
      handle.classList.remove('dragging');
      document.body.classList.remove('drawer-resizing');
      try { if (e && e.pointerId != null && handle.hasPointerCapture(e.pointerId)) handle.releasePointerCapture(e.pointerId); } catch (err) { /* ignore */ }
      persistDrawerWidth();
    }
    if (window.PointerEvent) {
      handle.addEventListener('pointerdown', onDown);
      // 监听 window：拖拽时指针可能移出 8px 热区甚至抽屉外
      window.addEventListener('pointermove', onMove);
      window.addEventListener('pointerup', onUp);
      window.addEventListener('pointercancel', onUp);
    } else {
      handle.addEventListener('mousedown', function (e) {
        onDown(e);
        window.addEventListener('mousemove', onMove);
        window.addEventListener('mouseup', function up() {
          window.removeEventListener('mousemove', onMove);
          window.removeEventListener('mouseup', up);
          onUp();
        });
      });
    }
    handle.addEventListener('dblclick', function (e) {
      e.preventDefault();
      applyDrawerWidth(DRAWER_DEFAULT_WIDTH, true);
      toast('已恢复默认宽度 ' + DRAWER_DEFAULT_WIDTH + 'px', 'info', 1500);
    });
    window.addEventListener('resize', function () {
      if (dragging || drawerDesiredWidth == null) return;
      applyDrawerWidth(drawerDesiredWidth, false);
    });
    applyDrawerWidth(drawerDesiredWidth == null ? loadDrawerWidth() : drawerDesiredWidth, false);
  }

  /* ---------------------------------------------------------------------- */
  function proxyBase() { return location.protocol === 'file:' ? PROXY_FILE_URL : ''; }

  async function parseResponse(res) {
    var text = '';
    try { text = await res.text(); } catch (e) { /* ignore */ }
    var data;
    try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
    if (!res.ok) {
      var msg = data && (data.error || data.message || data.Message || data.title);
      if (!msg && typeof data === 'string' && data) msg = data.slice(0, 400);
      var err = new Error(msg || ('HTTP ' + res.status));
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  async function proxyFetch(targetUrl, opts) {
    if (window.CX_DEMO_MOCK && window.CX_DEMO_MOCK.fetch) return window.CX_DEMO_MOCK.fetch(targetUrl, opts);
    opts = opts || {};
    var url = proxyBase() + '/proxy';
    var headers = Object.assign({ 'X-Target-Url': targetUrl }, opts.headers || {});
    var res;
    try {
      res = await fetch(url, { method: opts.method || 'GET', headers: headers, body: opts.body || null });
    } catch (e) {
      throw new Error('无法连接本地代理（' + url + '）。请先在本机运行 python proxy.py 后重试。原始错误：' + e.message);
    }
    return parseResponse(res);
  }

  async function proxyJson(path, payload, method) {
    if (window.CX_DEMO_MOCK && window.CX_DEMO_MOCK.json) return window.CX_DEMO_MOCK.json(path, payload, method);
    var url = proxyBase() + path;
    var res;
    try {
      res = await fetch(url, {
        method: method || 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload == null ? null : JSON.stringify(payload)
      });
    } catch (e) {
      throw new Error('无法连接本地代理（' + url + '）。请先在本机运行 python proxy.py 后重试。原始错误：' + e.message);
    }
    return parseResponse(res);
  }

  /* ---------------------------------------------------------------------- */
  function b64urlDecode(str) {
    var s = String(str || '').replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s);
    var bytes = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    try { return new TextDecoder('utf-8').decode(bytes); } catch (e) { return bin; }
  }
  function decodeJwt(token) {
    if (!token) return null;
    var parts = String(token).trim().split('.');
    if (parts.length < 2) return null;
    try { return JSON.parse(b64urlDecode(parts[1])); } catch (e) { return null; }
  }
  function pickAudience(claims) {
    var aud = claims && claims.aud;
    if (!aud) return '';
    if (Array.isArray(aud)) {
      for (var i = 0; i < aud.length; i++) if (typeof aud[i] === 'string' && aud[i].indexOf('/auth/realms/') >= 0) return aud[i];
      for (var j = 0; j < aud.length; j++) if (typeof aud[j] === 'string') return aud[j];
      return '';
    }
    return String(aud);
  }
  function parseApiKey(apiKey) {
    var key = String(apiKey || '').trim();
    if (!key) throw new Error('请输入 API Key');
    var claims = decodeJwt(key);
    if (!claims && window.CX_DEMO_MOCK && window.CX_DEMO_MOCK.parseApiKey) return window.CX_DEMO_MOCK.parseApiKey(key);
    if (!claims) throw new Error('API Key 格式无法识别：需要 Checkmarx One 的 JWT 格式 API Key（请在 Checkmarx One → 设置 → API Keys 中生成）');
    var realm = pickAudience(claims) || String(claims.iss || '');
    if (!/\/auth\/realms\//.test(realm)) {
      throw new Error('无法从 API Key 的 aud/iss 声明中解析 IAM 租户地址。请确认这是 Checkmarx One 的 API Key（包含 aud=https://<region>.iam.checkmarx.net/auth/realms/<tenant>）。');
    }
    realm = realm.replace(/\/+$/, '');
    var tenant = (realm.match(/\/auth\/realms\/([^\/]+)/) || [])[1] || '';
    var azp = claims.azp || claims.client_id || 'ast-app';
    return { claims: claims, realmUrl: realm, tenant: tenant, azp: azp };
  }
  function hostSwapApiBase(realmUrl) {
    try {
      var u = new URL(realmUrl);
      var host = u.host;
      if (host.indexOf('.iam.') >= 0) return 'https://' + host.replace('.iam.', '.ast.');
      if (host.indexOf('iam.') === 0) return 'https://ast.' + host.slice(4);
      return 'https://' + host;
    } catch (e) { return ''; }
  }
  function realmFromApiKey(apiKey) { return parseApiKey(apiKey).realmUrl; }

  async function loginWithApiKey(apiKey) {
    var parsed = parseApiKey(apiKey);
    var authUrl = parsed.realmUrl + '/protocol/openid-connect/token';
    var body = 'grant_type=refresh_token&client_id=' + encodeURIComponent(parsed.azp) +
      '&refresh_token=' + encodeURIComponent(String(apiKey).trim());
    var data;
    try {
      data = await proxyFetch(authUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
        body: body
      });
    } catch (e) {
      if (e.status === 400 || e.status === 401) {
        throw new Error('Checkmarx IAM 拒绝了该 API Key（' + (e.status || '') + '）。请确认 Key 未过期、未被吊销，且属于 ' + parsed.tenant + ' 租户。');
      }
      throw e;
    }
    if (!data || !data.access_token) throw new Error('登录响应中缺少 access_token，请确认 API Key 类型与租户是否正确。');
    var tokenClaims = decodeJwt(data.access_token) || {};
    var apiBase = String(tokenClaims['ast-base-url'] || '').replace(/\/+$/, '') || hostSwapApiBase(parsed.realmUrl);
    if (!apiBase) throw new Error('无法确定 Checkmarx One API 地址（access token 缺少 ast-base-url 声明）。');
    var info = {
      accessToken: data.access_token,
      expiresAt: Date.now() + (Number(data.expires_in || 3600) - 60) * 1000,
      apiBase: apiBase,
      realmUrl: parsed.realmUrl,
      tenant: parsed.tenant,
      azp: parsed.azp,
      apiKey: String(apiKey).trim()
    };
    return info;
  }

  var state = {
    session: null,          // {accessToken, expiresAt, apiBase, realmUrl, tenant, azp, apiKey}
    connected: false,
    projects: [],           // 全部项目
    selectedProjectIds: new Set(),   // 已生效的项目选择
    draftProjectIds: new Set(),      // 下拉中正在勾选的草稿（点「应用」才生效）
    projectQuery: '',                // 项目下拉内的搜索词（仅本次下拉有效，不持久化）
    projectMatchCount: 0,            // 当前搜索命中的项目数
    scans: [],              // 当前已拉取的扫描
    results: [],            // 当前扫描结果（已归一化）
    rows: [],
    branch: '',
    scanKey: '',            // '' = 每个项目最新扫描
    sevs: new Set(SEVS),
    q: '',
    sort: { key: 'severity', dir: 1 },
    selectedId: null,
    loading: false,
    requestId: 0,
    scanPollers: {},
    branchReloadSeq: 0
  };

  function saveConfig() {
    try {
      var rememberEl = $('#rememberKey');
      var remember = rememberEl ? rememberEl.checked : true;
      var key = state.session ? state.session.apiKey : ($('#apiKeyInput') ? $('#apiKeyInput').value.trim() : '');
      if (!remember && rememberEl) {
        // 未勾选「记住」时不落盘 API Key
        localStorage.setItem(LS_CFG, JSON.stringify({ apiKey: '', rememberKey: false, savedAt: Date.now() }));
        return;
      }
      localStorage.setItem(LS_CFG, JSON.stringify({ apiKey: key, rememberKey: remember, savedAt: Date.now() }));
    } catch (e) { /* ignore */ }
  }
  function loadConfig() {
    try { return JSON.parse(localStorage.getItem(LS_CFG) || '{}') || {}; } catch (e) { return {}; }
  }
  function clearConfig() {
    try { localStorage.removeItem(LS_CFG); } catch (e) { /* ignore */ }
    clearFilterMemory();
    clearScanMemory();
    resetScanMemoryState();
  }

  /* ---------------------------------------------------------------------- */
  /* 筛选记忆（仅本机 localStorage，按 租户+API 地址 隔离）                    */
  /*   - 项目/分支：点「应用」且本次数据加载有结果后写入；                    */
  /*   - 严重级别：点击标签即写入，下次打开/刷新自动恢复。                     */
  /* ---------------------------------------------------------------------- */
  function filterScope() {
    var s = state.session;
    if (!s) return '';
    return [s.tenant || '', s.apiBase || '', s.realmUrl || ''].join('|');
  }
  /** 校验记忆里的严重级别：只保留已知值；缺失或全部无效时返回 null（回退默认全选）。 */
  function normalizeSevs(list) {
    if (!Array.isArray(list)) return null;
    var out = SEVS.filter(function (s) { return list.indexOf(s) >= 0; });
    return out.length ? out : null;
  }
  /** 读取上次「应用」过的项目/分支选择与严重级别；从未有记录时返回 null（等价于空选 + 全部级别）。 */
  function loadFilterMemory() {
    var scope = filterScope();
    if (!scope) return null;
    try {
      var raw = JSON.parse(localStorage.getItem(LS_FILTER) || '{}') || {};
      var v = raw[scope];
      if (!v || typeof v !== 'object') return null;
      return {
        projectIds: Array.isArray(v.projectIds) ? v.projectIds.map(String) : [],
        branch: typeof v.branch === 'string' ? v.branch : '',
        sevs: normalizeSevs(v.sevs)
      };
    } catch (e) { return null; }
  }
  /** 写入记忆：项目/分支仅在「应用」且本次数据加载有结果之后调用（自动全部分支等）。 */
  function saveFilterMemory() {
    var scope = filterScope();
    if (!scope) return;
    try {
      var raw = JSON.parse(localStorage.getItem(LS_FILTER) || '{}') || {};
      raw[scope] = {
        projectIds: Array.from(state.selectedProjectIds),
        branch: state.branch || '',
        sevs: SEVS.filter(function (s) { return state.sevs.has(s); }),
        savedAt: Date.now()
      };
      localStorage.setItem(LS_FILTER, JSON.stringify(raw));
    } catch (e) { /* ignore */ }
  }
  /**
   * 只写入严重级别记忆：切换标签后立即调用。
   * 保留记录里已有的项目/分支，避免在登录恢复完成前把上次项目选择覆盖成空选。
   */
  function saveSeverityMemory() {
    var scope = filterScope();
    if (!scope) return;
    try {
      var raw = JSON.parse(localStorage.getItem(LS_FILTER) || '{}') || {};
      var rec = (raw[scope] && typeof raw[scope] === 'object') ? raw[scope] : {};
      rec.sevs = SEVS.filter(function (s) { return state.sevs.has(s); });
      rec.savedAt = Date.now();
      raw[scope] = rec;
      localStorage.setItem(LS_FILTER, JSON.stringify(raw));
    } catch (e) { /* ignore */ }
  }
  function clearFilterMemory() { try { localStorage.removeItem(LS_FILTER); } catch (e) { /* ignore */ } }

  /* ---------------------------------------------------------------------- */
  /* 本地扫描记忆（仅本机 localStorage，按 租户+API 地址 隔离）                */
  /*   - rows  ：上次填写的「文件夹路径 + Checkmarx One 项目名」，打开弹窗自动恢复；*/
  /*   - recent：最近实际提交过的「路径 + 项目名」组合，可在弹窗中一键填入。       */
  /* ---------------------------------------------------------------------- */
  function normalizeScanMemoryRow(r) {
    return { path: String((r && r.path) || '').trim(), name: String((r && r.name) || '').trim() };
  }
  /**
   * 记忆记录按「路径 + 项目名」去重（Windows 路径忽略大小写与斜杠方向），
   * 用于「最近扫描」列表去重。
   */
  function scanTargetKey(t) {
    var p = String((t && t.path) || '').toLowerCase().replace(/\\/g, '/');
    var n = String((t && t.name) || '').toLowerCase();
    return p + '\u0000' + n;
  }
  function loadScanMemory() {
    var scope = filterScope();
    if (!scope) return null;
    try {
      var raw = JSON.parse(localStorage.getItem(LS_SCAN_MEMORY) || '{}') || {};
      var v = raw[scope];
      if (!v || typeof v !== 'object') return null;
      var rows = (Array.isArray(v.rows) ? v.rows : []).map(normalizeScanMemoryRow)
        .filter(function (r) { return r.path || r.name; });
      var recent = (Array.isArray(v.recent) ? v.recent : []).map(normalizeScanMemoryRow)
        .filter(function (r) { return r.path; });
      return { rows: rows, recent: recent };
    } catch (e) { return null; }
  }
  /** 写入记忆：rows 必写；recent 传 null/undefined 时保留原值（输入过程中只更新行）。 */
  function saveScanMemoryRows(rows, recent) {
    var scope = filterScope();
    if (!scope) return;
    try {
      var raw = JSON.parse(localStorage.getItem(LS_SCAN_MEMORY) || '{}') || {};
      var prev = (raw[scope] && typeof raw[scope] === 'object') ? raw[scope] : {};
      raw[scope] = {
        rows: (rows || []).slice(0, SCAN_MEMORY_ROWS_MAX),
        recent: (recent != null ? recent : (Array.isArray(prev.recent) ? prev.recent : [])).slice(0, SCAN_MEMORY_RECENT_MAX),
        savedAt: Date.now()
      };
      localStorage.setItem(LS_SCAN_MEMORY, JSON.stringify(raw));
    } catch (e) { /* ignore */ }
  }
  /** 实际提交扫描时调用：把「路径 + 项目名」置顶「最近扫描」（去重）并持久化，返回最新列表。 */
  function rememberScanTargets(folders) {
    var rows = [], targets = [];
    (folders || []).forEach(function (f) {
      var r = normalizeScanMemoryRow(f);
      if (!r.path) return;
      rows.push(r);
      targets.push(r);
    });
    var scope = filterScope();
    if (!scope) return null;
    var prev = loadScanMemory();
    var recent = (prev && prev.recent ? prev.recent.slice() : []);
    for (var i = targets.length - 1; i >= 0; i--) {
      var key = scanTargetKey(targets[i]);
      recent = recent.filter(function (it) { return scanTargetKey(it) !== key; });
      recent.unshift({ path: targets[i].path, name: targets[i].name, at: Date.now() });
    }
    recent = recent.slice(0, SCAN_MEMORY_RECENT_MAX);
    saveScanMemoryRows(rows, recent);
    return recent;
  }
  function clearScanMemory() { try { localStorage.removeItem(LS_SCAN_MEMORY); } catch (e) { /* ignore */ } }

  /* ---------------------------------------------------------------------- */
  async function ensureSession() {
    if (!state.session) throw new Error('尚未登录');
    if (Date.now() > state.session.expiresAt) {
      state.session = await loginWithApiKey(state.session.apiKey);
    }
    return state.session;
  }

  async function apiGet(path) {
    var session = await ensureSession();
    var url = session.apiBase + path;
    try {
      return await proxyFetch(url, { headers: { 'Authorization': 'Bearer ' + session.accessToken, 'Accept': 'application/json' } });
    } catch (e) {
      if (e.status === 401) {
        state.session = await loginWithApiKey(session.apiKey);
        return proxyFetch(url, { headers: { 'Authorization': 'Bearer ' + state.session.accessToken, 'Accept': 'application/json' } });
      }
      throw e;
    }
  }

  /* ---------------------------------------------------------------------- */
  function showLoading(text, sub) {
    var el = $('#boardLoading');
    if (!el) return;
    el.classList.remove('hidden');
    $('#loadingText').textContent = text || '加载中…';
    $('#loadingSub').textContent = sub || '';
  }
  function hideLoading() {
    var el = $('#boardLoading');
    if (el) el.classList.add('hidden');
  }

  function projectById(id) {
    for (var i = 0; i < state.projects.length; i++) if (state.projects[i].id === id) return state.projects[i];
    return null;
  }
  function projectName(id) { var p = projectById(id); return p ? p.name : (id || '—'); }

  async function loadProjects() {
    var all = [];
    var offset = 0;
    for (var page = 0; page < 50; page++) {
      var data = await apiGet('/api/projects?limit=' + SCAN_PAGE + '&offset=' + offset);
      var list = (data && (data.projects || data.items)) || [];
      all = all.concat(list);
      var total = data && (data.totalCount || data.filteredTotalCount) || 0;
      if (!list.length || all.length >= total) break;
      offset += list.length;
    }
    all.sort(function (a, b) { return String(a.name || '').localeCompare(String(b.name || '')); });
    state.projects = all;
    var ids = new Set(all.map(function (p) { return p.id; }));
    /* 只剔除已失效的项目，不再自动全选（默认一个都不选，由用户自己勾选） */
    state.selectedProjectIds.forEach(function (id) { if (!ids.has(id)) state.selectedProjectIds.delete(id); });
    state.draftProjectIds.forEach(function (id) { if (!ids.has(id)) state.draftProjectIds.delete(id); });
    updateProjectUI();
  }

  async function loadScansForSelected() {
    var ids = Array.from(state.selectedProjectIds);
    if (!ids.length) { state.scans = []; return []; }
    var out = [];
    var errors = [];
    await Promise.all(ids.map(async function (pid) {
      try {
        var scans = [];
        var offset = 0;
        for (var page = 0; page < 30; page++) {
          var data = await apiGet('/api/scans?project-id=' + encodeURIComponent(pid) + '&limit=' + SCAN_PAGE + '&offset=' + offset);
          var list = (data && (data.scans || data.items)) || [];
          scans = scans.concat(list);
          var total = data && data.totalCount || 0;
          if (!list.length || scans.length >= total) break;
          offset += list.length;
        }
        scans.forEach(function (s) {
          s.projectId = s.projectId || s.projectID || pid;
          out.push(s);
        });
      } catch (e) {
        errors.push(projectName(pid) + ': ' + e.message);
      }
    }));
    var seen = {};
    state.scans = out.filter(function (s) {
      var key = s.id || (s.projectId + '|' + s.createdAt);
      if (seen[key]) return false;
      seen[key] = 1;
      return true;
    }).sort(function (a, b) { return new Date(b.createdAt || 0) - new Date(a.createdAt || 0); });
    return errors;
  }

  function completedScans() {
    return state.scans.filter(function (s) { return s.status === 'Completed' || s.status === 'Partial'; });
  }
  function updateFilterOptions() {
    /* 分支 */
    var branches = {};
    state.scans.forEach(function (s) { if (s.branch) branches[s.branch] = 1; });
    var branchSel = $('#branchSelect');
    if (branchSel) {
      var list = Object.keys(branches).sort();
      branchSel.innerHTML = '<option value="">全部分支</option>' + list.map(function (b) {
        return '<option value="' + esc(b) + '"' + (state.branch === b ? ' selected' : '') + '>' + esc(b) + '</option>';
      }).join('');
      branchSel.disabled = !list.length;
    }
    /* 扫描时间 */
    var scanSel = $('#scanSelect');
    if (scanSel) {
      /* 扫描时间只列当前分支下的扫描，避免与分支筛选结果不一致 */
      var scans = completedScans().filter(function (s) { return !state.branch || s.branch === state.branch; });
      var opts = ['<option value="">最新扫描（每个项目）</option>'];
      scans.slice(0, 200).forEach(function (s) {
        opts.push('<option value="' + esc(s.id) + '"' + (state.scanKey === s.id ? ' selected' : '') + '>' +
          fmtDate(s.createdAt) + ' · ' + esc(projectName(s.projectId)) + (s.branch ? ' · ' + esc(s.branch) : '') + '</option>');
      });
      scanSel.innerHTML = opts.join('');
      scanSel.disabled = !scans.length;
    }
  }

  function targetScans() {
    if (state.scanKey) return state.scans.filter(function (s) { return s.id === state.scanKey; });
    var scans = completedScans();
    var wanted = {};
    state.selectedProjectIds.forEach(function (pid) {
      var list = scans.filter(function (s) { return (s.projectId || '') === pid && (!state.branch || s.branch === state.branch); });
      list.sort(function (a, b) { return new Date(b.createdAt || 0) - new Date(a.createdAt || 0); });
      if (list.length) wanted[list[0].id] = list[0];
    });
    return Object.keys(wanted).map(function (id) { return wanted[id]; });
  }

  function normalizeResult(raw, scan, project) {
    var data = raw.data || {};
    var vuln = raw.vulnerabilityDetails || {};
    var cweResolved = KB.resolveCwe(vuln.cweId, data.queryName);
    var nodes = (data.nodes || []).map(function (n, i, arr) {
      return {
        file: n.fileName || '', line: n.line, column: n.column, name: n.name || '',
        label: i === 0 ? 'source' : (i === arr.length - 1 ? 'sink' : 'propagator')
      };
    });
    var lastNode = nodes.length ? nodes[nodes.length - 1] : null;
    return {
      id: raw.id || raw.similarityId || Math.random().toString(36).slice(2),
      similarityId: raw.similarityId || '',
      severity: String(raw.severity || 'INFO').toUpperCase(),
      state: raw.state || '',
      status: raw.status || '',
      queryName: data.queryName || raw.label || '—',
      groupName: data.group || '',
      language: data.languageName || '',
      cwe: cweResolved,
      cweRaw: vuln.cweId,
      fileName: data.filename || (lastNode && lastNode.file) || '',
      line: data.line != null ? data.line : (lastNode && lastNode.line) || '',
      column: lastNode && lastNode.column || '',
      description: raw.description || data.description || '',
      recommendations: raw.recommendations || data.remediation || '',
      remediationLink: data.remediationLink || '',
      nodes: nodes,
      cvss: vuln.cvss || {},
      cvssScore: vuln.cvssScore,
      firstFoundAt: raw.firstFoundAt || raw.created || '',
      foundAt: raw.foundAt || raw.created || '',
      type: raw.type || '',
      scanId: scan.id,
      projectId: project ? project.id : (scan.projectId || ''),
      projectName: project ? project.name : (scan.projectName || ''),
      branch: scan.branch || '',
      scanCreatedAt: scan.createdAt || ''
    };
  }

  /** 加载结果；返回 'ok' | 'no-project' | 'no-scan' | false（请求失败）。 */
  async function loadResults() {
    var reqId = ++state.requestId;
    state.selectedId = null;
    closeDetail();
    if (!state.selectedProjectIds.size) {
      /* 空选：看板显示「请先选择项目」引导，不发起任何请求 */
      state.results = [];
      state.rows = [];
      updateSeverityUI();
      renderTable('no-project');
      hideLoading();
      return 'no-project';
    }
    var scans = targetScans();
    if (!scans.length) {
      state.results = [];
      state.rows = [];
      updateSeverityUI();
      renderTable('no-scan');
      hideLoading();
      return 'no-scan';
    }
    showLoading('正在加载扫描结果…', scans.length + ' 个扫描 · ' + scans.map(function (s) { return projectName(s.projectId) + '/' + (s.branch || '-'); }).join('、'));
    var all = [];
    var errors = [];
    try {
      for (var i = 0; i < scans.length; i++) {
        var scan = scans[i];
        var project = projectById(scan.projectId);
        var offset = 0;
        for (var page = 0; page < 80; page++) {
          var data = await apiGet('/api/results?scan-id=' + encodeURIComponent(scan.id) + '&limit=' + RESULT_PAGE + '&offset=' + offset);
          var list = (data && (data.results || data.items)) || [];
          list.forEach(function (raw) {
            if (!raw) return;
            all.push(normalizeResult(raw, scan, project));
          });
          var total = data && data.totalCount || 0;
          if (!list.length || all.length >= total && list.length < RESULT_PAGE) break;
          if (!list.length || (offset + list.length) >= total) break;
          offset += list.length;
          if (all.length > 20000) break;
        }
        if (state.requestId !== reqId) return;
      }
      if (state.requestId !== reqId) return false;
      state.results = all;
      renderAll();
      hideLoading();
      if (errors.length) toast('部分扫描结果加载失败：' + errors.join('；'), 'err', 5000);
      return 'ok';
    } catch (e) {
      if (state.requestId !== reqId) return false;
      hideLoading();
      state.results = [];
      renderAll();
      showTableError('加载扫描结果失败：' + e.message);
      return false;
    }
  }

  /* ---------------------------------------------------------------------- */
  function renderAll() {
    updateSeverityUI();
    renderTable();
    updateDetailNav();
  }

  function withSearch(list) {
    var q = state.q.trim().toLowerCase();
    if (!q) return list;
    return list.filter(function (r) {
      var hay = [r.queryName, r.groupName, r.fileName, 'cwe-' + r.cwe, r.language, r.description, r.projectName].join(' ').toLowerCase();
      return hay.indexOf(q) >= 0;
    });
  }
  function currentRows() {
    var list = withSearch(state.results).filter(function (r) { return state.sevs.has(r.severity); });
    list.sort(function (a, b) {
      var va, vb, dir = state.sort.dir;
      if (state.sort.key === 'severity') { va = SEV_RANK[a.severity] == null ? 9 : SEV_RANK[a.severity]; vb = SEV_RANK[b.severity] == null ? 9 : SEV_RANK[b.severity]; }
      else if (state.sort.key === 'found') { va = a.foundAt || ''; vb = b.foundAt || ''; }
      else if (state.sort.key === 'query') { va = a.queryName; vb = b.queryName; }
      else if (state.sort.key === 'project') { va = rName(a); vb = rName(b); }
      else if (state.sort.key === 'file') { va = a.fileName; vb = b.fileName; }
      else if (state.sort.key === 'state') { va = a.state; vb = b.state; }
      else { va = a.id; vb = b.id; }
      if (va < vb) return -1 * dir;
      if (va > vb) return 1 * dir;
      return 0;
    });
    return list;
  }
  function rName(r) { return r.projectName || projectName(r.projectId) || ''; }

  function updateSeverityUI() {
    var searchable = withSearch(state.results);
    var counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    searchable.forEach(function (r) { if (counts[r.severity] != null) counts[r.severity]++; });
    $$('[data-sev]').forEach(function (el) {
      var sev = el.getAttribute('data-sev');
      if (SEVS.indexOf(sev) < 0) return;
      var on = state.sevs.has(sev);
      el.classList.toggle('on', on);
      el.classList.toggle('off', !on);
      $$('[data-count]', el).forEach(function (n) { n.textContent = counts[sev]; });
    });
    var totalEl = $('#totalCount');
    if (totalEl) totalEl.textContent = searchable.length;
  }

  function renderTable(emptyReason) {
    var showProject = new Set(state.results.map(function (r) { return r.projectId; })).size > 1;
    var cols = [
      { key: 'severity', label: '严重级别', width: '96px' },
      { key: 'query', label: '漏洞类型' },
      { key: 'project', label: '项目', show: showProject },
      { key: 'file', label: '文件 / 行' },
      { key: 'state', label: '状态' },
      { key: 'found', label: '发现时间', width: '110px' }
    ].filter(function (c) { return c.show !== false; });
    var head = $('#resultsHead');
    if (head) {
      head.innerHTML = '<tr>' + cols.map(function (c) {
        var sortable = ['severity', 'query', 'project', 'file', 'state', 'found'].indexOf(c.key) >= 0;
        var arrow = state.sort.key === c.key ? '<span class="arrow">' + (state.sort.dir > 0 ? '▲' : '▼') + '</span>' : '';
        return '<th' + (sortable ? ' class="sortable" data-sort="' + c.key + '"' : '') + (c.width ? ' style="width:' + c.width + '"' : '') + '>' + esc(c.label) + arrow + '</th>';
      }).join('') + '</tr>';
      $$('#resultsHead th[data-sort]').forEach(function (th) {
        th.addEventListener('click', function () {
          var key = th.getAttribute('data-sort');
          if (state.sort.key === key) state.sort.dir *= -1; else { state.sort.key = key; state.sort.dir = 1; }
          renderTable(emptyReason);
        });
      });
    }
    state.rows = currentRows();
    var body = $('#resultsBody');
    if (!body) return;
    if (!state.rows.length) {
      var reason = emptyReason || (!state.selectedProjectIds.size ? 'no-project' : !state.results.length ? 'empty' : 'filtered');
      var title, desc, actions;
      if (reason === 'no-project') {
        title = state.projects.length ? '请先选择项目' : '没有可用项目';
        desc = state.projects.length
          ? '在顶部「项目」下拉中勾选要查看的项目（可多选），点击「应用」后才会查询数据。项目与分支的选择会被记住，下次打开自动恢复。'
          : '当前 Checkmarx One 租户下没有可访问的项目，或账号没有项目访问权限。';
        actions = (state.projects.length ? '<button class="btn sm primary" id="emptyPickProjects">选择项目</button>' : '') +
          '<button class="btn sm ghost" id="emptyRefresh">刷新</button>';
      } else if (reason === 'no-scan') {
        title = '没有可用的已完成扫描';
        desc = '所选项目/分支下还没有已完成的扫描。可以点击「＋ 本地扫描」对本地代码发起一次扫描。';
        actions = '<button class="btn sm primary" id="emptyLocalScan">＋ 本地扫描</button>' +
          '<button class="btn sm ghost" id="emptyRefresh">刷新</button>';
      } else if (reason === 'empty') {
        title = '当前范围暂无漏洞结果';
        desc = 'Checkmarx One 没有返回任何结果；确认扫描已完成、账号有项目访问权限，或点击刷新重试。';
        actions = '<button class="btn sm primary" id="emptyLocalScan">＋ 本地扫描</button>' +
          '<button class="btn sm ghost" id="emptyRefresh">刷新</button>';
      } else {
        title = '没有匹配的漏洞';
        desc = '调整项目、分支、扫描时间或严重级别筛选条件后再试。';
        actions = '<button class="btn sm ghost" id="emptyRefresh">刷新</button>';
      }
      body.innerHTML = '<tr class="empty-row"><td colspan="' + cols.length + '">' +
        '<div class="empty-state"><div class="big">' + (reason === 'no-project' ? '📁' : '🔍') + '</div><h3>' + esc(title) + '</h3><p>' + esc(desc) + '</p>' +
        '<div class="action-row">' + actions + '</div></div></td></tr>';
      var b0 = $('#emptyPickProjects'); if (b0) b0.addEventListener('click', function (e) { e.stopPropagation(); openProjectMenu(); });
      var b1 = $('#emptyLocalScan'); if (b1) b1.addEventListener('click', openScan);
      var b2 = $('#emptyRefresh'); if (b2) b2.addEventListener('click', function () { refreshAll(true); });
    } else {
      body.innerHTML = state.rows.map(function (r) {
        var sev = SEV_RANK[r.severity] != null ? r.severity : 'INFO';
        var cells = {
          severity: '<span class="pill sev-' + esc(sev) + '">' + esc(sev) + '</span>',
          query: '<div class="vuln-name">' + esc(r.queryName) + '</div>' +
            '<div class="vuln-sub"><span class="mono">CWE-' + esc(r.cwe || '?') + '</span><span>·</span><span>' + esc(r.language || '—') + '</span>' +
            (r.status === 'RECURRENT' ? '<span class="pill status st-RECURRENT">复现</span>' : '') + '</div>',
          project: '<span class="proj-cell"><i class="sev-dot" style="background:' + esc((projectById(r.projectId) || {}).color || '#64748b') + '"></i>' + esc(rName(r)) + '</span>',
          file: '<div class="file-cell" title="' + esc(r.fileName) + '">' + esc(String(r.fileName || '').split('/').slice(-2).join('/')) + '<i>:' + esc(r.line) + '</i></div>',
          state: '<span class="pill state st-' + esc(r.state) + '">' + esc(STATE_LABEL[r.state] || r.state || '—') + '</span>',
          found: '<span title="' + esc(fmtDate(r.foundAt)) + '">' + esc(relTime(r.foundAt)) + '</span>'
        };
        return '<tr data-id="' + esc(r.id) + '"' + (state.selectedId === r.id ? ' class="selected"' : '') + '>' +
          cols.map(function (c) { return '<td>' + (cells[c.key] || '') + '</td>'; }).join('') + '</tr>';
      }).join('');
      $$('#resultsBody tr[data-id]').forEach(function (tr) {
        tr.addEventListener('click', function () {
          var id = tr.getAttribute('data-id');
          if (state.selectedId === id) { closeDetail(); return; }
          openDetail(id);
        });
      });
    }
    var countEl = $('#resultCount');
    if (countEl) {
      var total = withSearch(state.results).length;
      countEl.textContent = state.rows.length === total ? '共 ' + total + ' 个漏洞' : '筛选出 ' + state.rows.length + ' / ' + total + ' 个漏洞';
    }
  }

  function showTableError(msg) {
    var body = $('#resultsBody');
    if (!body) return;
    body.innerHTML = '<tr class="empty-row"><td colspan="6"><div class="empty-state" style="height:300px">' +
      '<div class="big">⚠️</div><h3>加载失败</h3><p>' + esc(msg) + '</p>' +
      '<div class="action-row"><button class="btn sm primary" id="errRetryBtn">重试</button></div></div></td></tr>';
    var b = $('#errRetryBtn');
    if (b) b.addEventListener('click', function () { refreshAll(true); });
  }

  /* ---------------------------------------------------------------------- */
  function detailMeta(k, v, mono) {
    return '<div class="m"><div class="k">' + esc(k) + '</div><div class="v' + (mono ? ' mono' : '') + '" title="' + esc(v) + '">' + esc(v) + '</div></div>';
  }
  function codeCard(kind, title, code, lang) {
    return '<div class="code-card ' + kind + '"><div class="c-head"><span class="t">' + esc(title) + '</span><span class="lang">' + esc(lang || '') + '</span></div><pre>' + esc(code) + '</pre></div>';
  }

  /** 详情抽屉与「一键复制」共用的攻击向量数据（内置知识库文案 + payload）。 */
  function attackInfo(r) {
    var kb = KB.lookup(r.cweRaw != null ? r.cweRaw : r.cwe, r.queryName);
    var entry = kb.entry;
    var generic = KB.generic || {};
    return {
      kb: kb,
      entry: entry,
      attackVector: (entry && entry.attackVector) || generic.attackVector || '',
      payload: (entry && entry.payload) || '',
      remediation: (entry && entry.remediation) || generic.remediation || {}
    };
  }

  /**
   * 一键复制用的「攻击向量」纯文本：
   * 攻击向量正文 + 攻击示例（Payload）。污点数据流由 flowCopyText 单独生成。
   */
  function attackSectionText(r) {
    var info = attackInfo(r);
    var lines = ['【攻击向量】', info.attackVector || '（暂无攻击向量说明）'];
    if (info.payload) lines.push('', '【攻击示例 / Payload】', info.payload);
    return lines.join('\n');
  }

  /**
   * 攻击向量区块的一键复制文本：漏洞信息 + 攻击向量 + 攻击示例 + 污点数据流，
   * 逐条保留序号、入口类/文件与行号；直接从页面框选复制时这些内容容易被 CSS 布局打散。
   */
  function attackCopyText(r) {
    var info = attackInfo(r);
    var breakLine = function (v) { return v != null && v !== '' ? v : '—'; };
    var head = '【漏洞】' + (r.queryName || '—') + '（CWE-' + (info.kb.cwe || '?') + ' · ' + (SEV_LABEL[r.severity] || r.severity) + ' · ' + (rName(r) || '—') + '）\n' +
      '【位置】' + breakLine(r.fileName) + ':' + breakLine(r.line);
    var parts = [head, attackSectionText(r)];
    var flow = flowCopyText(r);
    if (flow) parts.push(flow);
    return parts.join('\n\n');
  }

  /** 一键复制用的「污点数据流」纯文本：序号 + [source/propagator/sink] + 文件:行号 + 代码。 */
  function flowCopyText(r) {
    var nodes = r.nodes || [];
    if (!nodes.length) return '';
    var lines = ['【污点数据流】共 ' + nodes.length + ' 步'];
    nodes.forEach(function (n, i) {
      var tag = n.label === 'source' ? 'source' : (n.label === 'sink' ? 'sink' : 'propagator');
      lines.push((i + 1) + '. [' + tag + '] ' + (n.file || '—') + ':' + (n.line != null && n.line !== '' ? n.line : '—'));
      if (n.name) String(n.name).split(/\r?\n/).forEach(function (ln) { lines.push('   ' + ln); });
    });
    return lines.join('\n');
  }

  /** 详情抽屉「参考链接」列表（渲染与一键复制共用）。 */
  function detailRefs(r, info) {
    info = info || attackInfo(r);
    var kb = info.kb;
    var entry = info.entry;
    var refs = [];
    if (kb.cwe) refs.push({ label: 'CWE-' + kb.cwe + '（' + ((entry && entry.name) || '漏洞说明') + '）', url: KB.cweUrl(kb.cwe) });
    if (entry && entry.owasp) refs.push({ label: 'OWASP 参考', url: entry.owasp });
    if (r.remediationLink) refs.push({ label: 'Checkmarx 修复参考链接', url: r.remediationLink });
    refs.push({ label: 'Checkmarx 查询帮助 Query Help', url: 'https://docs.checkmarx.com' });
    return refs;
  }

  /** 一键复制用的「漏洞说明」纯文本（Checkmarx description 原文）。 */
  function descriptionCopyText(r) {
    var desc = String(r.description || '').trim();
    if (!desc) return '';
    return '【漏洞说明】\n' + desc;
  }

  /**
   * 一键复制用的「修复建议」纯文本：
   * Checkmarx 修复建议 + 内置修复方案 + 错误/修复代码示例 + 修复参考链接。
   */
  function remediationCopyText(r) {
    var info = attackInfo(r);
    var rem = info.remediation || {};
    var lines = ['【修复建议】'];
    var adv = String(r.recommendations || '').trim();
    if (adv) lines.push('Checkmarx 修复建议：', adv, '');
    if (rem.summary) lines.push('修复方案：', rem.summary, '');
    (rem.examples || []).forEach(function (ex) {
      if (!ex) return;
      var title = String(ex.title || '代码示例') + (ex.lang ? '（' + ex.lang + '）' : '');
      lines.push('【' + title + '】');
      if (ex.bad) lines.push('✗ 错误示例：', String(ex.bad), '');
      if (ex.good) lines.push('✓ 修复后：', String(ex.good), '');
    });
    var link = String(r.remediationLink || '').trim();
    if (link) lines.push('修复参考：', link);
    while (lines.length > 1 && lines[lines.length - 1] === '') lines.pop();
    return lines.length > 1 ? lines.join('\n') : '';
  }

  /** 一键复制用的「参考链接」纯文本：与其他区块一致，先写【参考链接】标题，再按「名称：URL」逐行列出。 */
  function refsCopyText(r) {
    return '【参考链接】\n' + detailRefs(r).map(function (ref) { return ref.label + '：' + ref.url; }).join('\n');
  }

  /**
   * 抽屉右上角「复制漏洞信息」的纯文本：按固定顺序输出 9 项——
   * 漏洞类型 / 风险等级 / CWE编号 / 受影响文件 / 漏洞说明 / 攻击向量 / 污点数据流 / 修复建议 / 参考链接。
   * 各区块直接复用对应的一键复制逻辑，保证格式一致；没有内容的字段整段省略。
   */
  function fullCopyText(r) {
    var info = attackInfo(r);
    var kb = info.kb;
    var head = ['【漏洞类型】' + (r.queryName || '—')];
    head.push('【风险等级】' + (r.severity || '—') + (SEV_LABEL[r.severity] ? ' · ' + SEV_LABEL[r.severity] : ''));
    if (kb.cwe) head.push('【CWE编号】CWE-' + kb.cwe + ((info.entry && info.entry.name) ? '（' + info.entry.name + '）' : ''));
    var file = String(r.fileName || '').trim();
    if (file) head.push('【受影响文件】' + file + (r.line != null && r.line !== '' ? ':' + r.line : ''));
    var parts = [head.join('\n')];
    var desc = descriptionCopyText(r);
    if (desc) parts.push(desc);
    if (String(info.attackVector || '').trim()) parts.push(attackSectionText(r));
    var flow = flowCopyText(r);
    if (flow) parts.push(flow);
    var remediation = remediationCopyText(r);
    if (remediation) parts.push(remediation);
    var refs = refsCopyText(r);
    if (refs) parts.push(refs);
    return parts.join('\n\n');
  }

  function detailHtml(r) {
    var info = attackInfo(r);
    var kb = info.kb;
    var entry = info.entry;
    var attackVector = info.attackVector;
    var payload = info.payload;
    var rem = info.remediation;
    var advSummary = r.recommendations || '';
    var examples = (rem.examples || []);
    var refs = detailRefs(r, info);

    var nodes = (r.nodes || []).map(function (n, i, arr) {
      return '<li class="flow-step" data-label="' + esc(n.label || 'propagator') + '">' +
        '<span class="node">' + (i + 1) + '</span>' +
        '<div class="fl-head"><span class="fl-file">' + esc(n.file || '—') + '</span><span class="fl-line">:' + esc(n.line != null ? n.line : '') + '</span>' +
        '<span class="fl-tag">' + esc(n.label === 'source' ? 'source' : n.label === 'sink' ? 'sink' : 'propagator') + '</span></div>' +
        (n.name ? '<code>' + esc(n.name) + '</code>' : '') + '</li>';
    }).join('');

    var cvssBadges = '';
    if (r.cvss && (r.cvss.attackVector || r.cvssScore != null)) {
      var bits = [];
      if (r.cvss.attackVector) bits.push('Attack Vector: ' + String(r.cvss.attackVector).toUpperCase());
      if (r.cvssScore != null) bits.push('CVSS ' + r.cvssScore);
      cvssBadges = '<div class="dt-badges" style="margin-top:8px">' + bits.map(function (b) {
        return '<span class="badge-soft">' + esc(b) + '</span>';
      }).join('') + '</div>';
    }

    return '' +
      '<div class="dt-head">' +
      '<div class="dt-title-row"><div>' +
      '<div class="dt-title">' + esc(r.queryName) + '</div>' +
      '<div class="dt-sub"><span>' + esc(r.groupName || 'Checkmarx One SAST') + '</span><span>·</span><span>' + esc(r.language || '—') + '</span><span>·</span><span>' + esc(rName(r)) + '</span></div>' +
      '</div>' +
      '<div class="dt-actions-top">' +
      '<button type="button" class="btn sm ghost dt-copy-all" data-dt-act="copy-full" title="复制完整漏洞信息（漏洞类型 / 风险等级 / CWE / 受影响文件 / 漏洞说明 / 攻击向量 / 污点数据流 / 修复建议 / 参考链接）">复制漏洞信息</button>' +
      '</div></div>' +
      '<div class="dt-badges">' +
      '<span class="pill sev-' + esc(r.severity) + '">' + esc(r.severity) + ' · ' + esc(SEV_LABEL[r.severity] || '') + '</span>' +
      (r.state ? '<span class="pill state st-' + esc(r.state) + '">' + esc(STATE_LABEL[r.state] || r.state) + '</span>' : '') +
      (r.status ? '<span class="pill status st-' + esc(r.status) + '">' + esc(STATUS_LABEL[r.status] || r.status) + '</span>' : '') +
      '<span class="badge-soft">CWE-' + esc(kb.cwe || '?') + ' ' + esc((entry && entry.name) || '') + '</span>' +
      '</div>' + cvssBadges + '</div>' +
      '<div class="dt-meta">' +
      detailMeta('项目', rName(r)) +
      detailMeta('分支', r.branch || '—') +
      detailMeta('扫描时间', fmtDate(r.scanCreatedAt)) +
      detailMeta('扫描 ID', r.scanId, true) +
      detailMeta('文件', r.fileName || '—', true) +
      detailMeta('行 / 列', (r.line != null && r.line !== '' ? r.line : '—') + ' : ' + (r.column || '—')) +
      detailMeta('首次发现', fmtDate(r.firstFoundAt)) +
      detailMeta('结果 ID', r.id, true) +
      '</div>' +
      '<div class="dt-body">' +
      '<section class="dt-sec"><h4>漏洞说明 <span class="en">description</span>' +
      '<button type="button" class="btn ghost sm sec-copy" data-copy-desc title="一键复制漏洞说明（Checkmarx 原文）">复制</button></h4>' +
      '<p>' + esc(r.description || '（Checkmarx 未返回描述）') + '</p></section>' +
      '<section class="dt-sec"><h4>攻击向量 <span class="en">attack vector</span>' +
      '<button type="button" class="btn ghost sm sec-copy" data-copy-attack title="一键复制攻击向量（含攻击示例与污点数据流：序号 / 类名 / 行号）">复制</button></h4>' +
      '<p>' + esc(attackVector) + '</p>' +
      (payload ? '<div class="payload"><div class="p-head"><span>攻击示例 / payload</span><button type="button" class="btn ghost sm" data-copy-payload>复制</button></div><pre>' + esc(payload) + '</pre></div>' : '') +
      '</section>' +
      (nodes ? '<section class="dt-sec"><h4>污点数据流 <span class="en">data flow</span><span class="count">' + (r.nodes || []).length + ' 步</span>' +
        '<button type="button" class="btn ghost sm sec-copy" data-copy-flow title="一键复制污点数据流（保留序号 / 类名 / 行号）">复制</button></h4>' +
        '<ol class="flow">' + nodes + '</ol></section>'
        : '<section class="dt-sec"><h4>污点数据流 <span class="en">data flow</span></h4><p class="hint">该结果没有数据流信息（配置类/依赖类检查结果通常如此）。</p></section>') +
      '<section class="dt-sec"><h4>修复建议 <span class="en">remediation</span>' +
      '<button type="button" class="btn ghost sm sec-copy" data-copy-remediation title="一键复制修复建议（含修复方案与错误/修复代码示例）">复制</button></h4>' +
      (advSummary ? '<p>' + esc(advSummary) + '</p>' : '') +
      (rem.summary ? '<p>' + esc(rem.summary) + '</p>' : '') +
      (examples.length ? examples.map(function (ex) {
        return '<div style="font-size:12px;font-weight:650;color:var(--text-2);margin:10px 0 6px;display:flex;gap:8px;align-items:center">' + esc(ex.title) + '<span class="badge-soft">' + esc(ex.lang || '') + '</span></div>' +
          '<div class="cmp">' + codeCard('bad', '✗ 错误示例', ex.bad, 'before') + codeCard('good', '✓ 修复后', ex.good, 'after') + '</div>';
      }).join('') : '<p class="hint">暂无内置代码示例，可参考下方 Checkmarx / OWASP 链接。</p>') +
      (r.remediationLink ? '<p style="margin-top:10px"><a href="' + esc(r.remediationLink) + '" target="_blank" rel="noopener">查看 Checkmarx 提供的修复参考 ↗</a></p>' : '') +
      '</section>' +
      '<section class="dt-sec"><h4>参考链接 <span class="en">learn more</span>' +
      '<button type="button" class="btn ghost sm sec-copy" data-copy-refs title="一键复制参考链接（名称 + URL）">复制</button></h4><ul class="refs">' +
      refs.map(function (ref) {
        return '<li><a href="' + esc(ref.url) + '" target="_blank" rel="noopener"><span class="ico">🔗</span><span>' + esc(ref.label) + '</span><span class="ext">↗</span></a></li>';
      }).join('') + '</ul></section>' +
      '</div>' +
      '<div class="dt-foot">' +
      '<button class="btn sm ghost" data-dt-act="copy" title="复制一行结果摘要（漏洞类型 | 等级 | 项目 | 文件:行 | 扫描 ID）">复制结果摘要</button>' +
      '<span class="spacer"></span>' +
      '<button class="btn sm primary" data-dt-act="open-cx">在 Checkmarx 中打开 ↗</button>' +
      '</div>';
  }

  function mountDetailShell() {
    if ($('#detailDrawer')) return;
    document.body.insertAdjacentHTML('beforeend',
      '<div class="detail-backdrop" id="detailBackdrop"></div>' +
      '<aside class="detail-drawer" id="detailDrawer" aria-hidden="true">' +
      '<div class="drawer-resizer" id="drawerResizer" role="separator" aria-orientation="vertical" title="拖拽调整宽度 · 双击恢复默认 520px"></div>' +
      '<div class="drawer-top"><div class="detail-nav">' +
      '<button class="icon-btn" data-detail-nav="prev" title="上一个">‹</button>' +
      '<span class="pos"></span>' +
      '<button class="icon-btn" data-detail-nav="next" title="下一个">›</button></div>' +
      '<button class="icon-btn" data-close-detail title="关闭 (Esc)">✕</button></div>' +
      '<div class="drawer-scroll"><div id="detailContent" class="detail-content"></div></div></aside>');
    $('#detailBackdrop').addEventListener('click', closeDetail);
    $$('[data-close-detail]').forEach(function (b) { b.addEventListener('click', closeDetail); });
    $$('[data-detail-nav]').forEach(function (b) {
      b.addEventListener('click', function () { navigateDetail(b.getAttribute('data-detail-nav')); });
    });
    $('#detailContent').addEventListener('click', function (e) {
      var copy = e.target.closest('[data-copy-payload]');
      if (copy) {
        var pre = copy.closest('.payload').querySelector('pre');
        copyText(pre.textContent);
        return;
      }
      var copyAttack = e.target.closest('[data-copy-attack]');
      if (copyAttack) {
        var attackRow = selectedResult();
        if (attackRow && attackRow.nodes && attackRow.nodes.length) {
          copyText(attackCopyText(attackRow), '攻击向量已复制（含 Payload 与污点数据流）');
        } else if (attackRow) {
          copyText(attackCopyText(attackRow), '攻击向量已复制');
        }
        return;
      }
      var copyFlow = e.target.closest('[data-copy-flow]');
      if (copyFlow) {
        var flowRow = selectedResult();
        if (flowRow) copyText(flowCopyText(flowRow), '污点数据流已复制（序号 / 类名 / 行号）');
        return;
      }
      var copyDesc = e.target.closest('[data-copy-desc]');
      if (copyDesc) {
        var descRow = selectedResult();
        if (descRow) {
          var descText = descriptionCopyText(descRow);
          if (descText) copyText(descText, '漏洞说明已复制');
          else toast('该漏洞没有说明内容', 'err');
        }
        return;
      }
      var copyRemediation = e.target.closest('[data-copy-remediation]');
      if (copyRemediation) {
        var remRow = selectedResult();
        if (remRow) {
          var remText = remediationCopyText(remRow);
          if (remText) copyText(remText, '修复建议已复制');
          else toast('该漏洞暂无修复建议内容', 'err');
        }
        return;
      }
      var copyRefs = e.target.closest('[data-copy-refs]');
      if (copyRefs) {
        var refsRow = selectedResult();
        if (refsRow) copyText(refsCopyText(refsRow), '参考链接已复制');
        return;
      }
      var act = e.target.closest('[data-dt-act]');
      if (act) handleDetailAction(act.getAttribute('data-dt-act'));
    });
    initDrawerResize();
  }

  function findRowIndex() {
    for (var i = 0; i < state.rows.length; i++) if (state.rows[i].id === state.selectedId) return i;
    return -1;
  }
  function updateDetailNav() {
    var idx = findRowIndex();
    $$('.detail-nav').forEach(function (nav) {
      var pos = nav.querySelector('.pos');
      if (pos) pos.textContent = idx >= 0 ? (idx + 1) + ' / ' + state.rows.length : '';
      var prev = nav.querySelector('[data-detail-nav="prev"]');
      var next = nav.querySelector('[data-detail-nav="next"]');
      if (prev) prev.disabled = idx <= 0;
      if (next) next.disabled = idx < 0 || idx >= state.rows.length - 1;
    });
  }
  function openDetail(id) {
    var r = null;
    for (var i = 0; i < state.rows.length; i++) if (state.rows[i].id === id) { r = state.rows[i]; break; }
    if (!r) return;
    state.selectedId = id;
    $$('#resultsBody tr[data-id]').forEach(function (tr) { tr.classList.toggle('selected', tr.getAttribute('data-id') === id); });
    $('#detailContent').innerHTML = detailHtml(r);
    $('#detailDrawer').classList.add('open');
    $('#detailDrawer').setAttribute('aria-hidden', 'false');
    $('#detailBackdrop').classList.add('open');
    updateDetailNav();
  }
  function closeDetail() {
    state.selectedId = null;
    var d = $('#detailDrawer');
    if (d) { d.classList.remove('open'); d.setAttribute('aria-hidden', 'true'); }
    var b = $('#detailBackdrop');
    if (b) b.classList.remove('open');
    $$('#resultsBody tr[data-id]').forEach(function (tr) { tr.classList.remove('selected'); });
    updateDetailNav();
  }
  function navigateDetail(dir) {
    var idx = findRowIndex();
    if (idx < 0) return;
    var next = idx + (dir === 'prev' ? -1 : 1);
    if (next < 0 || next >= state.rows.length) return;
    openDetail(state.rows[next].id);
    var row = $('#resultsBody tr.selected');
    if (row && row.scrollIntoView) row.scrollIntoView({ block: 'nearest' });
  }
  /** 当前抽屉里选中的结果（按 id 从当前表格行中取）。 */
  function selectedResult() {
    for (var i = 0; i < state.rows.length; i++) if (state.rows[i].id === state.selectedId) return state.rows[i];
    return null;
  }
  function handleDetailAction(act) {
    var r = selectedResult();
    if (!r) return;
    if (act === 'copy') {
      copyText(r.queryName + ' | ' + r.severity + ' | ' + rName(r) + ' | ' + r.fileName + ':' + r.line + ' | 扫描 ' + r.scanId, '结果摘要已复制');
    } else if (act === 'copy-full') {
      copyText(fullCopyText(r), '漏洞信息已复制（9 项）');
    } else if (act === 'open-cx') {
      var webBase = '';
      try {
        var apiUrl = new URL(state.session.apiBase);
        var tenant = state.session.tenant || '';
        if (/\.ast\.checkmarx\.net$/i.test(apiUrl.host) && tenant) {
          // 云版多租户：每个租户有独立的 Web 入口
          webBase = 'https://' + tenant + '.checkmarx.net';
        } else {
          // 单租户 / 自建域名：Web 入口通常与 API 同域
          webBase = apiUrl.origin;
        }
      } catch (e) { webBase = ''; }
      if (!webBase) { toast('请在设置中完成登录后再打开 Checkmarx', 'err'); return; }
      var url = webBase + '/#/projects/' + encodeURIComponent(r.projectId) + '/scans/' + encodeURIComponent(r.scanId);
      window.open(url, '_blank', 'noopener');
      toast('已尝试在 Checkmarx One 中打开该扫描；若页面路由不同，请从项目页进入', 'info', 3200);
    }
  }
  /**
   * 复制到剪贴板前统一规范化纯文本：复制出来的一律是「标准空格」+「标准换行」，
   * 避免从 API 数据 / 页面框选复制时混入肉眼难辨的特殊空白字符：
   *  - 不间断空格（U+00A0）、全角空格（U+3000）、窄空格等各种 Unicode 空格 → 标准空格（U+0020）；
   *  - 零宽字符、软连字符、BOM 等不可见字符 → 去掉；
   *  - Tab → 4 个空格；\r\n、\r、行分隔符 → \n。
   * 只处理复制出来的文本，页面上的显示不受影响。
   */
  var COPY_SPACE_RE = /[\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000]/g;
  var COPY_INVISIBLE_RE = /[\u00ad\u180e\u200b-\u200f\u2060\ufeff]/g;
  function normalizeCopyText(text) {
    return String(text == null ? '' : text)
      .replace(/\r\n?/g, '\n')
      .replace(/[\u0085\u2028\u2029]/g, '\n')
      .replace(COPY_INVISIBLE_RE, '')
      .replace(/\t/g, '    ')
      .replace(COPY_SPACE_RE, ' ');
  }
  function copyText(text, okMsg) {
    var payload = normalizeCopyText(text);
    var done = function () { toast(okMsg || '已复制到剪贴板', 'ok', 1500); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(payload).then(done, function () { fallbackCopy(payload, okMsg); });
    } else fallbackCopy(payload, okMsg);
  }
  function fallbackCopy(text, okMsg) {
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); toast(okMsg || '已复制到剪贴板', 'ok', 1500); } catch (e) { toast('复制失败，请手动选择', 'err'); }
    ta.remove();
  }

  /* ---------------------------------------------------------------------- */
  function connUI() {
    var pill = $('#connPill');
    if (!pill) return;
    if (state.connected && state.session) {
      pill.classList.remove('offline');
      pill.innerHTML = '<span class="pulse"></span><span>已连接</span><span class="who">· ' + esc((state.session.tenant || '').toUpperCase()) + '</span>';
    } else {
      pill.classList.add('offline');
      pill.innerHTML = '<span class="pulse"></span><span>未连接</span>';
    }
  }

  function mountLogin() {
    if ($('#loginOverlay')) return;
    var overlay = document.createElement('div');
    overlay.className = 'login-overlay';
    overlay.id = 'loginOverlay';
    overlay.innerHTML =
      '<div class="login-card">' +
      '<div class="login-brand"><div class="logo">CX</div><div><div class="bn">CxScope</div>' +
      '<div class="bs">Checkmarx One · 漏洞看板</div></div></div>' +
      '<h1>连接你的 Checkmarx</h1>' +
      '<p class="lead">粘贴 Checkmarx One 的 <b>API Key</b> 即可登录。与 IDEA 插件一致：无需用户名、密码，也不用手动选择区域 —— Key 会自动解析租户与 API 地址。</p>' +
      '<label class="fl">API Key <a href="javascript:void(0)" id="loginHelp">如何获取？</a></label>' +
      '<textarea id="apiKeyInput" spellcheck="false" placeholder="粘贴 Checkmarx One API Key（以 eyJ 开头的 JWT）"></textarea>' +
      '<label class="remember"><input type="checkbox" id="rememberKey" checked /> 记住 API Key（仅保存在本机浏览器 localStorage）</label>' +
      '<div class="login-row"><button class="btn primary" id="loginSubmit">登录</button></div>' +
      '<div class="login-error" id="loginError"></div>' +
      '<div class="proxy-hint" id="loginProxyHint">本地代理：<code id="proxyAddr">' + esc((location.protocol === 'file:' ? PROXY_FILE_URL : location.origin)) + '</code>。若登录失败，请先在本机运行 <code>python proxy.py</code>，再通过 <code>http://127.0.0.1:8787/</code> 打开本页面。</div>' +
      '<div class="login-foot">🔒 API Key 仅用于与本机代理通信，不经过第三方服务器</div>' +
      '</div>';
    document.body.appendChild(overlay);
    $('#loginSubmit').addEventListener('click', function () { doLogin(false); });
    $('#apiKeyInput').addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); doLogin(false); }
    });
    $('#loginHelp').addEventListener('click', function () {
      toast('Checkmarx One → 右上角设置 → API Keys → 生成 API Key（IDE 插件使用同一 Key）', 'info', 4200);
    });
    var saved = loadConfig();
    if (saved.apiKey) {
      $('#apiKeyInput').value = saved.apiKey;
      if (saved.rememberKey === false) $('#rememberKey').checked = false;
    }
    setTimeout(function () { var el = $('#apiKeyInput'); if (el) el.focus(); }, 50);
  }

  async function doLogin(silent, keyOverride) {
    var key = keyOverride || ($('#apiKeyInput') ? $('#apiKeyInput').value.trim() : '');
    var errEl = $('#loginError');
    if (!key) { if (errEl) errEl.textContent = '请输入 API Key'; return; }
    if (errEl) errEl.textContent = '';
    var btn = $('#loginSubmit');
    if (!silent && btn) setBusy(btn, true, '验证并登录…');
    try {
      var session = await loginWithApiKey(key);
      syncScanMemoryScope(session);   // 切换租户时清掉上一个租户的扫描行（记忆本身按租户隔离）
      state.session = session;
      state.connected = true;
      saveConfig();
      connUI();
      enterApp(silent);
      await refreshAll();
    } catch (e) {
      state.connected = false;
      connUI();
      if (errEl) errEl.textContent = e.message;
      if (silent) showLogin();
      if (!silent) toast(e.message, 'err', 5200);
    } finally {
      if (!silent && btn) setBusy(btn, false, '登录');
    }
  }

  function enterApp(instant) {
    var overlay = $('#loginOverlay');
    if (overlay) {
      overlay.classList.add('closing');
      setTimeout(function () { overlay.remove(); }, instant ? 0 : 280);
    }
    document.body.classList.remove('locked');
    if (!instant) toast('登录成功 · 已连接 Checkmarx One', 'ok', 2400);
  }

  function showLogin() {
    state.connected = false;
    connUI();
    document.body.classList.add('locked');
    mountLogin();
  }

  function logout(clearKey) {
    closeDetail();
    closeModals();
    state.session = null;
    state.connected = false;
    state.results = [];
    state.scans = [];
    state.projects = [];
    state.selectedProjectIds = new Set();
    state.draftProjectIds = new Set();
    state.scanKey = '';
    state.branch = '';
    connUI();
    if (clearKey) clearConfig();
    else {
      var cfg = loadConfig();
      cfg.apiKey = '';
      try { localStorage.setItem(LS_CFG, JSON.stringify(cfg)); } catch (e) { /* ignore */ }
    }
    /* 清空内存态（记忆仍保留在 localStorage，重新登录同一租户后自动恢复） */
    resetScanMemoryState();
    showLogin();
    toast('已断开连接', 'info', 1800);
  }

  /* ---------------------------------------------------------------------- */
  function mountSettings() {
    if ($('#settingsModal')) return;
    var layer = document.createElement('div');
    layer.className = 'modal-layer';
    layer.id = 'settingsModal';
    layer.innerHTML =
      '<div class="modal" style="width:640px">' +
      '<div class="modal-head"><div><div class="m-title">连接设置</div><div class="m-sub">Checkmarx One · 使用 API Key 登录（与 IDEA 插件一致）</div></div>' +
      '<button class="icon-btn close" data-close-modal="settingsModal">✕</button></div>' +
      '<div class="modal-body">' +
      '<div class="settings-block">' +
      '<div class="sb-title">API 凭据 <span class="en">credentials</span></div>' +
      '<div class="field"><label>API Key <a href="javascript:void(0)" data-help-key>如何获取？</a></label>' +
      '<div class="secret-wrap"><input type="password" id="settingsKey" spellcheck="false" placeholder="粘贴新的 API Key 后可测试/保存">' +
      '<button class="icon-btn eye" id="settingsEye" title="显示/隐藏">👁</button></div></div>' +
      '<div class="parse-grid" id="settingsParse"></div>' +
      '<div class="settings-foot"><button class="btn sm" id="testConnBtn">测试连接</button>' +
      '<span class="muted" style="font-size:11px">以上信息由 API Key 自动解析</span>' +
      '<span class="spacer"></span><button class="btn sm primary" id="saveSettingsBtn">保存</button></div>' +
      '</div>' +
      '<div class="settings-block">' +
      '<div class="sb-title">会话 <span class="en">session</span></div>' +
      '<div class="muted" style="font-size:12px;line-height:1.7">已通过 API Key 登录；access token 约 59 分钟后过期，过期后自动用 API Key 换取新 token。API Key 仅保存在本机浏览器。</div>' +
      '<div class="settings-foot"><button class="btn sm danger" id="logoutBtn">退出登录</button>' +
      '<button class="btn sm ghost" id="clearKeyBtn">清除本机凭据</button>' +
      '<span class="spacer"></span><span class="muted" style="font-size:11px">本页面通过本地代理访问 Checkmarx One</span></div>' +
      '</div>' +
      '</div></div>';
    document.body.appendChild(layer);
    $$('[data-close-modal="settingsModal"]', layer).forEach(function (b) { b.addEventListener('click', function () { layer.classList.remove('open'); }); });
    layer.addEventListener('click', function (e) { if (e.target === layer) layer.classList.remove('open'); });
    $('#settingsEye').addEventListener('click', function () {
      var inp = $('#settingsKey'); inp.type = inp.type === 'password' ? 'text' : 'password';
    });
    var help = layer.querySelector('[data-help-key]');
    if (help) help.addEventListener('click', function () { toast('Checkmarx One → 设置 → API Keys 生成 API Key', 'info', 3200); });
    $('#testConnBtn').addEventListener('click', async function () {
      var key = ($('#settingsKey').value || '').trim() || (state.session && state.session.apiKey) || '';
      if (!key) { toast('请先填写 API Key', 'err'); return; }
      var b = $('#testConnBtn');
      setBusy(b, true, '测试中…');
      try {
        var s = await loginWithApiKey(key);
        await proxyFetch(s.apiBase + '/api/projects?limit=1', { headers: { 'Authorization': 'Bearer ' + s.accessToken, 'Accept': 'application/json' } });
        toast('连接成功 · 租户 ' + s.tenant + ' · API ' + s.apiBase, 'ok', 3200);
      } catch (e) {
        toast('连接失败：' + e.message, 'err', 5200);
      } finally { setBusy(b, false, '测试连接'); }
    });
    $('#saveSettingsBtn').addEventListener('click', async function () {
      var key = ($('#settingsKey').value || '').trim();
      if (!key) { toast('请先填写 API Key', 'err'); return; }
      var b = $('#saveSettingsBtn');
      setBusy(b, true, '保存中…');
      try {
        var s = await loginWithApiKey(key);
        syncScanMemoryScope(s);
        state.session = s; state.connected = true; saveConfig(); connUI();
        renderSettingsParse();
        toast('设置已保存', 'ok', 1800);
        await refreshAll();
      } catch (e) { toast('保存失败：' + e.message, 'err', 5200); }
      finally { setBusy(b, false, '保存'); }
    });
    $('#logoutBtn').addEventListener('click', function () { layer.classList.remove('open'); logout(false); });
    $('#clearKeyBtn').addEventListener('click', function () { clearConfig(); toast('已清除本机保存的 API Key', 'ok', 1800); });
  }

  function renderSettingsParse() {
    var el = $('#settingsParse');
    if (!el) return;
    if (!state.session) { el.innerHTML = ''; return; }
    var s = state.session;
    el.innerHTML =
      '<div class="pg"><div class="k">区域 Region</div><div class="v">' + esc((s.realmUrl.match(/\/\/([^\/]+)/) || [])[1] || '—') + '</div></div>' +
      '<div class="pg"><div class="k">租户 Tenant</div><div class="v">' + esc(s.tenant) + '</div></div>' +
      '<div class="pg"><div class="k">API 地址</div><div class="v">' + esc(s.apiBase) + '</div></div>' +
      '<div class="pg"><div class="k">认证地址</div><div class="v">' + esc(s.realmUrl) + '</div></div>';
  }

  function openSettings() {
    mountSettings();
    var keyEl = $('#settingsKey');
    if (keyEl) keyEl.value = state.session ? state.session.apiKey : '';
    renderSettingsParse();
    $('#settingsModal').classList.add('open');
  }

  /* ---------------------------------------------------------------------- */
  function mountLinkModal() {
    if ($('#linkModal')) return;
    var layer = document.createElement('div');
    layer.className = 'modal-layer';
    layer.id = 'linkModal';
    layer.innerHTML =
      '<div class="modal" style="width:560px">' +
      '<div class="modal-head"><div><div class="m-title">打开扫描链接</div><div class="m-sub">粘贴 Checkmarx One 扫描结果页面链接，直接定位到该次扫描</div></div>' +
      '<button class="icon-btn close" data-close-modal="linkModal">✕</button></div>' +
      '<div class="modal-body">' +
      '<div class="link-help">支持浏览器地址栏中的扫描页面链接，例如：<br><code>https://tenant.checkmarx.net/#/projects/&lt;projectId&gt;/scans/&lt;scanId&gt;</code><br>页面会自动提取其中的扫描 ID；也可以直接粘贴扫描 ID（UUID）。</div>' +
      '<div class="field"><label>扫描结果链接 / 扫描 ID</label><input type="text" id="linkInput" spellcheck="false" placeholder="粘贴链接，例如 https://…/scans/5f2d9c1e-…" /></div>' +
      '<div id="linkError" class="login-error" style="min-height:16px"></div>' +
      '<div class="modal-foot" style="padding:0;border:0;background:transparent;margin-top:4px">' +
      '<span class="spacer"></span><button class="btn" data-close-modal="linkModal">取消</button>' +
      '<button class="btn primary" id="linkOpenBtn">打开扫描</button></div>' +
      '</div></div>';
    document.body.appendChild(layer);
    $$('[data-close-modal="linkModal"]', layer).forEach(function (b) { b.addEventListener('click', function () { layer.classList.remove('open'); }); });
    layer.addEventListener('click', function (e) { if (e.target === layer) layer.classList.remove('open'); });
    $('#linkInput').addEventListener('keydown', function (e) { if (e.key === 'Enter') openScanLink(); });
    $('#linkOpenBtn').addEventListener('click', openScanLink);
  }

  function extractScanId(input) {
    var text = String(input || '').trim();
    if (!text) return '';
    var uuidRe = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
    var matches = text.match(uuidRe);
    if (matches && matches.length) {
      // 优先取 /scans/<id> 后面的 UUID，其次取最后一个 UUID
      var m = text.match(/\/scans\/([0-9a-f-]{36})/i);
      if (m) return m[1];
      return matches[matches.length - 1];
    }
    return '';
  }

  async function openScanLink() {
    var input = $('#linkInput') ? $('#linkInput').value : '';
    var errEl = $('#linkError');
    if (errEl) errEl.textContent = '';
    var scanId = extractScanId(input);
    if (!scanId) { if (errEl) errEl.textContent = '没有从输入中识别到扫描 ID（UUID）。'; return; }
    var btn = $('#linkOpenBtn');
    setBusy(btn, true, '打开中…');
    try {
      if (!state.projects.length) await loadProjects();
      var scan = await apiGet('/api/scans/' + encodeURIComponent(scanId));
      if (!scan || !scan.id) throw new Error('未找到该扫描（' + scanId + '）');
      var pid = scan.projectId || scan.projectID;
      if (pid && projectById(pid) && !state.selectedProjectIds.has(pid)) {
        state.selectedProjectIds = new Set([pid]);
        updateProjectUI();
      }
      if (state.scans.every(function (s) { return s.id !== scan.id; })) state.scans.push(scan);
      state.scanKey = scan.id;
      updateFilterOptions();
      $('#linkModal').classList.remove('open');
      toast('已定位扫描 ' + scan.id.slice(0, 8) + '…（' + (scan.status || '') + '）', 'ok', 2200);
      var loaded = await loadResults();
      if (loaded !== false) saveFilterMemory();
    } catch (e) {
      if (errEl) errEl.textContent = e.message;
    } finally { setBusy(btn, false, '打开扫描'); }
  }

  function openLinkModal() { mountLinkModal(); $('#linkModal').classList.add('open'); setTimeout(function () { $('#linkInput').focus(); }, 60); }

  /* ---------------------------------------------------------------------- */
  var scanState = {
    running: false,
    folders: [{ path: '', name: '', projectId: '' }],
    pollers: {},
    createdProjectIds: [],
    createdBranch: 'master',
    /* 项目名组合框（选已有 Checkmarx One 项目 / 手输新项目名） */
    projectOpen: false,
    projectRow: -1,
    projectQuery: '',
    projectFiltering: false,
    projectActive: -1,
    projectSuppressOpen: false,
    projectsLoading: false,
    projectError: '',
    projectSeq: 0,
    /* 分支自动读取（本机 git，经 proxy.py /git-branches）：本地/远端分支、当前检出分支 */
    branchLocals: [],
    branchRemotes: [],
    branchCurrents: [],
    branchDefault: 'master',
    branchTouched: false,
    branchSeq: 0,
    branchLoading: false,
    branchMenuOpen: false,
    branchFiltering: false,
    branchSuppressOpen: false,
    /* 扫描中最小化：浮动进度条 */
    minimized: false,
    miniState: '',          // running | done | err
    miniHideTimer: null,
    /* 失败详情：展示在进度模块下方 */
    errors: [],
    /* 扫描文件夹/项目名记忆（localStorage，按租户隔离）：首次打开弹窗自动恢复 */
    memoryLoaded: false,
    saveTimer: null,
    recent: []
  };
  /* 文件夹路径变化后（防抖）重新读取 git 分支 */
  var scheduleScanBranches = debounce(function () { refreshScanBranches(); }, 500);

  /* ---------- 扫描文件夹/项目名记忆：恢复 / 保存 / 「最近扫描」一键填入 ---------- */
  function persistScanRowsFromState() {
    saveScanMemoryRows(scanState.folders.map(normalizeScanMemoryRow), null);
  }
  function scheduleScanMemorySave() {
    clearTimeout(scanState.saveTimer);
    scanState.saveTimer = setTimeout(function () {
      scanState.saveTimer = null;
      persistScanRowsFromState();
    }, 450);
  }
  /** 首次打开弹窗时恢复上次填写的文件夹与项目名；返回是否发生恢复。 */
  function restoreScanMemory() {
    if (scanState.memoryLoaded) return false;
    scanState.memoryLoaded = true;
    var mem = loadScanMemory();
    scanState.recent = (mem && mem.recent) || [];
    var saved = (mem && mem.rows) || [];
    if (!saved.length) return false;
    var touched = scanState.folders.some(function (f) {
      return String(f.path || '').trim() || String(f.name || '').trim();
    });
    if (touched) return false;
    scanState.folders = saved.map(function (r) {
      return { path: r.path, name: r.name || baseName(r.path), projectId: '' };
    });
    return true;
  }
  function renderScanRecent() {
    var box = $('#scanRecent');
    var chips = $('#scanRecentChips');
    if (!box || !chips) return;
    var recent = scanState.recent || [];
    if (!recent.length) {
      chips.innerHTML = '';
      box.classList.add('hidden');
      return;
    }
    chips.innerHTML = recent.map(function (it) {
      var name = it.name || baseName(it.path);
      var tip = (name ? name + '\n' : '') + it.path;
      return '<button type="button" class="sr-chip" data-scan-target data-path="' + esc(it.path) + '" data-name="' + esc(it.name || '') + '" title="' + esc(tip) + '">' +
        '<span class="sr-name">' + esc(name) + '</span>' +
        '<span class="sr-path">' + esc(it.path) + '</span></button>';
    }).join('');
    box.classList.remove('hidden');
  }
  /** 点击「最近扫描」：优先填入第一个空行；只有一行时替换该行；否则追加新行。 */
  function fillScanTarget(path, name) {
    path = String(path || '').trim();
    if (!path) return;
    closeScanProjectMenu();
    var folders = scanState.folders;
    var target = null;
    for (var i = 0; i < folders.length; i++) {
      if (!String(folders[i].path || '').trim() && !String(folders[i].name || '').trim()) { target = folders[i]; break; }
    }
    if (!target) {
      if (folders.length === 1) target = folders[0];
      else { target = { path: '', name: '', projectId: '' }; folders.push(target); }
    }
    target.path = path;
    target.name = String(name || '').trim() || baseName(path);
    target.projectId = '';
    syncScanFolderProject(target, target.name);
    renderScanFolders();
    scheduleScanMemorySave();
    refreshScanBranches();
    var idx = folders.indexOf(target);
    var row = scanProjectRowEl(idx);
    var input = row ? row.querySelector('.pname') : null;
    if (input) {
      scanState.projectSuppressOpen = true;   // 填入后聚焦输入框，但不要因为 focus 又展开下拉
      try { input.focus(); } catch (e) { /* ignore */ }
      scanState.projectSuppressOpen = false;
    }
  }
  /** 退出登录 / 清除本机凭据后重置内存态，避免换租户后残留上一个租户的行。 */
  function resetScanMemoryState() {
    clearTimeout(scanState.saveTimer);
    scanState.saveTimer = null;
    scanState.memoryLoaded = false;
    scanState.recent = [];
    scanState.folders = [{ path: '', name: '', projectId: '' }];
    if ($('#scanFolders')) renderScanFolders();
    renderScanRecent();
  }
  /** 登录/切换租户时：租户或 API 地址变化则重置内存态（记忆按作用域隔离，换租户不串数据）。 */
  function syncScanMemoryScope(nextSession) {
    var prev = state.session;
    if (!prev || !nextSession) return;
    if (prev.tenant === nextSession.tenant && prev.apiBase === nextSession.apiBase && prev.realmUrl === nextSession.realmUrl) return;
    resetScanMemoryState();
  }

  function mountScanModal() {
    if ($('#scanModal')) return;
    var layer = document.createElement('div');
    layer.className = 'modal-layer';
    layer.id = 'scanModal';
    layer.innerHTML =
      '<div class="modal" style="width:860px">' +
      '<div class="modal-head"><div><div class="m-title">本地扫描 · 指定文件夹</div>' +
      '<div class="m-sub">对本地代码文件夹发起 Checkmarx One 扫描，支持一次提交多个项目</div></div>' +
      '<button class="icon-btn" id="scanMinBtn" type="button" title="最小化（扫描在后台继续，完成后通知）">—</button>' +
      '<button class="icon-btn close" data-close-modal="scanModal">✕</button></div>' +
      '<div class="modal-body">' +
      '<p class="scan-lead">选择本机代码文件夹（可添加多个，每个文件夹对应一个 Checkmarx One 项目）。项目名可从已有 Checkmarx One 项目下拉中搜索选择；若为新项目，直接输入项目名即可（提交时自动创建）。本机代理会调用 Checkmarx One CLI 完成打包/上传/创建扫描，源码只上传到你的 Checkmarx One 租户。</p>' +
      '<div class="scan-callout"><span class="i">ⓘ</span><span>扫描由 Checkmarx One 在云端执行。本机代理（proxy.py）调用 Checkmarx One CLI（需已安装，可用 CX_CLI_PATH 指定路径）上传源码并创建扫描；创建成功后页面轮询扫描状态，完成后自动加载结果。</span></div>' +
      '<div class="scan-folder-labels"><span>#</span><span>本地文件夹</span><span title="可从下拉选择已有 Checkmarx One 项目；输入不存在的名称将创建新项目">Checkmarx One 项目名</span><span></span></div>' +
      '<div class="scan-folders" id="scanFolders"></div>' +
      '<div class="actions" style="margin-top:9px"><button class="btn sm ghost" id="addFolderBtn" type="button">＋ 添加文件夹</button>' +
      '<span class="muted" style="font-size:11px">支持多项目并行扫描 · 文件夹路径与项目名自动记住</span></div>' +
      '<div class="scan-recent hidden" id="scanRecent">' +
      '<div class="scan-recent-head"><span>最近扫描</span><span class="sr-sub">点击填入文件夹与项目名</span>' +
      '<span class="spacer"></span><button type="button" class="sr-clear" id="scanRecentClear" title="清除本机保存的扫描文件夹与项目名">清空记忆</button></div>' +
      '<div class="sr-chips" id="scanRecentChips"></div></div>' +
      '<div class="scan-options">' +
      '<label class="opt branch-opt" title="本地扫描使用的分支名（从所选文件夹的 git 仓库自动读取）">分支 ' +
      '<span class="branch-field">' +
      '<input type="text" id="scanBranch" spellcheck="false" autocomplete="off" value="master" placeholder="master / main / 其它分支" />' +
      '<button type="button" class="bp-toggle" id="scanBranchToggle" title="选择分支" aria-label="选择分支">▾</button>' +
      '<button type="button" class="btn sm ghost bp-refresh" id="scanBranchRefresh" title="重新读取 git 分支">↻</button>' +
      '</span>' +
      '<span class="branch-hint" id="scanBranchHint"></span>' +
      '</label>' +
      '<label class="opt"><input type="checkbox" id="scanSast" checked> SAST</label>' +
      '<label class="opt"><input type="checkbox" id="scanSca"> SCA</label>' +
      '<label class="opt"><input type="checkbox" id="scanIac"> IaC</label>' +
      '</div>' +
      '<div class="scan-progress" id="scanProgress"></div>' +
      '<div class="scan-errors hidden" id="scanErrors"></div>' +
      '<div class="scan-summary hidden" id="scanSummary"></div>' +
      '</div>' +
      '<div class="modal-foot">' +
      '<span class="tip" id="scanTip">扫描由本机 Checkmarx One CLI 提交，耗时取决于代码体量（通常 3–10 分钟）；提交后可关闭弹窗，扫描在云端继续</span>' +
      '<span class="spacer"></span>' +
      '<button class="btn" data-close-modal="scanModal">关闭</button>' +
      '<button class="btn primary" id="startScanBtn">开始扫描</button>' +
      '</div></div>';
    document.body.appendChild(layer);
    mountScanMiniChip();
    mountScanBranchMenu();
    mountScanProjectMenu();
    $$('[data-close-modal="scanModal"]', layer).forEach(function (b) {
      b.addEventListener('click', function () { closeScanModal(); });
    });
    layer.addEventListener('click', function (e) { if (e.target === layer) closeScanModal(); });
    var minBtn = $('#scanMinBtn');
    if (minBtn) minBtn.addEventListener('click', function () { minimizeScanModal(); });
    var branchRefreshBtn = $('#scanBranchRefresh');
    if (branchRefreshBtn) branchRefreshBtn.addEventListener('click', function () {
      /* 手动刷新 = 重新按规则自动取默认分支（覆盖此前手动输入的值） */
      scanState.branchTouched = false;
      refreshScanBranches();
    });
    var branchInput = $('#scanBranch');
    if (branchInput) {
      branchInput.addEventListener('input', function () {
        scanState.branchTouched = true;
        scanState.branchFiltering = true;   // 输入时才按关键词过滤下拉列表
        if (scanState.branchMenuOpen) syncScanBranchMenu();
      });
      branchInput.addEventListener('focus', function () {
        if (scanState.branchSuppressOpen) return;
        if (!scanState.branchLoading && !scanState.branchLocals.length && !scanState.branchRemotes.length && scanPaths().length) {
          refreshScanBranches();
        }
        openScanBranchMenu();
      });
      branchInput.addEventListener('click', function () { openScanBranchMenu(); });
      branchInput.addEventListener('keydown', function (e) {
        if (e.key === 'ArrowDown') {
          e.preventDefault();
          e.stopPropagation();
          openScanBranchMenu();
          var first = $('#scanBranchMenu .bp-item');
          if (first) first.focus();
        } else if (e.key === 'Escape' || e.key === 'Enter') {
          e.stopPropagation();
          closeScanBranchMenu();
        }
      });
    }
    var branchToggle = $('#scanBranchToggle');
    if (branchToggle) branchToggle.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      toggleScanBranchMenu();
    });
    $('#addFolderBtn').addEventListener('click', function () {
      scanState.folders.push({ path: '', name: '', projectId: '' });
      renderScanFolders();
      scheduleScanMemorySave();
      var rows = $$('#scanFolders [data-folder-row]');
      var last = rows[rows.length - 1];
      if (last) last.querySelector('.fpath').focus();
    });
    var recentChips = $('#scanRecentChips');
    if (recentChips) recentChips.addEventListener('click', function (e) {
      var chip = e.target && e.target.closest ? e.target.closest('[data-scan-target]') : null;
      if (!chip) return;
      fillScanTarget(chip.getAttribute('data-path'), chip.getAttribute('data-name'));
    });
    var clearMemoryBtn = $('#scanRecentClear');
    if (clearMemoryBtn) clearMemoryBtn.addEventListener('click', function () {
      clearTimeout(scanState.saveTimer);
      scanState.saveTimer = null;
      clearScanMemory();
      scanState.recent = [];
      scanState.memoryLoaded = true;   // 本次会话不再自动恢复
      scanState.folders = [{ path: '', name: '', projectId: '' }];
      renderScanFolders();
      renderScanRecent();
      toast('已清除本机保存的扫描文件夹与项目名', 'ok', 2200);
    });
    $('#startScanBtn').addEventListener('click', startLocalScan);
    renderScanFolders();
    renderScanRecent();
    syncScanBranchMenu();
  }

  function baseName(p) {
    if (!p) return '';
    var parts = String(p).replace(/[\\/]+$/, '').split(/[\\/]/);
    return parts[parts.length - 1] || '';
  }

  function renderScanFolders() {
    var box = $('#scanFolders');
    if (!box) return;
    closeScanProjectMenu();
    box.innerHTML = scanState.folders.map(function (f, i) {
      return '<div class="scan-folder-row" data-folder-row data-pstate="empty">' +
        '<span class="idx">' + (i + 1) + '</span>' +
        '<span class="path-wrap"><input type="text" class="fpath" spellcheck="false" placeholder="E:\\projects\\my-service（或点击浏览）" value="' + esc(f.path) + '">' +
        '<button type="button" class="btn sm browse" data-browse>浏览…</button></span>' +
        '<span class="pname-wrap">' +
        '<input type="text" class="pname" spellcheck="false" autocomplete="off" role="combobox" aria-expanded="false" aria-autocomplete="list" placeholder="选择已有项目或输入新项目名" value="' + esc(f.name) + '">' +
        '<span class="pn-badge" data-pn-badge></span>' +
        '<button type="button" class="pn-toggle" data-pn-toggle title="选择已有 Checkmarx One 项目" aria-label="选择已有 Checkmarx One 项目">▾</button>' +
        '</span>' +
        '<button type="button" class="icon-btn remove" data-remove-folder title="移除">✕</button>' +
        '</div>';
    }).join('');
    $$('#scanFolders [data-folder-row]').forEach(function (row, i) {
      var pathInput = row.querySelector('.fpath');
      var nameInput = row.querySelector('.pname');
      var f = scanState.folders[i];
      if (!f) return;
      if (typeof f.projectId !== 'string') f.projectId = '';
      updateScanFolderProjectUI(row, f);
      pathInput.addEventListener('input', function () {
        f.path = pathInput.value;
        if (!nameInput.value.trim()) {
          nameInput.value = baseName(pathInput.value);
          syncScanFolderProject(f, nameInput.value);
          updateScanFolderProjectUI(row, f);
        }
        scheduleScanBranches();   // 路径变化后（防抖）重新读取 git 分支
        scheduleScanMemorySave(); // 记住已填写的文件夹路径（防抖）
      });
      nameInput.addEventListener('input', function () {
        syncScanFolderProject(f, nameInput.value);
        updateScanFolderProjectUI(row, f);
        scheduleScanMemorySave();
        scanState.projectRow = i;
        scanState.projectQuery = nameInput.value;
        scanState.projectFiltering = true;
        scanState.projectActive = 0;
        if (!scanState.projectOpen) openScanProjectMenu(i, { filtering: true });
        else renderScanProjectMenu();
      });
      nameInput.addEventListener('focus', function () {
        if (scanState.projectSuppressOpen) return;
        openScanProjectMenu(i, { filtering: false });
      });
      nameInput.addEventListener('click', function () {
        if (!scanState.projectOpen || scanState.projectRow !== i) openScanProjectMenu(i, { filtering: false });
      });
      nameInput.addEventListener('keydown', function (e) {
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
          e.preventDefault();
          e.stopPropagation();
          if (!scanState.projectOpen) openScanProjectMenu(i, { filtering: true });
          moveScanProjectActive(e.key === 'ArrowDown' ? 1 : -1);
        } else if (e.key === 'Enter') {
          if (!scanState.projectOpen) return;
          e.preventDefault();
          e.stopPropagation();
          activateScanProjectItem();
        } else if (e.key === 'Escape') {
          if (!scanState.projectOpen) return;
          e.preventDefault();
          e.stopPropagation();   // 避免触发全局 Esc 关闭弹窗
          closeScanProjectMenu();
        } else if (e.key === 'Tab') {
          if (scanState.projectOpen) closeScanProjectMenu();
        }
      });
      var toggleBtn = row.querySelector('[data-pn-toggle]');
      if (toggleBtn) toggleBtn.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        if (scanState.projectOpen && scanState.projectRow === i) closeScanProjectMenu();
        else { nameInput.focus(); openScanProjectMenu(i, { filtering: false }); }
      });
      row.querySelector('[data-browse]').addEventListener('click', async function () {
        try {
          var res = await proxyJson('/pick-folder', {});
          if (res && res.path) {
            f.path = res.path;
            pathInput.value = res.path;
            if (!nameInput.value.trim()) {
              nameInput.value = baseName(res.path);
              syncScanFolderProject(f, nameInput.value);
              updateScanFolderProjectUI(row, f);
            }
            refreshScanBranches();   // 浏览选定文件夹后立即读取 git 分支
            scheduleScanMemorySave();
          }
        } catch (e) {
          toast(e.message + '（可手动输入文件夹路径）', 'err', 4500);
          pathInput.focus();
        }
      });
      row.querySelector('[data-remove-folder]').addEventListener('click', function () {
        if (scanState.folders.length <= 1) { toast('至少保留一个文件夹', 'err'); return; }
        closeScanProjectMenu();
        scanState.folders.splice(i, 1);
        renderScanFolders();
        scheduleScanBranches();
        scheduleScanMemorySave();
      });
    });
  }

  /* ---------------------------------------------------------------------- */
  /* 项目名组合框：从已有 Checkmarx One 项目中搜索选择；输入不存在的名称按新项目处理 */
  /* ---------------------------------------------------------------------- */
  function scanProjectNameKey(name) { return String(name == null ? '' : name).trim().toLowerCase(); }

  function findProjectByName(name) {
    var key = scanProjectNameKey(name);
    if (!key) return null;
    var list = state.projects || [];
    for (var i = 0; i < list.length; i++) {
      if (scanProjectNameKey(list[i].name) === key) return list[i];
    }
    return null;
  }
  function findProjectById(id) {
    if (!id) return null;
    var list = state.projects || [];
    for (var i = 0; i < list.length; i++) if (list[i].id === id) return list[i];
    return null;
  }
  /** 项目名状态：empty（未填）| existing（已有项目）| new（新项目，提交时自动创建）。 */
  function scanProjectState(f) {
    var name = String((f && f.name) || '').trim();
    if (!name) return 'empty';
    var bound = f.projectId ? findProjectById(f.projectId) : null;
    if (bound && scanProjectNameKey(bound.name) === scanProjectNameKey(name)) return 'existing';
    return findProjectByName(name) ? 'existing' : 'new';
  }
  /** 输入变化后同步模型：与已有项目同名（忽略大小写/首尾空格）则绑定其 ID，否则按新项目处理。 */
  function syncScanFolderProject(f, name) {
    f.name = String(name == null ? '' : name);
    var p = findProjectByName(f.name);
    f.projectId = p ? p.id : '';
  }
  function updateScanFolderProjectUI(row, f) {
    if (!row || !f) return;
    var st = scanProjectState(f);
    row.setAttribute('data-pstate', st);
    var badge = row.querySelector('[data-pn-badge]');
    if (badge) badge.textContent = st === 'existing' ? '已有' : st === 'new' ? '新项目' : '';
    var input = row.querySelector('.pname');
    if (input) {
      var name = String(f.name || '').trim();
      input.title = st === 'existing'
        ? '已关联已有 Checkmarx One 项目：' + name + '（扫描直接创建在该项目下）'
        : st === 'new'
          ? '「' + name + '」不是已有项目：开始扫描时将自动创建（需要创建项目权限）'
          : '选择已有 Checkmarx One 项目，或直接输入新项目名';
    }
  }
  function scanProjectKeywords() {
    var q = String(scanState.projectQuery || '').trim().toLowerCase();
    return q ? q.split(/\s+/).filter(Boolean) : [];
  }
  function scanProjectRowEl(i) {
    var rows = $$('#scanFolders [data-folder-row]');
    return (i >= 0 && i < rows.length) ? rows[i] : null;
  }
  function scanProjectInputEl(i) {
    var row = scanProjectRowEl(i);
    return row ? row.querySelector('.pname') : null;
  }

  function mountScanProjectMenu() {
    if ($('#scanProjectMenu')) return;
    var menu = document.createElement('div');
    menu.className = 'pn-menu hidden';
    menu.id = 'scanProjectMenu';
    document.body.appendChild(menu);
    /* 阻止 mousedown 抢走输入框焦点，便于连续输入/再次展开 */
    menu.addEventListener('mousedown', function (e) { e.preventDefault(); });
    menu.addEventListener('click', function (e) {
      var t = e.target;
      if (!t || !t.closest) return;
      if (t.closest('[data-pn-refresh]')) { refreshScanProjects(); return; }
      var item = t.closest('.pn-item');
      if (!item) return;
      if (item.getAttribute('data-pn-new') === '1') chooseScanNewProject();
      else chooseScanProjectById(item.getAttribute('data-project-id'));
    });
    document.addEventListener('click', function (e) {
      if (!scanState.projectOpen) return;
      var t = e.target;
      if (t && t.closest && (t.closest('.pname-wrap') || t.closest('#scanProjectMenu'))) return;
      closeScanProjectMenu();
    });
    window.addEventListener('resize', function () { if (scanState.projectOpen) closeScanProjectMenu(); });
    /* 弹窗内容滚动时关闭浮层，避免位置错位（下拉自身滚动除外） */
    window.addEventListener('scroll', function (e) {
      if (!scanState.projectOpen) return;
      var t = e.target;
      if (t && t.closest && t.closest('#scanProjectMenu')) return;
      closeScanProjectMenu();
    }, true);
  }

  function renderScanProjectMenu() {
    var menu = $('#scanProjectMenu');
    if (!menu) return;
    var kws = scanState.projectFiltering ? scanProjectKeywords() : [];
    var query = String(scanState.projectQuery || '').trim();
    var all = state.projects || [];
    var visible = all.filter(function (p) {
      var lower = String(p.name || '').toLowerCase();
      return kws.every(function (kw) { return lower.indexOf(kw) >= 0; });
    });
    var exact = query ? findProjectByName(query) : null;
    var showNew = !!query && !exact;
    var html = '<div class="pn-head"><span>选择 Checkmarx One 项目</span><span class="spacer"></span>' +
      (scanState.projectsLoading ? '<span class="pn-loading">刷新中…</span>' : '') +
      '<button type="button" class="pn-refresh" data-pn-refresh title="刷新项目列表" aria-label="刷新项目列表">↻</button></div>' +
      '<div class="pn-list">';
    if (!visible.length) {
      var emptyText = all.length
        ? '没有匹配「' + esc(query) + '」的项目'
        : (scanState.projectError ? '项目列表加载失败：' + esc(scanState.projectError) : '暂无已有项目');
      html += '<div class="pn-empty">' + emptyText +
        (query ? '<br>继续输入后开始扫描将按新项目创建。' : '') + '</div>';
    } else {
      html += visible.map(function (p) {
        return '<button type="button" class="pn-item" data-project-id="' + esc(p.id) + '" data-name="' + esc(p.name) + '">' +
          '<span class="pn-dot" style="background:' + esc(p.color || '#64748b') + '"></span>' +
          '<span class="pn-name">' + highlightProjectName(p.name, kws) + '</span>' +
          '</button>';
      }).join('');
    }
    if (showNew) {
      html += '<button type="button" class="pn-item pn-new" data-pn-new="1">' +
        '<span class="pn-plus">＋</span><span class="pn-name">新建项目「' + esc(query) + '」</span>' +
        '<span class="pn-sub">将自动创建</span></button>';
    }
    html += '</div>';
    var foot;
    if (!query) foot = '输入关键词筛选已有项目；没有匹配项时可直接输入新项目名';
    else if (!exact) foot = '「' + query + '」不是已有项目：开始扫描时将自动创建新项目（需要创建项目权限）';
    else foot = '已匹配已有项目「' + exact.name + '」';
    html += '<div class="pn-foot">' + esc(foot) + '</div>';
    menu.innerHTML = html;
    var items = $$('.pn-item', menu);
    if (!items.length) scanState.projectActive = -1;
    else if (scanState.projectActive < 0 || scanState.projectActive >= items.length) {
      scanState.projectActive = scanState.projectFiltering ? 0 : -1;
    }
    items.forEach(function (el, idx) { el.classList.toggle('active', idx === scanState.projectActive); });
    if (scanState.projectActive >= 0 && items[scanState.projectActive]) {
      try { items[scanState.projectActive].scrollIntoView({ block: 'nearest' }); } catch (e) { /* ignore */ }
    }
  }

  function positionScanProjectMenu() {
    var menu = $('#scanProjectMenu');
    var input = scanProjectInputEl(scanState.projectRow);
    if (!menu || !input || menu.classList.contains('hidden')) return;
    var rect = input.getBoundingClientRect();
    var vw = window.innerWidth || document.documentElement.clientWidth || 1280;
    var width = Math.max(rect.width + 40, 300);
    width = Math.min(width, Math.max(220, vw - 20));
    menu.style.width = width + 'px';
    var h = Math.min(menu.offsetHeight || 300, 300);
    var left = Math.max(10, Math.min(rect.left, vw - width - 10));
    var top = rect.bottom + 6;
    if (top + h > window.innerHeight - 10) top = Math.max(10, rect.top - 6 - h);
    menu.style.left = left + 'px';
    menu.style.top = top + 'px';
  }

  function openScanProjectMenu(i, opts) {
    var row = scanProjectRowEl(i);
    var input = row ? row.querySelector('.pname') : null;
    var menu = $('#scanProjectMenu');
    if (!row || !input || !menu) return;
    scanState.projectRow = i;
    scanState.projectQuery = input.value;
    scanState.projectFiltering = !!(opts && opts.filtering);
    scanState.projectActive = scanState.projectFiltering ? 0 : -1;
    renderScanProjectMenu();
    menu.classList.remove('hidden');
    scanState.projectOpen = true;
    input.setAttribute('aria-expanded', 'true');
    positionScanProjectMenu();
    /* 打开下拉时高亮当前已绑定的项目 */
    if (!scanState.projectFiltering) {
      var f = scanState.folders[i] || {};
      var items = $$('.pn-item', menu);
      var active = -1;
      items.forEach(function (el, idx) {
        if (f.projectId && el.getAttribute('data-project-id') === f.projectId) active = idx;
      });
      if (active >= 0) {
        scanState.projectActive = active;
        items.forEach(function (el, idx) { el.classList.toggle('active', idx === active); });
      }
    }
    if (!state.projects.length && !scanState.projectsLoading) refreshScanProjects();
  }

  function closeScanProjectMenu() {
    var menu = $('#scanProjectMenu');
    if (menu) menu.classList.add('hidden');
    scanState.projectOpen = false;
    var input = scanProjectInputEl(scanState.projectRow);
    if (input) input.setAttribute('aria-expanded', 'false');
  }

  function moveScanProjectActive(delta) {
    var menu = $('#scanProjectMenu');
    if (!menu) return;
    var items = $$('.pn-item', menu);
    if (!items.length) { scanState.projectActive = -1; return; }
    var n = items.length;
    var next = scanState.projectActive < 0
      ? (delta > 0 ? 0 : n - 1)
      : (scanState.projectActive + delta + n) % n;
    scanState.projectActive = next;
    items.forEach(function (el, idx) { el.classList.toggle('active', idx === next); });
    try { items[next].scrollIntoView({ block: 'nearest' }); } catch (e) { /* ignore */ }
  }

  function activateScanProjectItem() {
    var menu = $('#scanProjectMenu');
    if (!menu) return;
    var items = $$('.pn-item', menu);
    var el = items[scanState.projectActive] || items[0];
    if (el) el.click();
  }

  function applyScanProjectChoice(f, name, projectId) {
    f.name = String(name == null ? '' : name);
    f.projectId = projectId || '';
    var i = scanState.projectRow;
    var row = scanProjectRowEl(i);
    var input = row ? row.querySelector('.pname') : null;
    if (input) input.value = f.name;
    updateScanFolderProjectUI(row, f);
    closeScanProjectMenu();
    scheduleScanMemorySave();
    if (input) {
      scanState.projectSuppressOpen = true;   // 选完把焦点放回输入框，但不要因为 focus 又展开下拉
      try { input.focus(); } catch (e) { /* ignore */ }
      scanState.projectSuppressOpen = false;
    }
  }
  function chooseScanProjectById(id) {
    var f = scanState.folders[scanState.projectRow];
    var p = findProjectById(id);
    if (!f || !p) return;
    applyScanProjectChoice(f, p.name, p.id);
  }
  function chooseScanNewProject() {
    var f = scanState.folders[scanState.projectRow];
    var name = String(scanState.projectQuery || '').trim();
    if (!f || !name) return;
    applyScanProjectChoice(f, name, '');
  }

  /** 项目列表变化后：刷新所有行的「已有 / 新项目」标记；下拉打开时同步刷新列表。 */
  function syncScanProjectUI() {
    $$('#scanFolders [data-folder-row]').forEach(function (row, i) {
      var f = scanState.folders[i];
      if (f) updateScanFolderProjectUI(row, f);
    });
    if (scanState.projectOpen) {
      renderScanProjectMenu();
      positionScanProjectMenu();
    }
  }

  /** 打开本地扫描弹窗时实时刷新已有项目列表（失败时保留原列表，不阻塞扫描）。 */
  async function refreshScanProjects() {
    if (!state.session || scanState.projectsLoading) return;
    var seq = ++scanState.projectSeq;
    scanState.projectsLoading = true;
    scanState.projectError = '';
    if (scanState.projectOpen) renderScanProjectMenu();
    try {
      await loadProjects();
    } catch (e) {
      if (seq === scanState.projectSeq) scanState.projectError = e.message || '加载失败';
    } finally {
      if (seq !== scanState.projectSeq) return;
      scanState.projectsLoading = false;
      syncScanProjectUI();
    }
  }

  /* ---------- 分支自动读取（本机 git，经 proxy.py /git-branches） ---------- */
  function scanPaths() {
    return scanState.folders.map(function (f) { return String(f.path || '').trim(); }).filter(Boolean);
  }
  function setScanBranchHint(text, warn) {
    var el = $('#scanBranchHint');
    if (!el) return;
    el.textContent = text || '';
    el.className = 'branch-hint' + (warn ? ' warn' : '');
  }
  /** 默认分支：当前检出分支 > master > main > 第一个分支（本地分支优先）。 */
  function pickDefaultBranch(currents, locals) {
    if (currents && currents.length) return currents[0];
    if (locals && locals.indexOf('master') >= 0) return 'master';
    if (locals && locals.indexOf('main') >= 0) return 'main';
    if (locals && locals.length) return locals[0];
    return '';
  }
  /* ---------- 分支下拉（可输入 + 可点选；浮层挂 body，避免被弹窗 overflow 裁剪） ---------- */
  function scanBranchItems() {
    var locals = scanState.branchLocals || [];
    var remotes = scanState.branchRemotes || [];
    var items = locals.map(function (b) { return { name: b, remote: false }; });
    remotes.forEach(function (b) { if (locals.indexOf(b) < 0) items.push({ name: b, remote: true }); });
    return items;
  }
  function mountScanBranchMenu() {
    if ($('#scanBranchMenu')) return;
    var menu = document.createElement('div');
    menu.className = 'bp-menu hidden';
    menu.id = 'scanBranchMenu';
    document.body.appendChild(menu);
    /* mousedown 阻止焦点离开输入框，选完分支仍可继续输入/再次展开 */
    menu.addEventListener('mousedown', function (e) { e.preventDefault(); });
    menu.addEventListener('click', function (e) {
      var item = e.target && e.target.closest ? e.target.closest('.bp-item') : null;
      if (!item) return;
      chooseScanBranch(item.getAttribute('data-branch') || '');
    });
    menu.addEventListener('keydown', function (e) {
      var items = $$('.bp-item', menu);
      var idx = items.indexOf(document.activeElement);
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        e.stopPropagation();
        var next = items[Math.min(items.length - 1, idx + 1)];
        if (next) next.focus();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        e.stopPropagation();
        var prev = items[Math.max(0, idx - 1)];
        if (prev) prev.focus();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        e.stopPropagation();
        if (document.activeElement && document.activeElement.classList.contains('bp-item')) document.activeElement.click();
      } else if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        closeScanBranchMenu();
        var input = $('#scanBranch');
        if (input) input.focus();
      }
    });
    document.addEventListener('click', function (e) {
      if (!scanState.branchMenuOpen) return;
      var t = e.target;
      if (t && t.closest && (t.closest('.branch-field') || t.closest('#scanBranchMenu'))) return;
      closeScanBranchMenu();
    });
    window.addEventListener('resize', function () { if (scanState.branchMenuOpen) closeScanBranchMenu(); });
    /* 弹窗内容滚动时关闭浮层，避免位置错位 */
    window.addEventListener('scroll', function () { if (scanState.branchMenuOpen) closeScanBranchMenu(); }, true);
  }
  function renderScanBranchMenu() {
    var menu = $('#scanBranchMenu');
    if (!menu) return;
    var input = $('#scanBranch');
    var keyword = scanState.branchFiltering ? String(input ? input.value : '').trim().toLowerCase() : '';
    var current = String(input ? input.value : '').trim();
    var items = scanBranchItems();
    function renderGroup(label, list) {
      var filtered = list.filter(function (it) { return !keyword || it.name.toLowerCase().indexOf(keyword) >= 0; });
      if (!filtered.length) return '';
      return '<div class="bp-group">' + label + '</div>' + filtered.map(function (it) {
        return '<button type="button" class="bp-item' + (it.name === current ? ' on' : '') +
          '" data-branch="' + esc(it.name) + '" title="' + esc(it.name) + '">' + esc(it.name) + '</button>';
      }).join('');
    }
    var html = renderGroup('本地分支', items.filter(function (it) { return !it.remote; })) +
      renderGroup('远端分支', items.filter(function (it) { return it.remote; }));
    if (!html) {
      html = '<div class="bp-empty">' + (items.length
        ? '没有匹配「' + esc(keyword) + '」的分支，可直接输入分支名'
        : '未从 git 读取到分支：可直接输入分支名（默认 master / main）') + '</div>';
    }
    menu.innerHTML = html;
  }
  function positionScanBranchMenu() {
    var menu = $('#scanBranchMenu');
    var input = $('#scanBranch');
    if (!menu || !input || menu.classList.contains('hidden')) return;
    var rect = input.getBoundingClientRect();
    var width = Math.max(240, rect.width + 150);
    menu.style.width = Math.min(width, Math.max(220, window.innerWidth - 24)) + 'px';
    var h = Math.min(menu.offsetHeight || 240, 260);
    var left = Math.max(10, Math.min(rect.left, window.innerWidth - menu.offsetWidth - 10));
    var top = rect.bottom + 6;
    if (top + h > window.innerHeight - 10) top = Math.max(10, rect.top - 6 - h);
    menu.style.left = left + 'px';
    menu.style.top = top + 'px';
  }
  function openScanBranchMenu() {
    var menu = $('#scanBranchMenu');
    var input = $('#scanBranch');
    if (!menu || !input) return;
    scanState.branchFiltering = false;   // 打开下拉时展示全部分支，输入时才过滤
    renderScanBranchMenu();
    menu.classList.remove('hidden');
    scanState.branchMenuOpen = true;
    positionScanBranchMenu();
  }
  function closeScanBranchMenu() {
    var menu = $('#scanBranchMenu');
    if (menu) menu.classList.add('hidden');
    scanState.branchMenuOpen = false;
  }
  function toggleScanBranchMenu() {
    if (scanState.branchMenuOpen) closeScanBranchMenu();
    else openScanBranchMenu();
  }
  function chooseScanBranch(name) {
    var input = $('#scanBranch');
    if (input) input.value = name || '';
    scanState.branchTouched = true;
    closeScanBranchMenu();
    if (input) {
      /* 选完把焦点放回输入框，但不要因为 focus 又自动展开下拉 */
      scanState.branchSuppressOpen = true;
      input.focus();
      scanState.branchSuppressOpen = false;
    }
  }
  function syncScanBranchMenu() {
    renderScanBranchMenu();
    if (scanState.branchMenuOpen) positionScanBranchMenu();
  }
  async function refreshScanBranches() {
    var input = $('#scanBranch');
    if (!input) return;
    var paths = scanPaths();
    var seq = ++scanState.branchSeq;
    if (!paths.length) {
      scanState.branchLocals = []; scanState.branchRemotes = []; scanState.branchCurrents = [];
      syncScanBranchMenu();
      setScanBranchHint('');
      return;
    }
    scanState.branchLoading = true;
    setScanBranchHint('正在读取 git 分支…');
    try {
      var res = await proxyJson('/git-branches', { paths: paths });
      if (seq !== scanState.branchSeq) return;
      var repos = (res && res.repos) || [];
      var locals = [], remotes = [], currents = [], skipped = 0, firstErr = '';
      repos.forEach(function (r) {
        if (!r) return;
        if (r.ok && r.isRepo) {
          (r.locals || []).forEach(function (b) { if (b && locals.indexOf(b) < 0) locals.push(b); });
          (r.remotes || []).forEach(function (b) { if (b && remotes.indexOf(b) < 0) remotes.push(b); });
          if (r.current && currents.indexOf(r.current) < 0) currents.push(r.current);
        } else {
          skipped++;
          if (!firstErr) firstErr = r.error || '';
        }
      });
      scanState.branchLocals = locals;
      scanState.branchRemotes = remotes;
      scanState.branchCurrents = currents;
      syncScanBranchMenu();
      var total = locals.length + remotes.length;
      var def = pickDefaultBranch(currents, locals);
      if (def) scanState.branchDefault = def;
      /* 用户手动改过分支名时不覆盖；否则按「当前检出 > master > main > 第一个」自动填默认值 */
      if (!scanState.branchTouched || !input.value.trim()) input.value = def || input.value || scanState.branchDefault || 'master';
      if (total) {
        var msg = '已读取 ' + total + ' 个分支';
        if (currents.length === 1) msg = '当前检出分支 ' + currents[0] + '；共 ' + total + ' 个分支';
        if (remotes.length) msg += '（本地 ' + locals.length + ' / 远端 ' + remotes.length + '）';
        if (skipped) msg += '；' + skipped + ' 个文件夹未读取到 git 分支' + (firstErr ? '（' + firstErr + '）' : '');
        setScanBranchHint(msg);
      } else {
        var fallback = scanState.branchDefault || 'master';
        if (!input.value.trim()) input.value = fallback;
        setScanBranchHint('未读取到 git 分支（不是 git 仓库或 git 不可用），使用默认分支 ' + fallback + '，可手动输入', true);
      }
    } catch (e) {
      if (seq !== scanState.branchSeq) return;
      scanState.branchLocals = []; scanState.branchRemotes = []; scanState.branchCurrents = [];
      syncScanBranchMenu();
      if (!input.value.trim()) input.value = scanState.branchDefault || 'master';
      setScanBranchHint('读取 git 分支失败：' + e.message + '（可手动输入分支）', true);
    } finally {
      if (seq === scanState.branchSeq) scanState.branchLoading = false;
    }
  }

  /* ---------- 扫描最小化：浮动进度条 / 完成通知 ---------- */
  function mountScanMiniChip() {
    if ($('#scanMini')) return;
    var el = document.createElement('div');
    el.className = 'scan-mini hidden';
    el.id = 'scanMini';
    el.dataset.state = 'running';
    el.innerHTML = '<span class="sm-dot"></span>' +
      '<span class="sm-text" id="scanMiniText">本地扫描进行中…</span>' +
      '<span class="sm-sub" id="scanMiniSub">点击查看进度</span>' +
      '<button type="button" class="sm-x" id="scanMiniClose" title="隐藏（扫描继续，完成后仍会通知）">✕</button>';
    document.body.appendChild(el);
    el.addEventListener('click', function (e) {
      if (e.target && e.target.closest && e.target.closest('#scanMiniClose')) return;
      restoreScanModal();
    });
    var x = $('#scanMiniClose');
    if (x) x.addEventListener('click', function (e) { e.stopPropagation(); hideScanMiniChip(); });
  }
  function hideScanMiniChip() {
    clearTimeout(scanState.miniHideTimer);
    var el = $('#scanMini');
    if (el) el.classList.add('hidden');
  }
  function showScanMiniChip() {
    var el = $('#scanMini');
    if (!el) return;
    clearTimeout(scanState.miniHideTimer);
    el.classList.remove('hidden');
  }
  function updateScanMiniChip() {
    var el = $('#scanMini');
    if (!el) return;
    var textEl = $('#scanMiniText'), subEl = $('#scanMiniSub');
    var rows = $$('#scanProgress [data-prog]');
    var total = rows.length;
    var done = 0, failed = 0, pending = 0;
    rows.forEach(function (r) {
      if (r.classList.contains('done')) done++; else pending++;
      if (r.dataset.failed === '1') failed++;
    });
    el.classList.remove('done', 'err');
    var miniState = scanState.miniState || 'running';
    /* 有失败时等全部行都结束再显示失败态，避免其它扫描还在跑时就报失败 */
    if (failed && !pending) miniState = 'err';
    if (miniState === 'done' && pending) miniState = 'running';
    if (miniState === 'done') {
      el.classList.add('done');
      if (textEl) textEl.textContent = '本地扫描完成 · ' + total + '/' + total;
      if (subEl) subEl.textContent = '点击查看结果';
      clearTimeout(scanState.miniHideTimer);
      scanState.miniHideTimer = setTimeout(hideScanMiniChip, 12000);
    } else if (miniState === 'err') {
      el.classList.add('err');
      if (textEl) textEl.textContent = '本地扫描结束 · 成功 ' + Math.max(0, done - failed) + ' / 失败 ' + failed;
      if (subEl) subEl.textContent = '点击查看失败详情';
    } else {
      if (textEl) textEl.textContent = '本地扫描进行中 · ' + done + '/' + total;
      if (subEl) subEl.textContent = '点击查看进度';
    }
    el.dataset.state = miniState;
  }
  function minimizeScanModal() {
    var layer = $('#scanModal');
    if (!layer) return;
    closeScanBranchMenu();
    closeScanProjectMenu();
    /* 没有进行中的扫描（刚打开弹窗就点最小化）：直接收起，不显示浮动条 */
    if (!scanState.running && scanState.miniState !== 'done' && scanState.miniState !== 'err') {
      scanState.minimized = false;
      hideScanMiniChip();
      layer.classList.remove('open');
      return;
    }
    scanState.minimized = true;
    layer.classList.remove('open');
    updateScanMiniChip();
    showScanMiniChip();
  }
  function restoreScanModal() {
    var layer = $('#scanModal');
    if (!layer) return;
    scanState.minimized = false;
    hideScanMiniChip();
    closeScanBranchMenu();
    closeScanProjectMenu();
    layer.classList.add('open');
  }
  /** 关闭弹窗：扫描进行中时改为最小化，避免用户误以为扫描被中断。 */
  function closeScanModal() {
    closeScanBranchMenu();
    closeScanProjectMenu();
    if (scanState.running) { minimizeScanModal(); return; }
    scanState.minimized = false;
    hideScanMiniChip();
    var layer = $('#scanModal');
    if (layer) layer.classList.remove('open');
  }

  /* ---------- 失败详情：展示在进度模块下方（全宽、可换行、可复制） ---------- */
  function clearScanErrors() {
    scanState.errors = [];
    var box = $('#scanErrors');
    if (box) { box.innerHTML = ''; box.classList.add('hidden'); }
  }
  function renderScanErrors() {
    var box = $('#scanErrors');
    if (!box) return;
    var items = scanState.errors || [];
    if (!items.length) { box.innerHTML = ''; box.classList.add('hidden'); return; }
    var html = '<div class="se-head"><span>⚠ 失败详情（' + items.length + '）</span><span class="spacer"></span>' +
      '<button type="button" class="btn sm ghost" id="scanErrCopy">复制</button></div>';
    items.forEach(function (it) {
      html += '<div class="se-item">' +
        '<div class="se-who">' + esc(it.name || '未命名项目') + (it.path ? ' · ' + esc(it.path) : '') + '</div>' +
        '<div class="se-msg">' + esc(it.detail || '未知错误') + '</div></div>';
    });
    box.innerHTML = html;
    box.classList.remove('hidden');
    var copyBtn = $('#scanErrCopy');
    if (copyBtn) copyBtn.addEventListener('click', function () {
      copyText(items.map(function (it) {
        return (it.name || '') + (it.path ? '（' + it.path + '）' : '') + '：' + (it.detail || '');
      }).join('\n'), '已复制失败详情');
    });
  }
  function addScanError(name, path, detail) {
    scanState.errors.push({ name: name || '', path: path || '', detail: String(detail || '未知错误') });
    renderScanErrors();
  }

  function openScan() {
    mountScanModal();
    var layer = $('#scanModal');
    if (layer) layer.classList.add('open');
    scanState.minimized = false;
    hideScanMiniChip();
    closeScanBranchMenu();
    closeScanProjectMenu();
    /* 首次打开：按本机记忆恢复上次填写的文件夹与项目名（同一租户） */
    if (restoreScanMemory()) {
      renderScanFolders();
      toast('已恢复上次扫描的文件夹与项目名', 'info', 2600);
    }
    renderScanRecent();
    syncScanProjectUI();
    refreshScanProjects();   // 打开弹窗时刷新已有 Checkmarx One 项目列表
    if (scanPaths().length) refreshScanBranches();
  }
  function closeModals() {
    if (scanState.minimized) { scanState.minimized = false; hideScanMiniChip(); }
    closeScanBranchMenu();
    closeScanProjectMenu();
    $$('.modal-layer.open').forEach(function (m) { m.classList.remove('open'); });
  }

  function localScanTypes() {
    var types = [];
    if ($('#scanSast') && $('#scanSast').checked) types.push('sast');
    if ($('#scanSca') && $('#scanSca').checked) types.push('sca');
    if ($('#scanIac') && $('#scanIac').checked) types.push('kics');
    return types;
  }

  async function startLocalScan() {
    if (scanState.running) return;
    closeScanBranchMenu();
    closeScanProjectMenu();
    if (!state.session) { toast('请先登录 Checkmarx One', 'err'); return; }
    var rows = $$('#scanFolders [data-folder-row]');
    var folders = [];
    rows.forEach(function (row, i) {
      var path = row.querySelector('.fpath').value.trim();
      if (!path) return;
      var nameInput = row.querySelector('.pname');
      var f = scanState.folders[i] || {};
      var rawName = String(nameInput ? nameInput.value : f.name || '').trim() || baseName(path);
      /* 与已有项目同名（忽略大小写）→ 绑定其 projectId，扫描直接创建在已有项目下；否则按新项目名提交 */
      var matched = findProjectByName(rawName);
      var name = matched ? matched.name : rawName;
      folders.push({ path: path, name: name, projectId: matched ? matched.id : '' });
      f.name = name;
      f.projectId = matched ? matched.id : '';
    });
    if (!folders.length) { toast('请填写至少一个本地文件夹路径', 'err'); return; }
    var types = localScanTypes();
    if (!types.length) { toast('请至少选择一种扫描类型', 'err'); return; }
    /* 记住本次提交的文件夹与项目名：下次打开弹窗自动恢复，并进入「最近扫描」 */
    if (scanState.saveTimer) { clearTimeout(scanState.saveTimer); scanState.saveTimer = null; }
    scanState.memoryLoaded = true;
    var recentTargets = rememberScanTargets(folders);
    if (recentTargets) {
      scanState.recent = recentTargets;
      renderScanRecent();
    }
    /* 多个文件夹指向同一项目：允许（分别创建扫描），但给出提示 */
    var seenNames = {};
    var dupNames = [];
    folders.forEach(function (f) {
      var k = scanProjectNameKey(f.name);
      if (seenNames[k]) { if (dupNames.indexOf(f.name) < 0) dupNames.push(f.name); }
      seenNames[k] = 1;
    });
    if (dupNames.length) toast('注意：多个文件夹指向同一项目：' + dupNames.join('、') + '（将分别创建扫描）', 'info', 4500);
    var branchInput = $('#scanBranch');
    /* 分支为空时回退到自动读取的默认分支（回退默认），避免空分支提交 */
    var branch = (branchInput && branchInput.value.trim()) || scanState.branchDefault || 'master';
    if (branchInput) branchInput.value = branch;
    scanState.running = true;
    scanState.miniState = 'running';
    scanState.createdProjectIds = [];
    scanState.createdBranch = branch;
    localScanSawComplete = false;
    clearScanErrors();
    var btn = $('#startScanBtn');
    setBusy(btn, true, '提交中…');
    var prog = $('#scanProgress');
    prog.innerHTML = folders.map(function (f, i) {
      return '<div class="scan-prog-row" data-prog="' + i + '"><span class="pname2" title="' + esc(f.path) + '">' + esc(f.name) + '</span>' +
        '<span class="bar"><i class="indeterminate" style="width:12%"></i></span><span class="st">调用 CLI 创建扫描…</span></div>';
    }).join('');
    var summaryEl = $('#scanSummary');
    if (summaryEl) { summaryEl.classList.add('hidden'); summaryEl.innerHTML = ''; }
    updateScanMiniChip();
    try {
      var res = await proxyJson('/local-scan', {
        apiBase: state.session.apiBase,
        accessToken: state.session.accessToken,
        apiKey: state.session.apiKey,
        realmUrl: state.session.realmUrl,
        tenant: state.session.tenant,
        folders: folders,
        branch: branch,
        scanTypes: types
      });
      var scans = (res && res.scans) || [];
      var ok = scans.filter(function (s) { return s.ok; });
      var failed = scans.filter(function (s) { return !s.ok; });
      scanState.createdProjectIds = ok.map(function (s) { return s.projectId; }).filter(Boolean);
      scans.forEach(function (s, i) {
        var row = prog.querySelector('[data-prog="' + i + '"]');
        if (!row) return;
        var folder = folders[i] || {};
        if (!s.ok) {
          row.dataset.failed = '1';
          row.classList.add('done');
          row.querySelector('.st').textContent = '失败（详见下方）';
          row.querySelector('.bar > i').classList.remove('indeterminate');
          row.querySelector('.bar > i').style.width = '100%';
          row.querySelector('.bar > i').style.background = 'var(--high)';
          addScanError(folder.name || s.projectName || ('文件夹 ' + (i + 1)), folder.path, s.error || '未知错误');
        } else {
          row.querySelector('.st').textContent = '已创建扫描 ' + String(s.scanId).slice(0, 8) + '… 等待执行';
          row.dataset.scanId = s.scanId;
          pollLocalScan(s.scanId, row);
        }
      });
      updateScanMiniChip();
      if (!ok.length) {
        scanState.running = false;
        scanState.miniState = 'err';
        setBusy(btn, false, '重新扫描');
        toast('本地扫描创建失败，请查看弹窗下方失败详情', 'err', 5000);
        updateScanMiniChip();
        return;
      }
      toast('已创建 ' + ok.length + ' 个扫描，正在轮询进度…', 'info', 3000);
      if (failed.length) toast(failed.length + ' 个文件夹创建扫描失败，详见下方失败详情', 'err', 7000);
    } catch (e) {
      scanState.running = false;
      scanState.miniState = 'err';
      setBusy(btn, false, '重新扫描');
      toast('本地扫描失败：' + e.message, 'err', 6000);
      addScanError('提交失败', folders.map(function (f) { return f.path; }).join('、'), e.message);
      prog.innerHTML = '<div class="scan-prog-row" data-prog="0"><span class="pname2">提交失败</span>' +
        '<span class="bar"><i style="width:100%;background:var(--high)"></i></span><span class="st" title="详见下方失败详情">详见下方</span></div>';
      updateScanMiniChip();
    }
  }

  function pollLocalScan(scanId, row) {
    if (scanState.pollers[scanId]) return;
    var timer = setInterval(async function () {
      try {
        var scan = await apiGet('/api/scans/' + encodeURIComponent(scanId));
        var st = row.querySelector('.st');
        var bar = row.querySelector('.bar > i');
        if (!scan) return;
        var status = scan.status || 'Unknown';
        if (status === 'Completed' || status === 'Partial') {
          clearInterval(timer); delete scanState.pollers[scanId];
          row.classList.add('done');
          st.textContent = '完成';
          bar.classList.remove('indeterminate');
          bar.style.width = '100%';
          bar.style.background = 'var(--ok)';
          updateScanMiniChip();
          onLocalScanProgress();
        } else if (status === 'Failed' || status === 'Canceled') {
          clearInterval(timer); delete scanState.pollers[scanId];
          row.dataset.failed = '1';
          row.classList.add('done');
          st.textContent = '失败（详见下方）';
          bar.classList.remove('indeterminate');
          bar.style.width = '100%';
          bar.style.background = 'var(--high)';
          var nameEl = row.querySelector('.pname2');
          addScanError(nameEl ? nameEl.textContent : ('扫描 ' + String(scanId).slice(0, 8)), '',
            '扫描状态 ' + status + '（扫描 ID ' + scanId + '）');
          updateScanMiniChip();
          onLocalScanProgress();
        } else {
          st.textContent = status === 'Queued' ? '排队中…' : status === 'Running' ? '扫描中…' : status + '…';
          updateScanMiniChip();
        }
      } catch (e) {
        row.querySelector('.st').textContent = '状态查询失败，稍后重试';
      }
    }, 2500);
    scanState.pollers[scanId] = timer;
    setTimeout(function () {
      if (!scanState.pollers[scanId]) return;
      if (!document.body.contains(row)) { clearInterval(scanState.pollers[scanId]); delete scanState.pollers[scanId]; return; }
      clearInterval(scanState.pollers[scanId]); delete scanState.pollers[scanId];
      row.dataset.failed = '1';
      row.classList.add('done');
      row.querySelector('.st').textContent = '轮询超时，可刷新查看结果';
      addScanError(row.querySelector('.pname2') ? row.querySelector('.pname2').textContent : ('扫描 ' + String(scanId).slice(0, 8)),
        '', '轮询超时（45 分钟）未拿到最终状态（扫描 ID ' + scanId + '）');
      updateScanMiniChip();
      onLocalScanProgress();
    }, 45 * 60 * 1000);
  }

  var localScanSawComplete = false;
  function onLocalScanProgress() {
    var rows = $$('#scanProgress [data-prog]');
    if (!rows.length) return;
    var pending = rows.filter(function (r) { return !r.classList.contains('done'); });
    if (pending.length) { updateScanMiniChip(); return; }
    if (localScanSawComplete) return;
    localScanSawComplete = true;
    scanState.running = false;
    var failed = rows.filter(function (r) { return r.dataset.failed === '1'; });
    scanState.miniState = failed.length ? 'err' : 'done';
    var btn = $('#startScanBtn');
    if (btn) setBusy(btn, false, '重新扫描');
    var summary = $('#scanSummary');
    if (summary) {
      summary.classList.remove('hidden');
      summary.style.background = failed.length ? 'var(--high-soft)' : '';
      summary.style.color = failed.length ? 'var(--high)' : '';
      if (failed.length) {
        summary.innerHTML = '⚠ 部分扫描未完成（成功 ' + (rows.length - failed.length) + ' / 失败 ' + failed.length + '）' +
          '<span class="sub">失败详情见上方错误块，可复制后排查</span>' +
          '<span class="spacer" style="flex:1"></span>' +
          '<button class="btn sm" id="viewLocalResultsBtn">查看已完成结果</button>';
      } else {
        summary.innerHTML = '✓ 本地扫描已完成' +
          '<span class="sub">（扫描 ID：' + rows.map(function (r) { return String(r.dataset.scanId || '').slice(0, 8); }).join('、') + '）</span>' +
          '<span class="spacer" style="flex:1"></span>' +
          '<button class="btn sm primary" id="viewLocalResultsBtn">查看扫描结果</button>';
      }
      var b = $('#viewLocalResultsBtn');
      if (b) b.addEventListener('click', function () { viewLocalScanResults(); });
    }
    updateScanMiniChip();
    if (failed.length) {
      toast('本地扫描结束：' + (rows.length - failed.length) + ' 个成功、' + failed.length + ' 个失败，失败详情见弹窗下方', 'err', 6000);
    } else {
      toast(scanState.minimized ? '本地扫描已完成，点击左下角浮动条恢复弹窗查看结果' : '本地扫描完成，点击「查看扫描结果」刷新看板', 'ok', 5000);
    }
  }

  /** 本地扫描完成后：刷新项目列表，并只选中本次扫描对应的项目 */
  async function viewLocalScanResults() {
    scanState.minimized = false;
    hideScanMiniChip();
    closeScanBranchMenu();
    closeScanProjectMenu();
    var modal = $('#scanModal');
    if (modal) modal.classList.remove('open');
    var wanted = (scanState.createdProjectIds || []).slice();
    showLoading('正在刷新项目与扫描结果…');
    try {
      await loadProjects();
      var existing = {};
      state.projects.forEach(function (p) { existing[p.id] = 1; });
      wanted = wanted.filter(function (id) { return existing[id]; });
      if (wanted.length) {
        state.selectedProjectIds = new Set(wanted);
        state.draftProjectIds = new Set(wanted);
      }
      /* 本地扫描项目一个都没匹配到时保持当前选择（空选则显示「请先选择项目」引导） */
      state.branch = '';
      state.scanKey = '';
      updateProjectUI();
      var errors = await loadScansForSelected();
      if (errors && errors.length) toast('部分项目扫描加载失败：' + errors.join('；'), 'err', 5000);
      updateFilterOptions();
      var loaded = await loadResults();
      if (loaded !== false) saveFilterMemory();
      var localNames = [];
      wanted.forEach(function (id) { var p = projectById(id); if (p) localNames.push(p.name); });
      if (localNames.length) toast('已切换到本地扫描项目：' + localNames.join('、'), 'ok', 3000);
    } catch (e) {
      hideLoading();
      showTableError('刷新本地扫描结果失败：' + e.message);
    }
  }

  /* ---------------------------------------------------------------------- */
  /** 按记忆恢复项目/分支/严重级别选择：剔除已失效项目；无有效记忆则回退默认（不选项目 + 全部级别）。 */
  function restoreSelectionFromMemory(memory) {
    var ids = (memory && memory.projectIds) || [];
    var valid = ids.filter(function (id) { return !!projectById(id); });
    state.selectedProjectIds = new Set(valid);
    state.draftProjectIds = new Set(valid);
    state.scanKey = '';
    state.branch = (memory && memory.branch) || '';
    state.sevs = new Set((memory && memory.sevs) || SEVS);
  }

  async function refreshAll(keepSelection) {
    if (!state.session) return;
    var reqId = ++state.requestId;
    try {
      showLoading('正在加载项目…');
      await loadProjects();
      if (reqId !== state.requestId) return;

      var restored = null;
      if (!keepSelection || !state.selectedProjectIds.size) {
        /* 登录/重新连接/刷新且当前为空时：按上一次「应用」的项目+分支+严重级别恢复；没有记忆就一个都不选 */
        restored = loadFilterMemory();
        restoreSelectionFromMemory(restored);
      }
      updateProjectUI();

      if (!state.selectedProjectIds.size) {
        /* 空选：不请求 scans/results，直接展示「请先选择项目」引导 */
        state.scans = [];
        state.results = [];
        state.rows = [];
        state.scanKey = '';
        state.branch = '';
        updateFilterOptions();
        updateSeverityUI();
        renderTable('no-project');
        hideLoading();
        return;
      }

      showLoading('正在加载所选项目的扫描…');
      var errors = await loadScansForSelected();
      if (reqId !== state.requestId) return;
      if (errors && errors.length) toast('部分项目扫描加载失败：' + errors.join('；'), 'err', 5000);
      if (state.branch && !state.scans.some(function (s) { return s.branch === state.branch; })) state.branch = '';
      updateFilterOptions();
      var loaded = await loadResults();
      if (restored && loaded !== false) saveFilterMemory(); // 恢复完成后回写，顺带修正失效项目/分支
    } catch (e) {
      hideLoading();
      showTableError('加载失败：' + e.message);
      if (e.status === 401) toast('登录已过期，请重新登录', 'err', 4000);
    }
  }

  async function reloadScansAndResults() {
    if (!state.session) return;
    showLoading('正在加载所选项目的扫描…');
    try {
      await loadScansForSelected();
      if (state.branch && !state.scans.some(function (s) { return s.branch === state.branch; })) state.branch = '';
      updateFilterOptions();
      var loaded = await loadResults();
      if (loaded !== false) saveFilterMemory(); // 数据加载完成后再写入「上一次选择」记忆
    } catch (e) {
      hideLoading();
      showTableError(e.message);
    }
  }

  /* ---------------------------------------------------------------------- */
  /* 项目多选下拉：勾选只改草稿，点「应用」后才关闭下拉并只查询一次            */
  /* ---------------------------------------------------------------------- */
  function projectPickerLabel() {
    var n = state.selectedProjectIds.size;
    var total = state.projects.length;
    if (!n) return '选择项目';
    if (n === 1) return projectName(Array.from(state.selectedProjectIds)[0]);
    if (total && n === total) return '全部项目 (' + n + ')';
    return n + ' 个项目';
  }

  function isProjectMenuOpen() {
    var menu = $('#projectMenu');
    return !!menu && !menu.classList.contains('hidden');
  }

  /** 搜索关键词：去空白、转小写、按空白拆成多个（多关键词为 AND）。 */
  function projectKeywords() {
    var q = String(state.projectQuery || '').trim().toLowerCase();
    return q ? q.split(/\s+/).filter(Boolean) : [];
  }
  function hasProjectQuery() { return projectKeywords().length > 0; }

  /** 把命中关键词的片段包成 <mark>（先转义再拼接，避免注入）。 */
  function highlightProjectName(name, kws) {
    var raw = String(name == null ? '' : name);
    if (!kws.length) return esc(raw);
    var lower = raw.toLowerCase();
    var ranges = [];
    kws.forEach(function (kw) {
      var from = 0, idx;
      while ((idx = lower.indexOf(kw, from)) >= 0) {
        ranges.push([idx, idx + kw.length]);
        from = idx + kw.length;
      }
    });
    if (!ranges.length) return esc(raw);
    ranges.sort(function (a, b) { return a[0] - b[0] || b[1] - a[1]; });
    var merged = [];
    ranges.forEach(function (r) {
      var last = merged[merged.length - 1];
      if (last && r[0] <= last[1]) { if (r[1] > last[1]) last[1] = r[1]; }
      else merged.push([r[0], r[1]]);
    });
    var out = '', pos = 0;
    merged.forEach(function (r) {
      out += esc(raw.slice(pos, r[0])) + '<mark>' + esc(raw.slice(r[0], r[1])) + '</mark>';
      pos = r[1];
    });
    return out + esc(raw.slice(pos));
  }

  function renderProjectMenu() {
    var menu = $('#projectMenu');
    if (!menu) return;
    var all = state.projects;
    var focusInSearch = document.activeElement && document.activeElement.id === 'projectSearchInput';
    menu.innerHTML =
      '<div class="pop-head"><span>选择项目（可多选）</span>' +
        '<span class="links"><button type="button" data-proj-all>全选</button><button type="button" data-proj-none>清空</button></span></div>' +
      '<div class="proj-search">' +
        '<span class="s-icon" aria-hidden="true">🔍</span>' +
        '<input id="projectSearchInput" type="text" autocomplete="off" spellcheck="false" placeholder="搜索项目名称…" aria-label="搜索项目" value="' + esc(state.projectQuery) + '" />' +
        '<button type="button" class="s-clear" data-proj-search-clear title="清除搜索" aria-label="清除搜索">✕</button>' +
      '</div>' +
      '<div class="proj-list">' +
        (all.length ? all.map(function (p) {
          return '<label class="proj-item" data-project="' + esc(p.id) + '" data-name="' + esc(p.name) + '">' +
            '<input type="checkbox" ' + (state.draftProjectIds.has(p.id) ? 'checked' : '') + ' />' +
            '<span class="p-dot" style="background:' + esc(p.color || '#64748b') + '"></span>' +
            '<span class="p-name">' + esc(p.name) + '</span></label>';
        }).join('') : '<div class="proj-empty">暂无可用项目</div>') +
        '<div class="proj-empty no-match" data-proj-no-match hidden></div>' +
      '</div>' +
      '<div class="pop-foot">' +
        '<span class="draft-count" data-draft-count></span>' +
        '<span class="spacer"></span>' +
        '<button class="btn sm ghost" type="button" data-proj-cancel>取消</button>' +
        '<button class="btn sm primary" type="button" data-proj-apply>应用</button>' +
      '</div>';
    applyProjectFilter();
    if (focusInSearch) focusProjectSearch();
  }

  function updateDraftCount() {
    var el = $('#projectMenu [data-draft-count]');
    if (!el) return;
    var text = '已选 ' + state.draftProjectIds.size + ' / ' + state.projects.length + ' 个项目';
    if (hasProjectQuery()) text += ' · 匹配 ' + state.projectMatchCount + ' 个';
    el.textContent = text;
  }

  /** 「全选」按钮文案：有搜索词时只全选命中的项目。 */
  function updateProjectActionLabel() {
    var btn = $('#projectMenu [data-proj-all]');
    if (!btn) return;
    var filtered = hasProjectQuery();
    btn.textContent = filtered ? '全选匹配' : '全选';
    btn.title = filtered ? '全选当前搜索结果中的项目' : '全选全部项目';
  }

  /** 按搜索词过滤项目列表：只切 class / 高亮，不重建 DOM（保留勾选态与输入焦点）。 */
  function applyProjectFilter() {
    var menu = $('#projectMenu');
    if (!menu) return;
    var kws = projectKeywords();
    var shown = 0;
    $$('#projectMenu .proj-item', menu).forEach(function (item) {
      var name = item.getAttribute('data-name') || '';
      var lower = name.toLowerCase();
      var hit = kws.every(function (kw) { return lower.indexOf(kw) >= 0; });
      item.classList.toggle('is-hidden', !hit);
      var nameEl = item.querySelector('.p-name');
      if (nameEl) nameEl.innerHTML = highlightProjectName(name, kws);
      if (hit) shown++;
    });
    state.projectMatchCount = shown;
    var noMatch = menu.querySelector('[data-proj-no-match]');
    if (noMatch) {
      var showNoMatch = kws.length > 0 && shown === 0 && state.projects.length > 0;
      noMatch.hidden = !showNoMatch;
      if (showNoMatch) noMatch.textContent = '没有匹配「' + state.projectQuery.trim() + '」的项目';
    }
    var clearBtn = menu.querySelector('[data-proj-search-clear]');
    if (clearBtn) clearBtn.classList.toggle('hidden', kws.length === 0);
    var list = menu.querySelector('.proj-list');
    if (list) list.scrollTop = 0;
    updateProjectActionLabel();
    updateDraftCount();
  }

  function syncProjectQueryFromInput() {
    var input = $('#projectSearchInput');
    state.projectQuery = input ? input.value : '';
    applyProjectFilter();
  }

  function focusProjectSearch() {
    var input = $('#projectSearchInput');
    if (!input) return;
    try { input.focus({ preventScroll: true }); } catch (e) { input.focus(); }
    try { var n = input.value.length; input.setSelectionRange(n, n); } catch (e) { /* ignore */ }
  }

  function clearProjectSearch() {
    state.projectQuery = '';
    var input = $('#projectSearchInput');
    if (input) input.value = '';
    applyProjectFilter();
    focusProjectSearch();
  }

  /** 全选：只对当前可见（命中搜索）的项目生效，被过滤隐藏的项目保持原有勾选。 */
  function selectVisibleProjects() {
    $$('#projectMenu .proj-item:not(.is-hidden)').forEach(function (item) {
      var id = item.getAttribute('data-project');
      if (!id) return;
      state.draftProjectIds.add(id);
      var cb = item.querySelector('input[type="checkbox"]');
      if (cb) cb.checked = true;
    });
    updateDraftCount();
  }

  /** 清空：清空全部勾选（含被搜索过滤隐藏的项目）。 */
  function clearAllProjectDrafts() {
    state.draftProjectIds = new Set();
    $$('#projectMenu .proj-item input[type="checkbox"]').forEach(function (cb) { cb.checked = false; });
    updateDraftCount();
  }

  function openProjectMenu() {
    if (!state.projects.length) { toast('暂无可选项目', 'err'); return; }
    state.draftProjectIds = new Set(state.selectedProjectIds);
    state.projectQuery = '';
    renderProjectMenu();
    $('#projectMenu').classList.remove('hidden');
    focusProjectSearch();
  }

  /** 关闭下拉并丢弃草稿（点「取消」/ Esc / 点下拉外部时调用）。 */
  function hideProjectMenu() {
    var menu = $('#projectMenu');
    if (menu) menu.classList.add('hidden');
    state.projectQuery = '';
    state.draftProjectIds = new Set(state.selectedProjectIds);
  }

  function updateProjectUI() {
    var btn = $('#projectPickerBtn');
    if (btn) {
      var valEl = btn.querySelector('.val');
      if (valEl) valEl.textContent = projectPickerLabel();
      btn.disabled = !state.projects.length;
    }
    if (isProjectMenuOpen()) renderProjectMenu();
  }

  /** 提交草稿：关闭下拉；选择未变化则什么都不做；空选只展示引导，不请求数据。 */
  function applyDraftProjects() {
    var ids = state.projects.filter(function (p) { return state.draftProjectIds.has(p.id); })
      .map(function (p) { return p.id; });
    var prev = state.selectedProjectIds;
    var changed = ids.length !== prev.size || ids.some(function (id) { return !prev.has(id); });
    hideProjectMenu();
    if (!changed) { updateProjectUI(); return; }
    commitProjectSelection(ids);
  }

  function commitProjectSelection(ids) {
    state.selectedProjectIds = new Set(ids);
    state.draftProjectIds = new Set(ids);
    state.scanKey = '';
    updateProjectUI();
    if (!state.selectedProjectIds.size) {
      /* 用户主动清空：看板进入空状态、不请求数据，并记住“空选” */
      state.scans = [];
      state.results = [];
      state.rows = [];
      state.branch = '';
      updateFilterOptions();
      updateSeverityUI();
      renderTable('no-project');
      hideLoading();
      saveFilterMemory();
      toast('已清空项目选择', 'info', 1600);
      return;
    }
    /* 数据加载完成后才会写入记忆（见 reloadScansAndResults） */
    reloadScansAndResults();
  }

  /** 重置搜索/分支/扫描时间/严重级别（不影响项目选择），有结果后写入记忆。 */
  function resetAllFilters() {
    state.q = ''; state.branch = ''; state.scanKey = '';
    state.sevs = new Set(SEVS);
    if ($('#searchInput')) $('#searchInput').value = '';
    updateFilterOptions();
    saveSeverityMemory(); // 严重级别已恢复默认，立即写入记忆
    loadResults().then(function (loaded) { if (loaded !== false) saveFilterMemory(); });
  }

  function bindEvents() {
    /* 项目下拉：勾选只改草稿（不关闭、不查询），点「应用」才关闭并查询 */
    var pickerBtn = $('#projectPickerBtn');
    var menu = $('#projectMenu');
    if (pickerBtn && menu) {
      pickerBtn.addEventListener('click', function (e) {
        e.stopPropagation();
        if (isProjectMenuOpen()) hideProjectMenu(); else openProjectMenu();
      });
      menu.addEventListener('click', function (e) {
        e.stopPropagation(); // 下拉内部的点击不触发“点外部关闭”
        if (e.target.closest('[data-proj-search-clear]')) { clearProjectSearch(); return; }
        if (e.target.closest('[data-proj-all]')) { selectVisibleProjects(); return; }
        if (e.target.closest('[data-proj-none]')) { clearAllProjectDrafts(); return; }
        if (e.target.closest('[data-proj-cancel]')) { hideProjectMenu(); return; }
        if (e.target.closest('[data-proj-apply]')) { applyDraftProjects(); return; }
      });
      /* 项目搜索：纯前端过滤（不查询数据）；输入法组词期间先不过滤 */
      menu.addEventListener('input', function (e) {
        if (!e.target || e.target.id !== 'projectSearchInput') return;
        if (e.isComposing) return;
        syncProjectQueryFromInput();
      });
      menu.addEventListener('compositionend', function (e) {
        if (e.target && e.target.id === 'projectSearchInput') syncProjectQueryFromInput();
      });
      /* Esc：焦点在搜索框时先清搜索词，再关闭下拉（阻止冒泡，避免全局 Esc 直接关下拉） */
      menu.addEventListener('keydown', function (e) {
        if (e.key !== 'Escape' || !e.target || e.target.id !== 'projectSearchInput') return;
        e.preventDefault();
        e.stopPropagation();
        /* 以输入框里是否有文本为准（纯空格也算「有内容」，先清掉再按第二次才关闭） */
        if (e.target.value || state.projectQuery) clearProjectSearch(); else hideProjectMenu();
      });
      /* 点击下拉外部 = 取消本次勾选（不隐藏后立即查询） */
      document.addEventListener('click', function () { if (isProjectMenuOpen()) hideProjectMenu(); });
      menu.addEventListener('change', function (e) {
        var item = e.target.closest('[data-project]');
        if (!item) return;
        var id = item.getAttribute('data-project');
        if (e.target.checked) state.draftProjectIds.add(id);
        else state.draftProjectIds.delete(id);
        updateDraftCount();
      });
    }
    /* 重新选择分支：重新拉取所选项目的扫描数据，刷新「分支」「扫描时间」下拉后加载结果 */
    $('#branchSelect').addEventListener('change', async function (e) {
      var sel = e.target;
      state.branch = sel.value;
      state.scanKey = '';
      var token = ++state.branchReloadSeq;
      sel.disabled = true;
      showLoading('正在按分支重新加载扫描…');
      try {
        var errors = await loadScansForSelected();
        if (token !== state.branchReloadSeq) return;
        if (errors && errors.length) toast('部分项目扫描加载失败：' + errors.join('；'), 'err', 5000);
        if (state.branch && !state.scans.some(function (s) { return s.branch === state.branch; })) state.branch = '';
        updateFilterOptions();
        var loaded = await loadResults();
        if (loaded !== false) saveFilterMemory(); // 有结果之后再写入记忆
      } catch (err) {
        hideLoading();
        toast('重新加载分支扫描失败：' + err.message, 'err', 5000);
      } finally {
        if (token === state.branchReloadSeq) updateFilterOptions();
      }
    });
    $('#scanSelect').addEventListener('change', function (e) {
      state.scanKey = e.target.value;
      loadResults();
    });
    $('#searchInput').addEventListener('input', debounce(function (e) {
      state.q = e.target.value;
      renderAll();
    }, 150));
    $('#resetFilters') && $('#resetFilters').addEventListener('click', resetAllFilters);
    $('#resetFiltersBtn') && $('#resetFiltersBtn').addEventListener('click', resetAllFilters);
    $$('[data-sev]').forEach(function (el) {
      el.addEventListener('click', function () {
        var sev = el.getAttribute('data-sev');
        var next = new Set(state.sevs);
        if (next.has(sev)) {
          if (next.size === 1) { toast('至少保留一个严重级别', 'err'); return; }
          next.delete(sev);
        } else next.add(sev);
        state.sevs = next;
        renderAll();
        saveSeverityMemory(); // 立即记住等级选择，下次打开/刷新自动恢复
      });
    });
    $('#refreshBtn').addEventListener('click', function () { refreshAll(true); });
    $('#exportBtn').addEventListener('click', exportCsv);
    $('#settingsBtn').addEventListener('click', openSettings);
    $('#localScanBtn').addEventListener('click', openScan);
    $('#openLinkBtn').addEventListener('click', openLinkModal);
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') {
        var openModal = $$('.modal-layer.open').pop();
        if (openModal) {
          /* 扫描弹窗：扫描进行中按 Esc / 关闭 = 最小化，不中断扫描 */
          if (openModal.id === 'scanModal') closeScanModal();
          else openModal.classList.remove('open');
          return;
        }
        if (isProjectMenuOpen()) { hideProjectMenu(); return; }
        closeDetail();
        return;
      }
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        if (findRowIndex() >= 0) { e.preventDefault(); navigateDetail(e.key === 'ArrowUp' ? 'prev' : 'next'); }
      }
    });
    /* 页面框选复制（Ctrl+C / 右键复制）也走同一套规范化：
       页面显示不变，但写进剪贴板的纯文本使用标准空格与标准换行，不混入特殊空白字符。 */
    document.addEventListener('copy', function (e) {
      if (!e.clipboardData) return;
      var sel = window.getSelection ? window.getSelection() : null;
      if (!sel || sel.isCollapsed || !sel.rangeCount) return;
      var raw = sel.toString();
      if (!raw) return;
      var clean = normalizeCopyText(raw);
      if (clean === raw) return;
      e.clipboardData.setData('text/plain', clean);
      e.preventDefault();
    });
  }

  /* ---------------------------------------------------------------------- */
  function exportCsv() {
    var rows = state.rows;
    if (!rows.length) { toast('当前没有可导出的数据', 'err'); return; }
    var head = ['严重级别', '漏洞类型', 'CWE', '语言', '项目', '分支', '文件', '行', '状态', '标记', '发现时间', '扫描ID'];
    function q(v) { return '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"'; }
    var lines = [head.map(q).join(',')];
    rows.forEach(function (r) {
      lines.push([r.severity, r.queryName, 'CWE-' + (r.cwe || ''), r.language, rName(r), r.branch,
        r.fileName, r.line, STATE_LABEL[r.state] || r.state, STATUS_LABEL[r.status] || r.status, fmtDate(r.foundAt), r.scanId].map(q).join(','));
    });
    var blob = new Blob(['\ufeff' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'checkmarx-findings.csv';
    document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 300);
    toast('已导出 ' + rows.length + ' 条漏洞（CSV）', 'ok', 2000);
  }

  /* ---------------------------------------------------------------------- */
  async function init() {
    mountLogin();
    mountDetailShell();
    bindEvents();
    connUI();
    var cfg = loadConfig();
    if (cfg.apiKey) {
      var input = $('#apiKeyInput');
      if (input) input.value = cfg.apiKey;
      await doLogin(true, cfg.apiKey);
    }
    /* 代理可用性提示（演示模式无需代理） */
    if (!window.CX_DEMO_MOCK) {
      try {
        await fetch(proxyBase() + '/health', { method: 'GET' });
      } catch (e) {
        var hint = $('#loginProxyHint');
        if (hint) hint.innerHTML = '⚠️ 无法连接本地代理 <code>' + esc(proxyBase() || location.origin) + '</code>。请先在本机运行 <code>python proxy.py</code>，然后通过 <code>http://127.0.0.1:8787/</code> 打开本页面。';
      }
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();