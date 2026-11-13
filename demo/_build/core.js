/* ==========================================================================
   Checkmarx 漏洞看板 · 共用交互逻辑（三套 Demo 共用）
   数据来自 window.MOCK（由构建脚本注入），布局差异由各 Demo 的 CSS 决定。
   ========================================================================== */
(function () {
  'use strict';

  var MOCK = window.MOCK;
  if (!MOCK) { console.error('缺少 window.MOCK 演示数据'); return; }

  /* ----------------------------------------------------------------------
     配置 & 基础工具
     ---------------------------------------------------------------------- */
  var CFG = Object.assign({
    brand: 'CxScope',
    title: 'Checkmarx 漏洞看板',
    product: 'Checkmarx One',
    detailMode: 'drawer',        // drawer | inspector | modal
    defaultProjects: null,       // null = 全部项目
    autoLogin: false,
    theme: 'light',
    subtitle: 'SAST 漏洞统一看板'
  }, window.CX_DEMO || {});

  document.body.setAttribute('data-theme', CFG.theme === 'dark' ? 'dark' : 'light');

  var DEMO_NOW = new Date('2026-11-02T12:00:00+08:00').getTime();
  var SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  var SEV_LABEL = { CRITICAL: '严重', HIGH: '高危', MEDIUM: '中危', LOW: '低危', INFO: '信息' };
  var STATE_LABEL = { TO_VERIFY: '待确认', CONFIRMED: '已确认', IGNORED: '已忽略', URGENT: '紧急' };
  var STATUS_LABEL = { NEW: '新增', RECURRENT: '复现', FIXED: '已修复' };
  var TABLE_COLS = [
    { key: 'severity', label: '严重级别', width: '96px' },
    { key: 'query', label: '漏洞类型' },
    { key: 'project', label: '项目' },
    { key: 'file', label: '文件 / 行' },
    { key: 'state', label: '状态' },
    { key: 'found', label: '发现时间', width: '110px' }
  ];

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function pad(n) { return n < 10 ? '0' + n : String(n); }
  function fmtDate(iso) {
    if (!iso) return '—';
    var d = new Date(iso);
    if (isNaN(d)) return String(iso);
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }
  function relTime(iso) {
    if (!iso) return '—';
    var t = new Date(iso).getTime();
    if (isNaN(t)) return '—';
    var diff = Math.max(0, DEMO_NOW - t);
    var min = Math.round(diff / 60000);
    if (min < 1) return '刚刚';
    if (min < 60) return min + ' 分钟前';
    var h = Math.round(min / 60);
    if (h < 24) return h + ' 小时前';
    var d = Math.round(h / 24);
    if (d < 30) return d + ' 天前';
    return fmtDate(iso).slice(0, 10);
  }
  function sevRank(s) { return SEV_ORDER[s] == null ? 9 : SEV_ORDER[s]; }
  function isWideDetail() { return CFG.detailMode === 'modal'; }

  /* ----------------------------------------------------------------------
     索引
     ---------------------------------------------------------------------- */
  var projectById = {}, scanById = {};
  function reindex() {
    projectById = {};
    scanById = {};
    MOCK.projects.forEach(function (p) { projectById[p.id] = p; });
    MOCK.scans.forEach(function (s) { scanById[s.id] = s; });
  }
  reindex();

  function projectName(id) { return (projectById[id] || {}).name || '—'; }
  function projectColor(id) { return (projectById[id] || {}).color || '#64748b'; }
  function scanOf(f) { return scanById[f.scanId] || {}; }
  function branchOf(f) { return scanOf(f).branch || '—'; }
  function scanTimeOf(f) { return fmtDate(scanOf(f).createdAt); }

  /* ----------------------------------------------------------------------
     状态
     ---------------------------------------------------------------------- */
  var ALL_SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  var state = {
    loggedIn: false,
    projects: new Set(CFG.defaultProjects || MOCK.projects.map(function (p) { return p.id; })),
    branch: '',
    scanId: '',
    sevs: new Set(ALL_SEVS),
    q: '',
    sort: { key: 'severity', dir: 1 },
    selectedId: null,
    rows: [],
    localProjects: []
  };

  /* ----------------------------------------------------------------------
     Toast
     ---------------------------------------------------------------------- */
  function toast(msg, type, ms) {
    var stack = $('#toastStack');
    if (!stack) {
      stack = document.createElement('div');
      stack.className = 'toast-stack';
      stack.id = 'toastStack';
      document.body.appendChild(stack);
    }
    var el = document.createElement('div');
    el.className = 'toast ' + (type || 'info');
    el.innerHTML = (type === 'ok' ? '✓ ' : type === 'err' ? '⚠ ' : 'ℹ️ ') + esc(msg);
    stack.appendChild(el);
    setTimeout(function () {
      el.classList.add('leaving');
      setTimeout(function () { el.remove(); }, 220);
    }, ms || 2600);
  }

  /* ----------------------------------------------------------------------
     数据查询
     ---------------------------------------------------------------------- */
  function ctxFindings() {
    return MOCK.findings.filter(function (f) {
      if (!state.projects.has(f.projectId)) return false;
      if (state.branch && branchOf(f) !== state.branch) return false;
      if (state.scanId && f.scanId !== state.scanId) return false;
      return true;
    });
  }
  function withSearch(list) {
    var q = state.q.trim().toLowerCase();
    if (!q) return list;
    return list.filter(function (f) {
      var hay = [f.queryName, f.cweName, f.file, 'cwe-' + f.cwe, f.groupName, f.language, f.description, projectName(f.projectId)].join(' ').toLowerCase();
      return hay.indexOf(q) >= 0;
    });
  }
  function currentRows() {
    var list = withSearch(ctxFindings()).filter(function (f) { return state.sevs.has(f.severity); });
    list.sort(function (a, b) {
      var va, vb, dir = state.sort.dir;
      if (state.sort.key === 'severity') { va = sevRank(a.severity); vb = sevRank(b.severity); }
      else if (state.sort.key === 'found') { va = a.foundAt; vb = b.foundAt; }
      else if (state.sort.key === 'query') { va = a.queryName; vb = b.queryName; }
      else if (state.sort.key === 'project') { va = projectName(a.projectId); vb = projectName(b.projectId); }
      else if (state.sort.key === 'file') { va = a.file; vb = b.file; }
      else if (state.sort.key === 'state') { va = a.state; vb = b.state; }
      else { va = a.id; vb = b.id; }
      if (va < vb) return -1 * dir;
      if (va > vb) return 1 * dir;
      return 0;
    });
    return list;
  }
  function findingById(id) {
    for (var i = 0; i < MOCK.findings.length; i++) if (MOCK.findings[i].id === id) return MOCK.findings[i];
    return null;
  }
  function branchesOfSelected() {
    var set = {};
    MOCK.scans.forEach(function (s) { if (state.projects.has(s.projectId)) set[s.branch] = 1; });
    return Object.keys(set).sort();
  }
  function scansOfSelected() {
    var list = MOCK.scans.filter(function (s) {
      if (!state.projects.has(s.projectId)) return false;
      if (state.branch && s.branch !== state.branch) return false;
      return true;
    });
    list.sort(function (a, b) { return new Date(b.createdAt) - new Date(a.createdAt); });
    return list;
  }
  function projectFindingCount(pid) {
    var n = 0;
    MOCK.findings.forEach(function (f) { if (f.projectId === pid) n++; });
    return n;
  }
  function projectRiskCount(pid) {
    var n = 0;
    MOCK.findings.forEach(function (f) {
      if (f.projectId === pid && (f.severity === 'CRITICAL' || f.severity === 'HIGH')) n++;
    });
    return n;
  }

  /* ----------------------------------------------------------------------
     多项目选择 UI
     ---------------------------------------------------------------------- */
  function projItemHtml(p) {
    return '<label class="proj-item" data-project="' + esc(p.id) + '">' +
      '<input type="checkbox" ' + (state.projects.has(p.id) ? 'checked' : '') + ' />' +
      '<span class="p-dot" style="background:' + esc(p.color || '#64748b') + '"></span>' +
      '<span class="p-name">' + esc(p.name) + '</span>' +
      '<span class="p-meta">' + projectFindingCount(p.id) + ' 项</span>' +
      '</label>';
  }

  function updateProjectUI() {
    var ids = MOCK.projects.map(function (p) { return p.id; });
    /* 顶部下拉按钮 */
    var btn = $('#projectPickerBtn');
    if (btn) {
      var labelEl = btn.querySelector('.val') || btn;
      var n = state.projects.size;
      var text;
      if (n === 0) text = '选择项目';
      else if (n === 1) text = projectName(Array.from(state.projects)[0]);
      else if (n === ids.length) text = '全部项目 (' + n + ')';
      else text = n + ' 个项目';
      if (labelEl !== btn) labelEl.textContent = text; else btn.textContent = text;
    }
    /* 下拉菜单 */
    var menu = $('#projectMenu');
    if (menu) {
      menu.innerHTML =
        '<div class="pop-head"><span>选择项目（可多选）</span>' +
        '<span class="links"><button type="button" data-proj-all>全选</button>' +
        '<button type="button" data-proj-none>清空</button></span></div>' +
        MOCK.projects.map(projItemHtml).join('');
    }
    /* 侧边栏项目列表 */
    var list = $('#projectList');
    if (list) list.innerHTML = MOCK.projects.map(projItemHtml).join('');
    /* 顶部项目 Tab（Demo 3） */
    var chips = $('#projectChips');
    if (chips) {
      chips.innerHTML = MOCK.projects.map(function (p) {
        var on = state.projects.has(p.id);
        return '<button type="button" class="proj-tab' + (on ? ' on' : '') + '" data-project-tab="' + esc(p.id) + '">' +
          '<span class="p-dot" style="background:' + esc(p.color || '#64748b') + '"></span>' +
          esc(p.name) +
          '<span class="p-n">' + projectRiskCount(p.id) + '</span></button>';
      }).join('');
    }
  }

  function setProjects(ids, silent) {
    if (!ids.length) { toast('至少需要选择一个项目', 'err'); return; }
    state.projects = new Set(ids);
    if (state.branch && branchesOfSelected().indexOf(state.branch) < 0) state.branch = '';
    if (state.scanId && !scanById[state.scanId]) state.scanId = '';
    updateProjectUI();
    renderFilterOptions();
    renderAll();
    if (!silent) toast('项目范围已更新：' + (ids.length === 1 ? projectName(ids[0]) : ids.length + ' 个项目'), 'info', 1600);
  }

  function toggleProject(id) {
    var ids = Array.from(state.projects);
    var idx = ids.indexOf(id);
    if (idx >= 0) {
      if (ids.length === 1) { toast('至少需要选择一个项目', 'err'); return; }
      ids.splice(idx, 1);
    } else {
      ids.push(id);
    }
    setProjects(ids, true);
  }

  function bindProjectUI() {
    var btn = $('#projectPickerBtn');
    var menu = $('#projectMenu');
    if (btn && menu) {
      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        var open = menu.classList.toggle('open');
        menu.classList.toggle('hidden', !open);
      });
      menu.addEventListener('click', function (e) {
        e.stopPropagation();
        var all = e.target.closest('[data-proj-all]');
        var none = e.target.closest('[data-proj-none]');
        if (all) { setProjects(MOCK.projects.map(function (p) { return p.id; })); return; }
        if (none) { setProjects([MOCK.projects[0].id]); return; }
      });
      document.addEventListener('click', function () { menu.classList.add('hidden'); menu.classList.remove('open'); });
    }
    /* 任意项目勾选/切换（下拉、侧栏、Tab） */
    document.addEventListener('change', function (e) {
      var item = e.target.closest && e.target.closest('[data-project]');
      if (item && e.target.type === 'checkbox') {
        var id = item.getAttribute('data-project');
        var ids = Array.from(state.projects);
        if (e.target.checked) { ids.push(id); } else {
          if (ids.length === 1) { e.target.checked = true; toast('至少需要选择一个项目', 'err'); return; }
          ids = ids.filter(function (x) { return x !== id; });
        }
        setProjects(ids, true);
      }
    });
    document.addEventListener('click', function (e) {
      var tab = e.target.closest && e.target.closest('[data-project-tab]');
      if (tab) toggleProject(tab.getAttribute('data-project-tab'));
    });
  }

  /* ----------------------------------------------------------------------
     筛选栏（分支 / 扫描时间）
     ---------------------------------------------------------------------- */
  function renderFilterOptions() {
    var branchSel = $('#branchSelect');
    if (branchSel) {
      var branches = branchesOfSelected();
      branchSel.innerHTML = '<option value="">全部分支</option>' +
        branches.map(function (b) {
          return '<option value="' + esc(b) + '"' + (state.branch === b ? ' selected' : '') + '>' + esc(b) + '</option>';
        }).join('');
      branchSel.disabled = branches.length === 0;
    }
    var scanSel = $('#scanSelect');
    if (scanSel) {
      var scans = scansOfSelected();
      scanSel.innerHTML = '<option value="">最近一次扫描</option>' +
        scans.map(function (s) {
          return '<option value="' + esc(s.id) + '"' + (state.scanId === s.id ? ' selected' : '') + '>' +
            fmtDate(s.createdAt) + ' · ' + esc(s.branch) + ' · ' + esc(projectName(s.projectId)) + '</option>';
        }).join('');
      scanSel.disabled = scans.length === 0;
    }
  }

  function bindFilterUI() {
    var branchSel = $('#branchSelect');
    if (branchSel) branchSel.addEventListener('change', function () {
      state.branch = branchSel.value;
      state.scanId = '';
      renderFilterOptions();
      renderAll();
    });
    var scanSel = $('#scanSelect');
    if (scanSel) scanSel.addEventListener('change', function () {
      state.scanId = scanSel.value;
      renderAll();
    });
    var search = $('#searchInput');
    if (search) {
      var timer = null;
      search.addEventListener('input', function () {
        clearTimeout(timer);
        timer = setTimeout(function () { state.q = search.value; renderAll(); }, 120);
      });
    }
    var reset = $('#resetFiltersBtn');
    if (reset) reset.addEventListener('click', function () {
      state.q = ''; state.branch = ''; state.scanId = '';
      state.sevs = new Set(ALL_SEVS);
      var s = $('#searchInput'); if (s) s.value = '';
      renderFilterOptions(); renderAll();
      toast('已重置筛选条件', 'info', 1500);
    });
    var exportBtn = $('#exportBtn');
    if (exportBtn) exportBtn.addEventListener('click', exportCsv);
  }

  /* ----------------------------------------------------------------------
     严重级别筛选
     ---------------------------------------------------------------------- */
  function updateSeverityUI() {
    var searchable = withSearch(ctxFindings());
    var counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    searchable.forEach(function (f) { if (counts[f.severity] != null) counts[f.severity]++; });
    $$('[data-sev]').forEach(function (el) {
      var sev = el.getAttribute('data-sev');
      if (ALL_SEVS.indexOf(sev) < 0) return;
      var on = state.sevs.has(sev);
      el.classList.toggle('on', on);
      el.classList.toggle('off', !on);
      el.setAttribute('aria-pressed', on ? 'true' : 'false');
      $$('[data-count]', el).forEach(function (n) { n.textContent = counts[sev]; });
    });
    var totalEl = $('#totalCount');
    if (totalEl) totalEl.textContent = searchable.length;
  }

  function bindSeverityUI() {
    $$('[data-sev]').forEach(function (el) {
      var sev = el.getAttribute('data-sev');
      if (ALL_SEVS.indexOf(sev) < 0) return;
      el.addEventListener('click', function () {
        var next = new Set(state.sevs);
        if (next.has(sev)) {
          if (next.size === 1) { toast('至少保留一个严重级别', 'err'); return; }
          next.delete(sev);
        } else {
          next.add(sev);
        }
        state.sevs = next;
        updateSeverityUI();
        renderTable();
      });
    });
  }

  /* ----------------------------------------------------------------------
     表格
     ---------------------------------------------------------------------- */
  function visibleCols() {
    var showProject = state.projects.size !== 1;
    return TABLE_COLS.filter(function (c) { return c.key !== 'project' || showProject; });
  }

  function renderTable() {
    var cols = visibleCols();
    var head = $('#resultsHead');
    if (head) {
      head.innerHTML = '<tr>' + cols.map(function (c) {
        var sortable = ['severity', 'query', 'file', 'state', 'found'].indexOf(c.key) >= 0;
        var arrow = '';
        if (state.sort.key === c.key) arrow = '<span class="arrow">' + (state.sort.dir > 0 ? '▲' : '▼') + '</span>';
        return '<th' + (sortable ? ' class="sortable" data-sort="' + c.key + '"' : '') +
          (c.width ? ' style="width:' + c.width + '"' : '') + '>' + esc(c.label) + arrow + '</th>';
      }).join('') + '</tr>';
      $$('#resultsHead th[data-sort]').forEach(function (th) {
        th.addEventListener('click', function () {
          var key = th.getAttribute('data-sort');
          if (state.sort.key === key) state.sort.dir *= -1;
          else { state.sort.key = key; state.sort.dir = 1; }
          renderTable();
        });
      });
    }

    state.rows = currentRows();
    var body = $('#resultsBody');
    if (!body) return;
    if (!state.rows.length) {
      body.innerHTML = '<tr class="empty-row"><td colspan="' + cols.length + '">' +
        '<div class="empty-state" style="height:220px"><div class="big">🔍</div>' +
        '<h3>没有匹配的漏洞</h3><p>调整项目、分支、扫描时间或严重级别筛选条件后再试。</p></div></td></tr>';
    } else {
      body.innerHTML = state.rows.map(function (f) {
        var cells = {
          severity: '<span class="pill sev-' + esc(f.severity) + '">' + esc(f.severity) + '</span>',
          query: '<div class="vuln-name">' + esc(f.queryName) + '</div>' +
            '<div class="vuln-sub"><span class="mono">CWE-' + esc(f.cwe) + '</span><span>·</span><span>' + esc(f.language) + '</span>' +
            (f.status === 'RECURRENT' ? '<span class="pill status st-RECURRENT">复现</span>' : '') + '</div>',
          project: '<span class="proj-cell"><i class="sev-dot" style="background:' + esc(projectColor(f.projectId)) + '"></i>' + esc(projectName(f.projectId)) + '</span>',
          file: '<div class="file-cell" title="' + esc(f.file) + '">' + esc(f.file.split('/').slice(-2).join('/')) + '<i>:' + esc(f.line) + '</i></div>',
          state: '<span class="pill state st-' + esc(f.state) + '">' + esc(STATE_LABEL[f.state] || f.state) + '</span>',
          found: '<span title="' + esc(fmtDate(f.foundAt)) + '">' + esc(relTime(f.foundAt)) + '</span>'
        };
        return '<tr data-id="' + esc(f.id) + '"' + (state.selectedId === f.id ? ' class="selected"' : '') + '>' +
          cols.map(function (c) { return '<td>' + (cells[c.key] || '') + '</td>'; }).join('') + '</tr>';
      }).join('');
      $$('#resultsBody tr[data-id]').forEach(function (tr) {
        tr.addEventListener('click', function () {
          var id = tr.getAttribute('data-id');
          if (state.selectedId === id && CFG.detailMode !== 'inspector') { closeDetail(); return; }
          openDetail(id);
        });
      });
    }

    var countEl = $('#resultCount');
    if (countEl) {
      var total = withSearch(ctxFindings()).length;
      countEl.textContent = state.rows.length === total
        ? '共 ' + total + ' 个漏洞'
        : '筛选出 ' + state.rows.length + ' / ' + total + ' 个漏洞';
    }
  }

  function renderAll() {
    updateSeverityUI();
    renderTable();
    if (state.selectedId) {
      var f = findingById(state.selectedId);
      if (!f || state.rows.indexOf(f) < 0) {
        if (CFG.detailMode === 'inspector') { state.selectedId = null; closeDetail(); }
      }
    }
    updateDetailNav();
  }

  /* ----------------------------------------------------------------------
     漏洞详情
     ---------------------------------------------------------------------- */
  function metaItem(k, v, mono) {
    return '<div class="m"><div class="k">' + esc(k) + '</div><div class="v' + (mono ? ' mono' : '') + '" title="' + esc(v) + '">' + esc(v) + '</div></div>';
  }

  function detailHtml(f) {
    var rem = f.remediation || {};
    var refs = rem.refs || [];
    var examples = rem.examples || [];
    var wide = isWideDetail();

    var cmp = examples.map(function (ex) {
      return '<div class="cmp-title" style="font-size:12px;font-weight:650;color:var(--text-2);margin:10px 0 6px;display:flex;gap:8px;align-items:center">' +
        esc(ex.title) + '<span class="badge-soft">' + esc(ex.lang || '') + '</span></div>' +
        '<div class="' + (wide ? 'cmp-grid' : 'cmp') + '">' +
        '<div class="code-card bad"><div class="c-head"><span class="t">✗ 错误示例</span><span class="lang">before</span></div><pre>' + esc(ex.bad) + '</pre></div>' +
        '<div class="code-card good"><div class="c-head"><span class="t">✓ 修复后</span><span class="lang">after</span></div><pre>' + esc(ex.good) + '</pre></div>' +
        '</div>';
    }).join('');

    var flow = (f.dataFlow || []).map(function (n, i) {
      return '<li class="flow-step" data-label="' + esc(n.label) + '">' +
        '<span class="node">' + (i + 1) + '</span>' +
        '<div class="fl-head"><span class="fl-file">' + esc(n.file) + '</span><span class="fl-line">:' + esc(n.line) + '</span>' +
        '<span class="fl-tag">' + esc(n.label) + '</span></div>' +
        '<code>' + esc(n.code) + '</code></li>';
    }).join('');

    var payload = f.payload ?
      '<div class="payload"><div class="p-head"><span>攻击示例 / payload</span>' +
      '<button type="button" class="btn ghost sm" data-copy-payload>复制</button></div>' +
      '<pre>' + esc(f.payload) + '</pre></div>' : '';

    return '' +
      '<div class="dt-head">' +
      '<div class="dt-title-row"><div>' +
      '<div class="dt-title">' + esc(f.queryName) + '</div>' +
      '<div class="dt-sub"><span>' + esc(f.groupName) + '</span><span>·</span><span>' + esc(f.language) + '</span>' +
      '<span>·</span><span>' + esc(projectName(f.projectId)) + '</span></div>' +
      '</div></div>' +
      '<div class="dt-badges">' +
      '<span class="pill sev-' + esc(f.severity) + '">' + esc(f.severity) + ' · ' + esc(SEV_LABEL[f.severity] || '') + '</span>' +
      '<span class="pill state st-' + esc(f.state) + '">' + esc(STATE_LABEL[f.state] || f.state) + '</span>' +
      '<span class="pill status st-' + esc(f.status) + '">' + esc(STATUS_LABEL[f.status] || f.status) + '</span>' +
      '<span class="badge-soft">CWE-' + esc(f.cwe) + ' ' + esc(f.cweName || '') + '</span>' +
      '</div></div>' +
      '<div class="dt-meta">' +
      metaItem('项目', projectName(f.projectId)) +
      metaItem('分支', branchOf(f)) +
      metaItem('扫描时间', scanTimeOf(f)) +
      metaItem('扫描 ID', scanOf(f).id || f.scanId, true) +
      metaItem('文件', f.file, true) +
      metaItem('行 / 列', f.line + ' : ' + (f.column || 1)) +
      metaItem('首次发现', fmtDate(f.foundAt)) +
      metaItem('结果 ID', f.id, true) +
      '</div>' +
      '<div class="dt-body">' +
      '<section class="dt-sec"><h4>漏洞说明 <span class="en">description</span></h4><p>' + esc(f.description) + '</p></section>' +
      '<section class="dt-sec"><h4>攻击向量 <span class="en">attack vector</span></h4><p>' + esc(f.attackVector) + '</p>' + payload + '</section>' +
      (flow ? '<section class="dt-sec"><h4>污点数据流 <span class="en">data flow</span><span class="count">' + (f.dataFlow || []).length + ' 步</span></h4><ol class="flow">' + flow + '</ol></section>' :
        '<section class="dt-sec"><h4>污点数据流 <span class="en">data flow</span></h4><p class="hint">该结果由配置类检查产生，无数据流信息。</p></section>') +
      '<section class="dt-sec"><h4>修复建议 <span class="en">remediation</span></h4><p>' + esc(rem.summary || '') + '</p>' + cmp + '</section>' +
      '<section class="dt-sec"><h4>参考链接 <span class="en">learn more</span></h4><ul class="refs">' +
      refs.map(function (r) {
        return '<li><a href="' + esc(r.url) + '" target="_blank" rel="noopener"><span class="ico">🔗</span><span>' + esc(r.label) + '</span><span class="ext">↗</span></a></li>';
      }).join('') + '</ul></section>' +
      '</div>' +
      '<div class="dt-foot">' +
      '<button class="btn sm" data-dt-act="confirm">✓ 标记已确认</button>' +
      '<button class="btn sm ghost" data-dt-act="ignore">忽略</button>' +
      '<span class="spacer"></span>' +
      '<button class="btn sm ghost" data-dt-act="open-cx">在 Checkmarx 中打开 ↗</button>' +
      '</div>';
  }

  function mountDetailShell() {
    var mode = CFG.detailMode;
    var body = document.body;
    if (mode === 'inspector') {
      var host = $('#inspectorHost') || body;
      host.innerHTML =
        '<aside class="inspector-panel" id="inspectorPanel">' +
        '<div class="insp-top"><span>漏洞详情 · Inspector</span>' +
        '<div class="detail-nav"><span class="pos"></span>' +
        '<button class="icon-btn" data-detail-nav="prev" title="上一个 (↑)">‹</button>' +
        '<button class="icon-btn" data-detail-nav="next" title="下一个 (↓)">›</button>' +
        '<button class="icon-btn" data-close-detail title="关闭">✕</button></div></div>' +
        '<div class="insp-scroll"><div class="inspector-empty" id="detailEmpty">' +
        '<div class="big">🛡️</div><h3>选择一条漏洞查看详情</h3>' +
        '<p>左侧列为当前筛选结果。点击任意一行，这里会展示攻击向量、数据流与修复示例。</p></div>' +
        '<div id="detailContent" class="detail-content"></div></div></aside>';
    } else if (mode === 'drawer') {
      body.insertAdjacentHTML('beforeend',
        '<div class="detail-backdrop" id="detailBackdrop"></div>' +
        '<aside class="detail-drawer" id="detailDrawer" aria-hidden="true">' +
        '<div class="drawer-top"><div class="detail-nav">' +
        '<button class="icon-btn" data-detail-nav="prev" title="上一个">‹</button>' +
        '<span class="pos"></span>' +
        '<button class="icon-btn" data-detail-nav="next" title="下一个">›</button></div>' +
        '<button class="icon-btn" data-close-detail title="关闭 (Esc)">✕</button></div>' +
        '<div class="drawer-scroll"><div id="detailContent" class="detail-content"></div></div></aside>');
    } else {
      body.insertAdjacentHTML('beforeend',
        '<div class="modal-layer detail-modal-layer" id="detailModal">' +
        '<div class="modal"><div class="drawer-top"><div class="detail-nav">' +
        '<button class="icon-btn" data-detail-nav="prev" title="上一个">‹</button>' +
        '<span class="pos"></span>' +
        '<button class="icon-btn" data-detail-nav="next" title="下一个">›</button></div>' +
        '<button class="icon-btn" data-close-detail title="关闭 (Esc)">✕</button></div>' +
        '<div class="detail-modal-scroll"><div id="detailContent" class="detail-content"></div></div></div></div>');
    }
    $('[data-close-detail]') && $$('[data-close-detail]').forEach(function (b) { b.addEventListener('click', closeDetail); });
    $$('[data-detail-nav]').forEach(function (b) {
      b.addEventListener('click', function () { navigateDetail(b.getAttribute('data-detail-nav')); });
    });
    var backdrop = $('#detailBackdrop');
    if (backdrop) backdrop.addEventListener('click', closeDetail);
    var content = $('#detailContent');
    if (content) {
      content.addEventListener('click', function (e) {
        var copy = e.target.closest('[data-copy-payload]');
        if (copy) {
          var pre = copy.closest('.payload').querySelector('pre');
          copyText(pre.textContent);
          return;
        }
        var act = e.target.closest('[data-dt-act]');
        if (act) handleDetailAction(act.getAttribute('data-dt-act'));
      });
    }
  }

  function findRowIndex() {
    if (!state.selectedId) return -1;
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
    var f = findingById(id);
    if (!f) return;
    state.selectedId = id;
    $$('#resultsBody tr[data-id]').forEach(function (tr) {
      tr.classList.toggle('selected', tr.getAttribute('data-id') === id);
    });
    var content = $('#detailContent');
    if (!content) return;
    content.innerHTML = detailHtml(f);
    content.scrollTop = 0;
    var empty = $('#detailEmpty');
    if (empty) empty.classList.add('hidden');
    if (CFG.detailMode === 'drawer') {
      $('#detailDrawer').classList.add('open');
      $('#detailDrawer').setAttribute('aria-hidden', 'false');
      $('#detailBackdrop').classList.add('open');
    } else if (CFG.detailMode === 'modal') {
      $('#detailModal').classList.add('open');
    } else {
      var scroll = content.closest('.insp-scroll');
      if (scroll) scroll.scrollTop = 0;
    }
    updateDetailNav();
  }

  function closeDetail() {
    state.selectedId = null;
    var empty = $('#detailEmpty');
    if (empty) empty.classList.remove('hidden');
    if (CFG.detailMode === 'drawer') {
      var d = $('#detailDrawer'); if (d) { d.classList.remove('open'); d.setAttribute('aria-hidden', 'true'); }
      var b = $('#detailBackdrop'); if (b) b.classList.remove('open');
    } else if (CFG.detailMode === 'modal') {
      var m = $('#detailModal'); if (m) m.classList.remove('open');
    }
    $$('#resultsBody tr[data-id]').forEach(function (tr) { tr.classList.remove('selected'); });
    updateDetailNav();
  }

  function navigateDetail(dir) {
    var idx = findRowIndex();
    if (idx < 0) { if (state.rows.length) openDetail(state.rows[0].id); return; }
    var next = idx + (dir === 'prev' ? -1 : 1);
    if (next < 0 || next >= state.rows.length) return;
    openDetail(state.rows[next].id);
    var selectedRow = $('#resultsBody tr.selected');
    if (selectedRow && selectedRow.scrollIntoView) selectedRow.scrollIntoView({ block: 'nearest' });
  }

  function handleDetailAction(act) {
    var f = findingById(state.selectedId);
    if (!f) return;
    if (act === 'confirm') { f.state = 'CONFIRMED'; toast('已标记为「已确认」（演示）', 'ok', 1800); }
    else if (act === 'ignore') { f.state = 'IGNORED'; toast('已忽略该漏洞（演示）', 'info', 1800); }
    else if (act === 'open-cx') { toast('演示环境：真实版本将跳转 ' + (MOCK.tenant.web || 'https://checkmarx.net') + ' 对应扫描结果', 'info', 2400); return; }
    renderAll();
    openDetail(f.id);
  }

  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { toast('已复制到剪贴板', 'ok', 1500); },
        function () { fallbackCopy(text); });
    } else fallbackCopy(text);
  }
  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); toast('已复制到剪贴板', 'ok', 1500); } catch (e) { toast('复制失败，请手动选择', 'err'); }
    ta.remove();
  }

  /* ----------------------------------------------------------------------
     登录
     ---------------------------------------------------------------------- */
  function connUI() {
    var pill = $('#connPill');
    if (!pill) return;
    if (state.loggedIn) {
      pill.classList.remove('offline');
      pill.innerHTML = '<span class="pulse"></span><span>已连接</span><span class="who">· ' + esc(MOCK.tenant.region.toUpperCase()) + ' / ' + esc(MOCK.tenant.name) + '</span>';
    } else {
      pill.classList.add('offline');
      pill.innerHTML = '<span class="pulse"></span><span>未连接</span>';
    }
  }

  function mountLogin() {
    var overlay = document.createElement('div');
    overlay.className = 'login-overlay';
    overlay.id = 'loginOverlay';
    overlay.innerHTML =
      '<div class="login-card">' +
      '<div class="login-brand"><div class="logo">CX</div><div><div class="bn">' + esc(CFG.brand) + '</div>' +
      '<div class="bs">' + esc(CFG.product) + ' · ' + esc(CFG.subtitle) + '</div></div></div>' +
      '<h1>连接你的 Checkmarx</h1>' +
      '<p class="lead">粘贴 Checkmarx One 的 <b>API Key</b> 即可登录。与 IDEA 插件一致：无需用户名、密码，也不用手动选择区域 —— Key 会自动解析租户与 API 地址。</p>' +
      '<label class="fl">API Key <a href="javascript:void(0)" id="loginHelp">如何获取？</a></label>' +
      '<textarea id="apiKeyInput" spellcheck="false" placeholder="粘贴 API Key（这是演示环境，任意内容均可登录）"></textarea>' +
      '<div class="login-row"><button class="btn primary" id="loginSubmit">登录</button></div>' +
      '<div class="login-error" id="loginError"></div>' +
      '<div class="login-hint"><b>演示说明：</b>当前是静态 Demo，不会发起任何网络请求。真实版本将通过本地代理调用 Checkmarx One API，登录成功后自动隐藏此界面。</div>' +
      '<div class="login-foot">🔒 API Key 仅保存在本机浏览器 · 不经过第三方服务器</div>' +
      '</div>';
    document.body.appendChild(overlay);

    var input = $('#apiKeyInput');
    var err = $('#loginError');
    function doLogin() {
      var v = input.value.trim();
      if (!v) { err.textContent = '请输入 API Key'; input.focus(); return; }
      err.textContent = '';
      var btn = $('#loginSubmit');
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner"></span> 验证并登录…';
      setTimeout(function () { enterApp(false); }, 820);
    }
    $('#loginSubmit').addEventListener('click', doLogin);
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); doLogin(); }
    });
    $('#loginHelp').addEventListener('click', function () {
      toast('Checkmarx One → 设置 → API Keys 生成；IDEA 插件里也是同一个 API Key', 'info', 3600);
    });
    input.focus();
  }

  function enterApp(instant) {
    state.loggedIn = true;
    connUI();
    var overlay = $('#loginOverlay');
    if (overlay) {
      overlay.classList.add('closing');
      setTimeout(function () { overlay.remove(); }, instant ? 0 : 280);
    }
    document.body.classList.remove('locked');
    if (!instant) toast('登录成功 · 已连接 Checkmarx One（演示）', 'ok', 2400);
    if (!state.rows.length) renderAll();
  }

  function showLogin(clear) {
    closeDetail();
    state.loggedIn = false;
    connUI();
    document.body.classList.add('locked');
    if ($('#loginOverlay')) return;
    mountLogin();
    if (clear) { var i = $('#apiKeyInput'); if (i) i.value = ''; }
  }

  /* ----------------------------------------------------------------------
     设置弹窗
     ---------------------------------------------------------------------- */
  function mountSettings() {
    var layer = document.createElement('div');
    layer.className = 'modal-layer';
    layer.id = 'settingsModal';
    layer.innerHTML =
      '<div class="modal" style="width:620px">' +
      '<div class="modal-head"><div><div class="m-title">连接设置</div>' +
      '<div class="m-sub">' + esc(CFG.product) + ' · 使用 API Key 登录（与 IDEA 插件一致）</div></div>' +
      '<button class="icon-btn close" data-close-modal="settingsModal">✕</button></div>' +
      '<div class="modal-body">' +
      '<div class="settings-block">' +
      '<div class="sb-title">API 凭据 <span class="en">credentials</span></div>' +
      '<div class="field"><label>API Key <a href="javascript:void(0)" data-help-key>如何获取？</a></label>' +
      '<div class="secret-wrap"><input type="password" id="settingsKey" spellcheck="false" value="cx_demo_9f7a2c1e8b4d6a0f3e5c7b9d1a2f4e6c">' +
      '<button class="icon-btn eye" id="settingsEye" title="显示/隐藏">👁</button></div></div>' +
      '<div class="parse-grid">' +
      '<div class="pg"><div class="k">区域 Region</div><div class="v">' + esc(MOCK.tenant.region) + '（' + esc(MOCK.tenant.iam) + '）</div></div>' +
      '<div class="pg"><div class="k">租户 Tenant</div><div class="v">' + esc(MOCK.tenant.name) + '</div></div>' +
      '<div class="pg"><div class="k">API 地址</div><div class="v">https://' + esc(MOCK.tenant.api) + '</div></div>' +
      '<div class="pg"><div class="k">登录用户</div><div class="v">' + esc(MOCK.tenant.user) + '</div></div>' +
      '</div>' +
      '<div class="settings-foot">' +
      '<button class="btn sm" id="testConnBtn">测试连接</button>' +
      '<span class="muted" style="font-size:11px">Demo：以上信息由 API Key 自动解析</span>' +
      '<span class="spacer"></span><button class="btn sm primary" id="saveSettingsBtn">保存</button></div>' +
      '</div>' +
      '<div class="settings-block">' +
      '<div class="sb-title">会话 <span class="en">session</span></div>' +
      '<div class="muted" style="font-size:12px;line-height:1.7">已通过 API Key 登录。Token 约 59 分钟后过期，过期后自动用 API Key 换取新 Token；API Key 仅保存在本机浏览器。</div>' +
      '<div class="settings-foot"><button class="btn sm danger" id="logoutBtn">退出登录</button>' +
      '<span class="spacer"></span><span class="muted" style="font-size:11px">注销后将重新显示登录界面</span></div>' +
      '</div>' +
      '</div></div>';
    document.body.appendChild(layer);

    $$('[data-close-modal="settingsModal"]', layer).forEach(function (b) {
      b.addEventListener('click', function () { layer.classList.remove('open'); });
    });
    layer.addEventListener('click', function (e) { if (e.target === layer) layer.classList.remove('open'); });
    $('#settingsEye').addEventListener('click', function () {
      var inp = $('#settingsKey');
      inp.type = inp.type === 'password' ? 'text' : 'password';
    });
    $('#testConnBtn').addEventListener('click', function () {
      var b = $('#testConnBtn');
      b.disabled = true; b.innerHTML = '<span class="spinner"></span> 测试中…';
      setTimeout(function () {
        b.disabled = false; b.textContent = '测试连接';
        toast('连接成功 · Token 有效期 59 分钟（演示）', 'ok', 2400);
      }, 900);
    });
    $('#saveSettingsBtn').addEventListener('click', function () { toast('设置已保存到本机（演示）', 'ok', 1800); });
    var help = layer.querySelector('[data-help-key]');
    if (help) help.addEventListener('click', function () { toast('Checkmarx One → 设置 → API Keys 生成 API Key', 'info', 3200); });
    $('#logoutBtn').addEventListener('click', function () {
      layer.classList.remove('open');
      showLogin(true);
      toast('已退出登录', 'info', 1800);
    });
  }

  function openSettings() {
    var layer = $('#settingsModal');
    if (!layer) { mountSettings(); layer = $('#settingsModal'); }
    layer.classList.add('open');
  }

  /* ----------------------------------------------------------------------
     本地扫描
     ---------------------------------------------------------------------- */
  var scanState = { running: false, folders: [''], results: [] };

  function folderRowHtml(path, idx) {
    return '<div class="scan-folder-row" data-folder-row>' +
      '<span class="idx">' + (idx + 1) + '</span>' +
      '<span class="path-wrap"><input type="text" class="fpath" spellcheck="false" placeholder="E:\\projects\\my-service（或点击浏览）" value="' + esc(path || '') + '">' +
      '<button type="button" class="btn sm browse" data-browse>浏览…</button></span>' +
      '<input type="text" class="pname" spellcheck="false" placeholder="项目名（自动生成）">' +
      '<button type="button" class="icon-btn remove" data-remove-folder title="移除">✕</button>' +
      '</div>';
  }

  function mountScan() {
    var layer = document.createElement('div');
    layer.className = 'modal-layer';
    layer.id = 'scanModal';
    layer.innerHTML =
      '<div class="modal" style="width:820px">' +
      '<div class="modal-head"><div><div class="m-title">本地扫描 · 指定文件夹</div>' +
      '<div class="m-sub">对本地代码文件夹发起 Checkmarx One 扫描，支持一次提交多个项目</div></div>' +
      '<button class="icon-btn close" data-close-modal="scanModal">✕</button></div>' +
      '<div class="modal-body">' +
      '<p class="scan-lead">选择需要扫描的本地文件夹（可添加多个，每个文件夹对应一个 Checkmarx One 项目）。扫描在本地打包后上传，代码不会经过第三方服务器。</p>' +
      '<div class="scan-callout"><span class="i">ⓘ</span><span>演示环境仅模拟扫描流程；真实版本通过本地代理调用 Checkmarx One API / CLI 执行扫描并自动加载结果。</span></div>' +
      '<div class="scan-folder-labels"><span>#</span><span>本地文件夹</span><span>Checkmarx One 项目名</span><span></span></div>' +
      '<div class="scan-folders" id="scanFolders"></div>' +
      '<div class="actions" style="margin-top:9px"><button class="btn sm ghost" id="addFolderBtn">＋ 添加文件夹</button>' +
      '<span class="muted" style="font-size:11px">支持多项目并行扫描</span></div>' +
      '<div class="scan-options">' +
      '<label class="opt">分支 <input type="text" id="scanBranch" value="main"></label>' +
      '<label class="opt"><input type="checkbox" id="scanSast" checked> SAST</label>' +
      '<label class="opt"><input type="checkbox" id="scanSca"> SCA</label>' +
      '<label class="opt"><input type="checkbox" id="scanIac"> IaC</label>' +
      '<label class="opt"><input type="checkbox" id="scanAutoLoad" checked> 完成后自动加载结果</label>' +
      '</div>' +
      '<div class="scan-progress" id="scanProgress"></div>' +
      '<div class="scan-summary hidden" id="scanSummary"></div>' +
      '</div>' +
      '<div class="modal-foot">' +
      '<span class="tip" id="scanTip">扫描时间取决于代码体量，通常 3–10 分钟</span>' +
      '<span class="spacer"></span>' +
      '<button class="btn" data-close-modal="scanModal">取消</button>' +
      '<button class="btn primary" id="startScanBtn">开始扫描</button>' +
      '</div></div>';
    document.body.appendChild(layer);

    $$('[data-close-modal="scanModal"]', layer).forEach(function (b) {
      b.addEventListener('click', function () { if (!scanState.running) layer.classList.remove('open'); else toast('扫描进行中，请等待完成', 'err'); });
    });
    layer.addEventListener('click', function (e) { if (e.target === layer && !scanState.running) layer.classList.remove('open'); });

    function renderFolders() {
      $('#scanFolders').innerHTML = scanState.folders.map(folderRowHtml).join('');
      $$('#scanFolders [data-folder-row]').forEach(function (row, i) {
        var pathInput = row.querySelector('.fpath');
        var nameInput = row.querySelector('.pname');
        pathInput.addEventListener('input', function () {
          scanState.folders[i] = pathInput.value;
          if (!nameInput.value.trim()) nameInput.value = baseName(pathInput.value);
        });
        row.querySelector('[data-browse]').addEventListener('click', function () {
          pickFolder().then(function (name) {
            if (!name) return;
            scanState.folders[i] = name;
            pathInput.value = name;
            if (!nameInput.value.trim()) nameInput.value = baseName(name);
          }).catch(function () {
            toast('当前环境无法读取目录，请手动输入文件夹路径', 'info', 2400);
            pathInput.focus();
          });
        });
        row.querySelector('[data-remove-folder]').addEventListener('click', function () {
          if (scanState.folders.length <= 1) { toast('至少保留一个文件夹', 'err'); return; }
          scanState.folders.splice(i, 1);
          renderFolders();
        });
      });
    }
    renderFolders();

    $('#addFolderBtn').addEventListener('click', function () {
      scanState.folders.push('');
      renderFolders();
      var rows = $$('#scanFolders [data-folder-row]');
      var last = rows[rows.length - 1];
      if (last) last.querySelector('.fpath').focus();
    });

    $('#startScanBtn').addEventListener('click', startScan);
  }

  function baseName(p) {
    if (!p) return '';
    var s = String(p).replace(/[\\/]+$/, '');
    var parts = s.split(/[\\/]/);
    return parts[parts.length - 1] || '';
  }

  function pickFolder() {
    if (window.showDirectoryPicker) {
      return window.showDirectoryPicker().then(function (handle) { return handle.name; });
    }
    return Promise.reject(new Error('unsupported'));
  }

  function openScan() {
    var layer = $('#scanModal');
    if (!layer) { mountScan(); layer = $('#scanModal'); }
    layer.classList.add('open');
  }

  function startScan() {
    if (scanState.running) return;
    var rows = $$('#scanFolders [data-folder-row]');
    var folders = [];
    rows.forEach(function (row) {
      var path = row.querySelector('.fpath').value.trim();
      if (!path) return;
      var name = row.querySelector('.pname').value.trim() || baseName(path);
      folders.push({ path: path, name: name, sev: 0, done: false });
    });
    if (!folders.length) { toast('请先填写至少一个本地文件夹路径', 'err'); return; }
    scanState.running = true;
    var startBtn = $('#startScanBtn');
    startBtn.disabled = true; startBtn.innerHTML = '<span class="spinner"></span> 扫描中…';
    var prog = $('#scanProgress');
    prog.innerHTML = folders.map(function (f, i) {
      return '<div class="scan-prog-row" data-prog="' + i + '">' +
        '<span class="pname2">' + esc(f.name) + '</span>' +
        '<span class="bar"><i style="width:2%"></i></span>' +
        '<span class="st">准备中…</span></div>';
    }).join('');
    var steps = [
      { pct: 18, text: '打包中…' },
      { pct: 42, text: '上传中…' },
      { pct: 66, text: '排队等待扫描…' },
      { pct: 88, text: '扫描中…' },
      { pct: 100, text: '完成' }
    ];
    var doneCount = 0;
    folders.forEach(function (f, i) {
      var row = prog.querySelector('[data-prog="' + i + '"]');
      var bar = row.querySelector('.bar > i');
      var st = row.querySelector('.st');
      var si = 0;
      var delay = 480 + i * 260;
      var tick = setInterval(function () {
        var s = steps[si];
        bar.style.width = s.pct + '%';
        st.textContent = s.text;
        if (s.pct === 100) {
          clearInterval(tick);
          row.classList.add('done');
          doneCount++;
          if (doneCount === folders.length) finishScan(folders);
        }
        si++;
      }, delay + 120);
    });
    scanState.folders = folders.map(function (f) { return f.path; });
    scanState.results = folders;
  }

  function finishScan(folders) {
    scanState.running = false;
    var startBtn = $('#startScanBtn');
    startBtn.disabled = false; startBtn.textContent = '重新扫描';
    var summary = $('#scanSummary');
    var totalFindings = Math.min(MOCK.localScanFindings.length, folders.length * 2);
    summary.classList.remove('hidden');
    summary.innerHTML = '✓ ' + folders.length + ' 个项目扫描完成 · 新增 ' + totalFindings + ' 个漏洞' +
      '<span class="sub">（演示数据）</span>' +
      '<span class="spacer" style="flex:1"></span>' +
      '<button class="btn sm primary" id="loadLocalBtn">查看扫描结果</button>';
    var btn = $('#loadLocalBtn');
    if (btn) btn.addEventListener('click', function () { loadLocalResults(folders); });
    toast('本地扫描完成：' + folders.length + ' 个项目', 'ok', 2400);
    if ($('#scanAutoLoad') && $('#scanAutoLoad').checked) {
      setTimeout(function () { loadLocalResults(folders); }, 800);
    }
  }

  function loadLocalResults(folders) {
    /* 清理上一次本地扫描 */
    state.localProjects.forEach(function (pid) {
      MOCK.projects = MOCK.projects.filter(function (p) { return p.id !== pid; });
      MOCK.scans = MOCK.scans.filter(function (s) { return s.projectId !== pid; });
      MOCK.findings = MOCK.findings.filter(function (f) { return f.projectId !== pid; });
    });
    var addedProjects = [];
    reindex();
    var colors = ['#0ea5e9', '#8b5cf6', '#f59e0b', '#10b981', '#ec4899'];
    folders.forEach(function (f, i) {
      var pid = 'local-' + (i + 1);
      var branch = ($('#scanBranch') && $('#scanBranch').value.trim()) || 'main';
      var scanId = pid + '-scan';
      MOCK.projects.push({ id: pid, name: f.name || ('本地项目 ' + (i + 1)), repo: f.path, team: '本地扫描', color: colors[i % colors.length] });
      MOCK.scans.push({ id: scanId, projectId: pid, branch: branch, createdAt: new Date(DEMO_NOW - i * 3600 * 1000).toISOString(), duration: '—', engine: 'SAST' });
      var picks = MOCK.localScanFindings.filter(function (_, k) { return k % folders.length === i % folders.length; });
      if (!picks.length) picks = [MOCK.localScanFindings[i % MOCK.localScanFindings.length]];
      picks.slice(0, 2).forEach(function (tpl, k) {
        var nf = JSON.parse(JSON.stringify(tpl));
        nf.id = pid + '-f' + k;
        nf.projectId = pid;
        nf.scanId = scanId;
        nf.state = 'TO_VERIFY';
        nf.status = 'NEW';
        nf.foundAt = new Date(DEMO_NOW - (i * 3 + k) * 60000).toISOString();
        MOCK.findings.push(nf);
      });
      addedProjects.push(pid);
    });
    state.localProjects = addedProjects;
    reindex();
    state.projects = new Set(state.localProjects);
    state.branch = '';
    state.scanId = '';
    state.sevs = new Set(ALL_SEVS);
    var sm = $('#scanModal'); if (sm) sm.classList.remove('open');
    updateProjectUI();
    renderFilterOptions();
    renderAll();
    var first = MOCK.findings.filter(function (f) { return state.localProjects.indexOf(f.projectId) >= 0; }).sort(function (a, b) { return sevRank(a.severity) - sevRank(b.severity); })[0];
    if (first) openDetail(first.id);
    toast('已加载本地扫描结果：' + state.localProjects.length + ' 个项目', 'ok', 2600);
  }

  /* ----------------------------------------------------------------------
     导出 CSV
     ---------------------------------------------------------------------- */
  function exportCsv() {
    var rows = state.rows;
    if (!rows.length) { toast('当前没有可导出的数据', 'err'); return; }
    var cols = ['severity', 'queryName', 'cwe', 'language', 'project', 'branch', 'file', 'line', 'state', 'status', 'foundAt'];
    var head = ['严重级别', '漏洞类型', 'CWE', '语言', '项目', '分支', '文件', '行', '状态', '标记', '发现时间'];
    function esc2(v) { return '"' + String(v == null ? '' : v).replace(/"/g, '""') + '"'; }
    var lines = [head.map(esc2).join(',')];
    rows.forEach(function (f) {
      lines.push([f.severity, f.queryName, 'CWE-' + f.cwe, f.language, projectName(f.projectId), branchOf(f),
        f.file, f.line, STATE_LABEL[f.state] || f.state, STATUS_LABEL[f.status] || f.status, fmtDate(f.foundAt)].map(esc2).join(','));
    });
    var blob = new Blob(['\ufeff' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'checkmarx-findings-demo.csv';
    document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 300);
    toast('已导出 ' + rows.length + ' 条漏洞（CSV）', 'ok', 2000);
  }

  /* ----------------------------------------------------------------------
     全局键盘 / 初始化
     ---------------------------------------------------------------------- */
  function bindGlobal() {
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') {
        var openModal = $$('.modal-layer.open').pop();
        if (openModal) { openModal.classList.remove('open'); return; }
        closeDetail();
        return;
      }
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        var idx = findRowIndex();
        if (idx >= 0) { e.preventDefault(); navigateDetail(e.key === 'ArrowUp' ? 'prev' : 'next'); }
      }
    });
    $$('[data-open-settings]').forEach(function (b) { b.addEventListener('click', openSettings); });
    var settingsBtn = $('#settingsBtn');
    if (settingsBtn) settingsBtn.addEventListener('click', openSettings);
    $$('[data-open-scan]').forEach(function (b) { b.addEventListener('click', openScan); });
    var localBtn = $('#localScanBtn');
    if (localBtn) localBtn.addEventListener('click', openScan);
    var openSettingsLinks = $$('[data-open-settings]');
    if (openSettingsLinks.length === 0 && settingsBtn) { /* already bound */ }
  }

  function init() {
    reindex();
    var hash = new URLSearchParams(location.hash.replace(/^#/, ''));
    document.body.classList.add('locked');
    mountLogin();
    mountDetailShell();
    bindProjectUI();
    bindFilterUI();
    bindSeverityUI();
    bindGlobal();
    updateProjectUI();
    renderFilterOptions();

    var auto = CFG.autoLogin || hash.get('state') === 'board';
    if (hash.get('state') === 'login') auto = false;
    if (auto) enterApp(true);
    else if (hash.get('state') === 'board') enterApp(true);

    if (auto) {
      renderAll();
      var openId = hash.get('open');
      if (openId) setTimeout(function () { openDetail(openId); }, 60);
      var modal = hash.get('modal');
      if (modal === 'scan') setTimeout(openScan, 80);
      if (modal === 'settings') setTimeout(openSettings, 80);
      var sev = hash.get('sev');
      if (sev) {
        var list = sev.split(',').filter(function (s) { return ALL_SEVS.indexOf(s) >= 0; });
        if (list.length) state.sevs = new Set(list);
        renderAll();
      }
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();