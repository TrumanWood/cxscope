/* ==========================================================================
   CxScope · 当前页面 Demo（模拟 Checkmarx One）
   纯前端演示：拦截页面所有 Checkmarx API 调用，用本地 mock 数据返回；
   不发起任何真实网络请求，不需要本地代理，也不需要真实 API Key。

   由 app/build.py 注入到 demo/current-page-demo.html，位于 app.js 之前执行。
   ========================================================================== */
(function () {
  'use strict';

  var DATA = window.CX_DEMO_MOCK_DATA;
  if (!DATA || !DATA.projects) { console.warn('[CxScope Demo] 缺少演示数据'); return; }

  function clone(v) { return JSON.parse(JSON.stringify(v)); }
  function uuid() {
    if (window.crypto && window.crypto.randomUUID) return window.crypto.randomUUID();
    return 'demo-' + Date.now().toString(16) + '-' + Math.random().toString(16).slice(2);
  }
  function delay(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }
  function pathOf(url) {
    try { return new URL(url, location.href).pathname; } catch (e) { return String(url); }
  }
  function queryOf(url) {
    try { return new URL(url, location.href).searchParams; } catch (e) { return new URLSearchParams(); }
  }
  function page(items, q, defLimit) {
    var limit = parseInt(q.get('limit') || String(defLimit), 10);
    var offset = parseInt(q.get('offset') || '0', 10);
    if (isNaN(limit)) limit = defLimit;
    if (isNaN(offset)) offset = 0;
    return items.slice(offset, offset + limit);
  }
  function baseName(p) {
    if (!p) return '';
    var parts = String(p).replace(/[\\/]+$/, '').split(/[\\/]/);
    return parts[parts.length - 1] || '';
  }
  function escHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  /* 演示期间可变的本地数据（本地扫描新增的项目/扫描/结果只存在于当前页面） */
  var state = {
    projects: clone(DATA.projects),
    scans: clone(DATA.scans),
    results: clone(DATA.results || {}),
    folderIdx: 0
  };

  function findProject(id) {
    for (var i = 0; i < state.projects.length; i++) if (state.projects[i].id === id) return state.projects[i];
    return null;
  }

  function tokenResponse() {
    return { access_token: DATA.accessToken, expires_in: 3600, token_type: 'bearer', refresh_token: 'demo-refresh' };
  }

  /* ---------------- 模拟 Checkmarx One REST API ---------------- */
  async function mockFetch(targetUrl, opts) {
    var path = pathOf(targetUrl);
    var q = queryOf(targetUrl);
    var method = ((opts && opts.method) || 'GET').toUpperCase();

    if (path.indexOf('/protocol/openid-connect/token') >= 0) {
      await delay(650);
      return tokenResponse();
    }
    if (path === '/api/projects') {
      await delay(240);
      var projects = state.projects;
      var name = q.get('name');
      if (name) {
        name = name.toLowerCase();
        projects = projects.filter(function (p) {
          return p.name.toLowerCase() === name || p.name.toLowerCase().indexOf(name) >= 0;
        });
      }
      return {
        projects: page(projects, q, 100),
        totalCount: projects.length,
        filteredTotalCount: projects.length
      };
    }
    if (path === '/api/scans') {
      await delay(220);
      var pid = q.get('project-id');
      var scans = state.scans.filter(function (s) { return !pid || s.projectId === pid; });
      scans = scans.slice().sort(function (a, b) {
        return new Date(b.createdAt || 0) - new Date(a.createdAt || 0);
      });
      return { scans: page(scans, q, 100), totalCount: scans.length };
    }
    if (path.indexOf('/api/scans/') === 0) {
      await delay(180);
      var scanId = decodeURIComponent(path.slice('/api/scans/'.length));
      for (var i = 0; i < state.scans.length; i++) if (state.scans[i].id === scanId) return clone(state.scans[i]);
      throw new Error('演示数据中不存在扫描 ' + scanId);
    }
    if (path === '/api/results') {
      await delay(240);
      var sid = q.get('scan-id');
      var list = state.results[sid] || [];
      return { results: page(list, q, 500), totalCount: list.length, scanID: sid };
    }
    throw new Error('演示模式未模拟该接口：' + method + ' ' + path);
  }

  /* ---------------- 模拟本地代理接口 ---------------- */
  async function mockJson(path, payload, method) {
    if (path === '/local-scan') {
      await delay(1200);   // 模拟打包 + 上传
      var scans = [];
      var folders = (payload && payload.folders) || [];
      folders.forEach(function (folder) {
        var projectName = (folder.name || baseName(folder.path) || 'demo-project').trim();
        /* 优先使用前端选中的已有项目 ID；否则按名称（忽略大小写）匹配，仍不存在才新建 */
        var project = folder.projectId ? findProject(folder.projectId) : null;
        if (!project) {
          var lower = projectName.toLowerCase();
          for (var i = 0; i < state.projects.length; i++) {
            if (String(state.projects[i].name || '').toLowerCase() === lower) { project = state.projects[i]; break; }
          }
        }
        if (!project) {
          project = { id: uuid(), name: projectName };
          state.projects.push(project);
        }
        var scan = {
          id: uuid(),
          projectId: project.id,
          projectName: project.name,
          branch: (payload && payload.branch) || 'main',
          status: 'Queued',
          createdAt: new Date().toISOString()
        };
        state.scans.push(scan);
        state.results[scan.id] = [];
        scheduleScan(scan);
        scans.push({
          ok: true, scanId: scan.id, status: 'Queued',
          projectId: project.id, projectName: project.name, branch: scan.branch,
          fileCount: 87, sizeMB: 2.6
        });
      });
      return { scans: scans };
    }
    if (path === '/git-branches') {
      await delay(160);
      var paths = (payload && payload.paths) || (payload && payload.path ? [payload.path] : []);
      var repos = (paths || []).map(function (p) {
        var isRepo = !!p && String(p).toLowerCase().indexOf('no-git') < 0;
        return {
          path: p, ok: true, isRepo: isRepo,
          current: isRepo ? 'master' : '',
          locals: isRepo ? ['develop', 'main', 'master'] : [],
          remotes: isRepo ? ['origin/develop', 'origin/master'] : [],
          branches: isRepo ? ['develop', 'main', 'master', 'origin/develop', 'origin/master'] : [],
          error: isRepo ? '' : '不是 git 仓库'
        };
      });
      return { repos: repos };
    }
    if (path === '/pick-folder') {
      await delay(220);
      var candidates = DATA.sampleFolders || ['C:\\demo-projects\\demo-service'];
      var p = candidates[state.folderIdx % candidates.length];
      state.folderIdx++;
      return { path: p };
    }
    throw new Error('演示模式未模拟该接口：' + path);
  }

  function scheduleScan(scan) {
    setTimeout(function () { scan.status = 'Running'; }, 1200);
    setTimeout(function () {
      scan.status = 'Completed';
      var tpl = DATA.localResultsTemplate || [];
      var now = new Date().toISOString();
      state.results[scan.id] = tpl.map(function (raw, i) {
        var r = clone(raw);
        r.id = 'local-' + String(scan.id).slice(0, 8) + '-' + i;
        r.created = now;
        r.foundAt = now;
        r.firstFoundAt = now;
        return r;
      });
    }, 3300);
  }

  /* ---------------- 页面演示化（徽标 / 登录提示 / 示例链接） ---------------- */
  function injectStyle() {
    var style = document.createElement('style');
    style.textContent =
      '.demo-mode-badge{display:inline-flex;align-items:center;gap:5px;margin-left:2px;flex:none;' +
      'font-size:10px;font-weight:700;letter-spacing:.7px;color:#0e7490;background:#e0f7fa;' +
      'border:1px solid #a5f3fc;padding:3px 8px;border-radius:999px;white-space:nowrap}' +
      '.demo-mode-badge::before{content:"●";font-size:7px;color:#06b6d4}' +
      '@media(max-width:900px){.demo-mode-badge{display:none}}';
    document.head.appendChild(style);
  }

  function patchDom() {
    /* 顶栏 DEMO 徽标 */
    if (!document.querySelector('.demo-mode-badge')) {
      var brand = document.querySelector('.brand');
      if (brand) brand.insertAdjacentHTML('afterend', '<span class="demo-mode-badge">DEMO · 模拟数据</span>');
    }
    /* 登录页：替换代理提示 + 预填演示 API Key */
    var overlay = document.querySelector('#loginOverlay');
    if (overlay) {
      var hint = document.querySelector('#loginProxyHint');
      if (hint && hint.getAttribute('data-demo') !== '1') {
        hint.setAttribute('data-demo', '1');
        hint.innerHTML = '<b>演示模式：</b>不需要本地代理，也不会访问网络。API Key 已预填为 ' +
          '<code>DEMO-API-KEY</code>，直接点「登录」即可（也可随意输入）。<br>登录后会自动加载演示项目的扫描结果。';
      }
      var input = document.querySelector('#apiKeyInput');
      if (input && !input.value) input.value = 'DEMO-API-KEY';
    }
    /* 本地扫描弹窗：说明为模拟 */
    var scanModal = document.querySelector('#scanModal');
    if (scanModal) {
      var lead = scanModal.querySelector('.scan-lead');
      if (lead && lead.getAttribute('data-demo') !== '1') {
        lead.setAttribute('data-demo', '1');
        lead.innerHTML = '演示模式：选择代码文件夹（可点「浏览…」自动填入示例路径）后开始扫描，页面会模拟多项目并行扫描的进度与结果；不会真的上传任何源码。项目名可从演示项目下拉中选择已有项目，或直接输入新名称模拟新建项目。';
      }
      var callout = scanModal.querySelector('.scan-callout');
      if (callout && callout.getAttribute('data-demo') !== '1') {
        callout.setAttribute('data-demo', '1');
        callout.innerHTML = '<span class="i">ⓘ</span><span>演示模式：只模拟打包、上传与扫描进度，不会真的上传源码，也不会创建真实扫描。</span>';
      }
    }
    /* 扫描链接弹窗：给出演示示例链接 */
    var linkModal = document.querySelector('#linkModal');
    if (linkModal) {
      var help = linkModal.querySelector('.link-help');
      if (help && help.getAttribute('data-demo') !== '1') {
        help.setAttribute('data-demo', '1');
        help.innerHTML += '<br><br><b>演示示例：</b><br><code>' + escHtml(DATA.sampleScanUrl) + '</code>';
      }
    }
  }

  /* ---------------- 演示自动选择项目 ----------------
   当前页面默认不勾选项目、需要手动「应用」；演示态在登录后自动全选并应用一次，
   让首次打开就能直接看到看板数据（之后仍可自由修改项目/分支）。 */
  var demoAutoSelectDone = false;
  var demoAutoSelectTimer = null;
  function autoSelectDemoProjects() {
    if (demoAutoSelectDone) return;
    if (document.querySelector('#loginOverlay')) return;
    if (document.querySelectorAll('#resultsBody tr[data-id]').length > 0) {
      demoAutoSelectDone = true;
      clearInterval(demoAutoSelectTimer);
      return;
    }
    if (document.querySelector('#emptyPickProjects')) {
      demoAutoSelectDone = true;
      var pick = document.querySelector('#projectPickerBtn');
      if (pick) pick.click();
      setTimeout(function () {
        var all = document.querySelector('[data-proj-all]');
        if (all) all.click();
        var apply = document.querySelector('[data-proj-apply]');
        if (apply) apply.click();
      }, 150);
    }
  }
  document.addEventListener('DOMContentLoaded', function () {
    demoAutoSelectTimer = setInterval(autoSelectDemoProjects, 400);
    setTimeout(function () { clearInterval(demoAutoSelectTimer); }, 20000);
  });

  /* ---------------- 便于截图/分享的 URL 参数 ----------------
     #state=board            自动登录进入看板
     #state=board&open=1     进入看板并打开第 2 条漏洞详情
     #state=board&modal=scan 进入后打开本地扫描弹窗
     #state=board&modal=settings / modal=link
  ----------------------------------------------------------- */
  function handleHash() {
    var hash = new URLSearchParams(location.hash.replace(/^#/, ''));
    if (hash.get('state') !== 'board') return;
    var tries = 0;
    var timer = setInterval(function () {
      tries++;
      var btn = document.querySelector('#loginSubmit');
      if (btn && document.querySelector('#loginOverlay')) {
        clearInterval(timer);
        btn.click();
        setTimeout(afterLogin, 1000);
      }
      if (tries > 80) clearInterval(timer);
    }, 150);

    function afterLogin() {
      var waited = 0;
      var poll = setInterval(function () {
        waited += 200;
        if (document.querySelectorAll('#resultsBody tr[data-id]').length > 0) {
          clearInterval(poll);
          finalize();
          return;
        }
        if (waited > 15000) clearInterval(poll);
      }, 200);
    }

    function finalize() {
      if (hash.get('open')) {
        var rows = document.querySelectorAll('#resultsBody tr[data-id]');
        var idx = Math.min(Math.max(parseInt(hash.get('open'), 10) || 0, 0), rows.length - 1);
        if (rows[idx]) rows[idx].click();
      }
      var modal = hash.get('modal');
      if (modal === 'settings') document.querySelector('#settingsBtn').click();
      if (modal === 'scan') document.querySelector('#localScanBtn').click();
      if (modal === 'link') document.querySelector('#openLinkBtn').click();
    }
  }

  /* ---------------- 暴露给 app.js 的演示接口 ---------------- */
  window.CX_DEMO_MOCK = {
    isDemo: true,
    fetch: mockFetch,
    json: mockJson,
    parseApiKey: function (key) {
      return {
        claims: { aud: DATA.realmUrl, azp: 'ast-app' },
        realmUrl: DATA.realmUrl,
        tenant: DATA.tenant,
        azp: 'ast-app'
      };
    }
  };

  console.info('[CxScope Demo] 演示模式：所有 Checkmarx 数据均为本地模拟，不会发起网络请求。');
  /* 演示环境不打开真实 Checkmarx 页面 */
  window.open = function () { return null; };
  injectStyle();
  document.addEventListener('DOMContentLoaded', function () {
    patchDom();
    setTimeout(patchDom, 200);
    try {
      new MutationObserver(function () { patchDom(); }).observe(document.body, { childList: true, subtree: true });
    } catch (e) { /* ignore */ }
  });
  document.addEventListener('click', function () { setTimeout(patchDom, 0); }, true);
  setTimeout(handleHash, 100);
  window.addEventListener('hashchange', handleHash);
})();