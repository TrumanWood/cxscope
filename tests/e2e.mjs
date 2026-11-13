/**
 * 真实页面（index.html + proxy.py + mock Checkmarx One）端到端测试。
 * 零依赖：Node 22+ 内置 WebSocket + Chrome DevTools Protocol。
 *
 * 用法：node tests/e2e.mjs
 * 覆盖：API Key 登录（JWT aud/azp -> refresh_token -> ast-base-url）、
 *       项目多选（默认空选、勾选不查询、取消/应用、记住上次项目+分支+严重级别）、
 *       分支/扫描时间筛选、严重级别筛选、搜索、详情抽屉（漏洞说明/攻击向量/数据流/
 *       修复建议/参考链接 + 各区块一键复制（剪贴板文本只含标准空格与标准换行））、设置弹窗、扫描链接打开、
 *       本地扫描（走本机 Checkmarx One CLI：参数/环境变量传递正确；项目名组合框：筛选已有项目/新项目手输；
 *       git 分支自动读取与默认值/分支下拉点选/非 git 回退/最小化与完成通知/失败详情在下方展示/弹窗无横向滚动；
 *       文件夹路径与项目名记忆：写入本机、刷新后自动恢复、「最近扫描」一键填入、退出保留、清除凭据清空）、
 *       筛选联动（重选项目/分支刷新分支与扫描时间）、刷新后自动登录、退出登录。
 */
import { spawn, spawnSync } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const SHOTS = path.join(ROOT, 'shots');
const CHROME = [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe'
].find((p) => fs.existsSync(p));
if (!CHROME) { console.error('未找到 Chrome/Edge'); process.exit(1); }

/* 使用专用端口，避免与用户本机正在运行的 proxy.py / 其它演示服务冲突 */
const MOCK_PORT = 19100;
const PROXY_PORT = 18787;
const CDP_PORT = 19333;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function httpGet(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let b = '';
      res.on('data', (c) => (b += c));
      res.on('end', () => resolve({ status: res.statusCode, body: b }));
    }).on('error', reject);
  });
}

async function waitHttp(url, timeout = 20000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    try {
      const r = await httpGet(url);
      if (r.status === 200) return r.body;
    } catch (_) { /* not ready */ }
    await sleep(200);
  }
  throw new Error('等待失败: ' + url);
}

function run(cmd, args, opts = {}) {
  const child = spawn(cmd, args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], ...opts });
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdoutBuf = '';
  child.stderrBuf = '';
  child.stdout.on('data', (d) => (child.stdoutBuf += d));
  child.stderr.on('data', (d) => (child.stderrBuf += d));
  return child;
}

/* ------------------------------ CDP ------------------------------ */
let ws;
let nextId = 1;
const pending = new Map();
const pageErrors = [];

function send(method, params = {}) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}
async function evaluate(expression) {
  const r = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true, userGesture: true });
  if (r.exceptionDetails) {
    const d = r.exceptionDetails;
    throw new Error('页面异常: ' + (d.exception && d.exception.description ? d.exception.description : JSON.stringify(d)));
  }
  return r.result ? r.result.value : undefined;
}
async function waitUntil(expr, desc, timeout = 20000, interval = 120) {
  const start = Date.now();
  let last;
  while (Date.now() - start < timeout) {
    try { last = await evaluate(expr); if (last) return last; } catch (e) { last = 'eval-error: ' + e.message; }
    await sleep(interval);
  }
  throw new Error('等待超时（' + desc + '），最后值: ' + JSON.stringify(last));
}
const click = (sel) => `(function(){var e=document.querySelector(${JSON.stringify(sel)});if(!e)return false;e.click();return true;})()`;
const rows = `document.querySelectorAll('#resultsBody tr[data-id]').length`;
const text = (sel) => `(document.querySelector(${JSON.stringify(sel)})||{}).innerText || ''`;

/* 记录页面每次请求的 X-Target-Url，用于断言「勾选过程中不查询数据」 */
async function installFetchSpy() {
  await evaluate(`(function(){
    window.__apiCalls=[];
    var of=window.fetch;
    window.fetch=function(u,o){
      try{var h=(o&&o.headers)||{};window.__apiCalls.push(String(h['X-Target-Url']||''));}catch(e){}
      return of.apply(this,arguments);
    };
    return true;
  })()`);
}
async function apiCallsMatching(fragment) {
  return await evaluate(`(window.__apiCalls||[]).filter(function(u){return u.indexOf(${JSON.stringify(fragment)})>=0;}).length`);
}

const results = [];
function check(name, ok, extra) {
  results.push({ name, ok: !!ok, extra });
  console.log(`${ok ? '  ✓' : '  ✗'} ${name}${extra ? '  [' + extra + ']' : ''}`);
}

async function shot(name) {
  fs.mkdirSync(SHOTS, { recursive: true });
  const r = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(SHOTS, name), Buffer.from(r.data, 'base64'));
  console.log('  📸 ' + name);
}

/* -------------------- 抽屉宽度 / 横向滚动辅助 -------------------- */
async function drawerWidth() {
  return await evaluate(`Math.round(document.querySelector('#detailDrawer').getBoundingClientRect().width)`);
}
async function drawerOverflow() {
  return JSON.parse(await evaluate(`(function(){
    var sc = document.querySelector('.drawer-scroll');
    return JSON.stringify({
      scrollWidth: sc.scrollWidth,
      clientWidth: sc.clientWidth,
      overflowX: getComputedStyle(sc).overflowX,
      contentWidth: document.querySelector('#detailContent').scrollWidth
    });
  })()`));
}
/** 在抽屉左边缘按住并水平拖拽 dx 像素（dx > 0 表示向左拖，抽屉变宽） */
async function dragDrawerBy(dx) {
  const rect = JSON.parse(await evaluate(`(function(){
    var r = document.querySelector('#detailDrawer').getBoundingClientRect();
    return JSON.stringify({ left: r.left, top: r.top, width: r.width, height: r.height });
  })()`));
  const x0 = Math.round(rect.left + 4);
  const y0 = Math.round(rect.top + Math.min(260, rect.height - 40));
  const vw = await evaluate('window.innerWidth');
  // 鼠标坐标保持落在视口内，避免 CDP 丢弃视口外的事件
  const x1 = Math.min(Math.max(Math.round(x0 - dx), 5), vw - 5);
  await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: x0, y: y0, buttons: 0 });
  await send('Input.dispatchMouseEvent', { type: 'mousePressed', x: x0, y: y0, button: 'left', buttons: 1, clickCount: 1 });
  const steps = 8;
  for (let i = 1; i <= steps; i++) {
    await send('Input.dispatchMouseEvent', {
      type: 'mouseMoved', x: Math.round(x0 + (x1 - x0) * i / steps), y: y0, button: 'left', buttons: 1
    });
    await sleep(25);
  }
  await send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: x1, y: y0, button: 'left', buttons: 0, clickCount: 1 });
  await sleep(260);
}
async function dblclickResizer() {
  await evaluate(`document.querySelector('#drawerResizer').dispatchEvent(new MouseEvent('dblclick', { bubbles: true, cancelable: true }))`);
  await sleep(220);
}
async function openDetailByText(snippet) {
  await evaluate(`(function(){
    var rows = document.querySelectorAll('#resultsBody tr[data-id]');
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].innerText.indexOf(${JSON.stringify(snippet)}) >= 0) { rows[i].click(); return true; }
    }
    if (rows.length) { rows[0].click(); return true; }
    return false;
  })()`);
  await waitUntil(`document.querySelector('#detailDrawer').classList.contains('open')`, '详情抽屉打开');
  await sleep(420); // 等待抽屉滑入动画结束，避免拖拽坐标落在移动中的边缘
}

/* ------------------------------ main ------------------------------ */
(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-e2e-'));
  const keyFile = path.join(tmp, 'key.json');
  const fixture = path.join(tmp, 'sample-project');
  fs.mkdirSync(path.join(fixture, 'src'), { recursive: true });
  fs.writeFileSync(path.join(fixture, 'src', 'App.java'), 'public class App { public static void main(String[] a) {} }\n');
  fs.writeFileSync(path.join(fixture, 'README.md'), '# sample project\n');
  fs.writeFileSync(path.join(fixture, 'pom.xml'), '<project></project>\n');

  /* 本地扫描夹具：初始化为 git 仓库（当前分支 develop，另有 master），
     用于验证「分支自动读取 + 默认当前检出分支 > master」；没有 git 时相关断言自动跳过。 */
  let gitReady = false;
  try {
    const git = (args) => spawnSync('git', args, { stdio: 'ignore' });
    let init = git(['init', '-b', 'master', fixture]);
    if (init.status !== 0) init = git(['init', fixture]);
    if (init.status === 0) {
      git(['-C', fixture, 'add', '-A']);
      const commit = git(['-C', fixture, '-c', 'user.email=e2e@example.com', '-c', 'user.name=CxScope-E2E', 'commit', '-m', 'init fixture']);
      if (commit.status === 0) {
        const co = git(['-C', fixture, 'checkout', '-b', 'develop']);
        gitReady = co.status === 0;
      }
    }
  } catch (_) { gitReady = false; }

  /* 非 git 文件夹：验证读不到分支时回退为可手动输入 */
  const plainFolder = path.join(tmp, 'plain-folder');
  fs.mkdirSync(plainFolder, { recursive: true });
  fs.writeFileSync(path.join(plainFolder, 'main.py'), 'print("hi")\n');

  /* 本地扫描已改为调用 Checkmarx One CLI：生成测试用假 CLI（调用 mock 建扫描），
     并记录代理传给 CLI 的参数，供断言「确实走 CLI 而不是 REST 上传」。 */
  const fakeCliRecord = path.join(tmp, 'fake-cx-record.jsonl');
  const fakeCliScript = path.join(ROOT, 'tests', 'fake_cx_cli.py');
  let fakeCli;
  if (process.platform === 'win32') {
    fakeCli = path.join(tmp, 'fake-cx.cmd');
    fs.writeFileSync(fakeCli, '@echo off\r\npython "' + fakeCliScript + '" %*\r\n');
  } else {
    fakeCli = path.join(tmp, 'fake-cx');
    fs.writeFileSync(fakeCli, '#!/bin/sh\nexec python3 "' + fakeCliScript + '" "$@"\n', { mode: 0o755 });
  }

  const chromeProfile = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-e2e-chrome-'));
  const mock = run('python', ['tests/mock_cxone.py', '--port', String(MOCK_PORT), '--key-out', keyFile]);
  let proxy = null;
  let chrome = null;
  try {
    await waitHttp(`http://127.0.0.1:${MOCK_PORT}/health`);
    const key = JSON.parse(fs.readFileSync(keyFile, 'utf8'));
    console.log('mock ready; apiBase=' + key.apiBase + ' projects=' + Object.keys(key.projects).length + ' scans=' + Object.keys(key.scans).length);

    proxy = run('python', ['proxy.py'], {
      env: Object.assign({}, process.env, {
        PORT: String(PROXY_PORT), ALLOWED_HOSTS: '127.0.0.1', MAX_UPLOAD_MB: '50',
        SCAN_MODE: 'cli', CX_CLI_PATH: fakeCli, FAKE_CX_RECORD: fakeCliRecord
      })
    });
    await waitHttp(`http://127.0.0.1:${PROXY_PORT}/health`);

    chrome = spawn(CHROME, [
      '--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run',
      '--no-default-browser-check', '--remote-allow-origins=*', '--window-size=1600,1000',
      `--remote-debugging-port=${CDP_PORT}`, `--user-data-dir=${chromeProfile}`, 'about:blank'
    ], { stdio: 'ignore' });

    let page = null;
    for (let i = 0; i < 100 && !page; i++) {
      try {
        const r = await httpGet(`http://127.0.0.1:${CDP_PORT}/json/list`);
        const list = JSON.parse(r.body);
        page = list.find((t) => t.type === 'page' && t.webSocketDebuggerUrl);
      } catch (_) { /* not ready */ }
      if (!page) await sleep(150);
    }
    if (!page) throw new Error('DevTools 未就绪');
    ws = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && pending.has(msg.id)) {
        const { resolve, reject } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) reject(new Error(msg.error.message)); else resolve(msg.result);
        return;
      }
      if (msg.method === 'Runtime.exceptionThrown') {
        const d = msg.params.exceptionDetails;
        pageErrors.push((d.exception && d.exception.description) || d.text);
      }
      if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
        pageErrors.push(msg.params.args.map((a) => a.value || a.description || '').join(' '));
      }
    };
    await send('Page.enable');
    await send('Runtime.enable');

    const APP = `http://127.0.0.1:${PROXY_PORT}/`;

    /* ---------- 1. 登录页 ---------- */
    console.log('\n=== 1. API Key 登录 ===');
    await send('Page.navigate', { url: APP });
    await waitUntil(`document.readyState==='complete' && !!document.querySelector('#loginOverlay')`, '登录页加载');
    check('本地代理提供页面并显示 API Key 登录页', true);
    await sleep(400);
    await shot('real-login.png');
    const proxyHint = await evaluate(text('#loginProxyHint'));
    check('登录页提示本地代理地址', proxyHint.includes(String(PROXY_PORT)), proxyHint.slice(0, 60));

    await installFetchSpy();
    await evaluate(`(function(){var t=document.querySelector('#apiKeyInput');t.value=${JSON.stringify(key.apiKey)};t.dispatchEvent(new Event('input',{bubbles:true}));document.querySelector('#loginSubmit').click();return true;})()`);
    await waitUntil(`!document.querySelector('#loginOverlay') && document.querySelector('#projectPickerBtn') && !document.querySelector('#projectPickerBtn').disabled`, '登录完成、项目列表加载', 25000);
    await sleep(350);
    check('API Key 登录成功并进入看板', true);
    check('登录界面已隐藏', !(await evaluate(`!!document.querySelector('#loginOverlay')`)));
    check('连接状态显示已连接', (await evaluate(text('#connPill'))).includes('已连接'));
    check('项目默认一个都不选（按钮显示「选择项目」）', (await evaluate(text('#projectPickerBtn'))).includes('选择项目'));
    check('默认空选：看板显示「请先选择项目」引导', (await evaluate(text('#resultsBody'))).includes('请先选择项目'));
    check('默认空选：不请求扫描/结果数据', (await apiCallsMatching('/api/scans')) === 0 && (await apiCallsMatching('/api/results')) === 0);
    check('默认空选：项目下拉未自动展开', await evaluate(`document.querySelector('#projectMenu').classList.contains('hidden')`));
    await shot('real-empty-projects.png');

    /* 空状态引导入口 + Esc 关闭（不生效） */
    check('空状态提供「选择项目」入口', await evaluate(`!!document.querySelector('#emptyPickProjects')`));
    await evaluate(click('#emptyPickProjects'));
    check('点击「选择项目」打开多选下拉', await evaluate(`!document.querySelector('#projectMenu').classList.contains('hidden')`));
    await sleep(300); // 等下拉弹出动画结束再截图
    await shot('real-project-picker.png');
    await evaluate(`document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true,cancelable:true}))`);
    await sleep(180);
    check('Esc 关闭下拉且不生效', await evaluate(`document.querySelector('#projectMenu').classList.contains('hidden')`));

    /* 全选 + 应用：关闭下拉后只查询一次 */
    await evaluate(click('#projectPickerBtn'));
    await evaluate(click('#projectMenu [data-proj-all]'));
    check('下拉内「已选」计数实时更新', (await evaluate(text('[data-draft-count]'))).includes('已选 3 / 3'));
    await evaluate(click('#projectMenu [data-proj-apply]'));
    await waitUntil(`${rows} === 10`, '应用项目选择后加载 10 条最新扫描漏洞', 25000);
    check('应用项目选择后加载最新扫描结果（10 条）', true);
    check('点「应用」后下拉自动关闭', await evaluate(`document.querySelector('#projectMenu').classList.contains('hidden')`));
    const resultsCalls = await apiCallsMatching('/api/results');
    check('应用后仅按所选项目各查询一次结果（3 次）', resultsCalls === 3, 'results 请求 ' + resultsCalls + ' 次');
    check('按钮显示全部项目（3）', (await evaluate(text('#projectPickerBtn'))).includes('全部项目 (3)'));

    /* ---------- 2. 刷新后自动登录 + 恢复上次选择 ---------- */
    console.log('\n=== 2. 刷新后自动登录 ===');
    await send('Page.navigate', { url: APP });
    await waitUntil(`${rows} === 10`, '刷新后自动登录并恢复项目选择', 25000);
    check('刷新页面后使用本机保存的 API Key 自动登录', true);
    check('刷新后自动恢复上次应用的项目选择（3 个项目 / 10 条）', (await evaluate(text('#projectPickerBtn'))).includes('全部项目 (3)'));
    await evaluate(`document.querySelector('#projectMenu').classList.add('hidden')`);
    await installFetchSpy();
    await sleep(250);
    await shot('real-board.png');

    /* ---------- 3. 严重级别 / 分支 / 项目 / 搜索筛选 ---------- */
    console.log('\n=== 3. 筛选 ===');
    const counts = await evaluate(`(function(){var o={};document.querySelectorAll('[data-sev]').forEach(function(e){o[e.getAttribute('data-sev')]=e.querySelector('[data-count]').textContent});return JSON.stringify(o);})()`);
    const c = JSON.parse(counts);
    check('严重级别计数正确（CRIT/HIGH/MED/INFO）', c.CRITICAL === '2' && c.HIGH === '4' && c.MEDIUM === '3' && c.INFO === '1', counts);

    await evaluate(click('[data-sev="HIGH"]'));
    await sleep(150);
    check('点击 High 标签筛选（10 -> 6）', (await evaluate(rows)) === 6);
    await evaluate(click('[data-sev="HIGH"]'));
    await sleep(150);
    check('再次点击恢复 10 条', (await evaluate(rows)) === 10);

    await evaluate(`(function(){var s=document.querySelector('#branchSelect');s.value='develop';s.dispatchEvent(new Event('change',{bubbles:true}));return true;})()`);
    await waitUntil(`${rows} === 5`, '分支 develop 结果', 15000);
    check('分支 = develop 筛选（5 条）', true);
    const devScanOptions = JSON.parse(await evaluate(`JSON.stringify(Array.prototype.map.call(document.querySelectorAll('#scanSelect option'), function(o){return o.textContent;}))`));
    check('切到分支 develop 后重新拉取扫描时间（只列该分支扫描）',
      devScanOptions.length === 3 && devScanOptions.slice(1).every((t) => t.indexOf('develop') >= 0),
      JSON.stringify(devScanOptions));
    await evaluate(`(function(){var s=document.querySelector('#branchSelect');s.value='';s.dispatchEvent(new Event('change',{bubbles:true}));return true;})()`);
    await waitUntil(`${rows} === 10`, '恢复全部分支', 15000);
    check('恢复全部分支后扫描时间恢复（6 个扫描 + 默认项）',
      (await evaluate(`document.querySelectorAll('#scanSelect option').length`)) === 7);

    /* 项目多选新交互：勾选不关闭、不查询；点「应用」才关闭并查询 */
    await evaluate(click('#projectPickerBtn'));
    check('打开项目下拉', await evaluate(`!document.querySelector('#projectMenu').classList.contains('hidden')`));
    const resCallsBeforeDraft = await apiCallsMatching('/api/results');
    await evaluate(click(`#projectMenu [data-project="${key.projects['p-1003']}"] input`));
    await sleep(350);
    check('勾选项目后下拉保持展开（不立即隐藏）', await evaluate(`!document.querySelector('#projectMenu').classList.contains('hidden')`));
    check('勾选项目中看板数据不变（仍 10 条）', (await evaluate(rows)) === 10);
    check('勾选过程中不触发结果查询', (await apiCallsMatching('/api/results')) === resCallsBeforeDraft);
    await evaluate(click('#projectMenu [data-proj-cancel]'));
    await sleep(250);
    check('点「取消」关闭下拉且丢弃本次勾选', (await evaluate(rows)) === 10);
    await evaluate(click('#projectPickerBtn'));
    check('取消后重新打开，勾选态恢复为上次已应用的值', (await evaluate(`document.querySelectorAll('#projectMenu [data-project] input:checked').length`)) === 3);

    /* 点击下拉外部 = 取消本次勾选（不查询、不生效） */
    await evaluate(click(`#projectMenu [data-project="${key.projects['p-1002']}"] input`));
    const resCallsBeforeOutside = await apiCallsMatching('/api/results');
    await evaluate(`(function(){document.querySelector('.board-toolbar').click();return true;})()`);
    await sleep(250);
    check('点击下拉外部关闭下拉且不生效', await evaluate(`document.querySelector('#projectMenu').classList.contains('hidden')`) && (await evaluate(rows)) === 10);
    check('点击下拉外部不触发结果查询', (await apiCallsMatching('/api/results')) === resCallsBeforeOutside);
    await evaluate(click('#projectPickerBtn'));
    check('点外部关闭后重新打开，勾选态为上次已应用值（3 个）', (await evaluate(`document.querySelectorAll('#projectMenu [data-project] input:checked').length`)) === 3);

    await evaluate(click(`#projectMenu [data-project="${key.projects['p-1003']}"] input`));
    await evaluate(click('#projectMenu [data-proj-apply]'));
    await waitUntil(`${rows} === 7`, '应用后加载所选项目（7 条）', 20000);
    check('点「应用」后关闭下拉并查询：取消 web-portal（7 条）', await evaluate(`document.querySelector('#projectMenu').classList.contains('hidden')`));
    const appliedScanOpts = await evaluate(`document.querySelectorAll('#scanSelect option').length`);
    const appliedBranchOpts = await evaluate(`document.querySelectorAll('#branchSelect option').length`);
    check('重新选择项目后重新拉取分支与扫描时间（2 项目：4 个扫描 / 3 个分支）',
      appliedScanOpts === 5 && appliedBranchOpts === 4, `scan=${appliedScanOpts}, branch=${appliedBranchOpts}`);
    await evaluate(click('#projectPickerBtn'));
    await evaluate(click(`#projectMenu [data-project="${key.projects['p-1003']}"] input`));
    await evaluate(click('#projectMenu [data-proj-apply]'));
    await waitUntil(`${rows} === 10`, '恢复 web-portal 项目（10 条）', 20000);
    check('再次应用恢复 web-portal（10 条）', true);
    check('恢复项目后扫描时间恢复为全部 6 个扫描',
      (await evaluate(`document.querySelectorAll('#scanSelect option').length`)) === 7);

    /* ---------- 3.2 项目下拉搜索筛选 ---------- */
    console.log('\n=== 3.2 项目下拉搜索筛选 ===');
    const projSearchVisibleCount = `document.querySelectorAll('#projectMenu .proj-item[data-project]:not(.is-hidden)').length`;
    const projSearchCheckedCount = `document.querySelectorAll('#projectMenu .proj-item[data-project] input:checked').length`;
    const projSearchHiddenCount = `document.querySelectorAll('#projectMenu .proj-item[data-project].is-hidden').length`;
    const setProjSearch = (v) => `(function(){var i=document.querySelector('#projectMenu #projectSearchInput');if(!i)return false;i.value=${JSON.stringify(v)};i.dispatchEvent(new Event('input',{bubbles:true}));return true;})()`;
    const escProjSearch = `(function(){var i=document.querySelector('#projectMenu #projectSearchInput');if(!i)return false;i.focus();i.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true,cancelable:true}));return true;})()`;
    const projSearchShown = (sel) => `(function(){var e=document.querySelector(${JSON.stringify(sel)});return !!e && e.getClientRects().length > 0;})()`;

    /* 打开下拉：搜索框存在、自动聚焦、无查询时全选按钮为「全选」 */
    await evaluate(click('#projectPickerBtn'));
    await waitUntil(`!document.querySelector('#projectMenu').classList.contains('hidden') && !!document.querySelector('#projectMenu #projectSearchInput')`, '项目下拉打开并渲染搜索框');
    await waitUntil(`document.activeElement && document.activeElement.id === 'projectSearchInput'`, '搜索框自动聚焦', 5000);
    check('项目下拉新增搜索框（.proj-search > #projectSearchInput）', await evaluate(`(function(){var i=document.querySelector('#projectMenu .proj-search #projectSearchInput');return !!i && i.tagName === 'INPUT';})()`));
    check('搜索框 placeholder 含「搜索项目」', (await evaluate(`(document.querySelector('#projectMenu #projectSearchInput')||{}).placeholder||''`)).includes('搜索项目'));
    check('打开项目下拉时搜索框自动获得焦点', (await evaluate(`document.activeElement && document.activeElement.id`)) === 'projectSearchInput');
    check('无查询时全选按钮文本为「全选」', (await evaluate(text('#projectMenu [data-proj-all]'))).trim() === '全选');
    check('无查询时计数为「已选 3 / 3 个项目」', (await evaluate(text('#projectMenu [data-draft-count]'))).trim() === '已选 3 / 3 个项目', await evaluate(text('#projectMenu [data-draft-count]')));
    check('无查询时清除按钮处于隐藏态', await evaluate(`(function(){var b=document.querySelector('#projectMenu [data-proj-search-clear]');return !!b && b.classList.contains('hidden');})()`));

    /* 大小写不敏感 + 命中高亮 + 过滤期间不查询、不改草稿 */
    const searchResBefore = await apiCallsMatching('/api/results');
    const searchScanBefore = await apiCallsMatching('/api/scans');
    await evaluate(setProjSearch('USER'));
    await waitUntil(`${projSearchVisibleCount} === 1`, '搜索 USER 过滤出 1 个项目');
    await sleep(350);
    const userMatch = JSON.parse(await evaluate(`(function(){
      var it=document.querySelector('#projectMenu .proj-item[data-project][data-name="user-center"]');
      var m=it&&it.querySelector('.p-name mark');
      return JSON.stringify({visible:!!it&&!it.classList.contains('is-hidden'),mark:!!m,markText:m?m.textContent:'',dataName:it?it.getAttribute('data-name'):''});
    })()`));
    check('搜索大小写不敏感：仅 user-center 可见（data-name 正确）', userMatch.visible && userMatch.dataName === 'user-center', JSON.stringify(userMatch));
    check('命中片段以 <mark> 高亮', userMatch.mark && userMatch.markText.toLowerCase() === 'user', userMatch.markText);
    check('过滤项仍保留在 DOM（2 项带 is-hidden，共 3 项）', (await evaluate(projSearchHiddenCount)) === 2 && (await evaluate(`document.querySelectorAll('#projectMenu .proj-item[data-project]').length`)) === 3);
    check('有查询时全选按钮文本含「全选匹配」', (await evaluate(text('#projectMenu [data-proj-all]'))).includes('全选匹配'), await evaluate(text('#projectMenu [data-proj-all]')));
    check('有查询时计数追加「匹配 1 个」', (await evaluate(text('#projectMenu [data-draft-count]'))).includes('匹配 1 个'), await evaluate(text('#projectMenu [data-draft-count]')));
    check('搜索过滤不改变已勾选草稿（仍已选 3 / 3）', (await evaluate(projSearchCheckedCount)) === 3 && (await evaluate(text('#projectMenu [data-draft-count]'))).includes('已选 3 / 3'));
    const searchResAfter = await apiCallsMatching('/api/results');
    const searchScanAfter = await apiCallsMatching('/api/scans');
    check('搜索 / 键入期间不发起结果或扫描查询', searchResAfter === searchResBefore && searchScanAfter === searchScanBefore, 'results+' + (searchResAfter - searchResBefore) + ' scans+' + (searchScanAfter - searchScanBefore));
    await shot('real-project-search.png');

    /* 多关键词 AND：user 与 port 分别命中不同项目，组合后无结果 */
    await evaluate(setProjSearch('user port'));
    await waitUntil(`${projSearchVisibleCount} === 0`, '多关键词 AND 无匹配');
    await sleep(150);
    const noMatchText = await evaluate(text('#projectMenu [data-proj-no-match]'));
    check('多关键词按 AND 匹配：user port 无结果（0 项可见）', (await evaluate(projSearchVisibleCount)) === 0);
    check('无匹配时显示提示（文本含「没有匹配」）', noMatchText.includes('没有匹配'), noMatchText.replace(/\n/g, ' ').slice(0, 80));
    check('无匹配时计数为「匹配 0 个」', (await evaluate(text('#projectMenu [data-draft-count]'))).includes('匹配 0 个'), await evaluate(text('#projectMenu [data-draft-count]')));

    /* 清除按钮：清空查询并恢复全部项目可见，下拉保持展开 */
    await evaluate(click('#projectMenu [data-proj-search-clear]'));
    await waitUntil(`${projSearchVisibleCount} === 3`, '清除搜索恢复全部项目');
    check('点清除按钮恢复全部 3 个项目可见', (await evaluate(projSearchVisibleCount)) === 3);
    check('清除后搜索框 value 为空', (await evaluate(`(document.querySelector('#projectMenu #projectSearchInput')||{}).value||''`)) === '');
    check('清除后无匹配提示与清除按钮均隐藏', !(await evaluate(projSearchShown('#projectMenu [data-proj-no-match]'))) && (await evaluate(`(function(){var b=document.querySelector('#projectMenu [data-proj-search-clear]');return !!b && b.classList.contains('hidden');})()`)));

    /* Esc：查询非空 -> 清空查询且保持展开；查询为空 -> 关闭下拉 */
    await evaluate(setProjSearch('zzz'));
    await waitUntil(`${projSearchVisibleCount} === 0`, '搜索 zzz 无匹配');
    await evaluate(escProjSearch);
    await waitUntil(`(document.querySelector('#projectMenu #projectSearchInput')||{}).value === ''`, 'Esc 清空搜索查询');
    await sleep(150);
    check('查询非空时按 Esc 清空查询且下拉保持展开', await evaluate(`!document.querySelector('#projectMenu').classList.contains('hidden')`) && (await evaluate(projSearchVisibleCount)) === 3);
    await evaluate(escProjSearch);
    await sleep(250);
    check('查询为空时再按 Esc 关闭下拉', await evaluate(`document.querySelector('#projectMenu').classList.contains('hidden')`));

    /* 关闭后重新打开：搜索框重置为空、全部可见、勾选态保持已应用的值 */
    await evaluate(click('#projectPickerBtn'));
    await waitUntil(`!document.querySelector('#projectMenu').classList.contains('hidden') && !!document.querySelector('#projectMenu #projectSearchInput')`, '重新打开项目下拉');
    check('关闭后重新打开：搜索框重置为空且全部项目可见', (await evaluate(`(document.querySelector('#projectMenu #projectSearchInput')||{}).value||''`)) === '' && (await evaluate(projSearchVisibleCount)) === 3 && !(await evaluate(projSearchShown('#projectMenu [data-proj-no-match]'))));
    check('关闭后重新打开：勾选态保持已应用的 3 个项目', (await evaluate(projSearchCheckedCount)) === 3);

    /* 过滤 + 清空 + 全选匹配 + 应用：只勾选 1 个可见项目并只查询它 */
    await evaluate(setProjSearch('port'));
    await waitUntil(`${projSearchVisibleCount} === 1`, '搜索 port 过滤出 web-portal');
    const portVisibleName = await evaluate(`(function(){var it=document.querySelector('#projectMenu .proj-item[data-project]:not(.is-hidden)');return it?it.getAttribute('data-name'):'';})()`);
    check('搜索 "port" 仅显示 web-portal（1 项）', (await evaluate(projSearchVisibleCount)) === 1 && portVisibleName === 'web-portal', portVisibleName);
    await evaluate(click('#projectMenu [data-proj-none]'));
    await sleep(150);
    check('过滤状态下点「清空」清空全部勾选（含隐藏项）', (await evaluate(projSearchCheckedCount)) === 0 && (await evaluate(text('#projectMenu [data-draft-count]'))).includes('已选 0 / 3'), await evaluate(text('#projectMenu [data-draft-count]')));
    check('过滤状态下全选按钮文本含「全选匹配」', (await evaluate(text('#projectMenu [data-proj-all]'))).includes('全选匹配'));
    await evaluate(click('#projectMenu [data-proj-all]'));
    await sleep(150);
    check('「全选匹配」只勾选可见项目（已选 1 / 3）', (await evaluate(projSearchCheckedCount)) === 1 && (await evaluate(text('#projectMenu [data-draft-count]'))).includes('已选 1 / 3'), await evaluate(text('#projectMenu [data-draft-count]')));
    check('「全选匹配」不改动被过滤隐藏项目的勾选态（0 个隐藏项被选中）', (await evaluate(`(function(){var n=0;document.querySelectorAll('#projectMenu .proj-item[data-project].is-hidden input').forEach(function(i){if(i.checked)n++;});return n;})()`)) === 0);
    await evaluate(click('#projectMenu [data-proj-apply]'));
    await waitUntil(`${rows} === 3`, '应用过滤后的单项目（3 条）', 20000);
    check('应用过滤后只勾选 1 个项目 -> 结果行数正确（3 条）', (await evaluate(rows)) === 3);
    check('应用后按钮显示所选项目 web-portal', (await evaluate(text('#projectPickerBtn'))).includes('web-portal'), await evaluate(text('#projectPickerBtn')));
    check('应用后下拉自动关闭', await evaluate(`document.querySelector('#projectMenu').classList.contains('hidden')`));

    /* 恢复前置状态：重新全选 3 个项目并应用，回到 10 条 */
    await evaluate(click('#projectPickerBtn'));
    await waitUntil(`!document.querySelector('#projectMenu').classList.contains('hidden')`, '重新打开项目下拉（恢复全部项目）');
    check('应用过滤结果后重新打开：搜索框已重置、3 个项目全部可见', (await evaluate(`(document.querySelector('#projectMenu #projectSearchInput')||{}).value||''`)) === '' && (await evaluate(projSearchVisibleCount)) === 3);
    await evaluate(click('#projectMenu [data-proj-all]'));
    await sleep(120);
    check('恢复：无查询时「全选」选中全部 3 个项目', (await evaluate(projSearchCheckedCount)) === 3);
    await evaluate(click('#projectMenu [data-proj-apply]'));
    await waitUntil(`${rows} === 10`, '恢复全部项目 10 条', 20000);
    check('恢复全部项目（10 条），保持后续用例前置状态', true);

    /* 清空 + 应用：空状态、不请求 */
    await evaluate(click('#projectPickerBtn'));
    await evaluate(click('#projectMenu [data-proj-none]'));
    await evaluate(click('#projectMenu [data-proj-apply]'));
    await sleep(300);
    check('应用空选 -> 看板显示「请先选择项目」', (await evaluate(text('#resultsBody'))).includes('请先选择项目'));
    check('应用空选 -> 不查询数据（0 行）', (await evaluate(rows)) === 0);
    check('应用空选 -> 按钮显示「选择项目」', (await evaluate(text('#projectPickerBtn'))).includes('选择项目'));
    await evaluate(click('#projectPickerBtn'));
    await evaluate(click('#projectMenu [data-proj-all]'));
    await evaluate(click('#projectMenu [data-proj-apply]'));
    await waitUntil(`${rows} === 10`, '重新全选恢复 10 条', 20000);

    await evaluate(`(function(){var i=document.querySelector('#searchInput');i.value='SQL Injection';i.dispatchEvent(new Event('input',{bubbles:true}));return true;})()`);
    await sleep(400);
    check('搜索 SQL Injection（1 条）', (await evaluate(rows)) === 1);
    await evaluate(`(function(){var i=document.querySelector('#searchInput');i.value='';i.dispatchEvent(new Event('input',{bubbles:true}));return true;})()`);
    await sleep(400);

    /* ---------- 3.5 记住上一次选择（项目 + 分支 + 严重级别） ---------- */
    console.log('\n=== 3.5 记住上一次选择 ===');
    await evaluate(`(function(){var s=document.querySelector('#branchSelect');s.value='develop';s.dispatchEvent(new Event('change',{bubbles:true}));return true;})()`);
    await waitUntil(`${rows} === 5`, '分支 develop 结果（5 条）', 15000);
    await sleep(250);
    await send('Page.navigate', { url: APP });
    await waitUntil(`${rows} === 5`, '刷新后自动恢复分支选择', 25000);
    check('刷新后记住上一次分支选择（develop / 5 条）', true);
    check('分支下拉恢复为 develop', (await evaluate(`document.querySelector('#branchSelect').value`)) === 'develop');
    await evaluate(`(function(){var s=document.querySelector('#branchSelect');s.value='';s.dispatchEvent(new Event('change',{bubbles:true}));return true;})()`);
    await waitUntil(`${rows} === 10`, '恢复全部分支', 15000);

    /* 严重级别记忆：关闭 High 后刷新，应恢复为同样的等级筛选（10 - 4 = 6 条） */
    await evaluate(click('[data-sev="HIGH"]'));
    await sleep(200);
    check('关闭 High 后显示 6 条', (await evaluate(rows)) === 6);
    await sleep(250);
    await send('Page.navigate', { url: APP });
    await waitUntil(`${rows} === 6`, '刷新后自动恢复严重级别筛选', 25000);
    check('刷新后记住上一次严重级别选择（High 关闭 / 6 条）', true);
    check('High 标签恢复为关闭态', await evaluate(`document.querySelector('[data-sev="HIGH"]').classList.contains('off')`));
    check('严重级别记忆写入本机 localStorage', await evaluate(`(function(){try{var raw=JSON.parse(localStorage.getItem('cxs_filter_v1')||'{}');var k=Object.keys(raw)[0];return !!k&&Array.isArray(raw[k].sevs)&&raw[k].sevs.length===4&&raw[k].sevs.indexOf('HIGH')<0;}catch(e){return false;}})()`));
    await evaluate(click('[data-sev="HIGH"]'));
    await waitUntil(`${rows} === 10`, '恢复全部严重级别（10 条）', 10000);
    check('恢复 High 后回到 10 条', true);

    /* 项目记忆：只应用 payment-service（4 条），刷新后应自动恢复 */
    await evaluate(click('#projectPickerBtn'));
    await evaluate(click('#projectMenu [data-proj-none]'));
    await evaluate(click(`#projectMenu [data-project="${key.projects['p-1001']}"] input`));
    await evaluate(click('#projectMenu [data-proj-apply]'));
    await waitUntil(`${rows} === 4`, '只选 payment-service（4 条）', 20000);
    await sleep(250);
    await send('Page.navigate', { url: APP });
    await waitUntil(`${rows} === 4`, '刷新后自动恢复项目选择（4 条）', 25000);
    check('刷新后记住上一次项目选择（仅 payment-service / 4 条）', true);
    check('按钮显示上次选择的项目名', (await evaluate(text('#projectPickerBtn'))).includes('payment-service'));

    /* 恢复全部项目，供后续用例使用 */
    await evaluate(click('#projectPickerBtn'));
    await evaluate(click('#projectMenu [data-proj-all]'));
    await evaluate(click('#projectMenu [data-proj-apply]'));
    await waitUntil(`${rows} === 10`, '恢复全部项目 10 条', 20000);
    check('重新应用全部项目（10 条）', true);

    /* ---------- 4. 详情抽屉 ---------- */
    console.log('\n=== 4. 漏洞详情抽屉 ===');
    await evaluate(click('#resultsBody tr[data-id]'));
    await waitUntil(`document.querySelector('#detailDrawer').classList.contains('open')`, '详情抽屉打开');
    const detailText = await evaluate(text('#detailContent'));
    check('详情包含攻击向量', detailText.includes('攻击向量'));
    check('详情包含污点数据流（来自 API data.nodes）', detailText.includes('污点数据流') && detailText.includes('BackupTask.java'));
    check('详情包含修复建议与代码示例', detailText.includes('修复建议') && detailText.includes('错误示例') && detailText.includes('修复后'));
    check('详情包含 learn more 参考链接（CWE/OWASP）', detailText.includes('参考链接') && detailText.includes('CWE-'));
    await sleep(300);
    await shot('real-detail.png');

    /* 一键复制：漏洞说明 / 攻击向量（含污点数据流序号/类名/行号）/ 污点数据流 / 修复建议 / 参考链接 */
    await evaluate(`(function(){window.__copied='';try{Object.defineProperty(navigator,'clipboard',{configurable:true,value:{writeText:function(t){window.__copied=String(t);return Promise.resolve();}}});}catch(e){}return true;})()`);
    check('漏洞说明 / 攻击向量 / 污点数据流 / 修复建议 / 参考链接均提供一键复制按钮', (await evaluate(`document.querySelectorAll('.dt-sec h4 .sec-copy').length`)) === 5);
    await evaluate(click('[data-copy-attack]'));
    await sleep(250);
    const attackCopy = await evaluate('window.__copied || ""');
    check('攻击向量一键复制：含漏洞信息 / 攻击向量 / Payload', attackCopy.includes('【漏洞】Command Injection') && attackCopy.includes('【攻击向量】') && attackCopy.includes('【攻击示例 / Payload】'));
    check('攻击向量一键复制：保留数据流序号 / 类名 / 行号', /1\. \[source\] BackupTask\.java:66/.test(attackCopy) && /2\. \[sink\] BackupTask\.java:71/.test(attackCopy) && attackCopy.includes('request.getParameter'));
    check('攻击向量一键复制后有成功提示', (await evaluate(`((document.querySelector('.toast-stack .toast:last-child')||{}).innerText||'')`)).includes('攻击向量已复制'));
    await evaluate(click('[data-copy-flow]'));
    await sleep(250);
    const flowCopy = await evaluate('window.__copied || ""');
    check('污点数据流一键复制：仅含编号数据流且保留行号', flowCopy.includes('【污点数据流】共 2 步') && /1\. \[source\] BackupTask\.java:66/.test(flowCopy) && /2\. \[sink\] BackupTask\.java:71/.test(flowCopy) && !flowCopy.includes('【攻击向量】'));
    await evaluate(click('[data-copy-desc]'));
    await sleep(250);
    const descCopy = await evaluate('window.__copied || ""');
    check('漏洞说明一键复制：含标题与描述原文', descCopy.startsWith('【漏洞说明】') && descCopy.includes('系统命令执行'));
    check('漏洞说明一键复制后有成功提示', (await evaluate(`((document.querySelector('.toast-stack .toast:last-child')||{}).innerText||'')`)).includes('漏洞说明已复制'));
    await evaluate(click('[data-copy-remediation]'));
    await sleep(250);
    const remCopy = await evaluate('window.__copied || ""');
    check('修复建议一键复制：含修复方案与错误/修复代码示例', remCopy.includes('【修复建议】') && remCopy.includes('修复方案：') && remCopy.includes('✗ 错误示例：') && remCopy.includes('✓ 修复后：'));
    await evaluate(click('[data-copy-refs]'));
    await sleep(250);
    const refsCopy = await evaluate('window.__copied || ""');
    check('参考链接一键复制：以【参考链接】标题开头，含 CWE / OWASP / Query Help 名称与 URL', refsCopy.startsWith('【参考链接】') && refsCopy.includes('CWE-78') && refsCopy.includes('https://cwe.mitre.org') && refsCopy.includes('https://owasp.org') && refsCopy.includes('docs.checkmarx.com'));
    check('各区块一键复制结果均以【区块名】标题开头（格式一致）', [attackCopy, flowCopy, descCopy, remCopy, refsCopy].every((t) => /^【[^】]+】/.test(t)));

    /* 复制文本规范化：数据里的特殊空白字符一律变成标准空格（页面显示不变，只影响复制结果） */
    await evaluate(`(function(){var pre=document.querySelector('.payload pre');if(!pre)return false;pre.textContent='a\\u00a0b\\u3000c\\u200bd\\te\\r\\nf';return true;})()`);
    await evaluate(click('[data-copy-payload]'));
    await sleep(200);
    const payloadCopy = await evaluate('window.__copied || ""');
    check('复制攻击示例：特殊空白统一为标准空格（不间断/全角/零宽/Tab/CRLF）', payloadCopy === 'a b cd    e\nf', JSON.stringify(payloadCopy));
    const copyProbe = await evaluate(`(function(){
      var host=document.createElement('div');
      host.textContent='x\\u00a0y\\u3000z\\u200b\\tw';
      document.body.appendChild(host);
      var range=document.createRange();range.selectNodeContents(host);
      var sel=window.getSelection();sel.removeAllRanges();sel.addRange(range);
      var ev=new ClipboardEvent('copy',{bubbles:true,cancelable:true,clipboardData:new DataTransfer()});
      host.dispatchEvent(ev);
      var out=ev.clipboardData.getData('text/plain');
      var prevented=ev.defaultPrevented;
      sel.removeAllRanges();host.remove();
      return {out:out,prevented:prevented};
    })()`);
    check('页面框选复制（copy 事件）同样只输出标准空格与标准换行', copyProbe.prevented === true && /^x y z\s+w$/.test(copyProbe.out) && !/[\u00a0\u3000\u200b]/.test(copyProbe.out), JSON.stringify(copyProbe));

    /* 漏洞名称一行「复制漏洞信息」：一次复制完整 9 项 */
    check('漏洞名称一行提供「复制漏洞信息」按钮', await evaluate(`!!document.querySelector('.dt-title-row [data-dt-act="copy-full"]')`));
    await evaluate(click('.dt-title-row [data-dt-act="copy-full"]'));
    await sleep(250);
    const fullCopy = await evaluate('window.__copied || ""');
    const fullKeys = ['【漏洞类型】', '【风险等级】', '【CWE编号】', '【受影响文件】', '【漏洞说明】', '【攻击向量】', '【污点数据流】', '【修复建议】', '【参考链接】'];
    check('复制漏洞信息：9 项齐全且顺序正确', fullKeys.every((k, i) => fullCopy.indexOf(k) >= 0 && (i === 0 || fullCopy.indexOf(fullKeys[i - 1]) < fullCopy.indexOf(k))));
    check('复制漏洞信息：含关键内容与数据流序号/行号', fullCopy.includes('Command Injection') && fullCopy.includes('CRITICAL') && fullCopy.includes('CWE-78') && fullCopy.includes('BackupTask.java:71') && fullCopy.includes('1. [source] BackupTask.java:66') && fullCopy.includes('https://cwe.mitre.org'));

    const title1 = await evaluate(text('.dt-title'));
    await evaluate(click('[data-detail-nav="next"]'));
    await sleep(200);
    const title2 = await evaluate(text('.dt-title'));
    check('详情支持上下切换', title1 !== title2, title1 + ' -> ' + title2);
    await sleep(200);

    /* 无污点数据流的结果：缺失字段整段省略 */
    await evaluate(click('[data-close-detail]'));
    await sleep(200);
    await openDetailByText('Missing HSTS');
    await sleep(300);
    await evaluate(click('.dt-title-row [data-dt-act="copy-full"]'));
    await sleep(250);
    const hstsCopy = await evaluate('window.__copied || ""');
    check('复制漏洞信息：无污点数据流时整段省略该字段', hstsCopy.includes('【漏洞类型】Missing HSTS Header') && !hstsCopy.includes('【污点数据流】') && hstsCopy.includes('【参考链接】'));
    await evaluate(click('[data-close-detail]'));
    await sleep(300);

    /* ---------- 5. 设置弹窗 ---------- */
    console.log('\n=== 5. 设置弹窗 ===');
    await evaluate(click('#settingsBtn'));
    await waitUntil(`document.querySelector('#settingsModal').classList.contains('open')`, '设置弹窗打开');
    const settingsText = await evaluate(text('#settingsParse'));
    check('设置显示 API Key 自动解析的租户', settingsText.includes('mocktenant'), settingsText.replace(/\n/g, ' ').slice(0, 90));
    await evaluate(click('#settingsModal [data-close-modal="settingsModal"]'));
    await sleep(200);

    /* ---------- 5.5 抽屉：无横向滚动条 + 拖拽调整宽度 ---------- */
    console.log('\n=== 5.5 抽屉无横向滚动 + 拖拽宽度 ===');
    await evaluate(click('#openLinkBtn'));
    await waitUntil(`document.querySelector('#linkModal').classList.contains('open')`, '扫描链接弹窗打开');
    const stressUrl = 'https://acme.checkmarx.net/#/projects/' + key.projects['p-1001'] + '/scans/' + key.scans['s-1001-b'];
    await evaluate(`(function(){var i=document.querySelector('#linkInput');i.value=${JSON.stringify(stressUrl)};return true;})()`);
    await evaluate(click('#linkOpenBtn'));
    await waitUntil(`!document.querySelector('#linkModal').classList.contains('open')`, '链接弹窗关闭');
    await waitUntil(`${rows} === 2`, '超长内容扫描结果（2 条）', 20000);
    await openDetailByText('ExtremelyLongQueryName');
    let ov = await drawerOverflow();
    check('超长内容下抽屉无横向滚动条', ov.overflowX === 'hidden' && ov.scrollWidth <= ov.clientWidth + 1, JSON.stringify(ov));

    check('抽屉默认宽度 520px', Math.abs((await drawerWidth()) - 520) <= 1, await drawerWidth());
    const vw = await evaluate('window.innerWidth');
    const expectMax = Math.max(420, Math.floor(vw * 0.7));
    await dragDrawerBy(1400);
    check('拖拽上限 = 70vw（含最小 420px 兜底）', Math.abs((await drawerWidth()) - expectMax) <= 2, (await drawerWidth()) + ' / ' + expectMax);
    ov = await drawerOverflow();
    check('最宽时抽屉仍无横向滚动条', ov.scrollWidth <= ov.clientWidth + 1, JSON.stringify(ov));
    await shot('real-drawer-wide.png');

    await dragDrawerBy(-3000);
    check('拖拽下限 = 420px', Math.abs((await drawerWidth()) - 420) <= 2, await drawerWidth());
    ov = await drawerOverflow();
    check('最窄时抽屉仍无横向滚动条（超长内容）', ov.scrollWidth <= ov.clientWidth + 1, JSON.stringify(ov));

    await dragDrawerBy(280); // 420 -> ~700（向左拖拽 = 变宽）
    const w700 = await drawerWidth();
    check('拖拽到约 700px', w700 >= 640 && w700 <= 760, w700);
    await dblclickResizer();
    check('双击拖拽手柄恢复默认 520px', Math.abs((await drawerWidth()) - 520) <= 2, await drawerWidth());

    await dragDrawerBy(140); // 520 -> ~660（向左拖拽 = 变宽）
    const w660 = await drawerWidth();
    check('拖拽到约 660px', w660 >= 630 && w660 <= 700, w660);
    await evaluate(click('[data-close-detail]'));
    await sleep(350);
    await openDetailByText('ExtremelyLongQueryName');
    check('关闭后重新打开沿用记忆宽度', Math.abs((await drawerWidth()) - w660) <= 2, (await drawerWidth()) + ' vs ' + w660);

    await send('Page.navigate', { url: APP });
    await waitUntil(`${rows} === 10`, '刷新后自动登录', 25000);
    await openDetailByText('Command Injection');
    check('刷新页面后仍记住抽屉宽度', Math.abs((await drawerWidth()) - w660) <= 2, (await drawerWidth()) + ' vs ' + w660);
    await dblclickResizer(); // 恢复默认，避免影响后续截图
    await evaluate(click('[data-close-detail]'));
    await sleep(300);

    /* ---------- 6. 扫描链接 ---------- */
    console.log('\n=== 6. 扫描链接打开 ===');
    await evaluate(click('#openLinkBtn'));
    await waitUntil(`document.querySelector('#linkModal').classList.contains('open')`, '扫描链接弹窗打开');
    const scanUrl = 'https://acme.checkmarx.net/#/projects/' + key.projects['p-1002'] + '/scans/' + key.scans['s-1002-b'];
    await evaluate(`(function(){var i=document.querySelector('#linkInput');i.value=${JSON.stringify(scanUrl)};return true;})()`);
    await evaluate(click('#linkOpenBtn'));
    await waitUntil(`!document.querySelector('#linkModal').classList.contains('open')`, '链接弹窗关闭');
    await waitUntil(`${rows} === 3`, '扫描链接定位到指定扫描（3 条）', 20000);
    check('粘贴扫描页面链接 -> 定位该扫描结果（develop 扫描 3 条）', true);

    /* ---------- 7. 本地扫描（Checkmarx One CLI） ---------- */
    console.log('\n=== 7. 本地扫描（Checkmarx One CLI） ===');
    await evaluate(click('#localScanBtn'));
    await waitUntil(`document.querySelector('#scanModal').classList.contains('open')`, '本地扫描弹窗打开');
    await sleep(300);   // 等弹窗与项目列表刷新完成，避免下拉首次点击时序不稳
    /* 项目名：从已有 Checkmarx One 项目中搜索选择；新项目直接输入名称 */
    check('项目名输入框为可搜索组合框（下拉按钮 + 状态徽标）', await evaluate(`(function(){var r=document.querySelector('#scanFolders [data-folder-row]');return !!r.querySelector('.pname') && !!r.querySelector('.pn-toggle') && !!r.querySelector('[data-pn-badge]');})()`));
    check('未聚焦时项目下拉默认隐藏', await evaluate(`document.querySelector('#scanProjectMenu').classList.contains('hidden')`));
    await evaluate(click('#scanFolders [data-folder-row] .pname'));
    await sleep(300);
    await waitUntil(`!document.querySelector('#scanProjectMenu').classList.contains('hidden') && document.querySelectorAll('#scanProjectMenu .pn-item[data-project-id]').length === 3`, '项目下拉列出已有项目', 15000);
    const scanProjNames = JSON.parse(await evaluate(`JSON.stringify(Array.prototype.map.call(document.querySelectorAll('#scanProjectMenu .pn-item[data-project-id]'),function(o){return o.getAttribute('data-name');}))`));
    check('项目下拉列出已有 Checkmarx One 项目（payment-service / user-center / web-portal）', ['payment-service', 'user-center', 'web-portal'].every((n) => scanProjNames.indexOf(n) >= 0), JSON.stringify(scanProjNames));
    await evaluate(`(function(){var i=document.querySelector('#scanFolders [data-folder-row] .pname');i.value='user';i.dispatchEvent(new Event('input',{bubbles:true}));return true;})()`);
    await waitUntil(`document.querySelectorAll('#scanProjectMenu .pn-item[data-project-id]').length === 1`, '按关键词过滤已有项目');
    const scanProjFilter = JSON.parse(await evaluate(`(function(){var it=document.querySelector('#scanProjectMenu .pn-item[data-project-id]');var m=it&&it.querySelector('.pn-name mark');return JSON.stringify({name:it?it.getAttribute('data-name'):'',mark:!!m,markText:m?m.textContent:''});})()`));
    check('输入关键词实时筛选已有项目（user -> user-center）', scanProjFilter.name === 'user-center', JSON.stringify(scanProjFilter));
    check('筛选命中片段以 <mark> 高亮', scanProjFilter.mark && scanProjFilter.markText.toLowerCase() === 'user', scanProjFilter.markText);
    check('未匹配完整项目名时提供「新建项目」条目', await evaluate(`(function(){var el=document.querySelector('#scanProjectMenu .pn-item[data-pn-new]');return !!el && el.innerText.indexOf('新建项目')>=0;})()`));
    await shot('real-local-scan.png');
    await evaluate(`(function(){var el=document.querySelector('#scanProjectMenu .pn-item[data-project-id][data-name="user-center"]');if(el)el.click();return true;})()`);
    await sleep(200);
    check('点选已有项目后写入项目名并标记「已有」', (await evaluate(`document.querySelector('#scanFolders [data-folder-row] .pname').value`)) === 'user-center' && (await evaluate(`document.querySelector('#scanFolders [data-folder-row]').getAttribute('data-pstate')`)) === 'existing');
    check('选中已有项目后下拉关闭', await evaluate(`document.querySelector('#scanProjectMenu').classList.contains('hidden')`));
    await evaluate(`(function(){
        var row=document.querySelector('#scanFolders [data-folder-row]');
        var p=row.querySelector('.fpath'); p.value=${JSON.stringify(fixture)}; p.dispatchEvent(new Event('input',{bubbles:true}));
        return true;
    })()`);
    if (gitReady) {
      await waitUntil(`document.querySelector('#scanBranch').value === 'develop'`, '自动读取 git 分支并默认当前检出分支', 15000);
      const branchOpts = JSON.parse(await evaluate(`JSON.stringify(Array.prototype.map.call(document.querySelectorAll('#scanBranchMenu .bp-item'), function(o){return o.getAttribute('data-branch');}))`));
      check('git 分支下拉列出仓库分支（master / develop）',
        branchOpts.indexOf('master') >= 0 && branchOpts.indexOf('develop') >= 0, JSON.stringify(branchOpts));
      check('默认分支优先级：当前检出分支 develop 优先于 master', true);
      check('分支提示显示当前检出分支',
        (await evaluate(text('#scanBranchHint'))).indexOf('当前检出分支') >= 0, await evaluate(text('#scanBranchHint')));
      /* 点 ▾ 打开分支下拉浮层，选中 master 再切回 develop（验证点选可用） */
      await evaluate(click('#scanBranchToggle'));
      check('点「▾」打开分支下拉浮层',
        await evaluate(`!document.querySelector('#scanBranchMenu').classList.contains('hidden') && document.querySelectorAll('#scanBranchMenu .bp-item').length >= 2`));
      await evaluate(`(function(){var b=document.querySelector('#scanBranchMenu .bp-item[data-branch="master"]');if(b)b.click();return true;})()`);
      check('点选分支 master 后写入输入框', (await evaluate(`document.querySelector('#scanBranch').value`)) === 'master');
      await evaluate(`(function(){var i=document.querySelector('#scanBranch');i.value='develop';i.dispatchEvent(new Event('input',{bubbles:true}));return true;})()`);
      await shot('real-scan-branch-git.png');
    } else {
      check('未安装 git：分支控件回退为可手动输入（跳过 git 分支断言）',
        (await evaluate(`document.querySelector('#scanBranch').tagName`)) === 'INPUT');
    }
    /* 非 git 文件夹：回退为手动输入并给出提示，分支默认值保留 */
    await evaluate(`(function(){var p=document.querySelector('#scanFolders [data-folder-row] .fpath');p.value=${JSON.stringify(plainFolder)};p.dispatchEvent(new Event('input',{bubbles:true}));return true;})()`);
    await waitUntil(`document.querySelector('#scanBranchHint').innerText.indexOf('未读取到 git 分支') >= 0`, '非 git 文件夹回退提示', 15000);
    check('非 git 文件夹回退：提示可手动输入且分支默认值保留',
      (await evaluate(`document.querySelector('#scanBranch').value`)).length > 0, await evaluate(text('#scanBranchHint')));
    /* 恢复 git 仓库，再加一个不存在的文件夹，验证失败详情在下方展示 */
    await evaluate(`(function(){
        var p=document.querySelector('#scanFolders [data-folder-row] .fpath');p.value=${JSON.stringify(fixture)};p.dispatchEvent(new Event('input',{bubbles:true}));
        var n=document.querySelector('#scanFolders [data-folder-row] .pname');n.value='local-demo-svc';n.dispatchEvent(new Event('input',{bubbles:true}));
        return true;
    })()`);
    await waitUntil(`document.querySelector('#scanBranch').value === 'develop'`, '恢复 git 仓库默认分支', 15000);
    await waitUntil(`document.querySelector('#scanFolders [data-folder-row]').getAttribute('data-pstate') === 'new'`, '新项目名标记为「新项目」', 5000);
    check('手输不存在的项目名标记为「新项目」（提交时自动创建）', true);
    await evaluate(click('#addFolderBtn'));
    await evaluate(`(function(){
        var rows=document.querySelectorAll('#scanFolders [data-folder-row]');
        var row=rows[rows.length-1];
        var p=row.querySelector('.fpath'); p.value='C:\\\\cx-e2e-not-exists-folder'; p.dispatchEvent(new Event('input',{bubbles:true}));
        var n=row.querySelector('.pname'); n.value='bad-folder'; n.dispatchEvent(new Event('input',{bubbles:true}));
        return true;
    })()`);
    await evaluate(click('#startScanBtn'));
    await waitUntil(`!!document.querySelector('#scanProgress [data-prog="1"]')`, '扫描进度出现两个文件夹', 15000);
    /* 文件夹路径 + Checkmarx 项目名写入本机记忆（按租户隔离） */
    const scanMem = JSON.parse(await evaluate(`localStorage.getItem('cxs_scan_memory_v1') || '{}'`));
    const scanMemRec = scanMem[Object.keys(scanMem)[0] || ''] || {};
    const scanMemRows = scanMemRec.rows || [];
    check('本地扫描的文件夹路径与 Checkmarx 项目名写入本机记忆',
      scanMemRows.length === 2 &&
      scanMemRows[0].path === fixture && scanMemRows[0].name === 'local-demo-svc' &&
      scanMemRows[1].path === 'C:\\cx-e2e-not-exists-folder' && scanMemRows[1].name === 'bad-folder',
      JSON.stringify(scanMemRows));
    check('「最近扫描」记录最近提交的文件夹与项目名',
      Array.isArray(scanMemRec.recent) && scanMemRec.recent.length === 2 &&
      scanMemRec.recent.some((r) => r.path === fixture && r.name === 'local-demo-svc'),
      JSON.stringify(scanMemRec.recent));
    await sleep(120);
    await evaluate(click('#scanMinBtn'));
    check('扫描中最小化：弹窗收起并显示左下浮动进度条',
      await evaluate(`!document.querySelector('#scanModal').classList.contains('open') && !document.querySelector('#scanMini').classList.contains('hidden')`));
    await shot('real-local-scan-minimized.png');
    await waitUntil(`!document.querySelector('#scanSummary').classList.contains('hidden')`, '本地扫描完成', 60000);
    check('最小化时扫描完成（含失败）：浮动条切换到失败/结束状态并触发通知',
      (await evaluate(`document.querySelector('#scanMini').dataset.state`)) === 'err');
    check('浮动条显示成功/失败数量',
      (await evaluate(`document.querySelector('#scanMiniText').innerText`)).indexOf('失败 1') >= 0,
      await evaluate(`document.querySelector('#scanMiniText').innerText`));
    check('扫描完成 toast 通知可见',
      (await evaluate(`(document.querySelector('#toastStack')||{innerText:''}).innerText`)).indexOf('本地扫描结束') >= 0);
    await evaluate(click('#scanMini'));
    await sleep(250);
    check('点击浮动进度条恢复扫描弹窗',
      await evaluate(`document.querySelector('#scanModal').classList.contains('open') && document.querySelector('#scanMini').classList.contains('hidden')`));
    check('部分失败时汇总显示成功/失败数量',
      (await evaluate(text('#scanSummary'))).indexOf('部分扫描未完成') >= 0, await evaluate(text('#scanSummary')));
    check('失败异常在进度模块下方以全宽错误块展示',
      await evaluate(`!document.querySelector('#scanErrors').classList.contains('hidden') && document.querySelector('#scanErrors').offsetTop > document.querySelector('#scanProgress').offsetTop`));
    check('失败详情包含异常原因', (await evaluate(text('#scanErrors'))).indexOf('不存在') >= 0, (await evaluate(text('#scanErrors'))).slice(0, 160));
    const scanOverflow = JSON.parse(await evaluate(`(function(){var b=document.querySelector('#scanModal .modal-body');return JSON.stringify({sw:b.scrollWidth,cw:b.clientWidth,ox:getComputedStyle(b).overflowX});})()`));
    check('扫描弹窗无横向滚动条', scanOverflow.sw <= scanOverflow.cw + 1 && scanOverflow.ox === 'hidden', JSON.stringify(scanOverflow));
    const failSt = await evaluate(`document.querySelector('#scanProgress [data-prog="1"] .st').innerText`);
    check('进度行仅显示简短失败状态（长异常在下方错误块）', failSt.indexOf('不存在') < 0 && failSt.length <= 12, failSt);
    await shot('real-local-scan-errors.png');
    await evaluate(click('#viewLocalResultsBtn'));
    await waitUntil(`document.querySelector('#resultsBody').innerText.includes('Hardcoded API Key')`, '本地扫描结果回填', 30000);
    await waitUntil(`${rows} === 3`, '本地扫描结果 3 条', 15000);
    check('本地扫描结果回填看板（3 条）', true);
    await waitUntil(`document.querySelector('#projectPickerBtn .val').innerText.indexOf('local-demo-svc') >= 0`, '项目切到本地扫描项目', 15000);
    check('项目范围切到本地扫描项目', true, await evaluate(text('#projectPickerBtn')));
    const localText = await evaluate(text('#resultsBody'));
    check('本地扫描结果包含本地漏洞（Hardcoded API Key / Insecure Cookie 等）', localText.includes('Hardcoded API Key') && localText.includes('Insecure Cookie'));
    await shot('real-local-results.png');

    /* ---------- 7.1 扫描记忆：刷新后自动恢复文件夹与项目名 ---------- */
    console.log('\n=== 7.1 本地扫描记忆（刷新后自动恢复） ===');
    await send('Page.navigate', { url: APP });
    await waitUntil(`${rows} === 3`, '刷新后自动登录并恢复本地扫描项目', 25000);
    await evaluate(click('#localScanBtn'));
    await waitUntil(`document.querySelector('#scanModal').classList.contains('open')`, '再次打开本地扫描弹窗');
    await sleep(500);
    const restoredRows = JSON.parse(await evaluate(`(function(){return JSON.stringify(Array.prototype.map.call(document.querySelectorAll('#scanFolders [data-folder-row]'),function(r){return {path:r.querySelector('.fpath').value,name:r.querySelector('.pname').value};}));})()`));
    check('刷新页面后自动恢复上次扫描的文件夹路径与 Checkmarx 项目名',
      restoredRows.length === 2 && restoredRows[0].path === fixture && restoredRows[0].name === 'local-demo-svc' &&
      restoredRows[1].path === 'C:\\cx-e2e-not-exists-folder' && restoredRows[1].name === 'bad-folder',
      JSON.stringify(restoredRows));
    check('「最近扫描」列出可一键填入的历史目标',
      await evaluate(`(function(){var box=document.querySelector('#scanRecent');return !!box && !box.classList.contains('hidden') && document.querySelectorAll('#scanRecent .sr-chip').length === 2;})()`));
    await shot('real-local-scan-memory.png');

    /* ---------- 7.2 本地扫描：选择已有项目（CLI 按项目名匹配） ---------- */
    console.log('\n=== 7.2 本地扫描：选择已有项目（CLI 按项目名匹配） ===');
    await evaluate(click('#localScanBtn'));
    await waitUntil(`document.querySelector('#scanModal').classList.contains('open')`, '再次打开本地扫描弹窗');
    /* 只保留一个文件夹（移除上次失败文件夹），改为扫描已有项目 payment-service */
    await evaluate(`(function(){var rows=document.querySelectorAll('#scanFolders [data-folder-row]');if(rows.length>1){rows[rows.length-1].querySelector('[data-remove-folder]').click();}return true;})()`);
    /* 「最近扫描」一键填入：单行时替换当前行 */
    await evaluate(`(function(){var chips=document.querySelectorAll('#scanRecent .sr-chip');for(var i=0;i<chips.length;i++){if((chips[i].getAttribute('data-path')||'').indexOf('cx-e2e-not-exists-folder')>=0){chips[i].click();return true;}}return false;})()`);
    await sleep(250);
    const chipFilled = JSON.parse(await evaluate(`(function(){var row=document.querySelector('#scanFolders [data-folder-row]');return JSON.stringify({path:row.querySelector('.fpath').value,name:row.querySelector('.pname').value,count:document.querySelectorAll('#scanFolders [data-folder-row]').length});})()`));
    check('点击「最近扫描」一键填入文件夹与 Checkmarx 项目名',
      chipFilled.count === 1 && chipFilled.path === 'C:\\cx-e2e-not-exists-folder' && chipFilled.name === 'bad-folder',
      JSON.stringify(chipFilled));
    await evaluate(`(function(){
        var row=document.querySelector('#scanFolders [data-folder-row]');
        var p=row.querySelector('.fpath'); p.value=${JSON.stringify(fixture)}; p.dispatchEvent(new Event('input',{bubbles:true}));
        var n=row.querySelector('.pname'); n.value='payment-service'; n.dispatchEvent(new Event('input',{bubbles:true}));
        return true;
    })()`);
    await sleep(200);
    check('输入完整已有项目名自动匹配并标记「已有」', (await evaluate(`document.querySelector('#scanFolders [data-folder-row]').getAttribute('data-pstate')`)) === 'existing');
    await evaluate(click('#startScanBtn'));
    await waitUntil(`!document.querySelector('#scanSummary').classList.contains('hidden')`, '已有项目本地扫描完成', 60000);
    await evaluate(click('#viewLocalResultsBtn'));
    await waitUntil(`(document.querySelector('#toastStack')||{innerText:''}).innerText.indexOf('已切换到本地扫描项目：payment-service') >= 0`, '结果回填到已有项目 payment-service', 30000);
    await waitUntil(`${rows} === 3`, '已有项目扫描结果 3 条', 15000);
    check('选择已有项目后扫描创建在该项目下（CLI 按项目名匹配已有项目，结果回填原项目）', (await evaluate(text('#projectPickerBtn'))).includes('payment-service'));
    await shot('real-local-existing-project.png');

    /* ---------- 7.3 本地扫描走 CLI：断言代理确实调用 Checkmarx One CLI ---------- */
    console.log('\n=== 7.3 本地扫描走 CLI 断言 ===');
    const cliCalls = fs.existsSync(fakeCliRecord)
      ? fs.readFileSync(fakeCliRecord, 'utf8').trim().split('\n').filter(Boolean).map((line) => JSON.parse(line))
      : [];
    check('本地扫描由本机 Checkmarx One CLI 执行（记录到 CLI 调用）', cliCalls.length >= 2, '调用次数: ' + cliCalls.length);
    const firstCli = cliCalls[0] || { argv: [] };
    const cliArgs = firstCli.argv || [];
    check('CLI 参数包含 scan create / --async / --scan-info-format json（异步建扫描，页面轮询进度）',
      cliArgs[0] === 'scan' && cliArgs[1] === 'create' && cliArgs.includes('--async') &&
      cliArgs.indexOf('--scan-info-format') >= 0 && cliArgs[cliArgs.indexOf('--scan-info-format') + 1] === 'json',
      JSON.stringify(cliArgs.slice(0, 10)));
    check('CLI 参数包含项目名 / 分支 / 源码目录（-s）',
      cliArgs.indexOf('--project-name') >= 0 && cliArgs.indexOf('local-demo-svc') > 0 &&
      cliArgs.indexOf('--branch') >= 0 && cliArgs.indexOf(fixture) > 0 &&
      (cliArgs.indexOf('-s') >= 0 || cliArgs.indexOf('--file-source') >= 0),
      JSON.stringify(cliArgs.slice(0, 16)));
    check('CLI 通过 --base-uri 连接当前登录的 Checkmarx One（页面登录上下文）',
      (firstCli.baseUriEnv || '') === key.apiBase && cliArgs.indexOf(key.apiBase) > 0, firstCli.baseUriEnv);
    check('页面登录的 API Key 通过 CX_APIKEY 环境变量传给 CLI（不出现在命令行参数中）',
      firstCli.apiKeyEnv === true && !cliArgs.some((arg) => String(arg).indexOf(key.apiKey) >= 0));
    const healthBody = JSON.parse((await httpGet(`http://127.0.0.1:${PROXY_PORT}/health`)).body);
    check('代理健康检查报告本地扫描方式为 CLI 且能定位到 CLI 可执行文件',
      healthBody.scanMode === 'cli' && !!healthBody.cliPath,
      JSON.stringify({ scanMode: healthBody.scanMode, cliPath: healthBody.cliPath }));

    /* ---------- 8. 退出登录 ---------- */
    console.log('\n=== 8. 退出登录 ===');
    await evaluate(click('#settingsBtn'));
    await sleep(300);
    await evaluate(click('#logoutBtn'));
    await waitUntil(`!!document.querySelector('#loginOverlay')`, '退出后重新显示登录页', 10000);
    check('退出登录后重新显示 API Key 登录页', true);
    check('退出登录后保留项目/分支/严重级别记忆', await evaluate(`(function(){try{var raw=JSON.parse(localStorage.getItem('cxs_filter_v1')||'{}');var k=Object.keys(raw);return k.length>0&&Array.isArray(raw[k[0]].projectIds)&&raw[k[0]].projectIds.length===1&&Array.isArray(raw[k[0]].sevs)&&raw[k[0]].sevs.length===5;}catch(e){return false;}})()`));
    check('退出登录后保留本地扫描文件夹/项目名记忆', await evaluate(`(function(){try{var raw=JSON.parse(localStorage.getItem('cxs_scan_memory_v1')||'{}');var k=Object.keys(raw);return k.length>0&&Array.isArray(raw[k[0]].rows)&&raw[k[0]].rows.length>0&&Array.isArray(raw[k[0]].recent)&&raw[k[0]].recent.length>0;}catch(e){return false;}})()`));

    /* 重新登录 -> 恢复上次选择；「清除本机凭据」应同时清除记忆 */
    await evaluate(`(function(){var t=document.querySelector('#apiKeyInput');t.value=${JSON.stringify(key.apiKey)};t.dispatchEvent(new Event('input',{bubbles:true}));document.querySelector('#loginSubmit').click();return true;})()`);
    await waitUntil(`${rows} === 3`, '重新登录并恢复上次选择（3 条）', 25000);
    await waitUntil(`document.querySelector('#projectPickerBtn .val').innerText.indexOf('payment-service') >= 0`, '重新登录后恢复上次项目 payment-service', 25000);
    check('重新登录后自动恢复上次项目选择（payment-service / 3 条）', true);
    await evaluate(click('#settingsBtn'));
    await sleep(300);
    await evaluate(click('#clearKeyBtn'));
    await sleep(250);
    check('「清除本机凭据」同时清除项目/分支/严重级别记忆', await evaluate(`localStorage.getItem('cxs_filter_v1') === null`));
    check('「清除本机凭据」同时清除本地扫描文件夹/项目名记忆', await evaluate(`localStorage.getItem('cxs_scan_memory_v1') === null`));

    /* ---------- 9. JS 错误 ---------- */
    const realErrors = pageErrors.filter((e) => e && !/favicon/i.test(e));
    check('页面无 JS 报错', realErrors.length === 0, realErrors.slice(0, 3).join(' | ').slice(0, 240));

    const failed = results.filter((r) => !r.ok);
    console.log(`\n================ 结果：${results.length - failed.length}/${results.length} 通过 ================`);
    if (failed.length) {
      failed.forEach((f) => console.log('  FAIL: ' + f.name + (f.extra ? '  [' + f.extra + ']' : '')));
      process.exitCode = 1;
    }
    console.log('\n--- mock 日志末尾 ---');
    console.log((mock.stdoutBuf + mock.stderrBuf).split('\n').slice(-8).join('\n'));
    console.log('--- proxy 日志末尾 ---');
    console.log((proxy.stdoutBuf + proxy.stderrBuf).split('\n').slice(-10).join('\n'));
  } catch (e) {
    console.error('\n测试执行失败：', e);
    if (pageErrors.length) console.error('--- 页面 JS 错误 ---\n' + pageErrors.slice(0, 8).join('\n'));
    if (proxy) console.error('--- proxy 日志 ---\n' + (proxy.stdoutBuf + proxy.stderrBuf).split('\n').slice(-30).join('\n'));
    if (mock) console.error('--- mock 日志 ---\n' + (mock.stdoutBuf + mock.stderrBuf).split('\n').slice(-30).join('\n'));
    process.exitCode = 1;
  } finally {
    try { ws && ws.close(); } catch (_) { /* ignore */ }
    for (const child of [chrome, proxy, mock]) {
      try { child && child.kill(); } catch (_) { /* ignore */ }
    }
    await sleep(500);
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) { /* ignore */ }
    try { fs.rmSync(chromeProfile, { recursive: true, force: true }); } catch (_) { /* ignore */ }
  }
})();