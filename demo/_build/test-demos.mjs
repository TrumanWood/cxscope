/**
 * Demo 页面交互冒烟测试（零依赖，Node 22+，通过 Chrome DevTools Protocol 驱动无头 Chrome）。
 *
 * 用法：node demo/_build/test-demos.mjs
 * 验证：auto-login、严重级别筛选、分支筛选、搜索、行详情（抽屉/固定面板/弹窗）、
 *      项目多选、设置弹窗、本地扫描流程（多文件夹 -> 扫描进度 -> 结果回填）。
 */
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..', '..');
const DEMO_DIR = path.join(ROOT, 'demo');
const CHROME = [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe'
].find((p) => fs.existsSync(p));
if (!CHROME) { console.error('未找到 Chrome/Edge'); process.exit(1); }

const PORT = 9333;
const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-demo-test-'));
const chrome = spawn(CHROME, [
  '--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run',
  '--no-default-browser-check', '--remote-allow-origins=*', '--window-size=1600,1000',
  `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`, 'about:blank'
], { stdio: 'ignore' });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function httpGetJson(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => { try { resolve(JSON.parse(body)); } catch (e) { reject(e); } });
    }).on('error', reject);
  });
}

async function waitForDevtools() {
  for (let i = 0; i < 80; i++) {
    try {
      const list = await httpGetJson(`http://127.0.0.1:${PORT}/json/list`);
      const page = list.find((t) => t.type === 'page' && t.webSocketDebuggerUrl);
      if (page) return page;
    } catch (_) { /* not ready */ }
    await sleep(150);
  }
  throw new Error('DevTools 未就绪');
}

let ws;
let nextId = 1;
const pending = new Map();
const pageErrors = [];
let sessionPageErrors = [];

function send(method, params = {}) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function evaluate(expression) {
  const res = await send('Runtime.evaluate', {
    expression, returnByValue: true, awaitPromise: true, userGesture: true
  });
  if (res.exceptionDetails) {
    const d = res.exceptionDetails;
    throw new Error('页面异常: ' + (d.exception && d.exception.description ? d.exception.description : JSON.stringify(d)));
  }
  return res.result ? res.result.value : undefined;
}

async function waitUntil(expression, desc, timeout = 12000, interval = 120) {
  const start = Date.now();
  let last;
  while (Date.now() - start < timeout) {
    try {
      last = await evaluate(expression);
      if (last) return last;
    } catch (e) { last = 'eval-error: ' + e.message; }
    await sleep(interval);
  }
  throw new Error(`等待超时（${desc}），最后值: ${JSON.stringify(last)}`);
}

const results = [];
function check(name, ok, extra) {
  results.push({ name, ok: !!ok, extra });
  console.log(`${ok ? '  ✓' : '  ✗'} ${name}${extra ? '  [' + extra + ']' : ''}`);
}

async function navigate(url) {
  sessionPageErrors = [];
  await send('Page.navigate', { url });
  await waitUntil(`document.readyState === 'complete' && !!document.querySelector('#app')`, '页面加载', 12000);
  await sleep(350);
  // 自动登录后等待表格出现
  if (url.includes('state=board')) {
    await waitUntil(`document.querySelectorAll('#resultsBody tr[data-id]').length > 0`, '表格渲染', 12000);
  }
}

const click = (sel) => `(function(){var e=document.querySelector(${JSON.stringify(sel)});if(!e)return false;e.click();return true;})()`;
const rowCount = `document.querySelectorAll('#resultsBody tr[data-id]').length`;

async function testDemo(demo) {
  console.log(`\n=== ${demo.name} ===`);
  await navigate(demo.base + '#state=board');

  // 1. 登录后看板与登录界面隐藏
  const hasLogin = await evaluate(`!!document.querySelector('#loginOverlay')`);
  check('登录成功后登录界面已隐藏', !hasLogin);
  check('已连接状态显示', (await evaluate(`document.querySelector('#connPill').innerText`)).includes('已连接'));

  // 2. 总共 16 条
  check('初始行数 = 16', (await evaluate(rowCount)) === 16);

  // 3. 点击严重级别标签筛选
  await evaluate(click('[data-sev="CRITICAL"]'));
  await sleep(120);
  const afterCrit = await evaluate(rowCount);
  check('点击 Critical 标签筛选（16 -> 14）', afterCrit === 14, `实际 ${afterCrit}`);
  await evaluate(click('[data-sev="CRITICAL"]'));
  await sleep(120);
  check('再次点击恢复（14 -> 16）', (await evaluate(rowCount)) === 16);

  // 4. 分支筛选
  await evaluate(`(function(){var s=document.querySelector('#branchSelect');s.value='main';s.dispatchEvent(new Event('change',{bubbles:true}));return true;})()`);
  await sleep(150);
  const mainRows = await evaluate(rowCount);
  check('分支 = main 筛选（10 条）', mainRows === 10, `实际 ${mainRows}`);
  await evaluate(`(function(){var s=document.querySelector('#branchSelect');s.value='';s.dispatchEvent(new Event('change',{bubbles:true}));return true;})()`);
  await sleep(150);

  // 5. 搜索
  await evaluate(`(function(){var i=document.querySelector('#searchInput');i.value='SQL Injection';i.dispatchEvent(new Event('input',{bubbles:true}));return true;})()`);
  await sleep(320);
  check('搜索 “SQL Injection”（2 条）', (await evaluate(rowCount)) === 2);
  await evaluate(`(function(){var i=document.querySelector('#searchInput');i.value='';i.dispatchEvent(new Event('input',{bubbles:true}));return true;})()`);
  await sleep(320);
  check('清空搜索恢复 16 条', (await evaluate(rowCount)) === 16);

  // 6. 项目多选
  if (demo.kind === 'classic') {
    await evaluate(click('#projectPickerBtn'));
    await sleep(100);
    await evaluate(click('#projectMenu [data-project="p-1003"] input'));
    await sleep(180);
    check('多项目下拉：取消 web-portal（11 条）', (await evaluate(rowCount)) === 11);
    await evaluate(click('#projectMenu [data-project="p-1003"] input'));
    await sleep(180);
    check('重新勾选 web-portal（16 条）', (await evaluate(rowCount)) === 16);
    await evaluate(click('#projectPickerBtn'));
  } else if (demo.kind === 'board') {
    await evaluate(click('#projectList [data-project="p-1003"] input'));
    await sleep(180);
    check('侧栏项目多选：取消 web-portal（11 条）', (await evaluate(rowCount)) === 11);
    await evaluate(click('#projectList [data-project="p-1003"] input'));
    await sleep(180);
    check('重新勾选 web-portal（16 条）', (await evaluate(rowCount)) === 16);
  } else {
    await evaluate(click('#projectChips [data-project-tab="p-1003"]'));
    await sleep(180);
    check('项目 Tab 多选：取消 web-portal（11 条）', (await evaluate(rowCount)) === 11);
    await evaluate(click('#projectChips [data-project-tab="p-1003"]'));
    await sleep(180);
    check('重新选中 web-portal（16 条）', (await evaluate(rowCount)) === 16);
  }

  // 7. 行详情（抽屉 / 固定面板 / 弹窗）
  await evaluate(click('#resultsBody tr[data-id]'));
  await sleep(300);
  const detailText = await evaluate(`(document.querySelector('#detailContent')||{}).innerText || ''`);
  const openExpr = {
    drawer: `document.querySelector('#detailDrawer').classList.contains('open')`,
    inspector: `document.querySelector('#detailEmpty').classList.contains('hidden') && (document.querySelector('#detailContent').innerText||'').length>100`,
    modal: `document.querySelector('#detailModal').classList.contains('open')`
  }[demo.kind === 'classic' ? 'drawer' : demo.kind === 'board' ? 'inspector' : 'modal'];
  check('点击漏洞行打开详情（' + demo.detailLabel + '）', await evaluate(openExpr));
  check('详情包含攻击向量', detailText.includes('攻击向量'));
  check('详情包含修复建议', detailText.includes('修复建议'));
  check('详情包含 learn more 参考链接', detailText.includes('参考链接') && detailText.includes('CWE-'));
  check('详情包含修复代码示例', detailText.includes('错误示例') && detailText.includes('修复后'));
  const firstTitle = await evaluate(`document.querySelector('.dt-title').innerText`);
  await evaluate(click('[data-detail-nav="next"]'));
  await sleep(200);
  const nextTitle = await evaluate(`document.querySelector('.dt-title').innerText`);
  check('详情支持上一个/下一个切换', firstTitle !== nextTitle, `${firstTitle} -> ${nextTitle}`);
  await evaluate(click('[data-close-detail]'));
  await sleep(260);
  const closed = await evaluate(`(function(){
     var d=document.querySelector('#detailDrawer'); if(d) return !d.classList.contains('open');
     var m=document.querySelector('#detailModal'); if(m) return !m.classList.contains('open');
     var e=document.querySelector('#detailEmpty'); return !!(e && e.offsetParent !== null) || !document.querySelector('#detailContent').innerText;
  })()`);
  check('详情可关闭', closed);

  // 8. 设置弹窗（登录后可随时调出）
  await evaluate(click('#settingsBtn'));
  await sleep(260);
  check('设置弹窗可调出', await evaluate(`document.querySelector('#settingsModal').classList.contains('open')`));
  check('设置中显示 API Key 自动解析信息', (await evaluate(`document.querySelector('#settingsModal').innerText`)).includes('租户'));
  await evaluate(click('#settingsModal [data-close-modal="settingsModal"]'));
  await sleep(200);

  // 9. 本地扫描：多文件夹 -> 进度 -> 结果回填
  await evaluate(click('#localScanBtn'));
  await sleep(260);
  check('本地扫描弹窗可打开', await evaluate(`document.querySelector('#scanModal').classList.contains('open')`));
  await evaluate(`(function(){
      var rows=document.querySelectorAll('#scanFolders [data-folder-row]');
      var i1=rows[0].querySelector('.fpath'); i1.value='E:\\\\demo\\\\svc-a'; i1.dispatchEvent(new Event('input',{bubbles:true}));
      document.querySelector('#addFolderBtn').click();
      rows=document.querySelectorAll('#scanFolders [data-folder-row]');
      var i2=rows[1].querySelector('.fpath'); i2.value='E:\\\\demo\\\\svc-b'; i2.dispatchEvent(new Event('input',{bubbles:true}));
      document.querySelector('#scanAutoLoad').checked=false;
      return rows.length;
  })()`);
  check('支持添加多个文件夹（2 个）', (await evaluate(`document.querySelectorAll('#scanFolders [data-folder-row]').length`)) === 2);
  await evaluate(click('#startScanBtn'));
  await waitUntil(`!document.querySelector('#scanSummary').classList.contains('hidden')`, '本地扫描完成', 20000);
  const summary = await evaluate(`document.querySelector('#scanSummary').innerText`);
  check('多项目扫描进度完成', summary.includes('2 个项目扫描完成'), summary.replace(/\n/g, ' '));
  await evaluate(click('#loadLocalBtn'));
  await sleep(500);
  const localRows = await evaluate(rowCount);
  check('本地扫描结果回填看板（3 条）', localRows === 3, `实际 ${localRows}`);
  const bodyText = await evaluate(`document.body.innerText`);
  check('项目范围切到本地项目', bodyText.includes('svc-a') && bodyText.includes('svc-b'));

  // 10. 退出登录 -> 登录界面重新出现
  await evaluate(click('#settingsBtn'));
  await sleep(200);
  await evaluate(click('#logoutBtn'));
  await sleep(400);
  check('退出登录后重新显示登录界面', await evaluate(`!!document.querySelector('#loginOverlay')`));
  await evaluate(`(function(){var t=document.querySelector('#apiKeyInput');t.value='demo-api-key';document.querySelector('#loginSubmit').click();return true;})()`);
  await waitUntil(`!document.querySelector('#loginOverlay')`, '重新登录成功', 8000);
  check('演示环境可再次登录', !(await evaluate(`!!document.querySelector('#loginOverlay')`)));

  if (sessionPageErrors.length) {
    check('页面无 JS 报错', false, sessionPageErrors.join(' | ').slice(0, 200));
  } else {
    check('页面无 JS 报错', true);
  }
}

(async () => {
  try {
    const page = await waitForDevtools();
    ws = new WebSocket(page.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
    ws.onmessage = (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && pending.has(msg.id)) {
        const { resolve, reject } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) reject(new Error(msg.error.message));
        else resolve(msg.result);
        return;
      }
      if (msg.method === 'Runtime.exceptionThrown') {
        const d = msg.params.exceptionDetails;
        sessionPageErrors.push((d.exception && d.exception.description) || d.text);
      }
      if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
        sessionPageErrors.push(msg.params.args.map((a) => a.value || a.description || '').join(' '));
      }
    };
    await send('Page.enable');
    await send('Runtime.enable');

    const demos = [
      { name: 'Demo 1 · 经典控制台（抽屉）', kind: 'classic', detailLabel: '抽屉', base: 'file:///' + path.join(DEMO_DIR, 'demo-1-classic.html').replace(/\\/g, '/') },
      { name: 'Demo 2 · 看板分栏（固定详情）', kind: 'board', detailLabel: '固定面板', base: 'file:///' + path.join(DEMO_DIR, 'demo-2-board.html').replace(/\\/g, '/') },
      { name: 'Demo 3 · 深色作战室（弹窗）', kind: 'dark', detailLabel: '弹窗', base: 'file:///' + path.join(DEMO_DIR, 'demo-3-dark.html').replace(/\\/g, '/') }
    ];
    for (const d of demos) await testDemo(d);

    const failed = results.filter((r) => !r.ok);
    console.log(`\n================ 结果：${results.length - failed.length}/${results.length} 通过 ================`);
    if (failed.length) {
      failed.forEach((f) => console.log('  FAIL: ' + f.name + (f.extra ? '  [' + f.extra + ']' : '')));
      process.exitCode = 1;
    }
  } catch (e) {
    console.error('\n测试执行失败：', e);
    process.exitCode = 1;
  } finally {
    try { ws && ws.close(); } catch (_) { /* ignore */ }
    chrome.kill();
    await sleep(300);
    try { fs.rmSync(profile, { recursive: true, force: true }); } catch (_) { /* ignore */ }
  }
})();