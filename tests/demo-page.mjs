/**
 * 当前页面 Demo（demo/current-page-demo.html）端到端测试。
 * 零依赖：Node 22+ 内置 WebSocket + Chrome DevTools Protocol，直接打开 file:// 演示页。
 *
 * 用法：node tests/demo-page.mjs
 * 覆盖：演示登录（预填 Demo Key）、自动加载项目并展示数据、严重级别筛选与记忆、
 *       详情抽屉（含漏洞说明/修复建议/参考链接/攻击向量与数据流一键复制（剪贴板文本只含标准空格与标准换行）、
 *       拖拽宽度/无横向滚动）、扫描链接、
 *       本地扫描模拟（项目名组合框筛选已有项目 / 新项目手输 / 多文件夹进度 / 结果回填）、设置/退出登录、
 *       页面不发起任何 http(s) 网络请求、无 JS 报错。
 */
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const DEMO = path.join(ROOT, 'demo', 'current-page-demo.html');
const SHOTS = path.join(ROOT, 'demo', 'shots');
const CDP_PORT = 19444;
const CHROME = [
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'
].find((p) => fs.existsSync(p));
if (!CHROME) { console.error('未找到 Chrome/Edge'); process.exit(1); }
if (!fs.existsSync(DEMO)) { console.error('缺少 ' + DEMO + '，请先运行 python app/build.py'); process.exit(1); }

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function httpGet(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let b = '';
      res.on('data', (c) => (b += c));
      res.on('end', () => resolve(JSON.parse(b || '[]')));
    }).on('error', reject);
  });
}

let ws;
let nextId = 1;
const pending = new Map();
const pageErrors = [];
const networkRequests = [];

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

const results = [];
function check(name, ok, extra) {
  results.push({ name, ok: !!ok, extra });
  console.log(`${ok ? '  ✓' : '  ✗'} ${name}${extra ? '  [' + extra + ']' : ''}`);
}
async function shot(name) {
  const r = await send('Page.captureScreenshot', { format: 'png' });
  const p = path.join(SHOTS, name);
  fs.mkdirSync(SHOTS, { recursive: true });
  fs.writeFileSync(p, Buffer.from(r.data, 'base64'));
  console.log('  📸 ' + name);
}

async function dragDrawerBy(dx) {
  const rect = JSON.parse(await evaluate(`(function(){var r=document.querySelector('#detailDrawer').getBoundingClientRect();return JSON.stringify({left:r.left,top:r.top,width:r.width,height:r.height})})()`));
  const x0 = Math.round(rect.left + 4);
  const y0 = Math.round(rect.top + Math.min(240, rect.height - 40));
  const vw = await evaluate('window.innerWidth');
  const x1 = Math.min(Math.max(Math.round(x0 - dx), 5), vw - 5);
  await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: x0, y: y0, buttons: 0 });
  await send('Input.dispatchMouseEvent', { type: 'mousePressed', x: x0, y: y0, button: 'left', buttons: 1, clickCount: 1 });
  for (let i = 1; i <= 8; i++) {
    await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: Math.round(x0 + (x1 - x0) * i / 8), y: y0, button: 'left', buttons: 1 });
    await sleep(25);
  }
  await send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: x1, y: y0, button: 'left', buttons: 0, clickCount: 1 });
  await sleep(260);
}

/** 点击表格中包含指定文本的行（打开详情抽屉）。 */
async function openDetailByText(snippet) {
  const ok = await evaluate(`(function(){
    var rows = document.querySelectorAll('#resultsBody tr[data-id]');
    for (var i = 0; i < rows.length; i++) {
      if (rows[i].innerText.indexOf(${JSON.stringify(snippet)}) >= 0) { rows[i].click(); return true; }
    }
    return false;
  })()`);
  await waitUntil(`document.querySelector('#detailDrawer').classList.contains('open')`, '详情抽屉打开');
  return ok;
}

(async () => {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'cx-demo-page-'));
  const chrome = spawn(CHROME, [
    '--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run',
    '--no-default-browser-check', '--remote-allow-origins=*', '--window-size=1600,1000',
    `--remote-debugging-port=${CDP_PORT}`, `--user-data-dir=${profile}`, 'about:blank'
  ], { stdio: 'ignore' });
  try {
    let page = null;
    for (let i = 0; i < 100 && !page; i++) {
      try {
        const list = await httpGet(`http://127.0.0.1:${CDP_PORT}/json/list`);
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
      if (msg.method === 'Network.requestWillBeSent') {
        const u = msg.params.request.url;
        if (/^https?:\/\//i.test(u)) networkRequests.push(u);
      }
    };
    await send('Page.enable');
    await send('Runtime.enable');
    await send('Network.enable');

    const URL = 'file:///' + DEMO.replace(/\\/g, '/');
    await send('Page.navigate', { url: URL });

    /* 1. 登录页 */
    console.log('\n=== 1. 演示登录页 ===');
    await waitUntil(`!!document.querySelector('#loginOverlay')`, '登录页加载');
    check('Demo 登录页加载成功', true);
    check('API Key 已预填（DEMO-API-KEY）', (await evaluate(`document.querySelector('#apiKeyInput').value`)) === 'DEMO-API-KEY');
    check('登录页含演示模式提示', (await evaluate(text('#loginProxyHint'))).includes('演示模式'));
    await shot('current-login.png');

    /* 2. 登录 + 自动加载演示项目 */
    console.log('\n=== 2. 登录与看板 ===');
    await evaluate(click('#loginSubmit'));
    await waitUntil(`${rows} === 10`, '自动加载演示项目并展示 10 条漏洞', 25000);
    check('演示登录成功，自动选择项目并加载 10 条结果', true);
    check('顶栏显示 DEMO 徽标', !!(await evaluate(`!!document.querySelector('.demo-mode-badge')`)));
    check('连接状态为演示租户', (await evaluate(text('#connPill'))).includes('DEMO-TENANT'));
    await waitUntil(`!document.querySelector('#loginOverlay')`, '登录页隐藏', 8000);
    await sleep(500);
    await shot('current-board.png');

    /* 3. 筛选 */
    console.log('\n=== 3. 筛选 ===');
    await evaluate(click('[data-sev="HIGH"]'));
    await sleep(200);
    check('点击 High 标签筛选（10 -> 6）', (await evaluate(rows)) === 6);
    await evaluate(click('[data-sev="HIGH"]'));
    await sleep(200);
    check('再次点击恢复 10 条', (await evaluate(rows)) === 10);

    /* 严重级别记忆：关闭 High 后刷新，Demo 也应恢复同样的等级筛选（6 条） */
    await evaluate(click('[data-sev="HIGH"]'));
    await sleep(200);
    check('关闭 High 后显示 6 条', (await evaluate(rows)) === 6);
    await sleep(250);
    await send('Page.navigate', { url: URL });
    await waitUntil(`${rows} === 6`, '刷新后自动恢复严重级别筛选', 25000);
    check('刷新后记住上一次严重级别选择（High 关闭 / 6 条）', true);
    check('High 标签恢复为关闭态', await evaluate(`document.querySelector('[data-sev="HIGH"]').classList.contains('off')`));
    await evaluate(click('[data-sev="HIGH"]'));
    await sleep(200);
    check('恢复 High 后回到 10 条', (await evaluate(rows)) === 10);

    await evaluate(`(function(){var i=document.querySelector('#searchInput');i.value='SQL Injection';i.dispatchEvent(new Event('input',{bubbles:true}));return true;})()`);
    await sleep(400);
    check('搜索 SQL Injection（1 条）', (await evaluate(rows)) === 1);
    await evaluate(`(function(){var i=document.querySelector('#searchInput');i.value='';i.dispatchEvent(new Event('input',{bubbles:true}));return true;})()`);
    await sleep(400);

    /* 3.5 项目下拉搜索筛选（不改动项目选择，结束保持下拉关闭） */
    console.log('\n=== 3.5 项目下拉搜索筛选 ===');
    const demoProjVisibleCount = `document.querySelectorAll('#projectMenu .proj-item[data-project]:not(.is-hidden)').length`;
    const demoSetProjSearch = (v) => `(function(){var i=document.querySelector('#projectMenu #projectSearchInput');if(!i)return false;i.value=${JSON.stringify(v)};i.dispatchEvent(new Event('input',{bubbles:true}));return true;})()`;
    const demoEscProjSearch = `(function(){var i=document.querySelector('#projectMenu #projectSearchInput');if(!i)return false;i.focus();i.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true,cancelable:true}));return true;})()`;

    await evaluate(click('#projectPickerBtn'));
    await waitUntil(`!document.querySelector('#projectMenu').classList.contains('hidden') && !!document.querySelector('#projectMenu #projectSearchInput')`, '项目下拉打开并出现搜索框');
    await waitUntil(`document.activeElement && document.activeElement.id === 'projectSearchInput'`, '搜索框自动聚焦', 5000);
    check('项目下拉新增搜索框（.proj-search > #projectSearchInput）且自动获得焦点', (await evaluate(`!!document.querySelector('#projectMenu .proj-search #projectSearchInput')`)) && (await evaluate(`document.activeElement && document.activeElement.id`)) === 'projectSearchInput');
    check('无查询时计数为「已选 3 / 3」、全选按钮为「全选」', (await evaluate(text('#projectMenu [data-draft-count]'))).includes('已选 3 / 3') && (await evaluate(text('#projectMenu [data-proj-all]'))).trim() === '全选');

    /* 输入 user：大小写不敏感 + 命中高亮 + 计数追加匹配数 */
    await evaluate(demoSetProjSearch('user'));
    await waitUntil(`${demoProjVisibleCount} === 1`, '搜索 user 过滤出 1 项');
    const demoUserName = await evaluate(`(function(){var it=document.querySelector('#projectMenu .proj-item[data-project]:not(.is-hidden)');return it?it.getAttribute('data-name'):'';})()`);
    check('搜索 user 仅显示 user-center（大小写不敏感）且命中片段包裹 <mark>', (await evaluate(demoProjVisibleCount)) === 1 && demoUserName === 'user-center' && (await evaluate(`!!document.querySelector('#projectMenu .proj-item[data-project][data-name="user-center"] .p-name mark')`)), demoUserName);
    check('有查询时计数追加「匹配 1 个」且全选按钮含「全选匹配」', (await evaluate(text('#projectMenu [data-draft-count]'))).includes('匹配 1 个') && (await evaluate(text('#projectMenu [data-proj-all]'))).includes('全选匹配'));

    /* 输入 zzz：无匹配提示 */
    await evaluate(demoSetProjSearch('zzz'));
    await waitUntil(`${demoProjVisibleCount} === 0`, '搜索 zzz 无匹配');
    const demoNoMatch = await evaluate(text('#projectMenu [data-proj-no-match]'));
    check('搜索 zzz 时 0 项可见并显示无匹配提示（文本含「没有匹配」）', (await evaluate(demoProjVisibleCount)) === 0 && demoNoMatch.includes('没有匹配'), demoNoMatch.replace(/\n/g, ' ').slice(0, 80));

    /* 清除按钮：恢复 3 项、查询清空、下拉保持展开 */
    await evaluate(click('#projectMenu [data-proj-search-clear]'));
    await waitUntil(`${demoProjVisibleCount} === 3`, '清除搜索恢复 3 项');
    check('点清除按钮恢复全部 3 个项目且搜索框清空', (await evaluate(demoProjVisibleCount)) === 3 && (await evaluate(`(document.querySelector('#projectMenu #projectSearchInput')||{}).value||''`)) === '');

    /* Esc：查询非空 -> 清空查询且保持展开；查询为空 -> 关闭下拉 */
    await evaluate(demoSetProjSearch('zzz'));
    await waitUntil(`${demoProjVisibleCount} === 0`, '再次搜索 zzz 无匹配');
    await evaluate(demoEscProjSearch);
    await waitUntil(`(document.querySelector('#projectMenu #projectSearchInput')||{}).value === ''`, 'Esc 清空搜索查询');
    check('查询非空时按 Esc 清空查询且下拉保持展开', await evaluate(`!document.querySelector('#projectMenu').classList.contains('hidden')`) && (await evaluate(demoProjVisibleCount)) === 3);
    await evaluate(demoEscProjSearch);
    await sleep(250);
    check('查询为空时再按 Esc 关闭下拉', await evaluate(`document.querySelector('#projectMenu').classList.contains('hidden')`));
    check('搜索筛选未改变项目选择（仍为「全部项目 (3)」）', (await evaluate(text('#projectPickerBtn'))).includes('全部项目 (3)'), await evaluate(text('#projectPickerBtn')));

    /* 4. 详情抽屉 */
    console.log('\n=== 4. 详情抽屉 ===');
    await evaluate(click('#resultsBody tr[data-id]'));
    await waitUntil(`document.querySelector('#detailDrawer').classList.contains('open')`, '详情抽屉打开');
    await sleep(350);
    const detail = await evaluate(text('#detailContent'));
    check('详情包含攻击向量/数据流/修复建议/参考链接', ['攻击向量', '污点数据流', '修复建议', '参考链接'].every((k) => detail.includes(k)));

    const overflow = JSON.parse(await evaluate(`(function(){var sc=document.querySelector('.drawer-scroll');return JSON.stringify({sw:sc.scrollWidth,cw:sc.clientWidth})})()`));
    check('抽屉无横向滚动条', overflow.sw <= overflow.cw + 1, JSON.stringify(overflow));
    const w0 = await evaluate(`Math.round(document.querySelector('#detailDrawer').getBoundingClientRect().width)`);
    await dragDrawerBy(120);
    const w1 = await evaluate(`Math.round(document.querySelector('#detailDrawer').getBoundingClientRect().width)`);
    check('抽屉可拖拽调整宽度', w1 > w0 + 60, w0 + ' -> ' + w1);
    await sleep(300);
    await shot('current-detail.png');

    /* 一键复制：漏洞说明 / 攻击向量（含污点数据流序号/类名/行号）/ 污点数据流 / 修复建议 / 参考链接（截图之后再点，避免 toast 入镜） */
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

    /* 5. 扫描链接 */
    console.log('\n=== 5. 扫描链接 ===');
    await evaluate(click('#openLinkBtn'));
    await waitUntil(`document.querySelector('#linkModal').classList.contains('open')`, '扫描链接弹窗打开');
    await sleep(300);
    const sampleUrl = await evaluate(`window.CX_DEMO_MOCK_DATA.sampleScanUrl`);
    check('扫描链接弹窗含演示示例链接', (await evaluate(text('#linkModal'))).includes('演示示例'));
    await evaluate(`(function(){var i=document.querySelector('#linkInput');i.value = window.CX_DEMO_MOCK_DATA.sampleScanUrl; return true;})()`);
    await evaluate(click('#linkOpenBtn'));
    await waitUntil(`!document.querySelector('#linkModal').classList.contains('open')`, '扫描链接弹窗关闭');
    await waitUntil(`${rows} === 4`, '定位到示例扫描的 4 条结果', 20000);
    check('粘贴扫描链接 -> 定位该扫描结果（4 条）', true);

    /* 6. 本地扫描（模拟） */
    console.log('\n=== 6. 本地扫描（模拟） ===');
    await evaluate(click('#localScanBtn'));
    await waitUntil(`document.querySelector('#scanModal').classList.contains('open')`, '本地扫描弹窗打开');
    await sleep(300);
    check('本地扫描弹窗含演示说明', (await evaluate(text('#scanModal'))).includes('演示模式'));
    /* 项目名：从已有项目下拉中搜索选择；输入不存在的名称按新项目处理 */
    check('项目名为可搜索组合框（含下拉按钮与状态徽标）', await evaluate(`(function(){var r=document.querySelector('#scanFolders [data-folder-row]');return !!r.querySelector('.pname') && !!r.querySelector('.pn-toggle') && !!r.querySelector('[data-pn-badge]');})()`));
    check('未聚焦时项目下拉默认隐藏', await evaluate(`document.querySelector('#scanProjectMenu').classList.contains('hidden')`));
    await evaluate(`(function(){var i=document.querySelector('#scanFolders [data-folder-row] .pname');i.focus();return true;})()`);
    await waitUntil(`!document.querySelector('#scanProjectMenu').classList.contains('hidden') && document.querySelectorAll('#scanProjectMenu .pn-item[data-project-id]').length === 3`, '项目下拉列出演示项目', 10000);
    const demoProjNames = JSON.parse(await evaluate(`JSON.stringify(Array.prototype.map.call(document.querySelectorAll('#scanProjectMenu .pn-item[data-project-id]'),function(o){return o.getAttribute('data-name');}))`));
    check('项目下拉列出已有 Checkmarx One 项目', ['payment-service', 'user-center', 'web-portal'].every(function (n) { return demoProjNames.indexOf(n) >= 0; }), JSON.stringify(demoProjNames));
    /* 键盘：↓ 高亮首个项目项；Esc 只关闭下拉、不关闭弹窗 */
    await evaluate(`(function(){var i=document.querySelector('#scanFolders [data-folder-row] .pname');i.dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowDown',bubbles:true,cancelable:true}));return true;})()`);
    check('↓ 键高亮项目下拉项', (await evaluate(`document.querySelectorAll('#scanProjectMenu .pn-item.active').length`)) === 1);
    await evaluate(`(function(){var i=document.querySelector('#scanFolders [data-folder-row] .pname');i.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true,cancelable:true}));return true;})()`);
    await sleep(120);
    check('Esc 关闭项目下拉且不关闭扫描弹窗', await evaluate(`document.querySelector('#scanProjectMenu').classList.contains('hidden') && document.querySelector('#scanModal').classList.contains('open')`));
    await evaluate(click('#scanFolders [data-folder-row] .pname'));
    await waitUntil(`!document.querySelector('#scanProjectMenu').classList.contains('hidden')`, '重新打开项目下拉');
    await evaluate(`(function(){var i=document.querySelector('#scanFolders [data-folder-row] .pname');i.value='user';i.dispatchEvent(new Event('input',{bubbles:true}));return true;})()`);
    await waitUntil(`document.querySelectorAll('#scanProjectMenu .pn-item[data-project-id]').length === 1`, '按关键词筛选已有项目');
    const demoProjFilter = JSON.parse(await evaluate(`(function(){var it=document.querySelector('#scanProjectMenu .pn-item[data-project-id]');var m=it&&it.querySelector('.pn-name mark');return JSON.stringify({name:it?it.getAttribute('data-name'):'',mark:!!m,markText:m?m.textContent:''});})()`));
    check('输入关键词实时筛选已有项目（user -> user-center）', demoProjFilter.name === 'user-center', JSON.stringify(demoProjFilter));
    check('筛选命中片段以 <mark> 高亮', demoProjFilter.mark && demoProjFilter.markText.toLowerCase() === 'user', demoProjFilter.markText);
    check('未匹配完整项目名时提供「新建项目」条目', await evaluate(`(function(){var el=document.querySelector('#scanProjectMenu .pn-item[data-pn-new]');return !!el && el.innerText.indexOf('新建项目')>=0;})()`));
    await shot('current-local-scan-project.png');
    await evaluate(`(function(){var el=document.querySelector('#scanProjectMenu .pn-item[data-project-id][data-name="user-center"]');if(el)el.click();return true;})()`);
    await sleep(200);
    check('点选已有项目后写入项目名并标记「已有」', (await evaluate(`document.querySelector('#scanFolders [data-folder-row] .pname').value`)) === 'user-center' && (await evaluate(`document.querySelector('#scanFolders [data-folder-row]').getAttribute('data-pstate')`)) === 'existing');
    check('选中已有项目后下拉关闭', await evaluate(`document.querySelector('#scanProjectMenu').classList.contains('hidden')`));
    await evaluate(`(function(){
      var row=document.querySelector('#scanFolders [data-folder-row]');
      var p=row.querySelector('.fpath'); p.value='C:\\\\demo-projects\\\\demo-service'; p.dispatchEvent(new Event('input',{bubbles:true}));
      var n=row.querySelector('.pname'); n.value='demo-local-svc'; n.dispatchEvent(new Event('input',{bubbles:true}));
      return true;
    })()`);
    await sleep(150);
    check('手输不存在的项目名标记为「新项目」（模拟提交时新建）', (await evaluate(`document.querySelector('#scanFolders [data-folder-row]').getAttribute('data-pstate')`)) === 'new');
    await waitUntil(`document.querySelector('#scanBranchHint').innerText.indexOf('当前检出分支') >= 0`, '演示模式自动读取 git 分支', 10000);
    const demoBranchOpts = JSON.parse(await evaluate(`JSON.stringify(Array.prototype.map.call(document.querySelectorAll('#scanBranchMenu .bp-item'), function(o){return o.getAttribute('data-branch');}))`));
    check('演示模式分支下拉包含其余本地分支与远端分支',
      ['master', 'main', 'develop', 'origin/master'].every(function (b) { return demoBranchOpts.indexOf(b) >= 0; }), JSON.stringify(demoBranchOpts));
    check('演示模式默认分支 = 当前检出分支 master', (await evaluate(`document.querySelector('#scanBranch').value`)) === 'master');
    await evaluate(click('#scanBranchToggle'));
    check('演示模式点「▾」打开分支下拉浮层',
      await evaluate(`!document.querySelector('#scanBranchMenu').classList.contains('hidden') && document.querySelectorAll('#scanBranchMenu .bp-item').length >= 5`));
    await evaluate(`(function(){var b=document.querySelector('#scanBranchMenu .bp-item[data-branch="develop"]');if(b)b.click();return true;})()`);
    check('演示模式点选分支 develop 写入输入框',
      (await evaluate(`document.querySelector('#scanBranch').value`)) === 'develop');
    await evaluate(`(function(){var i=document.querySelector('#scanBranch');i.value='master';i.dispatchEvent(new Event('input',{bubbles:true}));return true;})()`);
    await evaluate(click('#startScanBtn'));
    await waitUntil(`!!document.querySelector('#scanProgress [data-prog]')`, '演示扫描进度出现', 10000);
    await evaluate(click('#scanMinBtn'));
    check('演示模式扫描中最小化：弹窗收起并显示浮动进度条',
      await evaluate(`!document.querySelector('#scanModal').classList.contains('open') && !document.querySelector('#scanMini').classList.contains('hidden')`));
    await waitUntil(`!document.querySelector('#scanSummary').classList.contains('hidden')`, '模拟本地扫描完成', 45000);
    check('模拟扫描进度完成', (await evaluate(text('#scanSummary'))).includes('本地扫描已完成'));
    check('最小化时模拟扫描完成：浮动条状态为完成',
      (await evaluate(`document.querySelector('#scanMini').dataset.state`)) === 'done');
    await evaluate(click('#scanMini'));
    await sleep(250);
    check('点击浮动进度条恢复扫描弹窗', await evaluate(`document.querySelector('#scanModal').classList.contains('open')`));
    await shot('current-local-scan.png');
    await evaluate(click('#viewLocalResultsBtn'));
    await waitUntil(`document.querySelector('#resultsBody').innerText.includes('Hardcoded API Key')`, '本地扫描结果回填', 25000);
    await waitUntil(`${rows} === 3`, '本地扫描结果 3 条', 15000);
    check('模拟本地扫描结果回填看板（3 条）', true);
    await shot('current-local-results.png');

    /* 7. 设置 / 退出登录 */
    console.log('\n=== 7. 设置与退出 ===');
    await evaluate(click('#settingsBtn'));
    await sleep(350);
    check('设置弹窗可调出且显示演示租户', (await evaluate(text('#settingsParse'))).includes('demo-tenant'));
    await evaluate(click('#logoutBtn'));
    await waitUntil(`!!document.querySelector('#loginOverlay')`, '退出后回到登录页', 10000);
    check('退出登录后回到演示登录页', true);

    /* 8. 无网络 / 无报错 */
    const badErrors = pageErrors.filter((e) => e && !/favicon/i.test(e));
    check('演示页面不发起任何 http(s) 网络请求', networkRequests.length === 0, networkRequests.slice(0, 3).join(' | '));
    check('页面无 JS 报错', badErrors.length === 0, badErrors.slice(0, 3).join(' | ').slice(0, 240));

    const failed = results.filter((r) => !r.ok);
    console.log(`\n================ 结果：${results.length - failed.length}/${results.length} 通过 ================`);
    if (failed.length) {
      failed.forEach((f) => console.log('  FAIL: ' + f.name + (f.extra ? '  [' + f.extra + ']' : '')));
      process.exitCode = 1;
    }
  } catch (e) {
    console.error('\n测试执行失败：', e);
    if (pageErrors.length) console.error('--- 页面 JS 错误 ---\n' + pageErrors.slice(0, 6).join('\n'));
    console.error('--- 网络请求 ---\n' + networkRequests.slice(0, 10).join('\n'));
    process.exitCode = 1;
  } finally {
    try { ws && ws.close(); } catch (_) { /* ignore */ }
    try { chrome.kill(); } catch (_) { /* ignore */ }
    await sleep(300);
    try { fs.rmSync(profile, { recursive: true, force: true }); } catch (_) { /* ignore */ }
  }
})();