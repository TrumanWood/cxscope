#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Checkmarx 本地代理（零依赖，仅使用 Python 标准库）。

功能：
    1. 提供前端页面：浏览器打开 http://127.0.0.1:8787/ 即加载同目录 index.html；
    2. 通用 API 转发：把浏览器请求转发到 Checkmarx One（/proxy，X-Target-Url 指定目标），
       解决浏览器无法直连 Checkmarx API 的 CORS / 认证头限制；
    3. 本地扫描：/local-scan 调用本机 Checkmarx One CLI（cx scan create --async）为每个
       文件夹创建扫描，返回扫描 ID 供页面轮询进度；CLI 缺失或失败时给出明确错误。
       也可用 SCAN_MODE=api 回退到旧的 REST 上传方式（仅兼容用，默认不启用）；
    4. 文件夹选择：/pick-folder 调起系统文件夹选择框（需要 tkinter，可选功能）；
    5. Git 分支：/git-branches 读取所选文件夹的本地/远程分支（只读，供本地扫描弹窗使用）。

本地扫描为什么走 CLI：
    官方 CLI 负责打包、上传与创建扫描（含企业代理、鉴权与分片上传等细节），
    比代理自己拼 REST 请求更稳；本代理只负责「调用 CLI + 解析扫描 ID + 把结果交给页面」，
    页面仍通过 Checkmarx One API 轮询进度与读取漏洞结果。

为什么需要它：
    Checkmarx 的 IAM 与 REST API 都不允许浏览器跨域（CORS）直连；本代理在服务端发起
    HTTPS 调用，并把响应透传给页面。代理只监听 127.0.0.1，且只允许转发到白名单内的
    Checkmarx 主机（默认 *.checkmarx.net / *.checkmarx.com）。

用法：
    python proxy.py                                    # 云版 Checkmarx One（默认即可）
    CX_CLI_PATH="C:\\tools\\cx.exe" python proxy.py    # 指定 Checkmarx One CLI（PATH 中找不到时）
    SCAN_MODE=api python proxy.py                      # 回退到旧 REST 上传方式（兼容用）
    EXTRA_HOST=checkmarx.corp.com python proxy.py      # 单租户/自建域名
    ALLOWED_HOSTS=checkmarx.corp.com,10.0.0.5 python proxy.py
    INSECURE=1 python proxy.py                         # 忽略自签证书（内网 https 常见）
    PORT=8788 python proxy.py                          # 换端口

然后浏览器打开 http://127.0.0.1:8787/ ，粘贴 Checkmarx One API Key 登录。

前置条件（本地扫描走 CLI 时）：
    本机需安装 Checkmarx One CLI（cx / cx.exe），并保证：
    - 可执行文件在 PATH 中，或通过环境变量 CX_CLI_PATH 指定完整路径；
    - CLI 能访问 Checkmarx One 租户（企业代理可沿用系统代理并配合 CLI 的 --proxy 参数）。
    页面登录用的 API Key 会通过环境变量 CX_APIKEY 传给 CLI 子进程，无需单独 cx auth。

安全说明：
    - 代理仅监听 127.0.0.1，且只转发到白名单内的主机，不是开放代理；
    - API Key 只存在于浏览器 localStorage、本机内存与 CLI 子进程环境中，不经过第三方服务器；
    - 本地扫描的源码由本机 Checkmarx One CLI 打包上传到 Checkmarx One（SCAN_MODE=api 时由代理直接上传）。
"""

import http.server
import socketserver
import urllib.request
import urllib.error
import json
import os
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
from urllib.parse import urlparse, quote

PORT = int(os.environ.get("PORT", "8787"))
BIND_HOST = os.environ.get("BIND_HOST", "127.0.0.1")
INSECURE = os.environ.get("INSECURE", "0") == "1"
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "200"))
TIMEOUT = int(os.environ.get("UPSTREAM_TIMEOUT", "180"))

# 本地扫描方式：
#   cli（默认）= 调用本机 Checkmarx One CLI 创建扫描（推荐）
#   api        = 旧方式：代理自己打包 -> REST 上传 -> POST /api/scans（仅兼容回退）
SCAN_MODE = (os.environ.get("SCAN_MODE", "cli").strip().lower() or "cli")
if SCAN_MODE not in ("cli", "api"):
    SCAN_MODE = "cli"

# Checkmarx One CLI 可执行文件路径；为空时在 PATH 中查找 cx / cx.exe
CX_CLI_PATH = os.environ.get("CX_CLI_PATH", "").strip()
# 单次 CLI 调用超时（秒）：含打包 + 上传 + 创建扫描；--async 下创建成功后立即返回
CX_CLI_TIMEOUT = int(os.environ.get("CX_CLI_TIMEOUT", "900"))
# 可选：SAST 预设名（如团队统一下发的 Company-Recommended）；为空则用租户默认预设
CX_SAST_PRESET = os.environ.get("CX_SAST_PRESET", "").strip()
# 可选：附加 CLI 参数（例：--proxy http://corp-proxy:8080 --ignore-proxy），空格分隔
CX_CLI_EXTRA_ARGS = os.environ.get("CX_CLI_EXTRA_ARGS", "").strip()

# 页面扫描类型（sast/sca/kics）-> CLI --scan-types 取值
CLI_SCAN_TYPES = {
    "sast": "sast",
    "sca": "sca",
    "iac": "iac-security",
    "kics": "iac-security",
    "apisec": "api-security",
    "api-security": "api-security",
}
UUID_PATTERN = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
UUID_RE = re.compile("^" + UUID_PATTERN + "$")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

# /git-branches 相关限制（只读接口，均可用常量调整）
GIT_TIMEOUT = 10          # 单次 git 命令超时（秒）
MAX_GIT_PATHS = 20        # 单次请求最多读取的文件夹数
MAX_GIT_BRANCHES = 500    # 单个仓库返回的分支总数上限（locals + remotes 去重后截断）

# 允许转发的域名（默认 Checkmarx 云版与官网域名）
ALLOWED_SUFFIXES = [".checkmarx.net", ".checkmarx.com"]
for env_name in ("EXTRA_HOST", "ALLOWED_HOSTS"):
    for h in os.environ.get(env_name, "").split(","):
        h = h.strip()
        if h:
            ALLOWED_SUFFIXES.append(h if h.startswith(".") else "." + h)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INDEX_FILE = os.path.join(BASE_DIR, "index.html")

EXCLUDE_DIRS = {
    ".git", ".svn", ".hg", ".idea", ".vscode", ".vs", "__pycache__", ".generated",
    "node_modules", ".venv", "venv", "env", ".env", "dist", "build",
    "target", "out", "bin", "obj", ".next", ".nuxt", ".gradle", ".mvn",
    "coverage", ".pytest_cache", ".mypy_cache", ".cache", ".terraform",
}
EXCLUDE_FILES = {".DS_Store", "Thumbs.db"}

_print_lock = threading.Lock()


def log(msg):
    with _print_lock:
        sys.stdout.write("[proxy] " + msg + "\n")
        sys.stdout.flush()


def ssl_context():
    if INSECURE:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return None


def host_allowed(host):
    host = (host or "").lower()
    for suffix in ALLOWED_SUFFIXES:
        s = suffix.lower().lstrip(".")
        if host == s or host.endswith("." + s):
            return True
    return False


def check_url_allowed(target):
    """校验目标 URL 协议与主机白名单，返回 (ok, reason)。"""
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        return False, "仅支持 http/https 目标"
    if not host_allowed(parsed.hostname or ""):
        return False, "目标主机不在白名单内: %s（用 EXTRA_HOST / ALLOWED_HOSTS 添加）" % (parsed.hostname or "")
    return True, ""


def http_request(method, url, headers=None, data=None, timeout=TIMEOUT):
    """发起上游 HTTP 请求，返回 (status, body_bytes, headers_dict)。"""
    headers = dict(headers or {})
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    ctx = ssl_context()
    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=timeout)
        return resp.status, resp.read(), {k.lower(): v for k, v in resp.getheaders()}
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:  # noqa: BLE001
            body = b""
        return e.code, body, {k.lower(): v for k, v in (e.headers or {}).items()}


def api_json(method, url, token=None, payload=None, timeout=TIMEOUT):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = None
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    status, raw, _ = http_request(method, url, headers=headers, data=body, timeout=timeout)
    data = None
    if raw:
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            data = raw.decode("utf-8", "replace")[:2000]
    if status < 200 or status >= 300:
        msg = data
        if isinstance(data, dict):
            msg = data.get("message") or data.get("Message") or data.get("error") or data.get("title") or data
        raise RuntimeError("%s %s -> HTTP %s: %s" % (method, url, status, str(msg)[:500]))
    return data


# ---------------------------------------------------------------------------
# 本地扫描
# ---------------------------------------------------------------------------
def build_zip(folder, zip_path):
    """把本地文件夹打成 zip（跳过常见依赖/构建目录），返回 (file_count, total_bytes)。"""
    base = os.path.abspath(folder)
    if not os.path.isdir(base):
        raise RuntimeError("文件夹不存在或不可访问: " + folder)
    max_bytes = MAX_UPLOAD_MB * 1024 * 1024
    total = 0
    count = 0
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for name in files:
                if name in EXCLUDE_FILES:
                    continue
                path = os.path.join(root, name)
                try:
                    size = os.path.getsize(path)
                except OSError:
                    continue
                total += size
                if total > max_bytes:
                    raise RuntimeError("文件夹超过 %d MB 上限，请缩小范围后重试: %s" % (MAX_UPLOAD_MB, folder))
                rel = os.path.relpath(path, base).replace("\\", "/")
                try:
                    zf.write(path, rel)
                    count += 1
                except (OSError, ValueError):
                    continue
    return count, total


def resolve_project_id(api_base, token, project_name):
    """按名称查找项目；不存在则创建。返回 project_id。"""
    data = api_json("GET", api_base + "/api/projects?name=" + quote(project_name) + "&limit=20", token=token)
    projects = (data or {}).get("projects") or (data or {}).get("items") or []
    for p in projects:
        if (p.get("name") or "").strip() == project_name.strip():
            return p.get("id")
    try:
        created = api_json("POST", api_base + "/api/projects", token=token, payload={"name": project_name})
        if isinstance(created, dict) and created.get("id"):
            return created["id"]
    except RuntimeError as e:
        # 可能是并发创建 / 权限不足：再查一次
        data = api_json("GET", api_base + "/api/projects?name=" + quote(project_name) + "&limit=20", token=token)
        for p in (data or {}).get("projects") or []:
            if (p.get("name") or "").strip() == project_name.strip():
                return p.get("id")
        raise RuntimeError("无法找到或创建项目「%s」，请确认账号有创建项目权限。原始错误：%s" % (project_name, e))
    raise RuntimeError("创建项目「%s」失败：Checkmarx 未返回项目 ID" % project_name)


# ---------------------------------------------------------------------------
# 本机 Checkmarx One CLI（本地扫描默认方式）
# ---------------------------------------------------------------------------
def detect_cx_cli():
    """查找 Checkmarx One CLI，返回 (可执行文件路径, 错误说明)；找不到时路径为空。"""
    if CX_CLI_PATH:
        candidate = os.path.expanduser(CX_CLI_PATH)
        if os.path.isfile(candidate):
            return candidate, ""
        found = shutil.which(CX_CLI_PATH)
        if found:
            return found, ""
        return "", "CX_CLI_PATH 指向的 Checkmarx One CLI 不存在: %s" % CX_CLI_PATH
    for name in ("cx", "cx.exe"):
        found = shutil.which(name)
        if found:
            return found, ""
    return "", ("未找到 Checkmarx One CLI（cx）。请安装 Checkmarx One CLI 并加入 PATH，"
                "或通过环境变量 CX_CLI_PATH 指定 cx.exe 的完整路径。")


def cli_scan_type_names(scan_types):
    """把页面勾选的扫描类型映射为 CLI 的 --scan-types 取值（保持顺序、去重）。"""
    names = []
    for item in scan_types or ["sast"]:
        mapped = CLI_SCAN_TYPES.get(str(item or "").strip().lower())
        if mapped and mapped not in names:
            names.append(mapped)
    return names or ["sast"]


def auth_base_from_realm(realm_url):
    """CLI 需要 IAM 根地址（即 .../auth/realms/<tenant> 之前的部分）。"""
    value = str(realm_url or "").strip().rstrip("/")
    marker = "/auth/realms/"
    if marker in value:
        return value.split(marker)[0]
    return value


def _strip_ansi(text):
    return ANSI_RE.sub("", text or "")


def _iter_dicts(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            for item in _iter_dicts(value):
                yield item
    elif isinstance(node, list):
        for value in node:
            for item in _iter_dicts(value):
                yield item


def _first_field(obj, keys, check):
    for node in _iter_dicts(obj):
        for key in keys:
            value = node.get(key)
            if isinstance(value, str) and check(value):
                return value.strip()
    return ""


def _find_uuid_field(obj, keys):
    return _first_field(obj, keys, lambda value: bool(UUID_RE.match(value)))


def _find_scan_node(data):
    """在 CLI JSON 输出中定位扫描对象（优先取同时带 id 与项目/状态字段的 dict）。"""
    for node in _iter_dicts(data):
        node_id = node.get("id") or node.get("scanId") or node.get("scanID")
        if not (isinstance(node_id, str) and UUID_RE.match(node_id.strip())):
            continue
        lowered = {str(key).lower() for key in node.keys()}
        if lowered & {"projectid", "projectname", "branch", "status"}:
            return node
    return None


def parse_cli_scan_info(output):
    """从 `cx scan create` 输出中提取扫描信息。

    同时兼容 --scan-info-format json（优先）与默认表格输出；解析不到时返回空字段，
    由调用方给出带原始输出的错误信息。
    """
    text = _strip_ansi(output or "")
    info = {"scanId": "", "projectId": "", "projectName": "", "status": ""}
    data = None
    stripped = text.strip()
    if stripped:
        try:
            data = json.loads(stripped)
        except ValueError:
            decoder = json.JSONDecoder()
            for match in re.finditer(r"[\[{]", stripped):
                try:
                    data, _end = decoder.raw_decode(stripped[match.start():])
                    break
                except ValueError:
                    continue
    if isinstance(data, (dict, list)):
        scan_node = _find_scan_node(data)
        target = scan_node if scan_node is not None else data
        info["scanId"] = _find_uuid_field(target, ("id", "scanId", "scanID", "scan_id"))
        info["projectId"] = _find_uuid_field(target, ("projectId", "projectID", "project_id"))
        info["projectName"] = _first_field(target, ("projectName", "project_name"), lambda value: True)
        info["status"] = _first_field(target, ("status", "Status"), lambda value: True)
    if not info["scanId"]:
        match = re.search(r"(?i)scan[\s_-]*id\s*[:\s]+(" + UUID_PATTERN + ")", text)
        if match:
            info["scanId"] = match.group(1)
    if not info["projectId"]:
        match = re.search(r"(?i)project[\s_-]*id\s*[:\s]+(" + UUID_PATTERN + ")", text)
        if match:
            info["projectId"] = match.group(1)
    if not info["projectName"]:
        match = re.search(r"(?i)project\s*name\s*:\s*([^\r\n]+)", text)
        if match:
            info["projectName"] = match.group(1).strip()
    if not info["status"]:
        match = re.search(r"(?im)^\s*status\s*:\s*([A-Za-z]+)", text)
        if match:
            info["status"] = match.group(1).strip()
    return info


def _cli_output_tail(text, limit=600):
    """压缩 CLI 输出，用于失败详情（去掉 ANSI 与空行、保留末尾若干行）。"""
    clean = _strip_ansi(text or "")
    lines = [line.strip() for line in clean.splitlines() if line.strip()]
    detail = " | ".join(lines[-8:]) if lines else ""
    return detail[:limit] or "无输出"


def create_scan_via_cli(folder, project_name, branch, scan_types, session):
    """单个文件夹：调用本机 Checkmarx One CLI 创建扫描（--async，不等待扫描结束）。

    session 需包含页面登录后拿到的 apiKey / apiBase / realmUrl / tenant：
    - apiKey 通过 CX_APIKEY 环境变量传给 CLI 子进程，避免出现在命令行中；
    - apiBase / realmUrl 用于 --base-uri / --base-auth-uri，使 CLI 不依赖本机既有配置
      也能连接当前登录的 Checkmarx One 租户。
    创建成功后返回扫描 ID，页面继续通过 Checkmarx One API 轮询进度。
    """
    cx_path, cli_error = detect_cx_cli()
    if not cx_path:
        raise RuntimeError(cli_error)
    folder = os.path.abspath(os.path.expanduser(str(folder or "")))
    if not os.path.exists(folder):
        raise RuntimeError("文件夹不存在: %s" % folder)
    if not os.path.isdir(folder):
        raise RuntimeError("路径不是文件夹: %s" % folder)

    api_key = str(session.get("apiKey") or "").strip()
    if not api_key:
        raise RuntimeError("缺少 API Key（请重新登录后再发起本地扫描）")
    api_base = str(session.get("apiBase") or "").rstrip("/")
    if not api_base:
        raise RuntimeError("缺少 Checkmarx One API 地址（请重新登录）")
    ok, reason = check_url_allowed(api_base)
    if not ok:
        raise RuntimeError("Checkmarx One API 地址不合法: " + reason)
    auth_base = auth_base_from_realm(session.get("realmUrl") or "")
    if not auth_base:
        raise RuntimeError("缺少 Checkmarx One IAM 地址（请重新登录）")
    ok, reason = check_url_allowed(auth_base)
    if not ok:
        raise RuntimeError("Checkmarx One IAM 地址不合法: " + reason)
    tenant = str(session.get("tenant") or "").strip()
    types = cli_scan_type_names(scan_types)
    branch = str(branch or "main").strip() or "main"

    cmd = [cx_path, "scan", "create",
           "--project-name", project_name,
           "--branch", branch,
           "-s", folder,
           "--scan-types", ",".join(types),
           "--exclude-git-folder",
           "--async",
           "--scan-info-format", "json",
           "--base-uri", api_base,
           "--base-auth-uri", auth_base]
    if tenant:
        cmd += ["--tenant", tenant]
    if INSECURE:
        cmd.append("--insecure")
    if CX_SAST_PRESET:
        cmd += ["--sast-preset-name", CX_SAST_PRESET]
    if CX_CLI_EXTRA_ARGS:
        cmd += shlex.split(CX_CLI_EXTRA_ARGS)

    env = os.environ.copy()
    env["CX_APIKEY"] = api_key
    env["CX_BASE_URI"] = api_base
    env["CX_BASE_AUTH_URI"] = auth_base
    if tenant:
        env["CX_TENANT"] = tenant

    log("调用 CLI 创建扫描: 项目=%s 分支=%s 类型=%s 目录=%s" % (project_name, branch, ",".join(types), folder))
    kwargs = {
        "shell": False,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": CX_CLI_TIMEOUT,
        "env": env,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    started = time.time()
    try:
        proc = subprocess.run(cmd, **kwargs)
    except FileNotFoundError:
        raise RuntimeError("无法启动 Checkmarx One CLI（%s），请检查 CX_CLI_PATH / PATH 配置" % cx_path)
    except subprocess.TimeoutExpired:
        raise RuntimeError("Checkmarx One CLI 执行超时（超过 %d 秒），请检查网络或缩小扫描目录后重试" % CX_CLI_TIMEOUT)
    except OSError as e:
        raise RuntimeError("Checkmarx One CLI 执行失败: %s" % e)
    elapsed = time.time() - started
    if proc.returncode != 0:
        detail = _cli_output_tail((proc.stderr or "") + "\n" + (proc.stdout or ""))
        raise RuntimeError("Checkmarx One CLI 创建扫描失败（退出码 %d）：%s" % (proc.returncode, detail))
    info = parse_cli_scan_info(proc.stdout or "")
    if not info.get("scanId"):
        # 个别版本把扫描信息输出到 stderr
        stderr_info = parse_cli_scan_info(proc.stderr or "")
        for key, value in stderr_info.items():
            if value and not info.get(key):
                info[key] = value
    if not info.get("scanId"):
        detail = _cli_output_tail((proc.stdout or "") + "\n" + (proc.stderr or ""))
        raise RuntimeError("Checkmarx One CLI 未返回扫描 ID。CLI 输出：%s" % detail)
    log("CLI 扫描已创建 %s（项目 %s，用时 %.1f 秒）" % (info["scanId"], project_name, elapsed))
    return {
        "ok": True,
        "mode": "cli",
        "scanId": info["scanId"],
        "status": info.get("status") or "Queued",
        "projectId": info.get("projectId") or "",
        "projectName": info.get("projectName") or project_name,
        "branch": branch,
    }


def create_scan_for_folder(api_base, token, folder, project_name, branch, scan_types, project_id=None):
    """单个文件夹：打包 -> 上传 -> 创建扫描。返回扫描信息。

    project_id：前端在下拉中选中的已有 Checkmarx One 项目 ID。传入时直接使用该 ID
    （避免同名/改名导致的误建项目）；为空时按项目名查找，不存在则创建新项目。
    """
    ok, reason = check_url_allowed(api_base)
    if not ok:
        raise RuntimeError("apiBase 不合法: " + reason)
    tmp_zip = tempfile.NamedTemporaryFile(prefix="cx-upload-", suffix=".zip", delete=False)
    tmp_zip.close()
    zip_path = tmp_zip.name
    try:
        count, total = build_zip(folder, zip_path)
        if count == 0:
            raise RuntimeError("文件夹为空或全部被排除规则跳过: " + folder)
        size_mb = total / 1024.0 / 1024.0
        log("打包完成 %s: %d 个文件, %.2f MB" % (folder, count, size_mb))

        upload = api_json("POST", api_base + "/api/uploads", token=token)
        presigned = None
        if isinstance(upload, dict):
            presigned = upload.get("url") or upload.get("uploadUrl") or upload.get("presignedUrl")
        if not presigned:
            raise RuntimeError("Checkmarx 未返回上传地址（/api/uploads 响应异常）")

        with open(zip_path, "rb") as f:
            payload = f.read()
        headers = {"Content-Type": "application/zip", "Content-Length": str(len(payload))}
        # 预签名上传地址有两种形态：
        # 1) 指向 Checkmarx 网关（如 https://eu.ast.checkmarx.net/storage/...）：网关仍需带上
        #    Bearer Token，缺失时返回 401；大文件正文发送到一半被网关断开，在 Windows 上就会
        #    表现为 <urlopen error [Errno 10053]>，所以这里必须补上 access token；
        # 2) 直接指向 S3/Azure 等对象存储：预签名本身就是凭证，额外携带 Authorization 反而会被
        #    S3 以 400「Only one auth mechanism allowed」拒绝，因此只在同主机/白名单主机时携带。
        presigned_host = (urlparse(presigned).hostname or "").lower()
        api_host = (urlparse(api_base).hostname or "").lower()
        if presigned_host and (presigned_host == api_host or host_allowed(presigned_host)):
            headers["Authorization"] = "Bearer " + token
        log("上传源码 %s: %d 个文件, zip %.2f MB ..." % (folder, count, len(payload) / 1024.0 / 1024.0))
        upload_start = time.time()
        try:
            status, body, _ = http_request("PUT", presigned, headers=headers, data=payload)
        except urllib.error.URLError as e:
            raise RuntimeError("上传源码连接中断（%s）；请检查网络/代理/防火墙后重试" % e)
        if status not in (200, 201, 204):
            raise RuntimeError("上传源码失败（HTTP %s）: %s" % (status, body[:300].decode("utf-8", "replace")))
        log("上传完成，用时 %.1f 秒" % (time.time() - upload_start))

        project_id = (project_id or "").strip() or resolve_project_id(api_base, token, project_name)
        config = []
        type_map = {"sast": "sast", "sca": "sca", "kics": "kics", "iac": "kics", "apisec": "apisec"}
        for t in scan_types or ["sast"]:
            mapped = type_map.get(t)
            if mapped and all(c.get("type") != mapped for c in config):
                config.append({"type": mapped, "value": {}})
        scan_payload = {
            "type": "upload",
            "handler": {"branch": branch, "uploadUrl": presigned},
            "project": {"id": project_id},
        }
        if config:
            scan_payload["config"] = config
        scan = api_json("POST", api_base + "/api/scans", token=token, payload=scan_payload)
        if not isinstance(scan, dict) or not scan.get("id"):
            raise RuntimeError("创建扫描失败：Checkmarx 未返回扫描 ID")
        log("扫描已创建 %s (项目 %s)" % (scan.get("id"), project_name))
        return {
            "ok": True,
            "scanId": scan.get("id"),
            "status": scan.get("status"),
            "projectId": project_id,
            "projectName": project_name,
            "branch": branch,
            "fileCount": count,
            "sizeMB": round(size_mb, 2),
        }
    finally:
        try:
            os.unlink(zip_path)
        except OSError:
            pass


def do_local_scan(payload):
    """POST /local-scan：为每个文件夹创建 Checkmarx One 扫描。

    - SCAN_MODE=cli（默认）：调用本机 Checkmarx One CLI（cx scan create --async）创建扫描，
      页面登录拿到的 API Key / API 地址 / IAM 地址随请求传入；CLI 创建成功后立即返回扫描 ID，
      页面再通过 Checkmarx One API 轮询进度并加载结果。
    - SCAN_MODE=api：旧的 REST 上传方式（代理打包 + 预签名上传 + POST /api/scans），仅兼容回退。

    注：CLI 方式按「项目名」在 Checkmarx One 中匹配/创建项目（CLI 没有 projectId 参数），
    因此前端传的 projectId 在 CLI 模式下不参与建扫描。
    """
    api_base = str(payload.get("apiBase") or "").rstrip("/")
    token = str(payload.get("accessToken") or "")
    session = {
        "apiKey": payload.get("apiKey") or "",
        "apiBase": api_base,
        "realmUrl": payload.get("realmUrl") or "",
        "tenant": payload.get("tenant") or "",
    }
    folders = payload.get("folders") or []
    branch = str(payload.get("branch") or "main").strip() or "main"
    scan_types = payload.get("scanTypes") or ["sast"]
    if not api_base:
        raise RuntimeError("缺少 apiBase（请先登录）")
    if SCAN_MODE == "cli" and not str(session["apiKey"]).strip():
        raise RuntimeError("缺少 API Key（请重新登录后再发起本地扫描）")
    if SCAN_MODE == "api" and not token:
        raise RuntimeError("缺少 accessToken（请先登录）")
    if not isinstance(folders, list) or not folders:
        raise RuntimeError("缺少要扫描的文件夹")
    results = []
    for item in folders:
        folder = str((item or {}).get("path") or "").strip()
        name = str((item or {}).get("name") or "").strip() or os.path.basename(folder.rstrip("\\/"))
        project_id = str((item or {}).get("projectId") or "").strip()
        try:
            if SCAN_MODE == "cli":
                results.append(create_scan_via_cli(folder, name, branch, scan_types, session))
            else:
                results.append(create_scan_for_folder(api_base, token, folder, name, branch, scan_types,
                                                      project_id=project_id or None))
        except Exception as e:  # noqa: BLE001
            results.append({"ok": False, "folder": folder, "projectName": name, "error": str(e)})
    return {"mode": SCAN_MODE, "scans": results}


def pick_folder():
    """通过独立子进程调起系统文件夹选择框，返回选择的路径（空字符串表示取消）。"""
    code = (
        "import tkinter as tk\n"
        "from tkinter import filedialog\n"
        "root = tk.Tk()\n"
        "root.withdraw()\n"
        "try:\n"
        "    root.attributes('-topmost', True)\n"
        "except Exception:\n"
        "    pass\n"
        "path = filedialog.askdirectory(title='选择要扫描的本地文件夹')\n"
        "print(path or '')\n"
        "root.destroy()\n"
    )
    try:
        out = subprocess.check_output([sys.executable, "-c", code], timeout=600,
                                      stderr=subprocess.STDOUT)
        return out.decode("utf-8", "replace").strip()
    except subprocess.CalledProcessError as e:
        detail = (e.output or b"").decode("utf-8", "replace").strip()
        if "tkinter" in detail or "No module named" in detail:
            raise RuntimeError("当前 Python 缺少 tkinter，无法调起系统文件夹选择框，请手动输入文件夹路径。")
        raise RuntimeError("文件夹选择框启动失败：%s（可手动输入路径）" % detail[:300])
    except subprocess.TimeoutExpired:
        raise RuntimeError("文件夹选择框超时，请手动输入路径。")


# ---------------------------------------------------------------------------
# Git 分支（只读，供本地扫描弹窗使用）
# ---------------------------------------------------------------------------
def _git_run(path, args):
    """在指定目录执行只读 git 命令，返回 (returncode, stdout, stderr)。

    - 列表参数 + shell=False，避免命令注入；
    - Windows 下加 CREATE_NO_WINDOW，避免弹出黑色命令行窗口；
    - 单次命令超时 GIT_TIMEOUT 秒；
    - 找不到 git / 超时 / 其它执行异常统一抛 RuntimeError（友好中文），由调用方
      转成 ok:false，绝不让整个请求返回 500。
    """
    cmd = ["git", "-C", path] + list(args)
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"  # 绝不等待账号密码输入
    kwargs = {
        "shell": False,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "timeout": GIT_TIMEOUT,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "env": env,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    try:
        proc = subprocess.run(cmd, **kwargs)
    except FileNotFoundError:
        raise RuntimeError("未找到 git 命令，请先安装 Git 并确保 git.exe 已加入 PATH")
    except subprocess.TimeoutExpired:
        raise RuntimeError("git 命令执行超时（超过 %d 秒）" % GIT_TIMEOUT)
    except OSError as e:
        raise RuntimeError("git 命令执行失败: %s" % e)
    return proc.returncode, (proc.stdout or ""), (proc.stderr or "")


def _git_error_detail(stderr, returncode):
    """把 git 的 stderr 压成一行简短说明，用于 error 字段。"""
    detail = (stderr or "").strip()
    if not detail:
        return "git 返回码 %d" % returncode
    return detail.splitlines()[0][:300]


def _git_entry(path):
    """创建契约中的 repo 对象模板（默认非仓库、无错误）。"""
    return {
        "path": path,
        "ok": True,
        "isRepo": False,
        "current": "",
        "locals": [],
        "remotes": [],
        "branches": [],
        "error": "",
    }


def _git_entry_error(path, error):
    """创建失败态的 repo 对象（单路径失败不影响其它路径）。"""
    entry = _git_entry(path)
    entry["ok"] = False
    entry["error"] = error
    return entry


def _git_branch_entry(path):
    """读取单个文件夹的 git 分支信息，返回契约中的 repo 对象。

    目录不存在 / 不是文件夹 / 不是 git 仓库 / 读取失败都在返回值里体现，
    不抛异常给 HTTP 层；只有 git 执行环境异常（无 git、超时等）才抛
    RuntimeError，由 do_git_branches 统一转成 ok:false。
    """
    if not os.path.exists(path):
        return _git_entry_error(path, "路径不存在: %s" % path)
    if not os.path.isdir(path):
        return _git_entry_error(path, "路径不是文件夹: %s" % path)

    entry = _git_entry(path)

    # 是否在 git 工作区内（子目录也算；裸仓库会返回 false）
    code, out, _stderr = _git_run(path, ["rev-parse", "--is-inside-work-tree"])
    if code != 0 or out.strip().lower() != "true":
        entry["error"] = "不是 git 仓库"
        return entry
    entry["isRepo"] = True

    # 当前分支；detached HEAD 时 git 输出 HEAD，按契约置空
    code, out, _stderr = _git_run(path, ["rev-parse", "--abbrev-ref", "HEAD"])
    if code == 0:
        current = out.strip()
        if current and current != "HEAD":
            entry["current"] = current
    # HEAD 读取失败（例如刚 git init 还没有任何提交）不算整体失败，current 留空

    # 本地分支
    code, out, stderr = _git_run(path, ["for-each-ref", "--format=%(refname:short)", "refs/heads"])
    if code != 0:
        raise RuntimeError("读取本地分支失败: %s" % _git_error_detail(stderr, code))
    locals_list = [line.strip() for line in out.splitlines() if line.strip()]

    # 远程分支（用完整 refname 再剥前缀：%(refname:short) 会把
    # refs/remotes/origin/HEAD 缩成 "origin"，无法可靠排除，故不用 short 形式）
    code, out, stderr = _git_run(path, ["for-each-ref", "--format=%(refname)", "refs/remotes"])
    if code != 0:
        raise RuntimeError("读取远程分支失败: %s" % _git_error_detail(stderr, code))
    remotes = []
    remote_prefix = "refs/remotes/"
    for line in out.splitlines():
        refname = line.strip()
        if not refname.startswith(remote_prefix):
            continue
        name = refname[len(remote_prefix):]
        if not name or name == "HEAD" or name.endswith("/HEAD"):
            continue
        remotes.append(name)

    # branches = locals + remotes，去重保序，最多 MAX_GIT_BRANCHES 个
    branches = []
    seen = set()
    for name in locals_list + remotes:
        if name in seen:
            continue
        seen.add(name)
        branches.append(name)

    entry["locals"] = locals_list
    entry["remotes"] = remotes
    entry["branches"] = branches[:MAX_GIT_BRANCHES]
    return entry


def do_git_branches(payload):
    """POST /git-branches：读取一批本地文件夹的 git 分支（只读）。

    请求：{"paths": ["E:\\repo1", ...]}，兼容 {"path": "..."}；
          paths 先 strip/去重（Windows 下大小写不敏感）/保序，最多 MAX_GIT_PATHS 个。
    响应：{"repos": [repo, ...]}；单个路径失败只写进对应 repo 的 error。
    请求本身不合法（空/类型错误）抛 RuntimeError，由 _handle_action 转 400。
    """
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise RuntimeError("请求体必须是 JSON 对象")
    raw_paths = payload.get("paths")
    if raw_paths is None and "path" in payload:
        raw_paths = [payload.get("path")]
    if not isinstance(raw_paths, list):
        raise RuntimeError("缺少 paths 参数（应为文件夹路径数组）")

    paths = []
    seen = set()
    for item in raw_paths:
        if not isinstance(item, str):
            continue
        path = item.strip()
        if not path:
            continue
        key = os.path.normcase(os.path.normpath(path))
        if key in seen:
            continue
        seen.add(key)
        paths.append(path)
        if len(paths) >= MAX_GIT_PATHS:
            break
    if not paths:
        raise RuntimeError("paths 不能为空（至少提供一个文件夹路径）")

    repos = []
    for path in paths:
        try:
            repos.append(_git_branch_entry(path))
        except RuntimeError as e:
            repos.append(_git_entry_error(path, str(e)))
        except Exception as e:  # noqa: BLE001
            repos.append(_git_entry_error(path, "读取 git 分支失败: %s" % e))
    return {"repos": repos}


# ---------------------------------------------------------------------------
# HTTP 服务
# ---------------------------------------------------------------------------
class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "CxScopeProxy/2.0"

    def log_message(self, fmt, *args):
        sys.stdout.write("[proxy] " + (fmt % args) + "\n")

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Expose-Headers", "*")

    def _send_json(self, status, obj):
        payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _error(self, status, msg):
        self._send_json(status, {"error": msg})

    def _read_body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length) if length > 0 else b""

    def _read_json_body(self):
        raw = self._read_body()
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError as e:
            raise RuntimeError("请求体不是合法 JSON: %s" % e)

    def _serve_index(self):
        try:
            with open(INDEX_FILE, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            self._error(404, "index.html 未找到，请把它放在与 proxy.py 同一目录。")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _route_get(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html", "/index.htm"):
            self._serve_index()
            return True
        if path == "/health":
            cli_path, cli_error = detect_cx_cli() if SCAN_MODE == "cli" else ("", "")
            self._send_json(200, {
                "ok": True,
                "version": "2.1",
                "allowedHosts": ALLOWED_SUFFIXES,
                "maxUploadMB": MAX_UPLOAD_MB,
                "localScan": True,
                "scanMode": SCAN_MODE,
                "cliPath": cli_path,
                "cliError": cli_error,
                "gitBranches": True,
            })
            return True
        if path == "/favicon.ico":
            self.send_response(204)
            self._cors()
            self.end_headers()
            return True
        return False

    def _proxy(self):
        target = self.headers.get("X-Target-Url")
        if not target:
            self._error(400, "缺少 X-Target-Url 请求头")
            return
        ok, reason = check_url_allowed(target)
        if not ok:
            self._error(403, reason)
            return
        body = self._read_body()
        skip = {"host", "x-target-url", "content-length", "connection", "accept-encoding",
                "origin", "referer", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"}
        fwd_headers = {}
        for k in self.headers.keys():
            if k.lower() in skip:
                continue
            fwd_headers[k] = self.headers[k]
        try:
            status, resp_body, resp_headers = http_request(self.command, target,
                                                           headers=fwd_headers,
                                                           data=body if body else None)
        except Exception as e:  # noqa: BLE001
            self._error(502, "上游请求失败: %s" % e)
            return
        self.send_response(status)
        self._cors()
        skip_resp = {"content-encoding", "content-length", "transfer-encoding", "connection",
                     "access-control-allow-origin", "access-control-allow-methods",
                     "access-control-allow-headers"}
        for k, v in resp_headers.items():
            if k in skip_resp:
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self._route_get():
            return
        self._proxy()

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/local-scan":
            self._handle_action(lambda: do_local_scan(self._read_json_body()))
            return
        if path == "/pick-folder":
            self._handle_action(lambda: {"path": pick_folder()})
            return
        if path == "/git-branches":
            self._handle_action(lambda: do_git_branches(self._read_json_body()))
            return
        self._proxy()

    def _handle_action(self, fn):
        try:
            result = fn()
            self._send_json(200, result)
        except RuntimeError as e:
            self._error(400, str(e))
        except Exception as e:  # noqa: BLE001
            self._error(500, "操作失败: %s" % e)

    def do_PUT(self):
        self._proxy()

    def do_DELETE(self):
        self._proxy()

    def do_PATCH(self):
        self._proxy()


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    if not os.path.exists(INDEX_FILE):
        print("警告: 未找到 index.html，页面将无法访问；请先运行 python app/build.py")
    print("=" * 66)
    print("CxScope · Checkmarx 本地代理已启动")
    print("  页面地址 : http://%s:%d/" % (BIND_HOST, PORT))
    print("  健康检查 : http://%s:%d/health" % (BIND_HOST, PORT))
    print("  允许主机 : %s" % ", ".join(ALLOWED_SUFFIXES))
    if SCAN_MODE == "cli":
        cli_path, cli_error = detect_cx_cli()
        if cli_path:
            print("  扫描方式 : Checkmarx One CLI（%s）" % cli_path)
            if CX_SAST_PRESET:
                print("  SAST 预设: %s" % CX_SAST_PRESET)
        else:
            print("  扫描方式 : Checkmarx One CLI（未找到：%s）" % cli_error)
    else:
        print("  扫描方式 : REST 上传（SCAN_MODE=api，兼容回退）")
        print("  上传上限 : %d MB" % MAX_UPLOAD_MB)
    print("  忽略证书 : %s" % ("是 (INSECURE=1)" if INSECURE else "否"))
    print("  按 Ctrl+C 停止")
    print("=" * 66)
    with Server((BIND_HOST, PORT), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n代理已停止。")


if __name__ == "__main__":
    main()