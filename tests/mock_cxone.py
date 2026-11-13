#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mock Checkmarx One 服务（仅用于本地端到端测试，零依赖）。

模拟：
    - IAM token 端点（refresh_token 换 access_token，API Key 为 JWT）
    - /api/projects、/api/scans、/api/scans/{id}、/api/results
    - /api/uploads + 预签名 PUT 上传 + POST /api/scans（SCAN_MODE=api 的旧本地扫描流程）
    - /mock/cli-scan：假 CLI（tests/fake_cx_cli.py）建扫描入口（SCAN_MODE=cli 流程）
    扫描创建后 2s -> Running，3.5s -> Completed，并生成结果。

用法：
    python tests/mock_cxone.py --port 9100 --key-out %TEMP%\\cx-mock-key.json
"""

import argparse
import base64
import json
import os
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "demo", "_build"))
import mockdata  # noqa: E402

TENANT = "mocktenant"
API_KEY = ""
ACCESS_TOKEN = ""
PORT = 9100


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_jwt(payload):
    header = {"alg": "none", "typ": "JWT"}
    return "%s.%s.sig" % (
        b64url(json.dumps(header).encode()),
        b64url(json.dumps(payload).encode()),
    )


def token_claims(token):
    try:
        parts = token.split(".")
        pad = "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(parts[1] + pad).decode())
    except Exception:  # noqa: BLE001
        return None


def sid(original):
    """把演示数据里的短 ID 映射为 CxOne 风格的 UUID（稳定）。"""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "cx-mock:" + str(original)))


# ---------------------------------------------------------------------------
# 数据
# ---------------------------------------------------------------------------
MOCK = mockdata.build()
PROJECTS = []
PROJECT_BY_ID = {}
SCANS = []
SCAN_BY_ID = {}
RESULTS_BY_SCAN = {}


def project_uuid(original_id):
    return sid("project:" + str(original_id))


def add_result_raw(finding, scan, project):
    vuln = finding.get("remediation") or {}
    data_flow = finding.get("dataFlow") or []
    nodes = [{
        "fileName": n.get("file"),
        "line": n.get("line"),
        "column": 1,
        "name": "%s: %s" % (n.get("label", ""), (n.get("code") or "")[:120]),
    } for n in data_flow]
    return {
        "id": sid("%s|%s" % (finding["id"], scan["id"])),
        "similarityId": sid("sim:" + finding["id"]),
        "type": "sast",
        "label": finding.get("queryName"),
        "status": finding.get("status", "NEW"),
        "state": finding.get("state", "TO_VERIFY"),
        "severity": finding.get("severity", "HIGH"),
        "created": finding.get("foundAt"),
        "firstFoundAt": finding.get("foundAt"),
        "foundAt": finding.get("foundAt"),
        "description": finding.get("description"),
        "recommendations": vuln.get("summary", ""),
        "vulnerabilityDetails": {
            "cweId": "CWE-%s" % finding.get("cwe"),
            "cvssScore": 7.5,
            "cvss": {"version": 3.1, "attackVector": "NETWORK"},
        },
        "data": {
            "queryName": finding.get("queryName"),
            "group": finding.get("groupName"),
            "languageName": finding.get("language"),
            "description": finding.get("description"),
            "filename": finding.get("file"),
            "line": finding.get("line"),
            "nodes": nodes,
            "remediation": vuln.get("summary", ""),
            "remediationLink": "https://docs.checkmarx.com",
        },
    }


def init_data():
    for p in MOCK["projects"]:
        proj = {"id": project_uuid(p["id"]), "name": p["name"], "originalId": p["id"]}
        PROJECTS.append(proj)
        PROJECT_BY_ID[proj["id"]] = proj
    for s in MOCK["scans"]:
        scan = {
            "id": sid("scan:" + s["id"]),
            "originalId": s["id"],
            "projectId": project_uuid(s["projectId"]),
            "branch": s["branch"],
            "status": "Completed",
            "createdAt": s["createdAt"],
            "updatedAt": s["createdAt"],
            "projectName": PROJECT_BY_ID[project_uuid(s["projectId"])]["name"],
        }
        SCANS.append(scan)
        SCAN_BY_ID[scan["id"]] = scan
        results = []
        for f in MOCK["findings"]:
            if f["scanId"] == s["id"]:
                results.append(add_result_raw(f, scan, PROJECT_BY_ID[scan["projectId"]]))
        RESULTS_BY_SCAN[scan["id"]] = results


def add_local_scan_results(scan, project):
    results = []
    for i, tpl in enumerate(MOCK["localScanFindings"]):
        finding = dict(tpl)
        finding["id"] = "local-%s-%d" % (scan["id"][:8], i)
        finding["scanId"] = scan["id"]
        finding["foundAt"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
        finding["state"] = "TO_VERIFY"
        finding["status"] = "NEW"
        results.append(add_result_raw(finding, scan, project))
    RESULTS_BY_SCAN[scan["id"]] = results


def add_overflow_stress_result():
    """给 s-1001-b 扫描追加一条超长内容结果，用于验证详情抽屉不出现横向滚动条。"""
    scan = SCAN_BY_ID.get(sid("scan:s-1001-b"))
    if not scan:
        return
    long_token = "ExtremelyLongUnbrokenTokenForHorizontalOverflowTest" * 6
    long_path = ("src/main/java/com/example/very/long/package/name/that/keeps/going/and/going/"
                 "AnotherLongDirectoryNameWithoutSpaces_" + long_token[:40] + "/"
                 "ExtremelyLongFileNameWithoutAnySpacesAtAllForTestingHorizontalOverflow.java")
    raw = {
        "id": sid("stress-result-1"),
        "similarityId": sid("stress-sim-1"),
        "type": "sast",
        "label": "Overflow Stress",
        "status": "NEW",
        "state": "TO_VERIFY",
        "severity": "LOW",
        "created": "2026-10-20T15:40:00+08:00",
        "firstFoundAt": "2026-10-20T15:40:00+08:00",
        "foundAt": "2026-10-20T15:40:00+08:00",
        "description": "横向溢出压力测试：" + long_token + " 以及超长路径 " + long_path,
        "recommendations": long_token,
        "vulnerabilityDetails": {"cweId": "CWE-22", "cvssScore": 3.1,
                                 "cvss": {"version": 3.1, "attackVector": "NETWORK"}},
        "data": {
            "queryName": "ExtremelyLongQueryNameWithoutAnySpaces_" + long_token[:48],
            "group": "Overflow Stress Test",
            "languageName": "Java",
            "description": long_token,
            "filename": long_path,
            "line": 12345,
            "nodes": [
                {"fileName": long_path, "line": 12345, "column": 1, "name": "source: " + long_token},
                {"fileName": "src/main/java/com/example/Service.java", "line": 88, "column": 9, "name": "sink: " + long_token},
            ],
            "remediation": long_token,
            "remediationLink": "https://docs.checkmarx.com",
        },
    }
    RESULTS_BY_SCAN.setdefault(scan["id"], []).append(raw)


def build_frontend_demo_data():
    """生成给纯前端演示页面（demo/current-page-demo.html）使用的 JSON 数据。"""
    if not PROJECTS:
        init_data()
        add_overflow_stress_result()
    realm = "https://demo.iam.checkmarx.net/auth/realms/demo-tenant"
    api_base = "https://demo.ast.checkmarx.net"
    now = int(time.time())
    api_key = make_jwt({
        "aud": realm, "iss": realm, "azp": "ast-app", "sub": "demo-user",
        "exp": now + 365 * 86400, "iat": now,
    })
    access_token = make_jwt({
        "ast-base-url": api_base, "aud": "ast-app", "sub": "demo-user",
        "exp": now + 3600, "iat": now,
    })
    dummy_scan = {"id": "template"}
    dummy_project = {"id": "template", "name": "template"}
    local_template = [add_result_raw(f, dummy_scan, dummy_project) for f in MOCK["localScanFindings"]]
    first = SCANS[0] if SCANS else None
    sample_url = ""
    if first:
        sample_url = "https://demo.checkmarx.net/#/projects/%s/scans/%s" % (first["projectId"], first["id"])
    return {
        "tenant": "demo-tenant",
        "region": "demo",
        "realmUrl": realm,
        "apiBase": api_base,
        "apiKey": api_key,
        "accessToken": access_token,
        "projects": [{"id": p["id"], "name": p["name"]} for p in PROJECTS],
        "scans": [{k: v for k, v in s.items() if k != "originalId"} for s in SCANS],
        "results": RESULTS_BY_SCAN,
        "localResultsTemplate": local_template,
        "sampleScanUrl": sample_url,
        "sampleFolders": [
            "C:\\demo-projects\\payment-service",
            "C:\\demo-projects\\user-center",
        ],
    }


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "MockCxOne/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[mock] " + (fmt % args) + "\n")

    def _json(self, status, obj):
        data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        return self.rfile.read(n) if n else b""

    def _authorized(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        claims = token_claims(auth[7:].strip())
        return bool(claims and claims.get("ast-base-url") and claims.get("exp", 0) > time.time())

    def _require_auth(self):
        if not self._authorized():
            self._json(401, {"message": "Unauthorized"})
            return False
        return True

    # ---- GET ----
    def do_GET(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        qs = parse_qs(parsed.query)
        if path == "/health":
            self._json(200, {"ok": True, "tenant": TENANT})
            return
        if path.startswith("/api/"):
            if not self._require_auth():
                return
            if path == "/api/projects":
                return self._list_projects(qs)
            if path == "/api/scans":
                return self._list_scans(qs)
            if path.startswith("/api/scans/"):
                scan = SCAN_BY_ID.get(path[len("/api/scans/"):])
                if not scan:
                    self._json(404, {"message": "scan not found"})
                    return
                self._json(200, scan)
                return
            if path == "/api/results":
                return self._list_results(qs)
        self._json(404, {"message": "not found"})

    def _list_projects(self, qs):
        names = [n.lower() for n in qs.get("name", [])]
        items = PROJECTS
        if names:
            items = [p for p in items if p["name"].lower() in names or any(n in p["name"].lower() for n in names)]
        try:
            limit = int(qs.get("limit", ["100"])[0])
            offset = int(qs.get("offset", ["0"])[0])
        except ValueError:
            limit, offset = 100, 0
        total = len(items)
        page = items[offset:offset + limit]
        self._json(200, {"projects": page, "totalCount": total, "filteredTotalCount": total})

    def _list_scans(self, qs):
        pid = (qs.get("project-id") or [""])[0]
        items = [s for s in SCANS if not pid or s["projectId"] == pid]
        items = sorted(items, key=lambda s: s.get("createdAt", ""), reverse=True)
        try:
            limit = int(qs.get("limit", ["100"])[0])
            offset = int(qs.get("offset", ["0"])[0])
        except ValueError:
            limit, offset = 100, 0
        self._json(200, {"scans": items[offset:offset + limit], "totalCount": len(items)})

    def _list_results(self, qs):
        scan_id = (qs.get("scan-id") or [""])[0]
        items = RESULTS_BY_SCAN.get(scan_id, [])
        try:
            limit = int(qs.get("limit", ["500"])[0])
            offset = int(qs.get("offset", ["0"])[0])
        except ValueError:
            limit, offset = 500, 0
        self._json(200, {"results": items[offset:offset + limit], "totalCount": len(items), "scanID": scan_id})

    # ---- POST ----
    def do_POST(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        raw = self._body()
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            payload = {}

        # IAM token endpoint
        if path.startswith("/auth/realms/") and path.endswith("/protocol/openid-connect/token"):
            form = parse_qs(raw.decode("utf-8"))
            grant = (form.get("grant_type") or [""])[0]
            refresh = (form.get("refresh_token") or [""])[0]
            if grant != "refresh_token" or refresh != API_KEY:
                self._json(401, {"error": "invalid_grant", "error_description": "invalid API key"})
                return
            tenant = path.split("/auth/realms/")[1].split("/")[0]
            self._json(200, {
                "access_token": ACCESS_TOKEN,
                "expires_in": 3600,
                "token_type": "bearer",
                "refresh_token": refresh,
                "tenant": tenant,
            })
            return

        # 测试用：假 CLI（tests/fake_cx_cli.py）通过它模拟 `cx scan create` 创建扫描，
        # 代理侧只关心 CLI 输出的扫描 ID，具体扫描进度仍由本 Mock 的 /api/scans/{id} 推进。
        if path == "/mock/cli-scan":
            name = str(payload.get("projectName") or "").strip()
            if not name:
                self._json(400, {"message": "projectName required"})
                return
            branch = str(payload.get("branch") or "main").strip() or "main"
            project = next((p for p in PROJECTS if p["name"] == name), None)
            if not project:
                project = {"id": str(uuid.uuid4()), "name": name}
                PROJECTS.append(project)
                PROJECT_BY_ID[project["id"]] = project
            scan = self._register_scan(project["id"], branch)
            self._json(201, {
                "id": scan["id"],
                "projectId": project["id"],
                "projectName": project["name"],
                "branch": branch,
                "status": scan["status"],
            })
            return

        if path.startswith("/api/"):
            if not self._require_auth():
                return
            if path == "/api/uploads":
                upload_id = str(uuid.uuid4())
                base = "http://127.0.0.1:%d" % PORT
                self._json(200, {"url": base + "/mock-s3/upload/" + upload_id})
                return
            if path == "/api/projects":
                name = (payload.get("name") or "").strip()
                if not name:
                    self._json(400, {"message": "name required"})
                    return
                for p in PROJECTS:
                    if p["name"] == name:
                        self._json(200, p)
                        return
                proj = {"id": str(uuid.uuid4()), "name": name}
                PROJECTS.append(proj)
                PROJECT_BY_ID[proj["id"]] = proj
                self._json(201, proj)
                return
            if path == "/api/scans":
                return self._create_scan(payload)
        self._json(404, {"message": "not found"})

    def _register_scan(self, pid, branch):
        """登记一次新扫描：Queued -> Running -> Completed，并生成本地扫描结果。"""
        scan = {
            "id": str(uuid.uuid4()),
            "projectId": pid,
            "projectName": PROJECT_BY_ID[pid]["name"],
            "branch": branch or "main",
            "status": "Queued",
            "createdAt": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "updatedAt": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        SCANS.append(scan)
        SCAN_BY_ID[scan["id"]] = scan
        RESULTS_BY_SCAN[scan["id"]] = []

        def advance():
            time.sleep(2.0)
            scan["status"] = "Running"
            scan["updatedAt"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            time.sleep(1.5)
            scan["status"] = "Completed"
            scan["updatedAt"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            add_local_scan_results(scan, PROJECT_BY_ID[pid])

        threading.Thread(target=advance, daemon=True).start()
        return scan

    def _create_scan(self, payload):
        handler = payload.get("handler") or {}
        project = payload.get("project") or {}
        pid = project.get("id")
        if pid not in PROJECT_BY_ID:
            self._json(400, {"message": "project not found: %s" % pid})
            return
        upload_url = handler.get("uploadUrl")
        if not upload_url:
            self._json(400, {"message": "uploadUrl required"})
            return
        scan = self._register_scan(pid, handler.get("branch") or "main")
        self._json(201, scan)

    # ---- PUT (mock S3) ----
    def do_PUT(self):
        parsed = urlparse(self.path)
        if parsed.path.startswith("/mock-s3/upload/"):
            # 与真实 Checkmarx 网关一致：预签名上传地址同样要求 Bearer Token，
            # 缺少 Authorization 时返回 401（真实环境大文件会表现为连接中断 10053）。
            if not self._authorized():
                self._json(401, {"message": "Unauthorized"})
                return
            data = self._body()
            sys.stderr.write("[mock] uploaded %d bytes\n" % len(data))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._json(404, {"message": "not found"})


def main():
    global API_KEY, ACCESS_TOKEN, PORT
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9100)
    ap.add_argument("--key-out", default="")
    args = ap.parse_args()
    PORT = args.port
    init_data()
    add_overflow_stress_result()
    realm = "http://127.0.0.1:%d/auth/realms/%s" % (PORT, TENANT)
    now = int(time.time())
    API_KEY = make_jwt({
        "aud": realm,
        "iss": realm,
        "azp": "ast-app",
        "sub": "mock-user",
        "exp": now + 365 * 86400,
        "iat": now,
    })
    ACCESS_TOKEN = make_jwt({
        "ast-base-url": "http://127.0.0.1:%d" % PORT,
        "aud": "ast-app",
        "sub": "mock-user",
        "exp": now + 3600,
        "iat": now,
    })
    if args.key_out:
        with open(args.key_out, "w", encoding="utf-8") as f:
            json.dump({
                "apiKey": API_KEY,
                "apiBase": "http://127.0.0.1:%d" % PORT,
                "scans": {s["originalId"]: s["id"] for s in SCANS if s.get("originalId")},
                "projects": {p["originalId"]: p["id"] for p in PROJECTS if p.get("originalId")},
            }, f)
    print("MOCK_READY apiBase=http://127.0.0.1:%d tenant=%s" % (PORT, TENANT), flush=True)
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()