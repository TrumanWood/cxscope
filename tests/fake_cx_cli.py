#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试用的假 Checkmarx One CLI（仅 e2e 使用，不连接真实 Checkmarx）。

代理会把 CX_CLI_PATH 指向本脚本（Windows 下经 .cmd 包装），并传入与真实 CLI
相同的参数与环境变量。本脚本：

    1. 把收到的参数、关键环境变量写入 FAKE_CX_RECORD（JSONL），供 e2e 断言代理调用是否正确；
    2. 校验扫描目录存在（真实 CLI 也会校验，不存在时同样失败）；
    3. 通过 mock 服务的 /mock/cli-scan 创建扫描，并输出与真实 CLI
       `--scan-info-format json` 一致的扫描信息（含 Scan ID / Project ID）；
    4. 用退出码 + 标准错误模拟真实 CLI 的失败行为。

环境变量：
    FAKE_CX_RECORD   可选，记录调用参数的文件路径
    CX_APIKEY        代理传入的 API Key（真实 CLI 用它认证；这里只记录是否传入，不记录明文）

mock 服务地址取自代理传入的 --base-uri。
"""

import json
import os
import sys
import urllib.error
import urllib.request


def fail(message):
    sys.stderr.write(message + "\n")
    return 1


def option(args, *names):
    """读取 `--flag value` 形式的参数值。"""
    for index, item in enumerate(args):
        if item in names and index + 1 < len(args):
            return args[index + 1]
    return ""


def has_flag(args, *names):
    return any(item in names for item in args)


def main(argv):
    record = os.environ.get("FAKE_CX_RECORD", "")
    if record:
        with open(record, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "argv": argv,
                "apiKeyEnv": bool(os.environ.get("CX_APIKEY")),
                "baseUriEnv": os.environ.get("CX_BASE_URI", ""),
                "authUriEnv": os.environ.get("CX_BASE_AUTH_URI", ""),
                "tenantEnv": os.environ.get("CX_TENANT", ""),
            }, ensure_ascii=False) + "\n")

    if not argv or argv[0] != "scan" or len(argv) < 2 or argv[1] != "create":
        return fail("fake cx: 仅支持 scan create，收到: %s" % " ".join(argv))
    if not has_flag(argv, "--async"):
        return fail("fake cx: 本地扫描应使用 --async（代理未按约定传参）")
    if option(argv, "--scan-info-format") != "json":
        return fail("fake cx: 期望 --scan-info-format json，实际: %r"
                    % option(argv, "--scan-info-format"))
    folder = option(argv, "-s", "--file-source")
    if not folder:
        return fail("fake cx: 缺少 -s/--file-source 参数")
    if not os.path.exists(folder):
        return fail("路径不存在: %s" % folder)
    project_name = option(argv, "--project-name")
    if not project_name:
        return fail("fake cx: 缺少 --project-name 参数")
    if not os.environ.get("CX_APIKEY"):
        return fail("fake cx: 缺少 CX_APIKEY（页面登录的 API Key 未传给 CLI）")
    base_uri = (option(argv, "--base-uri") or os.environ.get("CX_BASE_URI", "")).rstrip("/")
    if not base_uri:
        return fail("fake cx: 缺少 --base-uri 参数")
    branch = option(argv, "--branch") or "main"

    body = json.dumps({"projectName": project_name, "branch": branch}).encode("utf-8")
    request = urllib.request.Request(base_uri + "/mock/cli-scan", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            scan = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        return fail("fake cx: mock 创建扫描失败（HTTP %s）: %s" % (exc.code, detail))
    except Exception as exc:  # noqa: BLE001
        return fail("fake cx: 无法连接 mock 服务（%s）: %s" % (base_uri, exc))

    # 模拟真实 CLI `--scan-info-format json` 的输出（至少包含扫描 ID / 项目 ID 供代理解析）
    print(json.dumps({
        "id": scan.get("id"),
        "projectId": scan.get("projectId"),
        "projectName": scan.get("projectName") or project_name,
        "branch": branch,
        "status": scan.get("status") or "Queued",
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))