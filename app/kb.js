/* ==========================================================================
   Checkmarx 漏洞看板 · 内置知识库（攻击向量 / 修复建议 / 参考链接）
   说明：Checkmarx One API 返回 description、recommendations、data.remediation、
   data.nodes 等字段；但“攻击向量、修复代码示例”并非每条结果都以结构化形式提供，
   因此这里内置常见 CWE/漏洞类型的安全知识作为补充。未命中的类型回退到通用说明 +
   CWE / OWASP / Checkmarx Query Help 参考链接。
   ========================================================================== */
window.CX_KB = {
  cwes: {
    22: {
      name: '路径遍历',
      owasp: 'https://owasp.org/www-community/attacks/Path_Traversal',
      attackVector: '应用直接使用用户可控的文件名/路径拼接读取或写入文件时，攻击者可通过 ../ 序列逃逸出原目录，读取服务器任意文件（如配置、密钥、系统文件）。',
      payload: 'GET /download?name=..%2F..%2F..%2F..%2Fetc%2Fpasswd',
      remediation: {
        summary: '读取文件前先规范化路径并校验结果仍位于允许的根目录内；不要直接使用用户提供的文件名拼接路径。',
        examples: [{
          title: 'normalize 后校验根目录', lang: 'java',
          bad: 'File f = new File("/data/reports/" + request.getParameter("name"));\nreturn Files.readAllBytes(f.toPath());',
          good: 'Path base = Paths.get("/data/reports").toRealPath();\nPath target = base.resolve(name).normalize().toRealPath();\nif (!target.startsWith(base)) throw new SecurityException("非法路径");'
        }]
      }
    },
    78: {
      name: 'OS 命令注入',
      owasp: 'https://owasp.org/www-community/attacks/Command_Injection',
      attackVector: '应用把外部输入拼接进 shell 命令，攻击者可注入额外的命令分隔符（; | &&）在服务器上执行任意命令，完全控制应用主机。',
      payload: '; id > /tmp/pwned',
      remediation: {
        summary: '避免把外部输入拼接进 shell 命令。优先使用进程 API 的参数数组形式；必须调用 shell 时，对参数做白名单校验并转义。',
        examples: [{
          title: '改用 ProcessBuilder 参数列表', lang: 'java',
          bad: 'Runtime.getRuntime().exec("tar -czf /backup/" + request.getParameter("dir") + ".tgz");',
          good: 'new ProcessBuilder("tar", "-czf", backupFile.toString(), safeDir.toString())\n    .redirectErrorStream(true).start(); // safeDir 已白名单校验'
        }]
      }
    },
    79: {
      name: '跨站脚本（XSS）',
      owasp: 'https://owasp.org/www-community/attacks/xss/',
      attackVector: '应用把不可信内容直接输出到 HTML 上下文，攻击者提交带脚本的内容，在他人浏览页面时执行脚本，窃取会话或冒用身份。',
      payload: '<img src=x onerror=alert(document.cookie)>',
      remediation: {
        summary: '输出到 HTML 上下文前做编码/转义，优先使用框架自带的输出编码；富文本使用白名单清洗（如 DOMPurify）。',
        examples: [{
          title: '渲染前转义用户内容', lang: 'javascript',
          bad: 'commentBox.innerHTML = "<div>" + comment.content + "</div>";',
          good: 'commentBox.textContent = comment.content;\n// 或：commentBox.innerHTML = DOMPurify.sanitize(comment.content);'
        }]
      }
    },
    89: {
      name: 'SQL 注入',
      owasp: 'https://owasp.org/www-community/attacks/SQL_Injection',
      attackVector: '应用把用户输入直接拼接进 SQL 语句，攻击者可构造恶意输入改变查询语义，读取、篡改或删除数据库数据，甚至借此提权。',
      payload: "GET /api/items?id=1%27%20OR%20%271%27%3D%271%27%20--%20",
      remediation: {
        summary: '始终使用参数化查询或预编译语句，把 SQL 结构与用户输入分离；无法参数化时必须对标识符做严格白名单校验。',
        examples: [{
          title: '使用 PreparedStatement 参数化查询', lang: 'java',
          bad: 'String sql = "SELECT * FROM items WHERE id = \'" + id + "\'";\nStatement st = conn.createStatement();\nResultSet rs = st.executeQuery(sql);',
          good: 'String sql = "SELECT * FROM items WHERE id = ?";\nPreparedStatement ps = conn.prepareStatement(sql);\nps.setString(1, id);\nResultSet rs = ps.executeQuery();'
        }]
      }
    },
    90: {
      name: 'LDAP 注入',
      owasp: 'https://owasp.org/www-community/attacks/LDAP_Injection',
      attackVector: '应用把用户输入直接拼进 LDAP 过滤条件，攻击者可注入 LDAP 语法绕过认证或枚举目录中的用户与权限信息。',
      payload: 'username=*)(uid=*))(|(uid=*&password=whatever',
      remediation: {
        summary: '使用安全的 LDAP 编码工具对过滤条件中的特殊字符转义，或改用参数化的身份查询接口。',
        examples: [{
          title: '转义 LDAP 过滤特殊字符', lang: 'java',
          bad: 'String filter = "(uid=" + username + ")";\nctx.search(base, filter, controls);',
          good: 'String filter = "(uid=" + LdapEncoder.filterEncode(username) + ")";\nctx.search(base, filter, controls);'
        }]
      }
    },
    319: {
      name: '明文传输敏感数据',
      owasp: 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
      attackVector: '站点缺少 HSTS 等传输安全配置时，攻击者可在公共网络实施降级/中间人攻击，劫持会话或窃取凭据。',
      payload: 'curl -sI https://target.example | grep -i strict-transport-security',
      remediation: {
        summary: '在 HTTPS 响应中添加 Strict-Transport-Security 头，并确保所有 HTTP 请求与子域名均重定向到 HTTPS。',
        examples: [{
          title: 'Nginx 增加 HSTS', lang: 'nginx',
          bad: 'server {\n  listen 443 ssl;\n  server_name app.example;\n}',
          good: 'server {\n  listen 443 ssl;\n  server_name app.example;\n  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n}'
        }]
      }
    },
    327: {
      name: '使用已破解或有风险的加密算法',
      owasp: 'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
      attackVector: '使用 MD5/SHA-1 等快速哈希保存口令时，攻击者拿到数据库后可借助 GPU 或彩虹表快速还原弱口令，进而登录其他系统。',
      payload: 'hashcat -m 0 -a 0 hashes.txt rockyou.txt',
      remediation: {
        summary: '密码存储使用 Argon2/bcrypt/PBKDF2 等慢哈希并加盐；避免 MD5/SHA-1 等已被破解的算法。',
        examples: [{
          title: '使用 BCrypt 存储密码', lang: 'java',
          bad: 'String hash = DigestUtils.md5Hex(password);',
          good: 'String hash = BCrypt.hashpw(password, BCrypt.gensalt(12));\nboolean ok = BCrypt.checkpw(password, hash);'
        }]
      }
    },
    330: {
      name: '使用不充分的随机值',
      owasp: 'https://owasp.org/www-community/vulnerabilities/Insecure_Randomness',
      attackVector: '使用可预测的伪随机数生成令牌/验证码时，攻击者可推算随机序列，预测他人的重置令牌或会话标识。',
      payload: 'seed = System.currentTimeMillis(); new Random(seed).nextLong()',
      remediation: {
        summary: '安全敏感的随机值（Token、验证码、Session ID）必须使用加密安全随机数生成器（CSPRNG）。',
        examples: [{
          title: '使用 SecureRandom', lang: 'java',
          bad: 'String token = String.valueOf(new Random().nextLong());',
          good: 'byte[] buf = new byte[32];\nnew SecureRandom().nextBytes(buf);\nString token = Base64.getUrlEncoder().withoutPadding().encodeToString(buf);'
        }]
      }
    },
    502: {
      name: '不可信数据反序列化',
      owasp: 'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data',
      attackVector: '应用对不可信数据使用原生反序列化时，攻击者可构造恶意序列化链触发远程代码执行，危害通常为最高等级。',
      payload: 'SESSION=rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ...',
      remediation: {
        summary: '禁止对不可信数据使用原生反序列化；改用 JSON 等数据格式并校验类型，或使用带类型白名单的 ObjectInputFilter。',
        examples: [{
          title: '使用 ObjectInputFilter 白名单', lang: 'java',
          bad: 'ObjectInputStream in = new ObjectInputStream(request.getInputStream());\nObject o = in.readObject();',
          good: 'ObjectInputStream in = new ObjectInputStream(request.getInputStream());\nin.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.acme.dto.*;!*"));\nObject o = in.readObject();'
        }]
      }
    },
    532: {
      name: '日志中记录敏感信息',
      owasp: 'https://cwe.mitre.org/data/definitions/532.html',
      attackVector: '日志中记录口令、令牌等敏感字段时，具备日志读取权限的人员可直接获取凭据，扩大攻击面。',
      payload: "grep -o 'password=[^&]*' /var/log/app/access.log",
      remediation: {
        summary: '日志中禁止记录口令、令牌、证件号等敏感字段；必要时做脱敏后再输出。',
        examples: [{
          title: '日志脱敏', lang: 'java',
          bad: 'log.info("login attempt: user={} password={}", user, password);',
          good: 'log.info("login attempt: user={} password=***", user);'
        }]
      }
    },
    601: {
      name: '开放重定向',
      owasp: 'https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet',
      attackVector: '应用直接跳转到用户提供的地址时，攻击者可构造链接把用户引导至钓鱼站点，借助可信域名实施凭据窃取。',
      payload: 'GET /login?next=https%3A%2F%2Fevil.example',
      remediation: {
        summary: '重定向目标使用服务端映射的白名单关键字，不要直接使用请求参数中的 URL；跳转前校验域名属于可信列表。',
        examples: [{
          title: '使用白名单关键字映射', lang: 'java',
          bad: 'response.sendRedirect(request.getParameter("next"));',
          good: 'String target = ALLOWED_REDIRECTS.getOrDefault(nextKey, "/home");\nresponse.sendRedirect(target);'
        }]
      }
    },
    611: {
      name: 'XML 外部实体（XXE）',
      owasp: 'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing',
      attackVector: 'XML 解析器未禁用外部实体时，攻击者可通过上传包含实体的 XML 读取服务器文件或发起 SSRF 请求。',
      payload: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
      remediation: {
        summary: '禁用外部实体与 DTD 解析，使用安全的 XML 解析器配置；不要解析不可信来源的 XML。',
        examples: [{
          title: '关闭 DTD 与外部实体', lang: 'java',
          bad: 'DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nDocument doc = f.newDocumentBuilder().parse(inputStream);',
          good: 'DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nf.setFeature("http://xml.org/sax/features/external-general-entities", false);\nf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);'
        }]
      }
    },
    798: {
      name: '硬编码凭据',
      owasp: 'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
      attackVector: '凭据以明文形式硬编码在源码/配置中，任何能访问仓库或制品的人都能获取生产凭据，且轮换需要重新发版。',
      payload: 'jar -xf app.jar && strings *.class | grep -i passw',
      remediation: {
        summary: '把凭据移到密钥管理服务或环境变量/加密配置中，并定期轮换；仓库中不得出现任何明文口令。',
        examples: [{
          title: '从环境变量/密钥服务读取', lang: 'java',
          bad: 'private static final String DB_PASSWORD = "Passw0rd!";',
          good: 'String dbPassword = vault.read("secret/data/app-db").get("password");'
        }]
      }
    },
    918: {
      name: '服务端请求伪造（SSRF）',
      owasp: 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
      attackVector: '服务端根据用户输入发起请求时，攻击者可让服务端访问内网服务或云元数据接口，获取敏感信息或攻击内部系统。',
      payload: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
      remediation: {
        summary: '对外部 URL 做协议与目标地址白名单校验，禁止访问内网/环回/元数据地址；必要时通过固定出口代理发起请求。',
        examples: [{
          title: '校验目标地址与协议', lang: 'java',
          bad: 'URL url = new URL(request.getParameter("callback"));\nHttpURLConnection c = (HttpURLConnection) url.openConnection();',
          good: 'URI uri = URI.create(callback);\nif (!"https".equals(uri.getScheme()) || isInternalHost(uri.getHost()))\n    throw new IllegalArgumentException("非法回调地址");'
        }]
      }
    },
    1004: {
      name: '不安全的 Cookie 配置',
      owasp: 'https://owasp.org/www-community/controls/SecureCookieAttribute',
      attackVector: '会话 Cookie 未设置 HttpOnly/Secure/SameSite 时，可被页面脚本读取或经明文连接泄露，导致会话被劫持。',
      payload: 'document.cookie',
      remediation: {
        summary: '会话 Cookie 设置 HttpOnly、Secure 与合适的 SameSite 属性，避免被脚本读取或跨站携带。',
        examples: [{
          title: '设置安全属性', lang: 'javascript',
          bad: 'document.cookie = `sid=${token}`;',
          good: '// 服务端下发：Set-Cookie: sid=<token>; HttpOnly; Secure; SameSite=Lax'
        }]
      }
    },
    1321: {
      name: '原型污染',
      owasp: 'https://owasp.org/www-community/vulnerabilities/Prototype_Pollution',
      attackVector: '对象合并/解析逻辑未过滤 __proto__ 等特殊键时，攻击者可通过恶意 JSON 污染 Object.prototype，绕过前端权限判断或触发代码执行。',
      payload: '{"__proto__":{"isAdmin":true},"name":"guest"}',
      remediation: {
        summary: '合并对象时过滤 __proto__、constructor、prototype 等危险键，使用 Object.create(null) 或安全合并库。',
        examples: [{
          title: '过滤危险键再合并', lang: 'javascript',
          bad: 'function merge(target, src) {\n  for (const k in src) target[k] = src[k];\n  return target;\n}',
          good: 'function merge(target, src) {\n  for (const k of Object.keys(src)) {\n    if (["__proto__", "constructor", "prototype"].includes(k)) continue;\n    target[k] = src[k];\n  }\n  return target;\n}'
        }]
      }
    }
  },

  /* 按漏洞类型名称猜测 CWE（部分结果 cweId 缺失时使用） */
  queryHints: [
    { re: /sql/i, cwe: 89 },
    { re: /xss|cross.?site/i, cwe: 79 },
    { re: /path.?traversal|directory.?traversal/i, cwe: 22 },
    { re: /command.?inject|os.?command|code.?inject/i, cwe: 78 },
    { re: /ldap/i, cwe: 90 },
    { re: /xxe|xml.?external/i, cwe: 611 },
    { re: /ssrf|server.?side.?request/i, cwe: 918 },
    { re: /deserial/i, cwe: 502 },
    { re: /hardcoded|credential|password|secret/i, cwe: 798 },
    { re: /weak.?hash|md5|sha-?1|hash/i, cwe: 327 },
    { re: /random/i, cwe: 330 },
    { re: /redirect/i, cwe: 601 },
    { re: /prototype.?pollution/i, cwe: 1321 },
    { re: /hsts|transport/i, cwe: 319 },
    { re: /log/i, cwe: 532 },
    { re: /cookie/i, cwe: 1004 }
  ],

  generic: {
    attackVector: '该漏洞类型未命中内置知识库。请结合下方「漏洞说明」与污点数据流定位不可信输入到达敏感操作的路径，并参考 CWE / OWASP 链接确认利用方式与修复方案。',
    remediation: {
      summary: '优先根据 Checkmarx 提供的修复建议处理；通用原则：对不可信输入做严格校验/编码，按最小权限原则处理敏感操作，并为修复补充单元/集成测试。',
      examples: []
    }
  },

  /** 根据结果计算 CWE 编号（数字） */
  resolveCwe: function (cweRaw, queryName) {
    var m = String(cweRaw == null ? '' : cweRaw).match(/(\d+)/);
    if (m) return parseInt(m[1], 10);
    var q = String(queryName || '');
    for (var i = 0; i < this.queryHints.length; i++) {
      if (this.queryHints[i].re.test(q)) return this.queryHints[i].cwe;
    }
    return 0;
  },
  /** 获取知识条目（找不到返回 generic 结构） */
  lookup: function (cweRaw, queryName) {
    var cwe = this.resolveCwe(cweRaw, queryName);
    var entry = this.cwes[cwe];
    if (!entry) return { cwe: cwe, entry: null };
    return { cwe: cwe, entry: entry };
  },
  cweUrl: function (cwe) { return 'https://cwe.mitre.org/data/definitions/' + cwe + '.html'; }
};