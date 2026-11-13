# -*- coding: utf-8 -*-
"""构建页面：

1. index.html —— 真实页面（由 proxy.py 提供服务，调用本机代理访问 Checkmarx One）；
2. demo/current-page-demo.html —— 当前页面的纯前端 Demo（模拟 Checkmarx One，
   不需要 proxy、API Key，也不发起网络请求，可直接双击打开）。

用法：python app/build.py
输入：app/index.template.html + app/app.js + app/kb.js + app/demo-mock.js + demo/_build/core.css
"""

import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORE_CSS = os.path.join(ROOT, "demo", "_build", "core.css")


def read(path):
    with io.open(path, "r", encoding="utf-8") as f:
        return f.read()


def write(path, text):
    with io.open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def main():
    template = read(os.path.join(HERE, "index.template.html"))
    core_css = read(CORE_CSS)
    kb_js = read(os.path.join(HERE, "kb.js"))
    app_js = read(os.path.join(HERE, "app.js"))
    demo_mock_js = read(os.path.join(HERE, "demo-mock.js"))

    base = template.replace("/*__CORE_CSS__*/", core_css).replace("/*__KB_JS__*/", kb_js)
    app_block = '<script>\n/*__APP_JS__*/\n</script>'
    if app_block not in base:
        raise SystemExit("模板中未找到 /*__APP_JS__*/ 占位符")

    # 1) 真实页面
    index_html = base.replace(app_block, '<script>\n' + app_js + '\n</script>')
    index_path = os.path.join(ROOT, "index.html")
    write(index_path, index_html)
    print("built %-28s %8.1f KB" % ("index.html", os.path.getsize(index_path) / 1024.0))

    # 2) 当前页面的纯前端 Demo（注入演示数据 + mock 层，位于 app.js 之前）
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    import mock_cxone  # noqa: E402

    demo_data = mock_cxone.build_frontend_demo_data()
    data_json = json.dumps(demo_data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    demo_block = (
        '<script>\nwindow.CX_DEMO_MOCK_DATA = ' + data_json + ';\n</script>\n'
        '<script>\n' + demo_mock_js + '\n</script>\n'
        '<script>\n' + app_js + '\n</script>'
    )
    demo_html = base.replace(app_block, demo_block)
    demo_html = demo_html.replace(
        "<title>CxScope · Checkmarx One 漏洞看板</title>",
        "<title>CxScope · 当前页面 Demo（模拟数据）</title>",
    )
    demo_path = os.path.join(ROOT, "demo", "current-page-demo.html")
    write(demo_path, demo_html)
    print("built %-28s %8.1f KB" % ("demo/current-page-demo.html", os.path.getsize(demo_path) / 1024.0))


if __name__ == "__main__":
    main()