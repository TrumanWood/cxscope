# -*- coding: utf-8 -*-
"""把共用资源注入三套 Demo 模板，生成可直接双击打开的独立 HTML。

用法：python demo/_build/build.py
输出：demo/demo-1-classic.html / demo-2-board.html / demo-3-dark.html
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEMO_DIR = os.path.dirname(HERE)

TEMPLATES = [
    ("tpl-classic.html", "demo-1-classic.html"),
    ("tpl-board.html", "demo-2-board.html"),
    ("tpl-dark.html", "demo-3-dark.html"),
]


def main():
    sys.path.insert(0, HERE)
    import mockdata  # noqa: E402

    with open(os.path.join(HERE, "core.css"), "r", encoding="utf-8") as f:
        core_css = f.read()
    with open(os.path.join(HERE, "core.js"), "r", encoding="utf-8") as f:
        core_js = f.read()

    data = mockdata.build()
    mock_json = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    # 避免 JSON 意外闭合 script 标签
    mock_json = mock_json.replace("</", "<\\/")

    for tpl_name, out_name in TEMPLATES:
        with open(os.path.join(HERE, tpl_name), "r", encoding="utf-8") as f:
            html = f.read()
        html = html.replace("/*__CORE_CSS__*/", core_css)
        html = html.replace("/*__CORE_JS__*/", core_js)
        html = html.replace("/*__MOCK__*/", mock_json)
        out_path = os.path.join(DEMO_DIR, out_name)
        with open(out_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(html)
        print("built %-24s %8.1f KB" % (out_name, os.path.getsize(out_path) / 1024.0))


if __name__ == "__main__":
    main()