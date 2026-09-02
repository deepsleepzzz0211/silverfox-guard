# -*- coding: utf-8 -*-
"""从 CHANGELOG.md 提取指定版本的段落，输出为 GitHub Release 说明。

用法: python tools/extract_changelog.py 1.0.7  > release_notes.md
格式遵循 Keep a Changelog：`## [版本] - 日期` 起始，至下一个 `## [` 结束。
"""
import io
import sys


def main():
    if len(sys.argv) < 2:
        print("usage: extract_changelog.py <version>", file=sys.stderr)
        return 1
    version = sys.argv[1].strip().lstrip("v")
    lines = io.open("CHANGELOG.md", encoding="utf-8").read().splitlines()

    out, capture = [], False
    for line in lines:
        if line.startswith("## ["):
            if capture:
                break
            capture = line.startswith(f"## [{version}]")
            if capture:
                out.append(line)
            continue
        if capture:
            out.append(line)

    if not out:
        out = [f"## [{version}]", "", "详见 CHANGELOG.md。"]

    footer = [
        "",
        "---",
        "",
        "**安装**：解压 zip 后，在 Chrome/Edge 扩展管理页开启「开发者模式」→「加载已解压的扩展程序」选择解压目录。图文指南见仓库 `pages/guide/guide.html`。",
        "",
        "免责声明：启发式检测存在误报可能，仅供防护参考。",
        "",
    ]
    sys.stdout.write("\n".join(out + footer))
    return 0


if __name__ == "__main__":
    sys.exit(main())
