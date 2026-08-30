# -*- coding: utf-8 -*-
"""构建 dist/ 发布产物（开发者模式加载 / 未来商店 zip 通用）。

产出：
- dist/silverfox-guard/          仅含运行所需文件的干净目录（浏览器「加载解压缩的扩展」直接指向这里）
- dist/silverfox-guard-v<版本>.zip  同一内容的 zip（manifest 在压缩包根目录，未来上架 CWS/Edge 可直接用）

用法: python tools/build_dist.py
"""
import json
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
APP_NAME = "silverfox-guard"

# 扩展运行必需的文件/目录（不含 docs、test、tools、README 等开发文件）
INCLUDE = [
    "manifest.json",
    "background",
    "content",
    "data",
    "icons",
    "lib",
    "pages",
]
# 目录内仍需排除的开发文件
EXCLUDE_PARTS = {"docs", "test", "tools", ".zcode", "dist", "__pycache__"}
EXCLUDE_FILES = {"README.md", "package.json", "package-lock.json"}


def iter_files():
    for item in INCLUDE:
        src = ROOT / item
        if src.is_file():
            yield src
        elif src.is_dir():
            for p in src.rglob("*"):
                if p.is_file() and not (EXCLUDE_PARTS & set(p.relative_to(ROOT).parts)):
                    yield p


def main():
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    version = manifest["version"]

    app_dir = DIST / APP_NAME
    if app_dir.exists():
        shutil.rmtree(app_dir)
    app_dir.mkdir(parents=True)

    copied = 0
    for src in iter_files():
        if src.name in EXCLUDE_FILES:
            continue
        dest = app_dir / src.relative_to(ROOT)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        copied += 1

    zip_path = DIST / f"{APP_NAME}-v{version}.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(app_dir.rglob("*")):
            if p.is_file():
                zf.write(p, p.relative_to(app_dir).as_posix())

    print(f"version: {version}")
    print(f"dist dir : {app_dir}  ({copied} files)")
    print(f"dist zip : {zip_path}  ({zip_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
