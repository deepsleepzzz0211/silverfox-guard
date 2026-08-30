# -*- coding: utf-8 -*-
"""构建内置黑名单 data/blocklist.json。

数据来源：
- LGSRC Archive_2.md  银狐相关已核实恶意网站（含仿冒类别标注）
- LGSRC Archive_3.md  未核实的疑似恶意网站（高误报，仅作“疑似”档）
- OpenPhish 社区 feed 通用钓鱼 URL
- URLhaus text feed    通用恶意软件分发 URL

用法: python tools/build_blocklist.py
"""
import json
import re
import sys
import urllib.request
import urllib.parse
from datetime import datetime, timezone

SOURCES = {
    "lgsrc_verified": "https://raw.githubusercontent.com/Lingggao/LGSRC/main/Archive_2.md",
    "lgsrc_suspect": "https://raw.githubusercontent.com/Lingggao/LGSRC/main/Archive_3.md",
    "openphish": "https://openphish.com/feed.txt",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text/",
}

DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$"
)


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 silverfox-guard build"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read().decode("utf-8", "replace")


def deobfuscate(text):
    """还原 LGSRC 的 [.] 与 hxxp 混淆"""
    text = text.replace("[.]", ".").replace("(.)", ".")
    text = re.sub(r"^h(?:tt|xx)ps?://", "", text.strip())
    return text


def host_of(token):
    token = deobfuscate(token)
    if not token or "/" in token and "://" not in token and "." not in token.split("/")[0]:
        pass
    if "://" not in token:
        token = "http://" + token
    try:
        host = urllib.parse.urlparse(token).hostname or ""
    except ValueError:
        return ""
    host = host.lower().rstrip(".")
    return host if DOMAIN_RE.match(host) else ""


def base_domain(host):
    """去掉 www. 前缀，保留完整可拦截的域名后缀形式"""
    parts = host.split(".")
    if len(parts) > 2 and parts[0] in ("www", "web", "wap", "m"):
        return ".".join(parts[1:])
    return host


TWO_LEVEL_TLDS = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "hl.cn", "hk.cn", "tw.cn",
    "com.hk", "co.uk", "com.au",
}


def registrable_domain(host):
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in TWO_LEVEL_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


# 共享托管平台：恶意样本常借这些平台分发，但整域拦截会误杀正常访问，必须丢弃
SHARED_PLATFORMS = {
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    "sourceforge.net", "dropbox.com", "dropboxusercontent.com",
    "google.com", "microsoft.com", "live.com", "onedrive.com",
    "wordpress.com", "medium.com", "t.me",
}

# 租户型托管平台：每个子域是独立租户，可安全拦截完整子域；
# 仅当裸平台域名本身（如 "github.io"）出现时防御性丢弃
TENANT_PLATFORMS = {
    "github.io", "gitlab.io", "pages.dev", "vercel.app", "netlify.app",
    "workers.dev", "r2.dev", "azurewebsites.net", "herokuapp.com",
    "firebaseapp.com", "web.app", "glitch.me", "repl.co",
    "000webhostapp.com", "blogspot.com", "amazonaws.com", "cloudfront.net",
    "azureedge.net", "b-cdn.net", "fly.dev", "firebaseio.com", "codeberg.page",
}


def filter_platform(host):
    """共享平台整域丢弃；租户平台保留完整子域。返回 None 表示不入库。"""
    reg = registrable_domain(host)
    if reg in SHARED_PLATFORMS:
        return None
    if reg in TENANT_PLATFORMS and host == reg:
        return None
    return base_domain(host)


def parse_lgsrc_archive2(text):
    """Archive_2.md 表格：| 日期 | URL | 类别 | 有效载荷 | URLhaus | 编号 |"""
    out = {}
    for line in text.splitlines():
        if not line.strip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3 or not re.match(r"^\d{4}/", cells[0] or ""):
            continue
        cat = cells[2] if len(cells) > 2 else ""
        # URL 列 + 有效载荷列都可能是恶意分发地址
        for token_cell in (cells[1] if len(cells) > 1 else "", cells[3] if len(cells) > 3 else ""):
            for token in token_cell.split():
                host = host_of(token)
                d = filter_platform(host) if host else None
                if d:
                    out.setdefault(d, cat or "银狐关联恶意网站")
    return out


def parse_lgsrc_archive3(text):
    """Archive_3.md：``` 代码块内的疑似恶意域名（未核实）"""
    out = set()
    in_block = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("```"):
            in_block = not in_block
            continue
        if not in_block:
            continue
        for token in s.split():
            host = host_of(token)
            if host:
                d = filter_platform(host)
                if d:
                    out.add(d)
    return out


def domains_from_url_list(text):
    out = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = host_of(line)
        if host:
            d = filter_platform(host)
            if d:
                out.add(d)
    return out


def main():
    data = {
        "generatedAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "version": 1,
        "verified": {},    # 域名 -> 仿冒/恶意类别（已核实，硬拦截）
        "suspect": [],     # 未核实疑似域名（软警告）
        "phishing": [],    # OpenPhish 通用钓鱼
        "malware": [],     # URLhaus 恶意软件分发
    }

    print("fetching", SOURCES["lgsrc_verified"])
    data["verified"] = parse_lgsrc_archive2(fetch(SOURCES["lgsrc_verified"]))
    print("  verified domains:", len(data["verified"]))

    print("fetching", SOURCES["lgsrc_suspect"])
    suspect = parse_lgsrc_archive3(fetch(SOURCES["lgsrc_suspect"]))
    data["suspect"] = sorted(suspect - set(data["verified"]))
    print("  suspect domains:", len(data["suspect"]))

    print("fetching", SOURCES["openphish"])
    phishing = domains_from_url_list(fetch(SOURCES["openphish"]))
    data["phishing"] = sorted(phishing - set(data["verified"]))
    print("  phishing domains:", len(data["phishing"]))

    print("fetching", SOURCES["urlhaus"])
    malware = domains_from_url_list(fetch(SOURCES["urlhaus"]))
    data["malware"] = sorted(malware - set(data["verified"]) - set(phishing))
    print("  malware domains:", len(data["malware"]))

    with open("data/blocklist.json", "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
    total = len(data["verified"]) + len(data["suspect"]) + len(data["phishing"]) + len(data["malware"])
    print("wrote data/blocklist.json, total domains:", total)


if __name__ == "__main__":
    sys.exit(main())
