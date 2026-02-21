#!/usr/bin/env python3
"""
Fetch and process rules from remote sources, remove malicious lines,
merge groups, produce Surge (.conf) and Quantumult X (.snippet) outputs.

Run locally: python3 scripts/process_rules.py
"""
import os
import re
import sys
from urllib.parse import urljoin, urlparse

try:
    import requests
    from bs4 import BeautifulSoup
except Exception:
    print("Missing dependencies. Run: pip install -r requirements.txt")
    sys.exit(1)

BASE_ROOT = 'https://ruleset.skk.moe/'
BAD_PATTERNS = [
    "DOMAIN,this_ruleset_is_made_by_sukkaw.ruleset.skk.moe",
    "7h1s_rul35et_i5_mad3_by_5ukk4w-ruleset.skk.moe",
    "chat.z.ai",
]

OUT_DIR = 'generated'

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def save_file(path, content):
    ensure_dir(os.path.dirname(path))
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

def fetch_url(url):
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.text

def crawl_and_mirror(root_url=BASE_ROOT, dest='List'):
    """Crawl a simple directory listing and mirror files under dest/ preserving structure."""
    print(f"Crawling {root_url}")
    text = fetch_url(root_url)
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(text, 'html.parser')
    links = [a.get('href') for a in soup.find_all('a') if a.get('href')]
    files = []
    for href in links:
        if href in ('../', './'):
            continue
        full = urljoin(root_url, href)
        if href.endswith('/'):
            # recursive
            subpath = urljoin(root_url, href)
            try:
                subtext = fetch_url(subpath)
            except Exception:
                continue
            sub_soup = BeautifulSoup(subtext, 'html.parser')
            for a in sub_soup.find_all('a'):
                subhref = a.get('href')
                if not subhref or subhref in ('../', './'):
                    continue
                files.append(urljoin(subpath, subhref))
        else:
            files.append(full)

    saved = []
    for f in files:
        try:
            body = fetch_url(f)
        except Exception:
            continue
        # get relative path after /List/
        parsed = urlparse(f)
        rel = parsed.path
        idx = rel.find('/')
        if idx != -1:
            relpath = rel[idx+1:]
        else:
            relpath = os.path.basename(rel)
        local_path = os.path.join(dest, relpath)
        save_file(local_path, body)
        saved.append(local_path)
    print(f"Mirrored {len(saved)} files under {dest}/")
    return saved

def load_lines_from_sources(sources):
    lines = []
    for src in sources:
        if src.startswith('http://') or src.startswith('https://'):
            try:
                text = fetch_url(src)
            except Exception as e:
                print(f"Failed to fetch {src}: {e}")
                continue
        else:
            if not os.path.exists(src):
                print(f"Local source missing: {src}")
                continue
            with open(src, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
        for ln in text.splitlines():
            lines.append(ln.rstrip('\n'))
    return lines

def is_bad_line(line):
    if not line:
        return True
    for pat in BAD_PATTERNS:
        if pat in line:
            return True
    # ignore comments
    if line.strip().startswith('#'):
        return True
    return False

def extract_domain_token(line):
    """Return a standardized tuple (type, domain) or None if not domain-like."""
    if not line or line.strip() == '':
        return None
    # Remove inline comments
    line = re.split(r'\s+#', line, 1)[0].strip()
    if is_bad_line(line):
        return None
    # If comma exists, split first token and domain
    if ',' in line:
        left, right = line.split(',', 1)
        left = left.strip()
        domain = right.strip()
        # filter out IP/CIDR entries
        if re.search(r'IP|IP-CIDR|GEOIP|PORT|PROXY|PROCESS|USER-AGENT|FINAL', left, re.I):
            return None
        if re.match(r'[0-9]+\.|\d+:', domain):
            return None
        return (left.upper(), domain)
    # if starts with dot => suffix
    # if line.startswith('.'):
    #    return ('DOMAIN-SUFFIX', line.lstrip('.'))
    # if contains spaces or slashes or colons, skip
    if ' ' in line or '/' in line or ':' in line:
        return None
    # Otherwise treat as exact domain
    return ('DOMAIN', line)

def to_surge_line(token, domain):
    # For Surge: keep DOMAIN or DOMAIN-SUFFIX etc. If token is a single leading dot already handled.
    return f"{token},{domain}"

def to_qx_line(token, domain):
    # Map tokens as requested
    mapping = {
        'DOMAIN-SUFFIX': 'host-suffix',
        'DOMAIN': 'host',
        'DOMAIN-KEYWORD': 'host-keyword',
        'DOMAIN-WILDCARD': 'host-wildcard',
    }
    t = mapping.get(token, token.lower())
    return f"{t},{domain}"

def merge_and_write(group_sources, surge_out, qx_out):
    raw_lines = load_lines_from_sources(group_sources)
    entries = []
    for ln in raw_lines:
        if is_bad_line(ln):
            continue
        ed = extract_domain_token(ln)
        if not ed:
            continue
        entries.append(ed)

    # deduplicate preserving ordering
    seen = set()
    uniq = []
    for t,d in entries:
        key = (t.lower(), d.lower())
        if key in seen:
            continue
        seen.add(key)
        uniq.append((t, d))

    surge_lines = []
    qx_lines = []
    for t,d in uniq:
        # For Surge: if original token was a leading dot we already converted to DOMAIN-SUFFIX
        surge_lines.append(to_surge_line(t, d))
        qx_lines.append(to_qx_line(t, d))

    save_file(surge_out, '\n'.join(surge_lines) + '\n')
    save_file(qx_out, '\n'.join(qx_lines) + '\n')
    print(f"Wrote {len(surge_lines)} entries to {surge_out} and {len(qx_lines)} to {qx_out}")

def main():
    ensure_dir(OUT_DIR)

    # Mirror available files under remote List/ to local 'List/' dir when possible
    try:
        crawl_and_mirror(BASE_ROOT, dest='List')
    except Exception as e:
        print(f"Crawl failed: {e} -- continuing with explicit sources")

    # Define groups per user's request
    # 1a Apple CDN: merge domainset/apple_cdn.conf and non_ip/apple_cdn.conf
    apple_sources = [
        'List/domainset/apple_cdn.conf',
        'List/non_ip/apple_cdn.conf',
    ]
    merge_and_write(apple_sources,
                    os.path.join(OUT_DIR, 'Apple_CDN_for_Sruge.conf'),
                    os.path.join(OUT_DIR, 'Apple_CDN_for_QX.snippet'))

    # 1b CDNs
    cdn_sources = [
        'https://ruleset.skk.moe/List/domainset/cdn.conf',
        'https://ruleset.skk.moe/List/non_ip/cdn.conf',
    ]
    merge_and_write(cdn_sources,
                    os.path.join(OUT_DIR, 'CDNs_for_Sruge.conf'),
                    os.path.join(OUT_DIR, 'CDNs_for_QX.snippet'))

    # 1c AI global
    ai_sources = [
        'https://ruleset.skk.moe/List/non_ip/ai.conf',
        'https://ruleset.skk.moe/List/non_ip/apple_intelligence.conf',
        'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Surge/Anthropic/Anthropic.list',
        'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Surge/BardAI/BardAI.list',
        'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Gemini/Gemini.list',
        'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Copilot/Copilot_Resolve.list',
        'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Claude/Claude.list',
        'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/OpenAI/OpenAI_Resolve.list',
    ]
    merge_and_write(ai_sources,
                    os.path.join(OUT_DIR, 'AI_Global_for_Sruge.conf'),
                    os.path.join(OUT_DIR, 'AI_Global_for_QX.snippet'))

    # 1d CN Domestic
    cn_sources = [
        'https://ruleset.skk.moe/List/non_ip/direct.conf',
        'https://ruleset.skk.moe/List/non_ip/domestic.conf',
        'https://ruleset.skk.moe/List/non_ip/my_direct.conf',
        'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/China/China_All_No_Resolve.list',
        'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/GovCN/GovCN.list',
    ]
    merge_and_write(cn_sources,
                    os.path.join(OUT_DIR, 'CN_Domestic_for_Surge.conf'),
                    os.path.join(OUT_DIR, 'CN_Domestic_for_QX.snippet'))
    # skk_reject
    cn_sources = [
        'https://ruleset.skk.moe/List/domainset/reject.conf',
        'https://ruleset.skk.moe/List/domainset/reject_extra.conf',
        'https://ruleset.skk.moe/List/domainset/reject_phishing.conf',
        'https://ruleset.skk.moe/List/non_ip/reject.conf',
    ]
    merge_and_write(cn_sources,
                    os.path.join(OUT_DIR, 'skk_reject_for_Surge.conf'),
                    os.path.join(OUT_DIR, 'skk_reject_for_QX.snippet'))

    print('Done. Outputs are in the generated/ directory.')

if __name__ == '__main__':
    main()
