#!/usr/bin/env python3
"""
JS Grabber — Collect live JS URLs from targets using gau, katana, Wayback CDX API.
All tools run in parallel. Results are deduplicated and filtered for 200 OK via httpx.

Usage:
    python3 js_grabber.py -d target.com -o output.txt
    python3 js_grabber.py -dL domains.txt -o output.txt
"""

import os
import sys
import shutil
import argparse
import subprocess
import requests
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

TOOL_PATHS = {}


def _find_tool(name):
    """Find a tool binary."""
    if name in TOOL_PATHS:
        return TOOL_PATHS[name]

    candidates = [
        shutil.which(name),
        os.path.expanduser(f"~/go/bin/{name}"),
        f"/root/go/bin/{name}",
        f"/usr/local/bin/{name}",
        f"/usr/bin/{name}",
    ]

    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            TOOL_PATHS[name] = path
            return path

    return None


def check_tools():
    """Check required tools, return list of available collectors."""
    tools = {
        "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
        "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    }

    available = []

    for tool, install_cmd in tools.items():
        path = _find_tool(tool)
        if path:
            print(f"  [+] {tool}: OK")
            available.append(tool)
        else:
            print(f"  [-] {tool}: MISSING — {install_cmd}")

    # Always have wayback (just HTTP, no tool needed)
    print(f"  [+] wayback: OK (CDX API)")
    available.append("wayback")

    if "httpx" not in available:
        print("\n  [!] httpx is required. Install it first.")
        sys.exit(1)

    collectors = [t for t in available if t in ("gau", "katana", "wayback")]
    if not collectors:
        print("\n  [!] No collectors found. Install at least one: gau, katana")
        sys.exit(1)

    return collectors


def _filter_js(lines):
    """Filter lines to only .js URLs."""
    results = []
    for line in lines:
        url = line.strip()
        if not url:
            continue
        path_part = url.split("?")[0].split("#")[0]
        if path_part.endswith(".js"):
            results.append(url)
    return results


def run_gau(domain):
    """echo domain | gau — returns list of JS URLs."""
    tool = _find_tool("gau")
    if not tool:
        return [], "gau not found"
    try:
        result = subprocess.run(
            [tool],
            input=domain,
            capture_output=True, text=True
        )
        js_urls = _filter_js(result.stdout.splitlines())
        return js_urls, None
    except Exception as e:
        return [], str(e)


def run_katana(domain):
    """katana -u domain -silent — returns list of JS URLs."""
    tool = _find_tool("katana")
    if not tool:
        return [], "katana not found"
    try:
        result = subprocess.run(
            [tool, "-u", domain, "-silent"],
            capture_output=True, text=True
        )
        js_urls = _filter_js(result.stdout.splitlines())
        return js_urls, None
    except Exception as e:
        return [], str(e)


def run_wayback(domain):
    """Fetch JS URLs from Wayback Machine CDX API."""
    try:
        # First check if archive.org responds
        check = requests.head("https://web.archive.org", allow_redirects=True)
        if check.status_code >= 500:
            return [], "archive.org is down"
    except requests.RequestException:
        return [], "archive.org not reachable"

    try:
        encoded_domain = quote(domain + "/*", safe="")
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url={encoded_domain}"
            f"&output=text&fl=original&collapse=urlkey&from="
        )
        resp = requests.get(url)
        if resp.status_code != 200:
            return [], f"CDX API returned {resp.status_code}"

        js_urls = _filter_js(resp.text.splitlines())
        return js_urls, None

    except Exception as e:
        return [], str(e)


def collect_domain(domain, collectors):
    """Run all collectors in parallel for one domain. Returns list of JS URLs."""
    print(f"\n  [{domain}]")
    all_urls = []

    futures = {}
    with ThreadPoolExecutor(max_workers=3) as executor:
        if "gau" in collectors:
            futures[executor.submit(run_gau, domain)] = "gau"
        if "katana" in collectors:
            futures[executor.submit(run_katana, domain)] = "katana"
        if "wayback" in collectors:
            futures[executor.submit(run_wayback, domain)] = "wayback"

        for future in as_completed(futures):
            tool_name = futures[future]
            try:
                urls, err = future.result()
                if err:
                    print(f"    [!] {tool_name}: {err}")
                else:
                    all_urls.extend(urls)
                    print(f"    {tool_name}: {len(urls)}")
            except Exception as e:
                print(f"    [!] {tool_name}: {e}")

    return all_urls


def dedup(urls):
    """Deduplicate URL list, return sorted unique list."""
    seen = set()
    unique = []
    for url in urls:
        url = url.strip()
        if url and url not in seen:
            seen.add(url)
            unique.append(url)
    return sorted(unique)


def httpx_filter(urls, output_file):
    """Run httpx on URLs, keep only 200 OK, write to output file."""
    httpx_path = _find_tool("httpx")

    print(f"\n[*] httpx: checking {len(urls)} URLs for 200 OK...")

    try:
        input_data = "\n".join(urls)
        result = subprocess.run(
            [
                httpx_path,
                "-mc", "200",
                "-silent",
                "-threads", "50",
            ],
            input=input_data,
            capture_output=True,
            text=True
        )

        live = []
        seen = set()
        for line in result.stdout.splitlines():
            url = line.strip()
            if url and url not in seen:
                seen.add(url)
                live.append(url)

        with open(output_file, "w") as f:
            for url in live:
                f.write(url + "\n")

        return len(live)

    except Exception as e:
        print(f"[!] httpx error: {e}")
        return 0


def main():
    parser = argparse.ArgumentParser(
        description="JS Grabber — Collect live JS URLs from targets",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", metavar="DOMAIN", help="Single domain")
    group.add_argument("-dL", metavar="FILE", help="Domain list file")
    parser.add_argument("-o", metavar="FILE", required=True, help="Output file")

    args = parser.parse_args()

    if args.d:
        domains = [args.d.strip()]
    else:
        if not os.path.isfile(args.dL):
            print(f"[!] File not found: {args.dL}")
            sys.exit(1)
        with open(args.dL, "r") as f:
            domains = [l.strip() for l in f if l.strip() and not l.startswith("#")]

    if not domains:
        print("[!] No domains provided")
        sys.exit(1)

    print("[*] Checking tools...")
    collectors = check_tools()
    print(f"\n[*] {len(domains)} domain(s) | tools: {', '.join(collectors)}")

    out_dir = os.path.dirname(args.o)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # Collect from all domains
    all_urls = []

    for domain in domains:
        urls = collect_domain(domain, collectors)
        all_urls.extend(urls)

    if not all_urls:
        print("\n[!] No JS URLs found")
        sys.exit(0)

    # Dedup
    print(f"\n[*] Deduplicating {len(all_urls)} raw URLs...")
    unique_urls = dedup(all_urls)
    print(f"[+] {len(unique_urls)} unique JS URLs")

    # httpx filter
    live_count = httpx_filter(unique_urls, args.o)

    # Summary
    print(f"\n[*] Done")
    print(f"    Domains: {len(domains)}")
    print(f"    Raw: {len(all_urls)}")
    print(f"    Unique: {len(unique_urls)}")
    print(f"    Live (200): {live_count}")
    print(f"    Output: {args.o}")


if __name__ == "__main__":
    main()
