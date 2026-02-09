#!/usr/bin/env python3
"""
JS Grabber — Collect live JS URLs from targets using gau, waybackurls, katana, waymore.

Usage:
    python3 js_grabber.py -d target.com -o output.txt
    python3 js_grabber.py -dL domains.txt -o output.txt
"""

import os
import re
import sys
import shutil
import argparse
import subprocess
import tempfile

TOOL_PATHS = {}

# Regex to match JS file URLs — catches .js at end of path (before query string or fragment)
JS_URL_PATTERN = re.compile(r'\.js(?:\?[^#]*)?(?:#.*)?$', re.IGNORECASE)


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

    # waymore as Python module
    if name == "waymore":
        try:
            result = subprocess.run(
                ["python3", "-m", "waymore", "--help"],
                capture_output=True, timeout=10
            )
            if result.returncode == 0:
                TOOL_PATHS[name] = "waymore_module"
                return "waymore_module"
        except Exception:
            pass

    return None


def check_tools():
    """Check required tools, return list of available collectors."""
    tools = {
        "gau": "go install github.com/lc/gau/v2/cmd/gau@latest",
        "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
        "katana": "go install github.com/projectdiscovery/katana/cmd/katana@latest",
        "waymore": "pip3 install waymore",
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

    # httpx is critical
    if "httpx" not in available:
        print("\n  [!] httpx is required. Install it first.")
        sys.exit(1)

    collectors = [t for t in available if t in ("gau", "waybackurls", "katana", "waymore")]
    if not collectors:
        print("\n  [!] No collectors found. Install at least one: gau, waybackurls, katana, waymore")
        sys.exit(1)

    return collectors


def _filter_js(lines):
    """Filter lines to only .js URLs."""
    results = []
    for line in lines:
        url = line.strip()
        if not url:
            continue
        # Strip query string and fragment for the check
        path_part = url.split("?")[0].split("#")[0]
        if path_part.endswith(".js"):
            results.append(url)
    return results


def run_gau(domain, output_file):
    """Run gau, filter JS, append to output."""
    tool = _find_tool("gau")
    if not tool:
        return 0
    try:
        result = subprocess.run(
            [tool, "--threads", "5", "--subs", domain],
            capture_output=True, text=True, timeout=600
        )
        js_urls = _filter_js(result.stdout.splitlines())
        if js_urls:
            with open(output_file, "a") as f:
                f.write("\n".join(js_urls) + "\n")
        return len(js_urls)
    except subprocess.TimeoutExpired:
        print(f"    [!] gau timed out for {domain}")
        return 0
    except Exception as e:
        print(f"    [!] gau error: {e}")
        return 0


def run_waybackurls(domain, output_file):
    """Run waybackurls, filter JS, append to output."""
    tool = _find_tool("waybackurls")
    if not tool:
        return 0
    try:
        result = subprocess.run(
            [tool, domain],
            capture_output=True, text=True, timeout=600
        )
        js_urls = _filter_js(result.stdout.splitlines())
        if js_urls:
            with open(output_file, "a") as f:
                f.write("\n".join(js_urls) + "\n")
        return len(js_urls)
    except subprocess.TimeoutExpired:
        print(f"    [!] waybackurls timed out for {domain}")
        return 0
    except Exception as e:
        print(f"    [!] waybackurls error: {e}")
        return 0


def run_katana(domain, output_file):
    """Run katana, filter JS, append to output."""
    tool = _find_tool("katana")
    if not tool:
        return 0
    try:
        result = subprocess.run(
            [
                tool,
                "-u", f"https://{domain}",
                "-d", "3",
                "-jc",
                "-ef", "css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot",
                "-silent",
            ],
            capture_output=True, text=True, timeout=600
        )
        js_urls = _filter_js(result.stdout.splitlines())
        if js_urls:
            with open(output_file, "a") as f:
                f.write("\n".join(js_urls) + "\n")
        return len(js_urls)
    except subprocess.TimeoutExpired:
        print(f"    [!] katana timed out for {domain}")
        return 0
    except Exception as e:
        print(f"    [!] katana error: {e}")
        return 0


def run_waymore(domain, output_file):
    """Run waymore, filter JS, append to output."""
    tool = _find_tool("waymore")
    if not tool:
        return 0
    try:
        tmp_dir = tempfile.mkdtemp(prefix="waymore_")
        urls_file = os.path.join(tmp_dir, "urls.txt")

        if tool == "waymore_module":
            cmd = ["python3", "-m", "waymore", "-i", domain, "-mode", "U", "-oU", urls_file]
        else:
            cmd = [tool, "-i", domain, "-mode", "U", "-oU", urls_file]

        subprocess.run(cmd, capture_output=True, text=True, timeout=900)

        count = 0
        if os.path.isfile(urls_file):
            with open(urls_file, "r") as f:
                js_urls = _filter_js(f.readlines())
            if js_urls:
                with open(output_file, "a") as f:
                    f.write("\n".join(js_urls) + "\n")
                count = len(js_urls)

        shutil.rmtree(tmp_dir, ignore_errors=True)
        return count

    except subprocess.TimeoutExpired:
        print(f"    [!] waymore timed out for {domain}")
        return 0
    except Exception as e:
        print(f"    [!] waymore error: {e}")
        return 0


def collect_domain(domain, raw_file, collectors):
    """Run all collectors for one domain."""
    print(f"\n  [{domain}]")
    total = 0

    if "gau" in collectors:
        count = run_gau(domain, raw_file)
        print(f"    gau: {count}")
        total += count

    if "waybackurls" in collectors:
        count = run_waybackurls(domain, raw_file)
        print(f"    waybackurls: {count}")
        total += count

    if "katana" in collectors:
        count = run_katana(domain, raw_file)
        print(f"    katana: {count}")
        total += count

    if "waymore" in collectors:
        count = run_waymore(domain, raw_file)
        print(f"    waymore: {count}")
        total += count

    return total


def dedup(raw_file):
    """Read raw file, return sorted unique URLs."""
    if not os.path.isfile(raw_file):
        return []
    seen = set()
    unique = []
    with open(raw_file, "r") as f:
        for line in f:
            url = line.strip()
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
                "-timeout", "10",
            ],
            input=input_data,
            capture_output=True,
            text=True,
            timeout=3600
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

    except subprocess.TimeoutExpired:
        print("[!] httpx timed out. Saving unfiltered list.")
        with open(output_file, "w") as f:
            for url in urls:
                f.write(url + "\n")
        return len(urls)


def main():
    parser = argparse.ArgumentParser(
        description="JS Grabber — Collect live JS URLs from targets",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", metavar="DOMAIN", help="Single domain")
    group.add_argument("-dL", metavar="FILE", help="Domain list file")
    parser.add_argument("-o", metavar="FILE", required=True, help="Output file")

    args = parser.parse_args()

    # Build domain list
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

    # Check tools
    print("[*] Checking tools...")
    collectors = check_tools()
    print(f"\n[*] {len(domains)} domain(s) | tools: {', '.join(collectors)}")

    # Ensure output directory exists
    out_dir = os.path.dirname(args.o)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # Temp raw file
    raw_file = args.o + ".raw.tmp"
    open(raw_file, "w").close()

    # Collect
    total_raw = 0
    for domain in domains:
        total_raw += collect_domain(domain, raw_file, collectors)

    if total_raw == 0:
        print("\n[!] No JS URLs found")
        os.remove(raw_file)
        sys.exit(0)

    # Dedup
    print(f"\n[*] Deduplicating {total_raw} raw URLs...")
    unique_urls = dedup(raw_file)
    print(f"[+] {len(unique_urls)} unique JS URLs")

    # httpx filter
    live_count = httpx_filter(unique_urls, args.o)

    # Cleanup
    os.remove(raw_file)

    # Summary
    print(f"\n[*] Done")
    print(f"    Domains: {len(domains)}")
    print(f"    Raw: {total_raw}")
    print(f"    Unique: {len(unique_urls)}")
    print(f"    Live (200): {live_count}")
    print(f"    Output: {args.o}")


if __name__ == "__main__":
    main()
