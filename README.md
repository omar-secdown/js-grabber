# JS Grabber

Collect live JavaScript file URLs from target domains using multiple reconnaissance tools.

## Tools Used

| Tool | Source |
|------|--------|
| [gau](https://github.com/lc/gau) | Fetch known URLs from AlienVault OTX, Wayback Machine, Common Crawl |
| [katana](https://github.com/projectdiscovery/katana) | Active crawling with JS parsing |
| [httpx](https://github.com/projectdiscovery/httpx) | Filter for live (200 OK) URLs |

## Installation

```bash
# Install Go tools
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## Usage

```bash
# Single domain
python3 js_grabber.py -d target.com -o output.txt

# Domain list
python3 js_grabber.py -dL domains.txt -o output.txt
```

## How It Works

1. Runs gau and katana in parallel against each domain
2. Filters output to `.js` files only
3. Deduplicates all collected URLs
4. Runs httpx to keep only live URLs returning 200 OK
5. Saves clean, deduplicated results to the output file

## Output

A text file with one live JS URL per line, no duplicates:

```
https://target.com/static/app-9f3a2b.js
https://target.com/assets/vendor-chunk.js
https://cdn.target.com/js/main.bundle.js
```
