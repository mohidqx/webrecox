#!/usr/bin/env python3
"""WebRecox — cloud_enum.py
Enumerate public cloud assets (S3, Azure blob, GCS) for a keyword.
Pure-stdlib HEAD probes — no SDK required.

Usage: python3 cloud_enum.py <keyword>
"""
import sys, argparse, urllib.request, urllib.error, ssl, concurrent.futures as cf

CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE

PERMS = ["", "-dev", "-stage", "-prod", "-backup", "-data", "-assets", "-static", "-files", "-uploads", "-public", "-private"]
TARGETS = [
    ("AWS S3 (vhost)",  "https://{kw}.s3.amazonaws.com/"),
    ("AWS S3 (path)",   "https://s3.amazonaws.com/{kw}/"),
    ("Azure Blob",      "https://{kw}.blob.core.windows.net/"),
    ("Azure Web",       "https://{kw}.azurewebsites.net/"),
    ("Azure File",      "https://{kw}.file.core.windows.net/"),
    ("GCS",             "https://storage.googleapis.com/{kw}/"),
    ("DigitalOcean",    "https://{kw}.nyc3.digitaloceanspaces.com/"),
]

def probe(label, url):
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "WebRecox/15"})
        r = urllib.request.urlopen(req, timeout=8, context=CTX)
        return (label, url, r.status)
    except urllib.error.HTTPError as e:
        if e.code in (200, 301, 302, 403): return (label, url, e.code)
    except Exception:
        pass
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("keyword")
    ap.add_argument("-w", "--workers", type=int, default=20)
    args = ap.parse_args()
    jobs = [(label, tpl.format(kw=args.keyword + p)) for p in PERMS for (label, tpl) in TARGETS]
    found = 0
    with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
        for res in ex.map(lambda j: probe(*j), jobs):
            if res:
                found += 1
                print(f"[+] {res[2]}  {res[0]:14s}  {res[1]}")
    print(f"\n[+] {found} hits / {len(jobs)} probes", file=sys.stderr)

if __name__ == "__main__":
    main()
