# -*- coding: utf-8 -*-
"""Python app for Altare App Hosting with U3 storage access.

Zero third-party dependencies: Python 3 stdlib only.
Serves as a fixed HTTPS endpoint for ESP-32 to pull data from U3 (S3-compatible) storage.

Routes:
  GET /              -> service status
  GET /api/health    -> health check with U3 config
  GET /u3/<key>      -> fetch file from U3 bucket (for ESP-32)

U3 S3 config via Altare standard environment variables (set by "Connect to app"):
  S3_ENDPOINT           e.g. https://u3-asia.altare.global
  S3_REGION             e.g. asia
  S3_BUCKET             e.g. bucket01
  AWS_ACCESS_KEY_ID     access key
  AWS_SECRET_ACCESS_KEY secret key

Port is read from the PORT environment variable allocated by Altare.
"""
import os
import sys
import json
import hmac
import hashlib
import datetime
import http.client
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, unquote

# ---------------- U3 S3 configuration (Altare env vars) ----------------
U3_ENDPOINT = os.environ.get("S3_ENDPOINT", "")
U3_REGION = os.environ.get("S3_REGION", "")
U3_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID", "")
U3_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
U3_BUCKET = os.environ.get("S3_BUCKET", "")

if not U3_ENDPOINT:
    # Fallback for local development / python-app server
    U3_ENDPOINT = "https://u3-asia.altare.global"
    U3_REGION = U3_REGION or "asia"
    U3_BUCKET = U3_BUCKET or "bucket01"
    print("[warn] S3_ENDPOINT not set; using default. Set via Connect to app or altr env set.", flush=True)

# Altare sets ALTARE_URL automatically — the app's public HTTPS address.
ALTARE_URL = os.environ.get("ALTARE_URL", "")
if ALTARE_URL:
    print(f"[info] ALTARE_URL = {ALTARE_URL}", flush=True)
else:
    print("[info] ALTARE_URL not set (local dev or not deployed via Altare).", flush=True)


def _hmac_sha256(key: bytes, msg: str) -> bytes:
    """HMAC-SHA256, returns raw digest bytes."""
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def s3_sign_v4(method, canonical_uri, region, access_key, secret_key, host, payload_hash=""):
    """S3 Signature V4. Returns dict of headers to add to the request."""
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    # Canonical headers (alphabetical order, each ends with \n)
    canonical_headers = (
        f"host:{host}\n"
        f"x-amz-content-sha256:{payload_hash}\n"
        f"x-amz-date:{amz_date}\n"
    )
    signed_headers = "host;x-amz-content-sha256;x-amz-date"

    # Canonical request
    canonical_request = (
        f"{method}\n"
        f"{canonical_uri}\n"
        f"\n"                          # canonical query string (empty)
        f"{canonical_headers}\n"       # canonical headers + trailing newline
        f"{signed_headers}\n"
        f"{payload_hash}"
    )

    # String to sign
    credential_scope = f"{date_stamp}/{region}/s3/aws4_request"
    string_to_sign = (
        f"AWS4-HMAC-SHA256\n"
        f"{amz_date}\n"
        f"{credential_scope}\n"
        f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
    )

    # Signing key derivation
    signing_key = _hmac_sha256(
        _hmac_sha256(
            _hmac_sha256(
                _hmac_sha256(("AWS4" + secret_key).encode("utf-8"), date_stamp),
                region,
            ),
            "s3",
        ),
        "aws4_request",
    )

    # Signature
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

    # Authorization header
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    return {
        "Authorization": authorization,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
        "Host": host,
    }


def s3_get_object(bucket, key):
    """Fetch an object from U3 via S3 Signature V4. Returns (data_bytes, content_type_str)."""
    path = f"/{bucket}/{key}"
    parsed = urlparse(U3_ENDPOINT)
    host = parsed.netloc
    payload_hash = hashlib.sha256(b"").hexdigest()
    headers = s3_sign_v4("GET", path, U3_REGION, U3_ACCESS_KEY, U3_SECRET_KEY, host, payload_hash)
    headers["User-Agent"] = "python-http-client"

    conn = http.client.HTTPSConnection(host, timeout=30)
    conn.request("GET", path, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    content_type = resp.headers.get("Content-Type", "application/octet-stream")
    conn.close()
    return data, content_type


# ---------------- HTTP handler ----------------

class Handler(BaseHTTPRequestHandler):
    def _send_json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, code, data, content_type):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)

        if path == "/":
            body = b"python-app is running\n"
            self._send_bytes(200, body, "text/plain; charset=utf-8")
            return

        if path == "/api/health":
            self._send_json(200, {
                "ok": True,
                "service": "python-app",
                "altare_url": ALTARE_URL,
                "s3_endpoint": U3_ENDPOINT,
                "s3_bucket": U3_BUCKET,
                "s3_region": U3_REGION,
                "access_key_set": bool(U3_ACCESS_KEY),
                "secret_set": bool(U3_SECRET_KEY),
            })
            return

        if path.startswith("/u3/"):
            key = path[4:]
            if not key:
                self._send_json(400, {"error": "Missing object key"})
                return
            try:
                data, content_type = s3_get_object(U3_BUCKET, key)
                self._send_bytes(200, data, content_type)
            except http.client.HTTPException as e:
                self._send_json(502, {"error": f"U3 fetch failed: {e}"})
            except Exception as e:
                self._send_json(500, {"error": f"U3 fetch failed: {e}"})
            return

        self._send_json(404, {"error": "Not Found"})

    def log_message(self, fmt, *args):
        print("[app] " + (fmt % args), flush=True)


def serve(port):
    try:
        srv = HTTPServer(("0.0.0.0", port), Handler)
        print(f"[app] listening on 0.0.0.0:{port}", flush=True)
        srv.serve_forever()
    except OSError as exc:
        print(f"[app] port {port} unavailable: {exc}", flush=True)


def u3_selftest():
    """On startup, try to fetch a known object from U3 and report the result."""
    try:
        data, ctype = s3_get_object(U3_BUCKET, "hello.txt")
        print(f"[selftest] U3 OK: fetched hello.txt ({len(data)}B, {ctype})", flush=True)
    except Exception as e:
        print(f"[selftest] U3 FAIL: {e}", flush=True)


def http_endpoint_selftest(port):
    """After server starts, test the /u3/<key> endpoint via local HTTP."""
    import time
    time.sleep(2)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", "/u3/hello.txt")
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        print(f"[selftest] HTTP /u3/hello.txt on :{port} -> {resp.status} ({len(data)}B: {data[:60]})", flush=True)
    except Exception as e:
        print(f"[selftest] HTTP /u3/hello.txt on :{port} FAIL: {e}", flush=True)


def main():
    u3_selftest()

    # Altare allocates a port and provides it via PORT env var.
    port_env = os.environ.get("PORT", "")
    if port_env:
        try:
            ports = [int(port_env)]
        except ValueError:
            print(f"[error] PORT={port_env!r} is not a valid integer", flush=True)
            sys.exit(1)
    else:
        # Local development fallback
        ports = [8080]

    threads = [threading.Thread(target=serve, args=(p,), daemon=True) for p in ports]
    for t in threads:
        t.start()
    print(f"[app] python-app up, ports={ports}", flush=True)

    for p in ports:
        threading.Thread(target=http_endpoint_selftest, args=(p,), daemon=True).start()

    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
