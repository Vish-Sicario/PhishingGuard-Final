"""Reproducible functional regression test for PhishingGuard production.

This script checks deployment behaviour. It is NOT an accuracy/precision/recall
benchmark and deliberately avoids browsing known active malicious websites.
"""

import json
import sys
import urllib.error
import urllib.request

BASE_URL = "https://phishingguard-final-production-production.up.railway.app"
SCAN_ENDPOINT = BASE_URL + "/api/scan"

# Public benign websites used only as functional false-positive checks.
BENIGN_CASES = [
    "https://www.google.com/",
    "https://github.com/",
    "https://www.microsoft.com/",
    "https://www.bbc.com/",
    "https://www.wikipedia.org/",
    "https://www.python.org/",
    "https://www.cloudflare.com/",
]

# These reserved/non-public inputs test the API safety boundary. They must be
# rejected rather than fetched. They are not phishing-accuracy test samples.
BLOCKED_CASES = [
    "http://127.0.0.1/",
    "http://localhost/",
    "ftp://example.com/file",
    "http://10.0.0.1/",
]


def request_scan(url):
    payload = json.dumps({"url": url}).encode("utf-8")
    request = urllib.request.Request(
        SCAN_ENDPOINT,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            body = response.read().decode("utf-8")
            return response.status, json.loads(body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            parsed = {"detail": body}
        return exc.code, parsed


def pick(data, *names):
    for name in names:
        if name in data:
            return data[name]
    return None


def main():
    failures = 0
    print("PhishingGuard production functional regression")
    print("Endpoint:", SCAN_ENDPOINT)
    print()

    print("BENIGN LIVE-SITE CHECKS")
    for url in BENIGN_CASES:
        try:
            status, data = request_scan(url)
            score = pick(data, "overall_score", "risk_score", "score")
            level = pick(data, "risk_level", "level", "classification")
            final_url = pick(data, "final_url", "final_destination")
            passed = status == 200 and (level is None or str(level).upper() not in {"HIGH", "CRITICAL"})
            failures += 0 if passed else 1
            print(json.dumps({
                "url": url,
                "http": status,
                "score": score,
                "level": level,
                "final_url": final_url,
                "pass": passed,
            }, ensure_ascii=False))
        except Exception as exc:
            failures += 1
            print(json.dumps({"url": url, "pass": False, "error": str(exc)}))

    print()
    print("SAFETY-BOUNDARY CHECKS")
    for url in BLOCKED_CASES:
        try:
            status, data = request_scan(url)
            passed = 400 <= status < 500
            failures += 0 if passed else 1
            print(json.dumps({
                "url": url,
                "http": status,
                "pass": passed,
                "detail": pick(data, "detail", "error"),
            }, ensure_ascii=False))
        except Exception as exc:
            failures += 1
            print(json.dumps({"url": url, "pass": False, "error": str(exc)}))

    print()
    if failures:
        print(f"RESULT: FAIL ({failures} functional check(s) failed)")
        return 1

    print("RESULT: PASS")
    print("Note: PASS means functional regression checks passed; it is not a scientific model-performance metric.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
