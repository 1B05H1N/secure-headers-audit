#!/usr/bin/env python3
"""Audit and grade HTTP security response headers.

Fetches one or more URLs (or reads a saved header set) and grades the presence
and quality of the common security headers, producing a per-URL report and an
optional JSON summary. Standard library only.
"""
import argparse
import json
import re
import ssl
import sys
import urllib.request

USER_AGENT = "secure-headers-audit/1.0"
MIN_HSTS_MAX_AGE = 15552000  # 180 days

GRADE_BANDS = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


def letter_grade(score):
    for threshold, letter in GRADE_BANDS:
        if score >= threshold:
            return letter
    return "F"


def _check(name, ok, weight, detail):
    return {"header": name, "status": "pass" if ok else "fail", "weight": weight, "detail": detail}


def grade_headers(headers):
    """Grade a case-insensitive mapping of response headers. Pure function."""
    h = {str(k).lower(): str(v) for k, v in headers.items()}
    checks = []
    score = 100

    # Strict-Transport-Security (20)
    hsts = h.get("strict-transport-security")
    if not hsts:
        score -= 20
        checks.append(_check("Strict-Transport-Security", False, 20, "missing"))
    else:
        m = re.search(r"max-age=(\d+)", hsts)
        max_age = int(m.group(1)) if m else 0
        if max_age < MIN_HSTS_MAX_AGE:
            score -= 10
            checks.append(_check("Strict-Transport-Security", False, 20,
                                 "max-age too low (%d < %d)" % (max_age, MIN_HSTS_MAX_AGE)))
        else:
            checks.append(_check("Strict-Transport-Security", True, 20, "max-age=%d" % max_age))

    # Content-Security-Policy (25)
    csp = h.get("content-security-policy")
    if not csp:
        score -= 25
        checks.append(_check("Content-Security-Policy", False, 25, "missing"))
    elif "unsafe-inline" in csp or "unsafe-eval" in csp:
        score -= 10
        checks.append(_check("Content-Security-Policy", False, 25, "present but uses unsafe-inline/unsafe-eval"))
    else:
        checks.append(_check("Content-Security-Policy", True, 25, "present"))

    # X-Content-Type-Options (10)
    xcto = h.get("x-content-type-options", "")
    if xcto.strip().lower() == "nosniff":
        checks.append(_check("X-Content-Type-Options", True, 10, "nosniff"))
    else:
        score -= 10
        checks.append(_check("X-Content-Type-Options", False, 10, "missing or not nosniff"))

    # X-Frame-Options (15) - satisfied by CSP frame-ancestors too
    xfo = h.get("x-frame-options", "").strip().upper()
    frame_ancestors = csp and "frame-ancestors" in csp
    if xfo in ("DENY", "SAMEORIGIN") or frame_ancestors:
        checks.append(_check("X-Frame-Options", True, 15,
                             xfo or "covered by CSP frame-ancestors"))
    else:
        score -= 15
        checks.append(_check("X-Frame-Options", False, 15, "missing (no XFO or frame-ancestors)"))

    # Referrer-Policy (10)
    ref = h.get("referrer-policy", "").strip().lower()
    strong_ref = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin"}
    if ref in strong_ref:
        checks.append(_check("Referrer-Policy", True, 10, ref))
    else:
        score -= 10
        checks.append(_check("Referrer-Policy", False, 10, "missing or weak"))

    # Permissions-Policy (10)
    if h.get("permissions-policy"):
        checks.append(_check("Permissions-Policy", True, 10, "present"))
    else:
        score -= 10
        checks.append(_check("Permissions-Policy", False, 10, "missing"))

    # Information disclosure (10) - deduct for verbose Server / X-Powered-By
    disclosed = []
    server = h.get("server", "")
    if re.search(r"\d", server):
        disclosed.append("Server: %s" % server)
    if h.get("x-powered-by"):
        disclosed.append("X-Powered-By: %s" % h["x-powered-by"])
    if disclosed:
        score -= 10
        checks.append(_check("Information-Disclosure", False, 10, "; ".join(disclosed)))
    else:
        checks.append(_check("Information-Disclosure", True, 10, "no version banners"))

    score = max(0, score)
    return {"score": score, "grade": letter_grade(score), "checks": checks}


def fetch_headers(url, timeout=10, insecure=False):
    ctx = ssl._create_unverified_context() if insecure else None
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        return {k: v for k, v in resp.headers.items()}, resp.status


def audit_url(url, timeout=10, insecure=False):
    try:
        headers, status = fetch_headers(url, timeout, insecure)
    except Exception as exc:  # noqa: BLE001 - report and continue
        return {"url": url, "error": str(exc)}
    result = grade_headers(headers)
    result["url"] = url
    result["http_status"] = status
    return result


def format_report(result):
    if "error" in result:
        return "%s\n  ERROR: %s\n" % (result["url"], result["error"])
    lines = ["%s  [%s %d/100]" % (result["url"], result["grade"], result["score"])]
    for c in result["checks"]:
        mark = "PASS" if c["status"] == "pass" else "FAIL"
        lines.append("  [%s] %-24s %s" % (mark, c["header"], c["detail"]))
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Audit and grade HTTP security headers.")
    parser.add_argument("urls", nargs="*", help="one or more URLs to audit")
    parser.add_argument("--input", help="file with one URL per line")
    parser.add_argument("--headers-file", help="JSON file of headers to grade offline (no network)")
    parser.add_argument("--json", dest="json_out", help="write results to this JSON file")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--insecure", action="store_true", help="skip TLS certificate verification")
    args = parser.parse_args(argv)

    results = []
    if args.headers_file:
        with open(args.headers_file, encoding="utf-8") as fh:
            headers = json.load(fh)
        res = grade_headers(headers)
        res["url"] = args.headers_file
        results.append(res)
    else:
        urls = list(args.urls)
        if args.input:
            with open(args.input, encoding="utf-8") as fh:
                urls += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        if not urls:
            parser.error("provide URLs, --input, or --headers-file")
        for url in urls:
            results.append(audit_url(url, args.timeout, args.insecure))

    for res in results:
        sys.stdout.write(format_report(res))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)

    graded = [r for r in results if "score" in r]
    if graded and any(r["score"] < 70 for r in graded):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
