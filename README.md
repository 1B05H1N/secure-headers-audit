# secure-headers-audit

Audit and grade the HTTP security response headers of a site. Fetches URLs (or
grades a saved header set offline) and scores HSTS, CSP, X-Content-Type-Options,
X-Frame-Options, Referrer-Policy, Permissions-Policy, and version disclosure.
Pure Python standard library, no dependencies.

> **Goal:** a fast, scriptable "how hardened is this endpoint" check you can run
> against a list of hosts and drop into CI.

## What it does

- Fetches response headers over HTTPS (follows redirects, custom timeout)
- Grades presence and quality, not just presence (e.g. HSTS `max-age`, CSP `unsafe-inline`, weak `Referrer-Policy`)
- Treats CSP `frame-ancestors` as satisfying clickjacking protection
- Deducts for version banners (`Server`, `X-Powered-By`)
- Produces a letter grade (A-F) and a 0-100 score per URL
- Offline mode: grade a saved JSON header set with no network
- Non-zero exit when any URL scores below 70 (CI gate)

## Files

- `secure_headers_audit.py` - CLI and grading engine
- `sample-headers.json` - example header set for offline grading
- `test_secure_headers_audit.py` - unit tests

## Usage

```bash
# audit one or more URLs
python3 secure_headers_audit.py https://example.com https://example.org

# audit a list, save JSON
python3 secure_headers_audit.py --input urls.txt --json results.json

# grade a saved header set offline (no network)
python3 secure_headers_audit.py --headers-file sample-headers.json
```

## Test

```bash
python3 -m unittest -v
```

## Disclaimer

This repository reflects personal study and practice. It contains no employer
data or configuration. Grading weights are opinionated defaults - tune them to
your own baseline. Provided as-is; validate against your own context.

## License

MIT. See [LICENSE](LICENSE).
