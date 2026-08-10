import unittest

import secure_headers_audit as sha


STRONG = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=()",
}


class GradeTests(unittest.TestCase):
    def test_strong_headers_get_a(self):
        result = sha.grade_headers(STRONG)
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["grade"], "A")

    def test_missing_all_fails(self):
        result = sha.grade_headers({})
        self.assertEqual(result["grade"], "F")
        self.assertLess(result["score"], 60)

    def test_case_insensitive(self):
        lowered = {k.lower(): v for k, v in STRONG.items()}
        self.assertEqual(sha.grade_headers(lowered)["score"], 100)

    def test_weak_hsts_penalized(self):
        headers = dict(STRONG)
        headers["Strict-Transport-Security"] = "max-age=100"
        self.assertLess(sha.grade_headers(headers)["score"], 100)

    def test_csp_frame_ancestors_covers_xfo(self):
        headers = dict(STRONG)
        del headers["X-Frame-Options"]
        # CSP has frame-ancestors 'none', so XFO check still passes
        checks = {c["header"]: c["status"] for c in sha.grade_headers(headers)["checks"]}
        self.assertEqual(checks["X-Frame-Options"], "pass")

    def test_unsafe_inline_penalized(self):
        headers = dict(STRONG)
        headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
        self.assertLess(sha.grade_headers(headers)["score"], 100)

    def test_info_disclosure_penalized(self):
        headers = dict(STRONG)
        headers["Server"] = "Apache/2.4.51"
        headers["X-Powered-By"] = "PHP/8.1.0"
        self.assertLess(sha.grade_headers(headers)["score"], 100)


class GradeBandTests(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(sha.letter_grade(95), "A")
        self.assertEqual(sha.letter_grade(85), "B")
        self.assertEqual(sha.letter_grade(75), "C")
        self.assertEqual(sha.letter_grade(65), "D")
        self.assertEqual(sha.letter_grade(10), "F")


if __name__ == "__main__":
    unittest.main()
