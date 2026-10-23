
import unittest

from scanner.header_analyzer import analyze_security_headers


class TestSecurityHeaderAnalyzer(unittest.TestCase):

    def test_empty_headers_are_all_missing(self):
        result = analyze_security_headers({})
        self.assertEqual(result["counts"]["total"], 6)
        self.assertEqual(result["counts"]["missing"], 6)
        self.assertEqual(result["score"], 0)

    def test_header_names_are_case_insensitive(self):
        result = analyze_security_headers({
            "X-Content-Type-Options": "nosniff"
        })
        finding = next(
            f for f in result["findings"]
            if f["header"] == "X-Content-Type-Options"
        )
        self.assertEqual(finding["status"], "present")

    def test_nosniff_is_accepted(self):
        result = analyze_security_headers({
            "x-content-type-options": "nosniff"
        })
        finding = next(
            f for f in result["findings"]
            if f["header"] == "X-Content-Type-Options"
        )
        self.assertEqual(finding["status"], "present")

    def test_wrong_content_type_value_needs_review(self):
        result = analyze_security_headers({
            "X-Content-Type-Options": "other"
        })
        finding = next(
            f for f in result["findings"]
            if f["header"] == "X-Content-Type-Options"
        )
        self.assertEqual(finding["status"], "review")

    def test_unsafe_inline_csp_needs_review(self):
        result = analyze_security_headers({
            "Content-Security-Policy":
                "default-src 'self'; script-src 'unsafe-inline'"
        })
        finding = next(
            f for f in result["findings"]
            if f["header"] == "Content-Security-Policy"
        )
        self.assertEqual(finding["status"], "review")

    def test_valid_hsts_is_present(self):
        result = analyze_security_headers({
            "Strict-Transport-Security": "max-age=31536000"
        })
        finding = next(
            f for f in result["findings"]
            if f["header"] == "Strict-Transport-Security"
        )
        self.assertEqual(finding["status"], "present")

    def test_hsts_without_max_age_needs_review(self):
        result = analyze_security_headers({
            "Strict-Transport-Security": "includeSubDomains"
        })
        finding = next(
            f for f in result["findings"]
            if f["header"] == "Strict-Transport-Security"
        )
        self.assertEqual(finding["status"], "review")

    def test_hsts_zero_max_age_needs_review(self):
        result = analyze_security_headers({
            "Strict-Transport-Security": "max-age=0"
        })
        finding = next(
            f for f in result["findings"]
            if f["header"] == "Strict-Transport-Security"
        )
        self.assertEqual(finding["status"], "review")

    def test_invalid_input_type_is_rejected(self):
        with self.assertRaises(TypeError):
            analyze_security_headers([])

    def test_non_string_header_value_is_rejected(self):
        with self.assertRaises(TypeError):
            analyze_security_headers({"X-Frame-Options": None})

    def test_counts_add_up(self):
        result = analyze_security_headers({
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "INVALID"
        })
        counts = result["counts"]
        self.assertEqual(
            counts["present"] + counts["missing"] + counts["review"],
            counts["total"]
        )

    def test_no_network_connection_is_required(self):
        result = analyze_security_headers({
            "Referrer-Policy": "no-referrer"
        })
        self.assertIn(
            "No website connection was made",
            result["message"]
        )

    def test_score_is_zero_when_all_headers_are_missing(self):
        result = analyze_security_headers({})
        self.assertEqual(result["score"], 0)

    def test_two_present_headers_score_33(self):
        result = analyze_security_headers({
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN"
        })
        self.assertEqual(result["score"], 33)

    def test_review_headers_do_not_earn_points(self):
        result = analyze_security_headers({
            "X-Content-Type-Options": "invalid"
        })
        self.assertEqual(result["counts"]["review"], 1)
        self.assertEqual(result["score"], 0)

    def test_all_six_present_headers_score_100(self):
        result = analyze_security_headers({
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=(), microphone=()"
        })
        self.assertEqual(result["score"], 100)

    def test_malformed_permissions_policy_needs_review(self):
        result = analyze_security_headers({
            "Permissions-Policy": "not-a-policy"
        })
        finding = next(
            f for f in result["findings"]
            if f["header"] == "Permissions-Policy"
        )
        self.assertEqual(finding["status"], "review")
        self.assertIn("basic", finding["recommendation"].lower())

    def test_empty_permissions_policy_is_missing(self):
        result = analyze_security_headers({
            "Permissions-Policy": "   "
        })
        finding = next(
            f for f in result["findings"]
            if f["header"] == "Permissions-Policy"
        )
        self.assertEqual(finding["status"], "missing")

    def test_structured_permissions_policy_is_present_but_caveated(self):
        result = analyze_security_headers({
            "Permissions-Policy": "camera=(), microphone=()"
        })
        finding = next(
            f for f in result["findings"]
            if f["header"] == "Permissions-Policy"
        )
        self.assertEqual(finding["status"], "present")
        self.assertIn(
            "does not fully validate",
            finding["recommendation"]
        )

    def test_permissions_policy_rejects_empty_directive(self):
        result = analyze_security_headers({
            "Permissions-Policy": "camera=(),"
        })
        finding = next(
            f for f in result["findings"]
            if f["header"] == "Permissions-Policy"
        )
        self.assertEqual(finding["status"], "review")

    def test_report_explains_scoring_limitations(self):
        result = analyze_security_headers({})
        self.assertIn(
            "does not measure overall website security",
            result["scoring_method"]
        )


if __name__ == "__main__":
    unittest.main()
