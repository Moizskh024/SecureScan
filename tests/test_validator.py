
import unittest

from scanner.validator import validate_url


class TestURLValidator(unittest.TestCase):

    def test_accepts_https_url(self):
        result = validate_url("https://example.com")
        self.assertTrue(result["valid"])
        self.assertEqual(result["hostname"], "example.com")
        self.assertEqual(result["scheme"], "https")
        self.assertTrue(result["https"])

    def test_accepts_http_url(self):
        result = validate_url("http://example.com")
        self.assertTrue(result["valid"])
        self.assertEqual(result["scheme"], "http")
        self.assertFalse(result["https"])

    def test_rejects_unsupported_protocol(self):
        self.assertFalse(
            validate_url("ftp://example.com")["valid"]
        )

    def test_rejects_empty_input(self):
        self.assertFalse(validate_url("")["valid"])

    def test_rejects_plain_text(self):
        self.assertFalse(validate_url("not-a-url")["valid"])

    def test_rejects_localhost(self):
        self.assertFalse(
            validate_url("http://localhost")["valid"]
        )

    def test_rejects_localhost_subdomain(self):
        self.assertFalse(
            validate_url("http://service.localhost")["valid"]
        )

    def test_rejects_embedded_credentials(self):
        self.assertFalse(
            validate_url(
                "https://user:password@example.com"
            )["valid"]
        )

    def test_rejects_private_ipv4_address(self):
        self.assertFalse(
            validate_url("http://192.168.1.10")["valid"]
        )

    def test_rejects_loopback_ipv4_address(self):
        self.assertFalse(
            validate_url("http://127.0.0.1")["valid"]
        )

    def test_rejects_malformed_hostname(self):
        self.assertFalse(
            validate_url("https://-invalid.example")["valid"]
        )

    def test_rejects_unsupported_port(self):
        self.assertFalse(
            validate_url("https://example.com:99999")["valid"]
        )

    def test_rejects_non_string_input(self):
        for value in (None, 123, True, [], {}):
            with self.subTest(value=value):
                self.assertFalse(validate_url(value)["valid"])

    def test_rejects_excessively_long_url(self):
        self.assertFalse(
            validate_url("https://example.com/" + ("a" * 2048))[
                "valid"
            ]
        )

    def test_rejects_ipv6_loopback(self):
        self.assertFalse(
            validate_url("http://[::1]")["valid"]
        )

    def test_rejects_private_ipv6(self):
        self.assertFalse(
            validate_url("http://[fc00::1]")["valid"]
        )

    def test_rejects_port_zero(self):
        self.assertFalse(
            validate_url("https://example.com:0")["valid"]
        )

    def test_rejects_malformed_port(self):
        self.assertFalse(
            validate_url("https://example.com:abc")["valid"]
        )

    def test_rejects_url_with_whitespace(self):
        self.assertFalse(
            validate_url("https://example .com")["valid"]
        )

    def test_accepts_uppercase_https_scheme(self):
        result = validate_url("HTTPS://example.com")
        self.assertTrue(result["valid"])
        self.assertEqual(result["scheme"], "https")

    def test_normalizes_trailing_hostname_dot(self):
        result = validate_url("https://example.com.")
        self.assertTrue(result["valid"])
        self.assertEqual(result["hostname"], "example.com")

    def test_rejects_consecutive_hostname_dots(self):
        self.assertFalse(
            validate_url("https://example..com")["valid"]
        )

    def test_rejects_hostname_with_underscore(self):
        self.assertFalse(
            validate_url("https://bad_name.example")["valid"]
        )

    def test_rejects_hostname_with_leading_hyphen(self):
        self.assertFalse(
            validate_url("https://-bad.example")["valid"]
        )

    def test_rejects_hostname_with_trailing_hyphen(self):
        self.assertFalse(
            validate_url("https://bad-.example")["valid"]
        )

    def test_rejects_single_label_hostname(self):
        self.assertFalse(
            validate_url("https://intranet")["valid"]
        )

    def test_rejects_backslash(self):
        self.assertFalse(
            validate_url(r"https://example.com\@evil.example")[
                "valid"
            ]
        )

    def test_rejects_control_characters(self):
        self.assertFalse(
            validate_url("https://example.com/\npath")["valid"]
        )

    def test_rejects_ipv4_mapped_private_ipv6(self):
        self.assertFalse(
            validate_url("http://[::ffff:192.168.1.10]")["valid"]
        )

    def test_rejects_ipv6_transition_address(self):
        self.assertFalse(
            validate_url("http://[2002:0808:0808::1]")["valid"]
        )

    def test_rejects_ipv6_zone_identifier(self):
        self.assertFalse(
            validate_url("http://[fe80::1%25eth0]")["valid"]
        )

    def test_rejects_empty_port(self):
        self.assertFalse(
            validate_url("https://example.com:")["valid"]
        )

    def test_rejects_unbracketed_ipv6(self):
        self.assertFalse(
            validate_url("http://2001:4860:4860::8888")["valid"]
        )

    def test_rejects_missing_hostname(self):
        self.assertFalse(
            validate_url("https:///path")["valid"]
        )

    def test_rejects_missing_scheme(self):
        self.assertFalse(
            validate_url("example.com")["valid"]
        )

    def test_accepts_public_ipv4_literal(self):
        result = validate_url("https://8.8.8.8")
        self.assertTrue(result["valid"])
        self.assertEqual(result["hostname"], "8.8.8.8")

    def test_accepts_public_ipv6_literal(self):
        result = validate_url("https://[2001:4860:4860::8888]")
        self.assertTrue(result["valid"])
        self.assertEqual(
            result["hostname"], "2001:4860:4860::8888"
        )

    def test_result_says_no_connection_was_made(self):
        result = validate_url("https://example.com")
        self.assertTrue(result["valid"])
        self.assertIn("No connection was made", result["message"])

    def test_rejects_url_longer_than_limit(self):
        result = validate_url(
            "https://example.com/" + ("x" * 2048)
        )
        self.assertFalse(result["valid"])

    def test_accepts_url_with_path_query_and_fragment(self):
        result = validate_url(
            "https://example.com/path?q=hello#section"
        )
        self.assertTrue(result["valid"])
        self.assertEqual(result["hostname"], "example.com")

    # Additional Stage 11 regression tests

    def test_rejects_malformed_ipv6_brackets(self):
        self.assertFalse(
            validate_url("https://[::1")["valid"]
        )

    def test_rejects_credentials_with_empty_password(self):
        self.assertFalse(
            validate_url("https://user:@example.com")["valid"]
        )

    def test_rejects_multiple_trailing_hostname_dots(self):
        self.assertFalse(
            validate_url("https://example.com..")["valid"]
        )

    def test_rejects_empty_port_on_ipv6_literal(self):
        self.assertFalse(
            validate_url("https://[2001:4860:4860::8888]:")[
                "valid"
            ]
        )

    def test_accepts_valid_non_default_port(self):
        result = validate_url("https://example.com:8443")
        self.assertTrue(result["valid"])

    def test_accepts_url_with_query_and_fragment(self):
        result = validate_url(
            "https://example.com/?next=%2Fhome#details"
        )
        self.assertTrue(result["valid"])


if __name__ == "__main__":
    unittest.main()
