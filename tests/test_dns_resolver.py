
import socket
import unittest
from unittest.mock import Mock

from scanner.dns_resolver import resolve_public_hostname


def fake_dns_answer(*addresses):
    """Build mocked getaddrinfo results without performing DNS."""
    results = []

    for address in addresses:
        if ":" in address:
            family = socket.AF_INET6
            sockaddr = (address, 443, 0, 0)
        else:
            family = socket.AF_INET
            sockaddr = (address, 443)

        results.append(
            (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)
        )

    return results


class TestSafeDNSResolution(unittest.TestCase):

    def setUp(self):
        self.resolver = Mock(
            return_value=fake_dns_answer("8.8.8.8")
        )

    def test_accepts_public_ipv4_answer(self):
        result = resolve_public_hostname(
            "example.com", resolver=self.resolver
        )
        self.assertTrue(result["allowed"])
        self.assertEqual(result["addresses"], ["8.8.8.8"])
        self.resolver.assert_called_once()

    def test_accepts_public_ipv6_answer(self):
        resolver = Mock(
            return_value=fake_dns_answer("2001:4860:4860::8888")
        )
        result = resolve_public_hostname("example.com", resolver=resolver)
        self.assertTrue(result["allowed"])
        self.assertEqual(result["addresses"], ["2001:4860:4860::8888"])

    def test_rejects_private_ipv4_answer(self):
        resolver = Mock(return_value=fake_dns_answer("192.168.1.10"))
        result = resolve_public_hostname("example.com", resolver=resolver)
        self.assertFalse(result["allowed"])
        self.assertIn("restricted", result["error"])

    def test_rejects_loopback_answer(self):
        resolver = Mock(return_value=fake_dns_answer("127.0.0.1"))
        result = resolve_public_hostname("example.com", resolver=resolver)
        self.assertFalse(result["allowed"])

    def test_rejects_link_local_answer(self):
        resolver = Mock(return_value=fake_dns_answer("169.254.169.254"))
        result = resolve_public_hostname("example.com", resolver=resolver)
        self.assertFalse(result["allowed"])

    def test_rejects_mixed_public_and_private_answers(self):
        resolver = Mock(
            return_value=fake_dns_answer("8.8.8.8", "192.168.1.10")
        )
        result = resolve_public_hostname("example.com", resolver=resolver)
        self.assertFalse(result["allowed"])
        self.assertEqual(len(result["addresses"]), 2)

    def test_rejects_mixed_public_and_loopback_answers(self):
        resolver = Mock(
            return_value=fake_dns_answer("1.1.1.1", "127.0.0.1")
        )
        result = resolve_public_hostname("example.com", resolver=resolver)
        self.assertFalse(result["allowed"])

    def test_rejects_empty_dns_response(self):
        resolver = Mock(return_value=[])
        result = resolve_public_hostname("example.com", resolver=resolver)
        self.assertFalse(result["allowed"])
        self.assertEqual(result["addresses"], [])
        self.assertIn("no IP addresses", result["error"])

    def test_handles_dns_lookup_error(self):
        resolver = Mock(side_effect=socket.gaierror("simulated failure"))
        result = resolve_public_hostname("example.com", resolver=resolver)
        self.assertFalse(result["allowed"])
        self.assertIn("could not be resolved", result["error"])

    def test_handles_unexpected_resolver_error(self):
        resolver = Mock(side_effect=RuntimeError("private internal detail"))
        result = resolve_public_hostname("example.com", resolver=resolver)
        self.assertFalse(result["allowed"])
        self.assertNotIn("private internal detail", result["error"])

    def test_rejects_malformed_dns_result(self):
        resolver = Mock(return_value=[("invalid-result",)])
        result = resolve_public_hostname("example.com", resolver=resolver)
        self.assertFalse(result["allowed"])
        self.assertIn("invalid address result", result["error"])

    def test_rejects_invalid_address_inside_dns_result(self):
        resolver = Mock(return_value=fake_dns_answer("not-an-ip"))
        result = resolve_public_hostname("example.com", resolver=resolver)
        self.assertFalse(result["allowed"])
        self.assertEqual(result["addresses"], [])

    def test_rejects_localhost_without_resolving(self):
        resolver = Mock()
        result = resolve_public_hostname("localhost", resolver=resolver)
        self.assertFalse(result["allowed"])
        resolver.assert_not_called()

    def test_rejects_localhost_subdomain_without_resolving(self):
        resolver = Mock()
        result = resolve_public_hostname(
            "service.localhost", resolver=resolver
        )
        self.assertFalse(result["allowed"])
        resolver.assert_not_called()

    def test_accepts_public_ip_literal_without_dns(self):
        resolver = Mock()
        result = resolve_public_hostname("8.8.8.8", resolver=resolver)
        self.assertTrue(result["allowed"])
        resolver.assert_not_called()

    def test_rejects_private_ip_literal_without_dns(self):
        resolver = Mock()
        result = resolve_public_hostname(
            "192.168.1.10", resolver=resolver
        )
        self.assertFalse(result["allowed"])
        resolver.assert_not_called()

    def test_rejects_non_string_hostname(self):
        resolver = Mock()
        result = resolve_public_hostname(None, resolver=resolver)
        self.assertFalse(result["allowed"])
        resolver.assert_not_called()

    def test_rejects_empty_hostname_without_dns(self):
        resolver = Mock()
        result = resolve_public_hostname("", resolver=resolver)
        self.assertFalse(result["allowed"])
        resolver.assert_not_called()

    def test_normalizes_hostname_case_and_trailing_dot(self):
        resolver = Mock(return_value=fake_dns_answer("8.8.8.8"))
        result = resolve_public_hostname("EXAMPLE.COM.", resolver=resolver)
        self.assertTrue(result["allowed"])
        self.assertEqual(result["hostname"], "example.com")
        resolver.assert_called_once_with(
            "example.com", None, type=socket.SOCK_STREAM
        )

    def test_rejects_hostname_with_consecutive_dots_without_dns(self):
        resolver = Mock()
        result = resolve_public_hostname("example..com", resolver=resolver)
        self.assertFalse(result["allowed"])
        resolver.assert_not_called()

    def test_rejects_hostname_with_underscore_without_dns(self):
        resolver = Mock()
        result = resolve_public_hostname(
            "bad_name.example", resolver=resolver
        )
        self.assertFalse(result["allowed"])
        resolver.assert_not_called()

    def test_rejects_hostname_with_leading_hyphen_without_dns(self):
        resolver = Mock()
        result = resolve_public_hostname("-bad.example", resolver=resolver)
        self.assertFalse(result["allowed"])
        resolver.assert_not_called()

    def test_rejects_hostname_with_port_without_dns(self):
        resolver = Mock()
        result = resolve_public_hostname("example.com:443", resolver=resolver)
        self.assertFalse(result["allowed"])
        resolver.assert_not_called()

    def test_rejects_ipv4_mapped_private_ipv6(self):
        resolver = Mock()
        result = resolve_public_hostname(
            "::ffff:192.168.1.10", resolver=resolver
        )
        self.assertFalse(result["allowed"])
        resolver.assert_not_called()

    def test_deduplicates_dns_answers(self):
        resolver = Mock(
            return_value=fake_dns_answer("8.8.8.8", "8.8.8.8")
        )
        result = resolve_public_hostname("example.com", resolver=resolver)
        self.assertTrue(result["allowed"])
        self.assertEqual(result["addresses"], ["8.8.8.8"])

    def test_rejects_dns_result_with_ipv6_zone_identifier(self):
        resolver = Mock(return_value=fake_dns_answer("fe80::1"))
        result = resolve_public_hostname("example.com", resolver=resolver)
        self.assertFalse(result["allowed"])

    def test_rejects_hostname_with_slash_without_dns(self):
        resolver = Mock()
        result = resolve_public_hostname(
            "example.com/path", resolver=resolver
        )
        self.assertFalse(result["allowed"])
        resolver.assert_not_called()

    def test_rejects_multiple_trailing_dots_without_dns(self):
        resolver = Mock()
        result = resolve_public_hostname(
            "example.com..", resolver=resolver
        )
        self.assertFalse(result["allowed"])
        self.assertEqual(result["addresses"], [])
        self.assertEqual(result["error"], "Invalid hostname.")
        resolver.assert_not_called()

    def test_rejects_whitespace_then_multiple_trailing_dots_without_dns(self):
        resolver = Mock()
        result = resolve_public_hostname(
            "  example.com..  ", resolver=resolver
        )
        self.assertFalse(result["allowed"])
        self.assertEqual(result["addresses"], [])
        self.assertEqual(result["error"], "Invalid hostname.")
        resolver.assert_not_called()


if __name__ == "__main__":
    unittest.main()
