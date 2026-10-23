
import socket
import unittest
from unittest.mock import Mock, patch

from scanner.preflight import preflight_assess
from app import app


def fake_dns_answer(*addresses):
    """Create fake DNS results in socket.getaddrinfo format."""
    results = []

    for address in addresses:
        if ":" in address:
            family = socket.AF_INET6
            sockaddr = (address, 443, 0, 0)
        else:
            family = socket.AF_INET
            sockaddr = (address, 443)

        results.append(
            (
                family,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                sockaddr,
            )
        )

    return results


class TestPreflightAssessment(unittest.TestCase):

    def test_rejects_invalid_url_before_dns(self):
        resolver = Mock()

        result = preflight_assess(
            "ftp://example.com",
            resolver=resolver,
        )

        self.assertFalse(result["safe"])
        self.assertEqual(result["stage"], "url_validation")
        resolver.assert_not_called()

    def test_accepts_public_ipv4_dns_answer(self):
        resolver = Mock(return_value=fake_dns_answer("8.8.8.8"))

        result = preflight_assess(
            "https://example.com",
            resolver=resolver,
        )

        self.assertTrue(result["safe"])
        self.assertEqual(result["status"], "preflight_passed")
        self.assertEqual(result["hostname"], "example.com")
        self.assertEqual(result["addresses"], ["8.8.8.8"])
        self.assertEqual(result["scheme"], "https")
        resolver.assert_called_once()

    def test_accepts_public_ipv6_dns_answer(self):
        resolver = Mock(
            return_value=fake_dns_answer("2001:4860:4860::8888")
        )

        result = preflight_assess(
            "https://example.com",
            resolver=resolver,
        )

        self.assertTrue(result["safe"])
        self.assertEqual(
            result["addresses"],
            ["2001:4860:4860::8888"],
        )

    def test_rejects_private_dns_answer(self):
        resolver = Mock(
            return_value=fake_dns_answer("192.168.1.10")
        )

        result = preflight_assess(
            "https://example.com",
            resolver=resolver,
        )

        self.assertFalse(result["safe"])
        self.assertEqual(result["stage"], "destination_policy")

    def test_rejects_mixed_public_and_private_dns_answers(self):
        resolver = Mock(
            return_value=fake_dns_answer(
                "8.8.8.8",
                "192.168.1.10",
            )
        )

        result = preflight_assess(
            "https://example.com",
            resolver=resolver,
        )

        self.assertFalse(result["safe"])
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["stage"], "destination_policy")

    def test_rejects_mixed_public_and_loopback_dns_answers(self):
        resolver = Mock(
            return_value=fake_dns_answer(
                "8.8.8.8",
                "127.0.0.1",
            )
        )

        result = preflight_assess(
            "https://example.com",
            resolver=resolver,
        )

        self.assertFalse(result["safe"])
        self.assertEqual(result["stage"], "destination_policy")

    def test_handles_dns_failure(self):
        resolver = Mock(
            side_effect=socket.gaierror("simulated DNS failure")
        )

        result = preflight_assess(
            "https://example.com",
            resolver=resolver,
        )

        self.assertFalse(result["safe"])
        self.assertEqual(result["stage"], "destination_policy")
        self.assertEqual(result["status"], "rejected")

    def test_handles_unexpected_dns_resolver_error(self):
        resolver = Mock(
            side_effect=RuntimeError("simulated internal error")
        )

        result = preflight_assess(
            "https://example.com",
            resolver=resolver,
        )

        self.assertFalse(result["safe"])
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["stage"], "destination_policy")
        self.assertNotIn("simulated internal error", result["error"])

    def test_rejects_empty_dns_answer(self):
        resolver = Mock(return_value=[])

        result = preflight_assess(
            "https://example.com",
            resolver=resolver,
        )

        self.assertFalse(result["safe"])
        self.assertEqual(result["stage"], "destination_policy")

    def test_rejects_malformed_dns_result(self):
        resolver = Mock(return_value=[("invalid-result",)])

        result = preflight_assess(
            "https://example.com",
            resolver=resolver,
        )

        self.assertFalse(result["safe"])
        self.assertEqual(result["stage"], "destination_policy")

    def test_rejects_malformed_hostname_before_dns(self):
        resolver = Mock()

        result = preflight_assess(
            "https://example..com",
            resolver=resolver,
        )

        self.assertFalse(result["safe"])
        self.assertEqual(result["stage"], "url_validation")
        resolver.assert_not_called()

    def test_public_ip_literal_does_not_use_dns(self):
        resolver = Mock()

        result = preflight_assess(
            "https://8.8.8.8",
            resolver=resolver,
        )

        self.assertTrue(result["safe"])
        self.assertEqual(result["addresses"], ["8.8.8.8"])
        resolver.assert_not_called()

    def test_private_ip_literal_is_rejected_before_dns(self):
        resolver = Mock()

        result = preflight_assess(
            "https://192.168.1.10",
            resolver=resolver,
        )

        self.assertFalse(result["safe"])
        resolver.assert_not_called()

    def test_result_says_no_website_connection_was_made(self):
        resolver = Mock(return_value=fake_dns_answer("8.8.8.8"))

        result = preflight_assess(
            "https://example.com",
            resolver=resolver,
        )

        self.assertIn(
            "No website connection was made",
            result["message"],
        )

    def test_rejected_result_says_no_connection_was_made(self):
        resolver = Mock(
            return_value=fake_dns_answer("192.168.1.10")
        )

        result = preflight_assess(
            "https://example.com",
            resolver=resolver,
        )

        self.assertFalse(result["safe"])
        self.assertIn(
            "No website connection was made",
            result["message"],
        )

    def test_success_result_contains_expected_fields(self):
        resolver = Mock(return_value=fake_dns_answer("8.8.8.8"))

        result = preflight_assess(
            "https://example.com",
            resolver=resolver,
        )

        self.assertTrue(result["safe"])
        self.assertEqual(result["status"], "preflight_passed")
        self.assertEqual(result["stage"], "complete")
        self.assertEqual(result["url"], "https://example.com")
        self.assertEqual(result["hostname"], "example.com")
        self.assertEqual(result["scheme"], "https")
        self.assertTrue(result["https"])
        self.assertEqual(result["addresses"], ["8.8.8.8"])

    def test_unsupported_scheme_is_rejected_before_dns(self):
        resolver = Mock()

        result = preflight_assess(
            "ftp://example.com",
            resolver=resolver,
        )

        self.assertFalse(result["safe"])
        self.assertEqual(result["stage"], "url_validation")
        resolver.assert_not_called()


class TestPreflightRoute(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()

    @patch("app.preflight_assess")
    def test_preflight_route_returns_assessment(self, mocked_assess):
        mocked_assess.return_value = {
            "safe": True,
            "status": "preflight_passed",
            "stage": "complete",
            "hostname": "example.com",
            "addresses": ["8.8.8.8"],
            "message": (
                "Preflight checks passed. "
                "No website connection was made."
            ),
        }

        response = self.client.post(
            "/api/preflight",
            json={"url": "https://example.com"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["safe"])
        mocked_assess.assert_called_once_with("https://example.com")

    def test_preflight_route_rejects_missing_url(self):
        response = self.client.post(
            "/api/preflight",
            json={},
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.get_json()["safe"])

    def test_preflight_route_rejects_non_json_request(self):
        response = self.client.post(
            "/api/preflight",
            data="url=https://example.com",
            content_type="application/x-www-form-urlencoded",
        )

        self.assertEqual(response.status_code, 415)


if __name__ == "__main__":
    unittest.main()
