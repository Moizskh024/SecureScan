
import unittest

from scanner.destination_policy import (
    all_addresses_are_public,
    is_allowed_public_ip,
)


class TestDestinationPolicy(unittest.TestCase):

    def test_accepts_public_ipv4(self):
        self.assertTrue(is_allowed_public_ip("8.8.8.8"))

    def test_accepts_public_ipv6(self):
        self.assertTrue(
            is_allowed_public_ip("2001:4860:4860::8888")
        )

    def test_rejects_loopback_ipv4(self):
        self.assertFalse(is_allowed_public_ip("127.0.0.1"))

    def test_rejects_loopback_ipv6(self):
        self.assertFalse(is_allowed_public_ip("::1"))

    def test_rejects_private_ipv4(self):
        self.assertFalse(is_allowed_public_ip("192.168.1.10"))

    def test_rejects_private_ipv6(self):
        self.assertFalse(is_allowed_public_ip("fc00::1"))

    def test_rejects_link_local_ipv4(self):
        self.assertFalse(is_allowed_public_ip("169.254.10.20"))

    def test_rejects_metadata_ipv4(self):
        self.assertFalse(
            is_allowed_public_ip("169.254.169.254")
        )

    def test_rejects_unspecified_addresses(self):
        self.assertFalse(is_allowed_public_ip("0.0.0.0"))
        self.assertFalse(is_allowed_public_ip("::"))

    def test_rejects_multicast_addresses(self):
        self.assertFalse(is_allowed_public_ip("224.0.0.1"))
        self.assertFalse(is_allowed_public_ip("ff02::1"))

    def test_rejects_ipv4_mapped_private_ipv6(self):
        self.assertFalse(
            is_allowed_public_ip("::ffff:192.168.1.10")
        )

    def test_accepts_ipv4_mapped_public_ipv6(self):
        self.assertTrue(
            is_allowed_public_ip("::ffff:8.8.8.8")
        )

    def test_rejects_scoped_ipv6(self):
        self.assertFalse(is_allowed_public_ip("fe80::1%12"))

    def test_rejects_malformed_ip(self):
        self.assertFalse(is_allowed_public_ip("not-an-ip"))

    def test_rejects_non_string_ip(self):
        self.assertFalse(is_allowed_public_ip(None))

    def test_rejects_empty_address_list(self):
        self.assertFalse(all_addresses_are_public([]))

    def test_accepts_only_public_answers(self):
        self.assertTrue(
            all_addresses_are_public(["8.8.8.8", "1.1.1.1"])
        )

    def test_rejects_mixed_public_and_private_answers(self):
        self.assertFalse(
            all_addresses_are_public(["8.8.8.8", "192.168.1.10"])
        )

    def test_rejects_list_containing_invalid_answer(self):
        self.assertFalse(
            all_addresses_are_public(["8.8.8.8", "not-an-ip"])
        )

    def test_rejects_non_collection_input(self):
        self.assertFalse(all_addresses_are_public(None))

    def test_rejects_string_instead_of_address_list(self):
        self.assertFalse(all_addresses_are_public("8.8.8.8"))


if __name__ == "__main__":
    unittest.main()
