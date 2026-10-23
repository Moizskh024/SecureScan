
"""URL syntax validation for SecureScan.

This module does not resolve DNS or make network requests.
Destination IP policy is checked separately during preflight.
"""

import ipaddress
import re
from urllib.parse import urlsplit

from scanner.destination_policy import is_allowed_public_ip


DOMAIN_LABEL = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


def _invalid(error):
    """Return a consistent invalid-URL result."""
    return {"valid": False, "error": error}


def validate_url(value):
    """Validate URL syntax and reject obviously restricted destinations."""
    if not isinstance(value, str):
        return _invalid("Enter a valid URL.")

    value = value.strip()

    if not value:
        return _invalid("Enter a website URL.")

    if len(value) > 2048:
        return _invalid(
            "The URL must be 2048 characters or fewer."
        )

    if any(ord(char) <= 32 or ord(char) == 127 for char in value):
        return _invalid(
            "The URL contains whitespace or control characters."
        )

    if "\\" in value:
        return _invalid("Backslashes are not allowed in URLs.")

    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()

        if scheme not in ("http", "https"):
            return _invalid(
                "Only HTTP and HTTPS URLs are supported."
            )

        if not parsed.netloc or not parsed.hostname:
            return _invalid(
                "Enter a URL containing a hostname."
            )

        if parsed.username is not None or parsed.password is not None:
            return _invalid(
                "URLs containing username or password credentials "
                "are not allowed."
            )

        # Explicitly reject an authority ending with a colon.
        # urlsplit() otherwise treats an empty port as if no port exists.
        authority = parsed.netloc

        if authority.endswith(":"):
            return _invalid("The URL contains an empty port.")

        port = parsed.port

        if port is not None and not 1 <= port <= 65535:
            return _invalid(
                "The port must be between 1 and 65535."
            )

        hostname = parsed.hostname.lower()

        if hostname.endswith("."):
            hostname = hostname[:-1]

        if not hostname:
            return _invalid("The hostname is empty.")

        if (
            hostname == "localhost"
            or hostname.endswith(".localhost")
        ):
            return _invalid(
                "Localhost destinations are not allowed."
            )

        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            address = None

        if address is not None:
            if not is_allowed_public_ip(str(address)):
                return _invalid(
                    "Non-public or restricted IP addresses are not allowed."
                )

            normalized_hostname = address.compressed

        else:
            try:
                normalized_hostname = (
                    hostname.encode("idna").decode("ascii")
                )
            except (UnicodeError, ValueError):
                return _invalid(
                    "The hostname format is invalid."
                )

            if len(normalized_hostname) > 253:
                return _invalid("The hostname is too long.")

            labels = normalized_hostname.split(".")

            if len(labels) < 2:
                return _invalid(
                    "Enter a fully qualified hostname, "
                    "such as example.com."
                )

            if any(
                not label or not DOMAIN_LABEL.fullmatch(label)
                for label in labels
            ):
                return _invalid(
                    "The hostname format is invalid."
                )

        return {
            "valid": True,
            "url": value,
            "hostname": normalized_hostname,
            "scheme": scheme,
            "https": scheme == "https",
            "message": (
                "URL format accepted. "
                "No connection was made to the website."
            ),
        }

    except (ValueError, UnicodeError):
        return _invalid("The URL or port format is invalid.")


if __name__ == "__main__":
    examples = [
        "https://example.com",
        "http://127.0.0.1",
        "https://example.com:",
    ]

    for example in examples:
        print(example, "->", validate_url(example))
