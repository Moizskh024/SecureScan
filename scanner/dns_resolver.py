
"""DNS-only hostname resolution with public-IP policy checks."""

import ipaddress
import re
import socket

from scanner.destination_policy import all_addresses_are_public
from scanner.destination_policy import is_allowed_public_ip


_HOST_LABEL_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


def _failure(hostname, message):
    return {
        "allowed": False,
        "hostname": hostname,
        "addresses": [],
        "error": message,
    }


def _valid_hostname(hostname):
    """Validate an ASCII DNS hostname after normalization."""
    if not hostname or len(hostname) > 253:
        return False

    # IP literals are handled separately.
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        pass

    labels = hostname.split(".")

    # Require a dotted hostname rather than a single-label name.
    if len(labels) < 2:
        return False

    return all(
        len(label) <= 63 and bool(_HOST_LABEL_RE.fullmatch(label))
        for label in labels
    )


def resolve_public_hostname(hostname, resolver=None):
    """
    Resolve a hostname and allow it only if every returned IP is public.

    DNS resolution does not establish an HTTP connection.
    The resolver can be injected for isolated unit tests.
    """
    if not isinstance(hostname, str):
        return _failure(None, "Hostname must be a string.")

    # Accept at most one optional trailing DNS root dot.
    # Do not silently normalize malformed names such as example.com..
    hostname = hostname.strip().lower()

    if hostname.endswith("."):
        hostname = hostname[:-1]

    if (
        not hostname
        or any(
            character.isspace()
            or ord(character) < 32
            or ord(character) == 127
            for character in hostname
        )
        or "\\" in hostname
        or "://" in hostname
        or "%" in hostname
    ):
        return _failure(hostname or None, "Invalid hostname.")

    if hostname == "localhost" or hostname.endswith(".localhost"):
        return _failure(hostname, "Localhost destinations are not allowed.")

    # Check IP literals directly; do not send them to DNS.
    try:
        parsed_ip = ipaddress.ip_address(hostname)
    except ValueError:
        parsed_ip = None

    if parsed_ip is not None:
        allowed = is_allowed_public_ip(str(parsed_ip))
        return {
            "allowed": allowed,
            "hostname": hostname,
            "addresses": [str(parsed_ip)] if allowed else [],
            "error": None if allowed else "IP address is not allowed.",
        }

    if not _valid_hostname(hostname):
        return _failure(hostname, "Invalid hostname.")

    if resolver is None:
        resolver = socket.getaddrinfo

    try:
        results = resolver(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except (OSError, socket.gaierror):
        return _failure(hostname, "Hostname could not be resolved.")
    except Exception:
        # Do not return internal resolver exception details to the client.
        return _failure(
            hostname,
            "An unexpected DNS resolver error occurred.",
        )

    addresses = set()

    try:
        for result in results:
            if not isinstance(result, (tuple, list)) or len(result) < 5:
                return _failure(
                    hostname,
                    "DNS returned an invalid address result.",
                )

            sockaddr = result[4]

            if not isinstance(sockaddr, (tuple, list)) or not sockaddr:
                return _failure(
                    hostname,
                    "DNS returned an invalid address result.",
                )

            address_text = sockaddr[0]

            if not isinstance(address_text, str) or "%" in address_text:
                return _failure(
                    hostname,
                    "DNS returned an invalid address result.",
                )

            parsed_address = ipaddress.ip_address(address_text)
            addresses.add(str(parsed_address))

    except (IndexError, TypeError, ValueError, KeyError):
        return _failure(
            hostname,
            "DNS returned an invalid address result.",
        )
    except Exception:
        return _failure(
            hostname,
            "DNS returned an invalid address result.",
        )

    normalized_addresses = sorted(addresses)

    if not normalized_addresses:
        return _failure(hostname, "DNS returned no IP addresses.")

    if not all_addresses_are_public(normalized_addresses):
        return {
            "allowed": False,
            "hostname": hostname,
            "addresses": normalized_addresses,
            "error": "DNS returned a restricted or non-public address.",
        }

    return {
        "allowed": True,
        "hostname": hostname,
        "addresses": normalized_addresses,
        "error": None,
    }


if __name__ == "__main__":
    print("SecureScan DNS resolver")
    print("DNS resolution only; no HTTP requests are made.")
