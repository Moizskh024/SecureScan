
import ipaddress


def is_allowed_public_ip(value):
    """
    Allow only public IP addresses for preliminary policy checks.

    This function does not resolve hostnames or connect to websites.
    It is not, by itself, authorization to make a network request.
    """
    if not isinstance(value, str) or not value or "%" in value:
        return False

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    if isinstance(address, ipaddress.IPv6Address):
        # Reject IPv6 transition addresses using explicit network ranges.
        # This avoids relying on properties missing in some Python versions.
        if (
            address in ipaddress.IPv6Network("2002::/16")
            or address in ipaddress.IPv6Network("2001::/32")
        ):
            return False

        # Check IPv4-mapped IPv6 addresses using the embedded IPv4 address.
        if address.ipv4_mapped is not None:
            return is_allowed_public_ip(str(address.ipv4_mapped))

    return (
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_reserved
    )


def all_addresses_are_public(addresses):
    """
    Return True only when the collection is nonempty and every address
    passes the public-IP policy check.
    """
    if isinstance(addresses, (str, bytes)):
        return False

    try:
        resolved = list(addresses)
    except TypeError:
        return False

    return bool(resolved) and all(
        is_allowed_public_ip(address) for address in resolved
    )
