
from scanner.validator import validate_url
from scanner.dns_resolver import resolve_public_hostname


def preflight_assess(value, resolver=None):
    """
    Perform URL validation and destination-policy checks.

    A successful result means the URL passed these preliminary checks.
    This function does not make HTTP requests or connect to a website.

    resolver can be injected by tests to simulate DNS answers offline.
    """
    validation = validate_url(value)

    if not validation.get("valid"):
        return {
            "safe": False,
            "status": "rejected",
            "stage": "url_validation",
            "error": validation.get("error", "URL validation failed."),
            "message": (
                "Preflight rejected the URL. "
                "No website connection was made."
            ),
        }

    hostname = validation["hostname"]

    resolution = resolve_public_hostname(
        hostname,
        resolver=resolver,
    )

    if not resolution["allowed"]:
        return {
            "safe": False,
            "status": "rejected",
            "stage": "destination_policy",
            "hostname": hostname,
            "error": resolution.get(
                "error",
                "The destination did not pass policy checks.",
            ),
            "message": (
                "Preflight rejected the destination. "
                "No website connection was made."
            ),
        }

    return {
        "safe": True,
        "status": "preflight_passed",
        "stage": "complete",
        "url": validation["url"],
        "hostname": hostname,
        "scheme": validation["scheme"],
        "https": validation["https"],
        "addresses": resolution["addresses"],
        "message": (
            "Preflight checks passed. "
            "No website connection was made."
        ),
    }
