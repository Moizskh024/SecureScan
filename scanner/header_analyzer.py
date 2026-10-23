
"""Offline HTTP security header analyzer and educational scorer."""

import re


RECOMMENDED_HEADERS = {
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "purpose": "Helps control which sources can load page content.",
    },
    "strict-transport-security": {
        "name": "Strict-Transport-Security",
        "purpose": "Tells browsers to use HTTPS for future connections.",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "purpose": "Helps prevent MIME-type sniffing when set to nosniff.",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "purpose": "Helps control whether a page can be embedded in frames.",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "purpose": "Controls how much referrer information browsers send.",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "purpose": "Controls access to supported browser features.",
    },
}

VALID_REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}

# This checks only the basic directive=value structure.
# It is not a complete Permissions-Policy grammar validator.
_PERMISSIONS_DIRECTIVE_RE = re.compile(
    r'^[a-z][a-z0-9-]*\s*=\s*\([^()]*\)$',
    re.IGNORECASE,
)


def _permissions_policy_has_basic_structure(value):
    """Check the basic structure of comma-separated policy directives."""
    if not isinstance(value, str) or not value.strip():
        return False

    directives = value.split(",")

    if not directives:
        return False

    for directive in directives:
        directive = directive.strip()

        if not directive:
            return False

        if not _PERMISSIONS_DIRECTIVE_RE.fullmatch(directive):
            return False

    return True


def analyze_security_headers(headers):
    """Analyze supplied header data without DNS or network requests."""
    if not isinstance(headers, dict):
        raise TypeError("Headers must be supplied as a dictionary.")

    normalized = {}

    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError("Header names and values must be strings.")

        key = name.strip().lower()

        if key:
            normalized[key] = value.strip()

    findings = []

    for key, details in RECOMMENDED_HEADERS.items():
        value = normalized.get(key, "")
        status = "present"
        recommendation = (
            "Review the value and confirm it suits the application."
        )

        if not value:
            status = "missing"
            recommendation = (
                f"Consider configuring {details['name']} "
                "after testing compatibility."
            )

        elif key == "content-security-policy":
            lowered = value.lower()

            if (
                "unsafe-inline" in lowered
                or "'unsafe-eval'" in lowered
            ):
                status = "review"
                recommendation = (
                    "Review unsafe-inline or unsafe-eval directives. "
                    "Prefer a carefully tested policy without them "
                    "where possible."
                )

        elif key == "strict-transport-security":
            lowered = value.lower().replace(" ", "")
            max_age_parts = [
                part for part in lowered.split(";")
                if part.startswith("max-age=")
            ]

            if len(max_age_parts) != 1:
                status = "review"
                recommendation = (
                    "Configure exactly one valid max-age directive. "
                    "HSTS should be enabled only for HTTPS websites."
                )
            else:
                try:
                    max_age = int(
                        max_age_parts[0].split("=", 1)[1]
                    )

                    if max_age < 0:
                        status = "review"
                        recommendation = (
                            "Use a non-negative integer for max-age."
                        )
                    elif max_age == 0:
                        status = "review"
                        recommendation = (
                            "A max-age of zero disables active HSTS "
                            "protection. Review the value."
                        )
                except ValueError:
                    status = "review"
                    recommendation = (
                        "Use a valid integer for the HSTS max-age."
                    )

        elif key == "x-content-type-options":
            if value.lower() != "nosniff":
                status = "review"
                recommendation = "Use the value nosniff."

        elif key == "x-frame-options":
            if value.upper() not in {"DENY", "SAMEORIGIN"}:
                status = "review"
                recommendation = (
                    "Use DENY or SAMEORIGIN if appropriate. Consider "
                    "CSP frame-ancestors for modern frame control."
                )

        elif key == "referrer-policy":
            policy = value.lower()

            if policy not in VALID_REFERRER_POLICIES:
                status = "review"
                recommendation = (
                    "Choose a recognized Referrer-Policy value. "
                    "Consider strict-origin-when-cross-origin or "
                    "no-referrer."
                )
            elif policy == "unsafe-url":
                status = "review"
                recommendation = (
                    "unsafe-url may disclose full referrer URLs. "
                    "Consider a more restrictive policy."
                )

        elif key == "permissions-policy":
            if not _permissions_policy_has_basic_structure(value):
                status = "review"
                recommendation = (
                    "The value does not match the expected basic "
                    "feature=(allowlist) structure. Review the syntax."
                )
            else:
                recommendation = (
                    "The basic directive structure looks plausible, "
                    "but this analyzer does not fully validate "
                    "Permissions-Policy syntax, directive names, "
                    "allowlist values, or browser behavior. "
                    "Review the policy against your requirements."
                )

        findings.append({
            "header": details["name"],
            "status": status,
            "value": value if value else None,
            "purpose": details["purpose"],
            "recommendation": recommendation,
        })

    counts = {
        "present": sum(
            finding["status"] == "present" for finding in findings
        ),
        "missing": sum(
            finding["status"] == "missing" for finding in findings
        ),
        "review": sum(
            finding["status"] == "review" for finding in findings
        ),
        "total": len(findings),
    }

    score = (
        round(counts["present"] / counts["total"] * 100)
        if counts["total"]
        else 0
    )

    return {
        "counts": counts,
        "score": score,
        "score_label": "Security Header Coverage",
        "scoring_method": (
            "Each of the six recommended headers is worth one point. "
            "Only present findings earn a point; missing and review "
            "findings earn zero. This score does not measure overall "
            "website security."
        ),
        "findings": findings,
        "message": (
            "Offline header analysis complete. "
            "No website connection was made."
        ),
    }
