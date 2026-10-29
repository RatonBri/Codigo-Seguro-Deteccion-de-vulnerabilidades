from __future__ import annotations

import ipaddress
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .core import Finding, make_finding


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, request, fp, code, msg, headers, newurl
    ):
        return None


def validate_url(
    url: str, allowed_hosts: list[str] | None = None
) -> str:
    allowed_hosts = allowed_hosts or []
    parsed = urlsplit(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS are allowed.")

    if parsed.username or parsed.password:
        raise ValueError("Credentials in URLs are not allowed.")

    if parsed.query or parsed.fragment:
        raise ValueError(
            "Query strings and fragments are not allowed "
            "in HTTP scan targets."
        )

    if not parsed.hostname:
        raise ValueError("The URL must contain a hostname.")

    # Accessing .port validates malformed port specifications.
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid URL port.") from exc

    host = parsed.hostname.lower().rstrip(".")

    local = host == "localhost"

    try:
        address = ipaddress.ip_address(host)
        local = address.is_loopback
    except ValueError:
        pass

    allowlist = {
        item.lower().rstrip(".")
        for item in allowed_hosts
    }

    if not local and host not in allowlist:
        raise ValueError(
            f"Host '{host}' is not allowed. "
            "Use --allow-host only for systems you own "
            "or are explicitly authorized to test."
        )

    return url


def check_http(
    url: str,
    allowed_hosts: list[str] | None = None,
    timeout: float = 5.0,
) -> tuple[list[Finding], list[str]]:
    validate_url(url, allowed_hosts)

    findings: list[Finding] = []
    warnings: list[str] = []

    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        NoRedirect(),
    )

    request = urllib.request.Request(
        url,
        method="HEAD",
        headers={"User-Agent": "VibeShield/0.2"},
    )

    try:
        with opener.open(
            request, timeout=timeout
        ) as response:
            headers = {
                key.lower(): value
                for key, value in response.headers.items()
            }
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = {
            key.lower(): value
            for key, value in exc.headers.items()
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        warnings.append(
            f"HTTP check failed: {type(exc).__name__}"
        )
        return findings, warnings

    if status >= 400:
        warnings.append(
            f"HTTP HEAD returned status {status}; "
            "header assessment may be incomplete."
        )

    recommended = {
        "x-content-type-options": "X-Content-Type-Options",
        "content-security-policy": "Content-Security-Policy",
        "referrer-policy": "Referrer-Policy",
    }

    for key, display_name in recommended.items():
        if key not in headers:
            findings.append(make_finding(
                "VS017",
                "",
                1,
                f"Response from {url} lacks {display_name}.",
                evidence=f"Missing header: {display_name}",
            ))

    if (
        urlsplit(url).scheme == "https"
        and "strict-transport-security" not in headers
    ):
        findings.append(make_finding(
            "VS018",
            "",
            1,
            f"HTTPS response from {url} lacks HSTS.",
            evidence="Missing Strict-Transport-Security",
        ))

    return findings, warnings