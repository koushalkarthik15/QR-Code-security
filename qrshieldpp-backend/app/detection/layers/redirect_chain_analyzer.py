"""Redirect-chain analysis for QRShield++.

Capabilities:
- Uses HTTP HEAD requests
- Resolves full redirect chains
- Extracts redirect count
- Detects domain switches
- Detects HTTPS -> HTTP downgrade
- Calculates final domain age (RDAP best-effort)
- Produces risk score in [0.0, 1.0]
"""

from __future__ import annotations

import argparse
import json
import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen


# HTTP status codes that indicate a redirect.
REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
ALLOWED_SCHEMES = {"http", "https"}
DISALLOWED_HOSTS = {"localhost", "localhost.localdomain"}

# Partial public suffix support for better registrable-domain matching.
SECOND_LEVEL_SUFFIXES = {
    "ac.uk",
    "co.in",
    "co.jp",
    "co.uk",
    "com.au",
    "com.br",
    "com.cn",
    "com.hk",
    "com.mx",
    "com.sg",
    "com.tr",
    "edu.au",
    "gov.uk",
    "net.au",
    "org.au",
    "org.uk",
}


@dataclass
class RedirectHop:
    """One response-hop in the redirect chain."""

    url: str
    status_code: int
    location: str | None
    scheme: str
    host: str
    registrable_domain: str


@dataclass
class RedirectChainResult:
    """Full output of redirect-chain analysis."""

    input_url: str
    normalized_input_url: str
    final_url: str
    final_host: str
    final_registrable_domain: str
    chain: list[RedirectHop]
    redirect_count: int
    domain_switch_count: int
    has_domain_switch: bool
    https_to_http_downgrade: bool
    final_domain_created_at: str | None
    final_domain_age_days: int | None
    risk_score: float
    risk_factors: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert result to JSON-serializable dictionary."""
        payload = asdict(self)
        payload["chain"] = [asdict(hop) for hop in self.chain]
        return payload


class _NoRedirectHandler(HTTPRedirectHandler):
    """urllib handler that disables automatic redirect following."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


class RedirectChainAnalyzer:
    """Analyze redirect behavior and compute a threat-oriented risk score."""

    def __init__(
        self,
        timeout_seconds: float = 6.0,
        max_redirects: int = 12,
        user_agent: str = "QRShield++ RedirectAnalyzer/1.0",
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self._head_opener = build_opener(_NoRedirectHandler())

    def analyze(self, url: str) -> RedirectChainResult:
        """Run redirect-chain analysis with HEAD requests."""
        errors: list[str] = []
        risk_factors: list[str] = []

        try:
            normalized_url = self._normalize_url(url)
        except ValueError as exc:
            errors.append(str(exc))
            return RedirectChainResult(
                input_url=url,
                normalized_input_url="",
                final_url="",
                final_host="",
                final_registrable_domain="",
                chain=[],
                redirect_count=0,
                domain_switch_count=0,
                has_domain_switch=False,
                https_to_http_downgrade=False,
                final_domain_created_at=None,
                final_domain_age_days=None,
                risk_score=1.0,
                risk_factors=["URL validation failed"],
                errors=errors,
            )
        current_url = normalized_url
        visited_urls = {normalized_url}
        chain: list[RedirectHop] = []

        domain_switch_count = 0
        https_to_http_downgrade = False
        redirect_count = 0

        for _ in range(self.max_redirects + 1):
            status_code, location, response_error = self._head_once(current_url)
            if response_error:
                errors.append(response_error)

            parsed_current = urlsplit(current_url)
            current_host = parsed_current.hostname or ""
            current_reg_domain = self._registrable_domain(current_host)

            chain.append(
                RedirectHop(
                    url=current_url,
                    status_code=status_code,
                    location=location,
                    scheme=parsed_current.scheme.lower(),
                    host=current_host.lower(),
                    registrable_domain=current_reg_domain,
                )
            )

            if status_code not in REDIRECT_STATUS_CODES or not location:
                break

            redirect_count += 1
            try:
                next_url = self._normalize_url(urljoin(current_url, location))
            except ValueError as exc:
                errors.append(f"Redirect target rejected: {exc}")
                break
            parsed_next = urlsplit(next_url)
            next_host = parsed_next.hostname or ""
            next_reg_domain = self._registrable_domain(next_host)

            if current_reg_domain and next_reg_domain and current_reg_domain != next_reg_domain:
                domain_switch_count += 1

            if parsed_current.scheme.lower() == "https" and parsed_next.scheme.lower() == "http":
                https_to_http_downgrade = True

            if next_url in visited_urls:
                errors.append(f"Redirect loop detected at URL: {next_url}")
                break

            visited_urls.add(next_url)
            current_url = next_url
        else:
            errors.append("Maximum redirects reached before chain resolution.")

        final_url = current_url
        final_host = (urlsplit(final_url).hostname or "").lower()
        final_reg_domain = self._registrable_domain(final_host)

        final_domain_created_at, final_domain_age_days, age_error = self._lookup_domain_age_days(
            final_reg_domain
        )
        if age_error:
            errors.append(age_error)

        if redirect_count >= 3:
            risk_factors.append(f"High redirect count: {redirect_count}")
        elif redirect_count > 0:
            risk_factors.append(f"Redirect count: {redirect_count}")

        if domain_switch_count > 0:
            risk_factors.append(f"Domain switches detected: {domain_switch_count}")

        if https_to_http_downgrade:
            risk_factors.append("HTTPS to HTTP downgrade detected")

        if final_domain_age_days is None:
            risk_factors.append("Final domain age unavailable")
        elif final_domain_age_days < 30:
            risk_factors.append(f"Very young final domain: {final_domain_age_days} days")
        elif final_domain_age_days < 90:
            risk_factors.append(f"Young final domain: {final_domain_age_days} days")

        risk_score = self._compute_risk_score(
            redirect_count=redirect_count,
            domain_switch_count=domain_switch_count,
            https_to_http_downgrade=https_to_http_downgrade,
            final_domain_age_days=final_domain_age_days,
            has_errors=bool(errors),
        )

        return RedirectChainResult(
            input_url=url,
            normalized_input_url=normalized_url,
            final_url=final_url,
            final_host=final_host,
            final_registrable_domain=final_reg_domain,
            chain=chain,
            redirect_count=redirect_count,
            domain_switch_count=domain_switch_count,
            has_domain_switch=domain_switch_count > 0,
            https_to_http_downgrade=https_to_http_downgrade,
            final_domain_created_at=final_domain_created_at,
            final_domain_age_days=final_domain_age_days,
            risk_score=risk_score,
            risk_factors=risk_factors,
            errors=errors,
        )

    def _head_once(self, url: str) -> tuple[int, str | None, str | None]:
        """Issue one HEAD request without auto-following redirects."""
        target_error = self._validate_target_url(url)
        if target_error:
            return 0, None, target_error

        request = Request(
            url=url,
            method="HEAD",
            headers={
                "User-Agent": self.user_agent,
                "Accept": "*/*",
                "Connection": "close",
            },
        )

        try:
            with self._head_opener.open(request, timeout=self.timeout_seconds) as response:
                status_code = int(getattr(response, "status", 200))
                location = response.headers.get("Location")
                return status_code, location, None
        except HTTPError as exc:
            # For redirects and many server errors, HTTPError still includes headers.
            location = exc.headers.get("Location") if exc.headers else None
            code = int(exc.code)
            if code in REDIRECT_STATUS_CODES:
                return code, location, None
            return code, location, f"HTTP error {code} for {url}"
        except URLError as exc:
            return 0, None, f"URL error for {url}: {exc.reason}"
        except socket.timeout:
            return 0, None, f"Timeout while requesting {url}"
        except Exception as exc:  # noqa: BLE001
            return 0, None, f"Unexpected request error for {url}: {exc}"

    @staticmethod
    def _normalize_url(url: str) -> str:
        candidate = (url or "").strip()
        if not candidate:
            raise ValueError("URL is empty.")
        parsed = urlsplit(candidate)
        if not parsed.scheme:
            candidate = f"http://{candidate}"
            parsed = urlsplit(candidate)
        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            raise ValueError("Only http/https URLs are supported.")
        if not parsed.hostname:
            raise ValueError("URL host is empty.")
        return candidate

    @staticmethod
    def _is_disallowed_ip(host: str) -> bool:
        try:
            parsed_ip = ip_address(host.strip("[]"))
        except ValueError:
            return False
        return (
            parsed_ip.is_private
            or parsed_ip.is_loopback
            or parsed_ip.is_link_local
            or parsed_ip.is_multicast
            or parsed_ip.is_reserved
            or parsed_ip.is_unspecified
        )

    @classmethod
    def _validate_target_url(cls, url: str) -> str | None:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            return f"Disallowed URL scheme: {parsed.scheme or 'none'}"

        host = (parsed.hostname or "").strip().lower()
        if not host:
            return "Target host is empty."
        if host in DISALLOWED_HOSTS:
            return "Target host is disallowed."
        if cls._is_disallowed_ip(host):
            return "Target host resolves to a disallowed network address."

        try:
            port = parsed.port or (443 if scheme == "https" else 80)
        except ValueError:
            return "Invalid URL port."
        try:
            addrinfo = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            return f"Unable to resolve target host: {exc}"

        for _, _, _, _, sockaddr in addrinfo:
            ip_text = str(sockaddr[0]).split("%")[0]
            if cls._is_disallowed_ip(ip_text):
                return "Target host resolves to a disallowed network address."

        return None

    @staticmethod
    def _is_ip(host: str) -> bool:
        if not host:
            return False
        try:
            ip_address(host.strip("[]"))
            return True
        except ValueError:
            return False

    @classmethod
    def _registrable_domain(cls, host: str) -> str:
        """Approximate registrable domain (eTLD+1 style)."""
        clean_host = (host or "").strip(".").lower()
        if not clean_host:
            return ""
        if cls._is_ip(clean_host):
            return clean_host

        labels = [part for part in clean_host.split(".") if part]
        if len(labels) <= 2:
            return clean_host

        suffix_2 = ".".join(labels[-2:])
        if suffix_2 in SECOND_LEVEL_SUFFIXES and len(labels) >= 3:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])

    def _lookup_domain_age_days(self, domain: str) -> tuple[str | None, int | None, str | None]:
        """Best-effort domain age lookup using RDAP."""
        if not domain:
            return None, None, "Final domain is empty; cannot calculate age."
        if self._is_ip(domain):
            return None, None, "Final domain is an IP address; domain age not applicable."

        rdap_url = f"https://rdap.org/domain/{domain}"
        request = Request(
            url=rdap_url,
            method="GET",
            headers={"User-Agent": self.user_agent, "Accept": "application/json"},
        )

        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8", errors="replace"))
        except Exception as exc:  # noqa: BLE001
            return None, None, f"Domain age lookup failed for {domain}: {exc}"

        created_at = self._extract_creation_date(payload)
        if created_at is None:
            return None, None, f"Creation date not found in RDAP response for {domain}."

        now = datetime.now(timezone.utc)
        age_days = max((now - created_at).days, 0)
        return created_at.isoformat(), age_days, None

    @staticmethod
    def _extract_creation_date(payload: dict[str, Any]) -> datetime | None:
        events = payload.get("events") or []
        if not isinstance(events, list):
            return None

        candidates: list[datetime] = []
        preferred_actions = {"registration", "registered", "creation", "created"}

        for event in events:
            if not isinstance(event, dict):
                continue
            action = str(event.get("eventAction", "")).strip().lower()
            date_text = str(event.get("eventDate", "")).strip()
            if not date_text:
                continue
            parsed_date = RedirectChainAnalyzer._parse_datetime(date_text)
            if parsed_date is None:
                continue
            if action in preferred_actions:
                candidates.append(parsed_date)

        if candidates:
            return min(candidates)

        # Fallback: earliest parsable event date.
        fallback_dates: list[datetime] = []
        for event in events:
            if not isinstance(event, dict):
                continue
            date_text = str(event.get("eventDate", "")).strip()
            if not date_text:
                continue
            parsed_date = RedirectChainAnalyzer._parse_datetime(date_text)
            if parsed_date is not None:
                fallback_dates.append(parsed_date)
        if fallback_dates:
            return min(fallback_dates)
        return None

    @staticmethod
    def _parse_datetime(date_text: str) -> datetime | None:
        text = date_text.strip()
        if not text:
            return None
        # Support RFC3339 with trailing Z.
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _compute_risk_score(
        redirect_count: int,
        domain_switch_count: int,
        https_to_http_downgrade: bool,
        final_domain_age_days: int | None,
        has_errors: bool,
    ) -> float:
        """Heuristic weighted risk score normalized to [0, 1]."""
        score = 0.0

        # More hops generally indicates potential cloaking.
        score += min(0.35, redirect_count * 0.07)

        # Domain transitions are suspicious in QR-driven phishing campaigns.
        score += min(0.30, domain_switch_count * 0.12)

        # Downgrade from HTTPS to HTTP is a strong risk signal.
        if https_to_http_downgrade:
            score += 0.30

        # Young domains correlate with malicious disposable infrastructure.
        if final_domain_age_days is None:
            score += 0.05
        elif final_domain_age_days < 7:
            score += 0.25
        elif final_domain_age_days < 30:
            score += 0.20
        elif final_domain_age_days < 90:
            score += 0.13
        elif final_domain_age_days < 365:
            score += 0.07

        # Mild uncertainty penalty when chain or RDAP had errors.
        if has_errors:
            score += 0.05

        return round(min(max(score, 0.0), 1.0), 4)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze URL redirect chains for QRShield++.")
    parser.add_argument("--url", required=True, help="URL to analyze.")
    parser.add_argument("--timeout-seconds", type=float, default=6.0, help="Per-request timeout.")
    parser.add_argument("--max-redirects", type=int, default=12, help="Maximum redirects to follow.")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    analyzer = RedirectChainAnalyzer(
        timeout_seconds=args.timeout_seconds,
        max_redirects=args.max_redirects,
    )
    result = analyzer.analyze(args.url)
    print(json.dumps(result.to_dict(), indent=2))


if __name__ == "__main__":
    main()
