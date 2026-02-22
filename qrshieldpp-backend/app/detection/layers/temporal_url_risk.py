"""Time-based URL risk modeling for QRShield++.

Why temporal behavior matters in security:
- Attack infrastructure changes quickly; freshly registered domains are common in
  phishing and disposable campaigns.
- Sudden spikes in scan activity around the same domain can signal active abuse
  waves that static URL checks may miss.
- Time-decayed scan history emphasizes recent behavior while still retaining
  weak memory of older observations.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


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
class TemporalRiskResult:
    """URL temporal-risk output for one scan event."""

    input_url: str
    normalized_url: str
    host: str
    registrable_domain: str
    scan_timestamp_utc: str
    total_scans_for_domain: int
    recent_scan_count_1h: int
    decayed_scan_frequency: float
    frequency_risk: float
    domain_created_at: str | None
    domain_age_days: int | None
    domain_age_risk: float
    risk_score: float
    risk_factors: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert result to a JSON-serializable dictionary."""
        return asdict(self)


class TemporalURLRiskModel:
    """Temporal model that tracks scan frequency and domain-age risk."""

    def __init__(
        self,
        scan_decay_half_life_hours: float = 24.0,
        frequency_scale: float = 8.0,
        domain_age_decay_days: float = 180.0,
        recent_window_hours: float = 1.0,
        history_retention_days: int = 30,
        domain_age_cache_ttl_hours: int = 48,
        user_agent: str = "QRShield++ TemporalRisk/1.0",
    ) -> None:
        self.scan_decay_half_life_hours = max(1.0, float(scan_decay_half_life_hours))
        self.frequency_scale = max(0.1, float(frequency_scale))
        self.domain_age_decay_days = max(1.0, float(domain_age_decay_days))
        self.recent_window_hours = max(0.1, float(recent_window_hours))
        self.history_retention_days = max(1, int(history_retention_days))
        self.domain_age_cache_ttl_hours = max(1, int(domain_age_cache_ttl_hours))
        self.user_agent = user_agent

        self._scan_history: dict[str, deque[datetime]] = defaultdict(deque)
        self._domain_age_cache: dict[str, tuple[datetime | None, datetime]] = {}

    @staticmethod
    def temporal_security_explanation() -> str:
        """Short explanation for project reports and analyst notes."""
        return (
            "Temporal behavior reveals risk that static snapshots miss: "
            "newly created domains and sudden scan-frequency spikes are strong "
            "signals of active phishing campaigns."
        )

    def assess_scan(self, url: str, scanned_at: datetime | str | None = None) -> TemporalRiskResult:
        """Record one scan event and return normalized temporal risk in [0, 1]."""
        errors: list[str] = []
        risk_factors: list[str] = []

        scan_time = self._coerce_datetime(scanned_at)
        normalized_url = self._normalize_url(url)
        host = (urlsplit(normalized_url).hostname or "").lower()
        registrable_domain = self._registrable_domain(host)

        if not registrable_domain:
            errors.append("Unable to extract registrable domain from URL.")
            return TemporalRiskResult(
                input_url=url,
                normalized_url=normalized_url,
                host=host,
                registrable_domain=registrable_domain,
                scan_timestamp_utc=scan_time.isoformat(),
                total_scans_for_domain=0,
                recent_scan_count_1h=0,
                decayed_scan_frequency=0.0,
                frequency_risk=0.0,
                domain_created_at=None,
                domain_age_days=None,
                domain_age_risk=0.35,
                risk_score=0.4,
                risk_factors=["Domain extraction failed"],
                errors=errors,
            )

        self._prune_scan_history(registrable_domain, scan_time)
        self._scan_history[registrable_domain].append(scan_time)

        decayed_frequency, recent_scans = self._decayed_frequency(registrable_domain, scan_time)
        total_scans = len(self._scan_history[registrable_domain])
        frequency_risk = self._frequency_risk(decayed_frequency)

        domain_created_at, domain_age_days, age_error = self._domain_age_days(
            registrable_domain, scan_time
        )
        if age_error:
            errors.append(age_error)
        domain_age_risk = self._domain_age_risk(domain_age_days)

        risk_score = self._combine_risk(
            frequency_risk=frequency_risk,
            domain_age_risk=domain_age_risk,
            recent_scans=recent_scans,
            has_errors=bool(errors),
        )

        if total_scans >= 5:
            risk_factors.append(f"Elevated scan volume for domain: {total_scans}")
        if recent_scans >= 3:
            risk_factors.append(f"Burst behavior: {recent_scans} scans in the last hour")
        if domain_age_days is None:
            risk_factors.append("Domain age unavailable")
        elif domain_age_days < 30:
            risk_factors.append(f"Very young domain: {domain_age_days} days")
        elif domain_age_days < 90:
            risk_factors.append(f"Young domain: {domain_age_days} days")

        return TemporalRiskResult(
            input_url=url,
            normalized_url=normalized_url,
            host=host,
            registrable_domain=registrable_domain,
            scan_timestamp_utc=scan_time.isoformat(),
            total_scans_for_domain=total_scans,
            recent_scan_count_1h=recent_scans,
            decayed_scan_frequency=round(decayed_frequency, 6),
            frequency_risk=round(frequency_risk, 6),
            domain_created_at=(domain_created_at.isoformat() if domain_created_at else None),
            domain_age_days=domain_age_days,
            domain_age_risk=round(domain_age_risk, 6),
            risk_score=round(self._clip01(risk_score), 6),
            risk_factors=risk_factors,
            errors=errors,
        )

    def _prune_scan_history(self, domain: str, now_utc: datetime) -> None:
        """Drop stale history to keep memory bounded and decay meaningful."""
        threshold = now_utc - timedelta(days=self.history_retention_days)
        history = self._scan_history[domain]
        while history and history[0] < threshold:
            history.popleft()

    def _decayed_frequency(self, domain: str, now_utc: datetime) -> tuple[float, int]:
        """Compute exponentially-decayed scan frequency and recent burst count."""
        history = self._scan_history[domain]
        lambda_rate = math.log(2.0) / self.scan_decay_half_life_hours

        weighted = 0.0
        recent_scans = 0
        for scan_time in history:
            age_hours = max((now_utc - scan_time).total_seconds() / 3600.0, 0.0)
            weighted += math.exp(-lambda_rate * age_hours)
            if age_hours <= self.recent_window_hours:
                recent_scans += 1

        return weighted, recent_scans

    def _frequency_risk(self, decayed_frequency: float) -> float:
        """Map decayed frequency to risk with an exponential saturation curve."""
        # Higher scan pressure approaches 1.0 quickly, but stays bounded.
        return 1.0 - math.exp(-max(decayed_frequency, 0.0) / self.frequency_scale)

    def _domain_age_risk(self, domain_age_days: int | None) -> float:
        """Compute domain-age risk where younger domains are riskier."""
        if domain_age_days is None:
            return 0.35
        return math.exp(-max(float(domain_age_days), 0.0) / self.domain_age_decay_days)

    def _combine_risk(
        self,
        frequency_risk: float,
        domain_age_risk: float,
        recent_scans: int,
        has_errors: bool,
    ) -> float:
        """Blend temporal signals into final normalized risk score."""
        burst_risk = 1.0 - math.exp(-max(float(recent_scans), 0.0) / 3.0)
        score = 0.55 * frequency_risk + 0.35 * domain_age_risk + 0.10 * burst_risk
        if has_errors:
            score += 0.05
        return self._clip01(score)

    def _domain_age_days(
        self,
        domain: str,
        reference_time_utc: datetime,
    ) -> tuple[datetime | None, int | None, str | None]:
        """Get domain creation time and age via cached RDAP lookup."""
        if self._is_ip(domain):
            return None, None, "Domain is an IP address; domain-age signal is not applicable."

        created_at, cache_error = self._get_or_fetch_domain_creation(domain, reference_time_utc)
        if cache_error:
            return None, None, cache_error
        if created_at is None:
            return None, None, "Creation date unavailable in RDAP response."

        age_days = max((reference_time_utc - created_at).days, 0)
        return created_at, age_days, None

    def _get_or_fetch_domain_creation(
        self,
        domain: str,
        now_utc: datetime,
    ) -> tuple[datetime | None, str | None]:
        """Read cache first; fallback to RDAP request when stale or missing."""
        cached = self._domain_age_cache.get(domain)
        if cached is not None:
            created_at, fetched_at = cached
            age_hours = (now_utc - fetched_at).total_seconds() / 3600.0
            if age_hours <= self.domain_age_cache_ttl_hours:
                return created_at, None

        rdap_url = f"https://rdap.org/domain/{domain}"
        request = Request(
            url=rdap_url,
            method="GET",
            headers={"User-Agent": self.user_agent, "Accept": "application/json"},
        )

        try:
            with urlopen(request, timeout=8.0) as response:
                payload = json.loads(response.read().decode("utf-8", errors="replace"))
        except Exception as exc:  # noqa: BLE001
            return None, f"Domain-age RDAP lookup failed for {domain}: {exc}"

        created_at = self._extract_creation_date(payload)
        self._domain_age_cache[domain] = (created_at, now_utc)
        return created_at, None

    @staticmethod
    def _extract_creation_date(payload: dict[str, Any]) -> datetime | None:
        events = payload.get("events") or []
        if not isinstance(events, list):
            return None

        preferred_actions = {"registration", "registered", "creation", "created"}
        preferred_dates: list[datetime] = []
        fallback_dates: list[datetime] = []

        for event in events:
            if not isinstance(event, dict):
                continue
            action = str(event.get("eventAction", "")).strip().lower()
            event_date_raw = str(event.get("eventDate", "")).strip()
            if not event_date_raw:
                continue
            parsed = TemporalURLRiskModel._parse_datetime(event_date_raw)
            if parsed is None:
                continue
            fallback_dates.append(parsed)
            if action in preferred_actions:
                preferred_dates.append(parsed)

        if preferred_dates:
            return min(preferred_dates)
        if fallback_dates:
            return min(fallback_dates)
        return None

    @staticmethod
    def _parse_datetime(value: str) -> datetime | None:
        text = value.strip()
        if not text:
            return None
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
    def _normalize_url(url: str) -> str:
        text = (url or "").strip()
        if not text:
            return ""
        parsed = urlsplit(text)
        if not parsed.scheme:
            return f"http://{text}"
        return text

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
        clean_host = (host or "").strip(".").lower()
        if not clean_host:
            return ""
        if cls._is_ip(clean_host):
            return clean_host

        labels = [label for label in clean_host.split(".") if label]
        if len(labels) <= 2:
            return clean_host

        suffix_2 = ".".join(labels[-2:])
        if suffix_2 in SECOND_LEVEL_SUFFIXES and len(labels) >= 3:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])

    @staticmethod
    def _coerce_datetime(value: datetime | str | None) -> datetime:
        if value is None:
            return datetime.now(timezone.utc)
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        parsed = TemporalURLRiskModel._parse_datetime(value)
        if parsed is None:
            return datetime.now(timezone.utc)
        return parsed

    @staticmethod
    def _clip01(score: float) -> float:
        return max(0.0, min(1.0, float(score)))


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Temporal URL risk scoring for QRShield++.")
    parser.add_argument("--url", required=True, help="URL to score.")
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Number of sequential scan events to simulate for the same URL.",
    )
    parser.add_argument(
        "--interval-minutes",
        type=float,
        default=0.0,
        help="Minutes between simulated scans when --repeat > 1.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    model = TemporalURLRiskModel()
    now = datetime.now(timezone.utc)
    results: list[dict[str, Any]] = []

    for idx in range(max(1, args.repeat)):
        ts = now + timedelta(minutes=idx * args.interval_minutes)
        result = model.assess_scan(args.url, scanned_at=ts)
        results.append(result.to_dict())

    payload = {
        "explanation": model.temporal_security_explanation(),
        "results": results,
    }
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()

