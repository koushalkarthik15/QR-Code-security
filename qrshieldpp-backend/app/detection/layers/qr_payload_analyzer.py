"""Structural QR payload analysis for URL and non-URL QR content.

Scope:
- Payload type detection (http/https, upi, tel, sms, other)
- UPI parameter parsing and structural/social-engineering heuristics
- Advisory-only risk scoring (does not block payment execution)
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Literal
from urllib.parse import parse_qs, urlsplit


PayloadType = Literal["http_https", "upi", "tel", "sms", "other"]

HOST_LIKE_PATTERN = re.compile(r"(?i)^(?:[a-z0-9-]+\.)+[a-z]{2,}(?:[/?#:].*)?$")
HTTP_PATTERN = re.compile(r"(?i)^https?://")

UPI_PAYEE_PATTERN = re.compile(r"(?i)^[a-z0-9][a-z0-9._-]{1,255}@[a-z][a-z0-9.-]{1,63}$")
MERCHANT_ID_PATTERN = re.compile(r"(?i)^[a-z0-9._:@-]{4,64}$")
MERCHANT_HINT_PATTERN = re.compile(
    r"(?i)\b(shop|store|mart|traders?|enterprise|services?|hotel|restaurant|ltd|llp|pvt|private)\b"
)
SOCIAL_ENGINEERING_HINT_PATTERN = re.compile(
    r"(?i)\b(urgent|verify|secure|refund|offer|winner|support|helpline|customer\s*care|claim)\b"
)
LOOKALIKE_PATTERN = re.compile(r"(?i)(rn|vv|[01]{2,}|[o0][o0]|[l1i]{2,})")

KNOWN_BRAND_TOKENS = {
    "amazon",
    "axis",
    "bhim",
    "flipkart",
    "gpay",
    "googlepay",
    "hdfc",
    "icici",
    "paytm",
    "phonepe",
    "sbi",
}

CONFUSABLE_CHAR_MAP = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "7": "t",
        "@": "a",
        "$": "s",
    }
)


def _first_query_value(params: dict[str, list[str]], key: str) -> str:
    values = params.get(key, [])
    if not values:
        return ""
    return values[0].strip()


@dataclass
class PayloadSignal:
    """One structural/social-engineering risk signal."""

    code: str
    weight: float
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class QRPayloadAnalysisResult:
    """Payload-level analysis result."""

    payload_type: PayloadType
    normalized_payload: str
    risk_score: float
    warnings: list[str]
    signals: list[PayloadSignal] = field(default_factory=list)
    upi_parameters: dict[str, Any] | None = None
    note: str = (
        "Structural and social-engineering analysis only. "
        "This result is advisory and does not execute or block payments."
    )
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["signals"] = [item.to_dict() for item in self.signals]
        return payload


class QRPayloadAnalyzer:
    """Analyze QR payloads without requiring an HTTP/HTTPS URL."""

    def analyze(self, qr_content: str, qr_type_hint: str = "auto") -> QRPayloadAnalysisResult:
        raw = (qr_content or "").strip()
        if not raw:
            return QRPayloadAnalysisResult(
                payload_type="other",
                normalized_payload="",
                risk_score=0.75,
                warnings=["QR payload is empty."],
                signals=[PayloadSignal(code="empty_payload", weight=1.4, detail="QR payload is empty")],
                errors=["qr_content cannot be empty."],
            )

        payload_type = self.detect_payload_type(raw, qr_type_hint=qr_type_hint)

        if payload_type == "http_https":
            normalized = self._normalize_http_payload(raw)
            return QRPayloadAnalysisResult(
                payload_type=payload_type,
                normalized_payload=normalized,
                risk_score=0.0,
                warnings=[],
            )
        if payload_type == "upi":
            return self._analyze_upi_payload(raw)
        if payload_type == "tel":
            return self._analyze_tel_payload(raw)
        if payload_type == "sms":
            return self._analyze_sms_payload(raw)
        return self._analyze_other_payload(raw)

    @staticmethod
    def detect_payload_type(payload: str, qr_type_hint: str = "auto") -> PayloadType:
        text = (payload or "").strip()
        lower = text.lower()

        parsed = urlsplit(text)
        scheme = parsed.scheme.lower()
        if scheme in {"http", "https"}:
            return "http_https"
        if scheme == "upi":
            return "upi"
        if scheme == "tel":
            return "tel"
        if scheme == "sms":
            return "sms"

        if lower.startswith(("http://", "https://")):
            return "http_https"
        if lower.startswith("upi://"):
            return "upi"
        if lower.startswith("tel:"):
            return "tel"
        if lower.startswith("sms:"):
            return "sms"

        if HOST_LIKE_PATTERN.match(text):
            return "http_https"

        hint = (qr_type_hint or "").strip().lower()
        if hint == "url" and " " not in text:
            if "." in text and ":" not in text.split("/")[0]:
                return "http_https"
        return "other"

    @staticmethod
    def _normalize_http_payload(payload: str) -> str:
        text = (payload or "").strip()
        if HTTP_PATTERN.match(text):
            return text
        return f"http://{text}"

    def _analyze_upi_payload(self, payload: str) -> QRPayloadAnalysisResult:
        parsed = urlsplit(payload)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        pa = _first_query_value(query_params, "pa")
        pn = _first_query_value(query_params, "pn")
        am_raw = _first_query_value(query_params, "am")
        cu = _first_query_value(query_params, "cu")
        mc = _first_query_value(query_params, "mc")
        mid = _first_query_value(query_params, "mid")
        tid = _first_query_value(query_params, "tid")
        tr = _first_query_value(query_params, "tr")

        signals: list[PayloadSignal] = []
        errors: list[str] = []

        def add_signal(code: str, weight: float, detail: str) -> None:
            signals.append(PayloadSignal(code=code, weight=round(max(weight, 0.0), 4), detail=detail))

        netloc_or_path = (parsed.netloc or parsed.path or "").lower().strip("/")
        if netloc_or_path and netloc_or_path != "pay":
            add_signal(
                "unexpected_upi_action",
                0.18,
                f"Unexpected UPI action target '{netloc_or_path}'.",
            )

        payee_valid = False
        payee_lookalike = False
        merchant_id_missing = False
        merchant_id_suspicious = False
        amount_prefilled = False
        amount_value: Decimal | None = None

        pa_lower = pa.lower()
        if not pa:
            add_signal("missing_payee_address", 0.75, "UPI payee address (pa) is missing.")
        elif not UPI_PAYEE_PATTERN.fullmatch(pa):
            add_signal("invalid_payee_address", 0.7, "UPI payee address format is invalid.")
        else:
            payee_valid = True
            local_part, handle_part = pa_lower.split("@", 1)
            if len(local_part) < 2 or len(handle_part) < 2:
                add_signal("weak_payee_address", 0.2, "UPI payee address appears incomplete.")
            digit_ratio = (sum(ch.isdigit() for ch in local_part) / max(len(local_part), 1)) if local_part else 0.0
            if digit_ratio >= 0.45:
                add_signal(
                    "digit_heavy_payee_id",
                    0.22,
                    "UPI payee ID uses many digits, which can mimic look-alike IDs.",
                )
            if LOOKALIKE_PATTERN.search(local_part):
                payee_lookalike = True
                add_signal(
                    "lookalike_payee_id",
                    0.28,
                    "UPI payee ID contains look-alike character patterns.",
                )
            normalized_local = local_part.translate(CONFUSABLE_CHAR_MAP)
            if normalized_local != local_part:
                for token in KNOWN_BRAND_TOKENS:
                    if token in normalized_local and token not in local_part:
                        payee_lookalike = True
                        add_signal(
                            "confusable_brand_pattern",
                            0.24,
                            f"UPI ID resembles brand token '{token}' using confusable characters.",
                        )
                        break

        if not pn:
            add_signal("missing_payee_name", 0.08, "Payee name (pn) is missing.")

        pn_lower = pn.lower()
        if SOCIAL_ENGINEERING_HINT_PATTERN.search(f"{pn_lower} {pa_lower}".strip()):
            add_signal(
                "social_engineering_terms",
                0.2,
                "Payee details contain urgency/support words commonly used in social-engineering scams.",
            )

        brand_in_name = [token for token in KNOWN_BRAND_TOKENS if token in pn_lower]
        if brand_in_name and pa_lower:
            local_and_handle = pa_lower.replace(".", "").replace("_", "")
            for token in brand_in_name:
                if token not in local_and_handle:
                    add_signal(
                        "brand_impersonation_mismatch",
                        0.3,
                        f"Payee name references '{token}' but UPI ID does not align with that brand.",
                    )
                    break

        if am_raw:
            amount_prefilled = True
            add_signal(
                "prefilled_amount",
                0.25,
                f"QR includes a pre-filled amount ({am_raw}). Verify before payment.",
            )
            try:
                amount_value = Decimal(am_raw)
            except InvalidOperation:
                add_signal("invalid_amount", 0.45, "UPI amount is not a valid number.")
            else:
                if amount_value <= 0:
                    add_signal("non_positive_amount", 0.55, "UPI amount must be greater than zero.")
                elif amount_value >= Decimal("2000"):
                    add_signal("large_amount", 0.18, "UPI amount is higher than typical small payments.")
                if amount_value >= Decimal("10000"):
                    add_signal("very_large_amount", 0.25, "UPI amount is very high for a QR payment request.")

        cu_upper = cu.upper()
        if not cu:
            add_signal("missing_currency", 0.08, "Currency (cu) is missing.")
        elif cu_upper != "INR":
            add_signal("unexpected_currency", 0.4, f"UPI currency '{cu}' is unexpected for standard UPI flows.")

        merchant_fields = {
            "mc": mc,
            "mid": mid,
            "tid": tid,
            "tr": tr,
        }
        has_any_merchant_id = any(bool(value) for value in merchant_fields.values())

        if mc:
            if not re.fullmatch(r"\d{4}", mc):
                merchant_id_suspicious = True
                add_signal("invalid_merchant_code", 0.34, "Merchant category code (mc) must be a 4-digit value.")
            elif mc == "0000":
                merchant_id_suspicious = True
                add_signal("placeholder_merchant_code", 0.22, "Merchant category code appears to be placeholder data.")

        for key in ("mid", "tid", "tr"):
            value = merchant_fields[key]
            if value and not MERCHANT_ID_PATTERN.fullmatch(value):
                merchant_id_suspicious = True
                add_signal(
                    f"invalid_{key}",
                    0.24,
                    f"Merchant identifier '{key}' has an unusual format.",
                )

        merchant_looking = bool(MERCHANT_HINT_PATTERN.search(pn_lower)) or bool(
            MERCHANT_HINT_PATTERN.search(pa_lower)
        )
        if merchant_looking and not has_any_merchant_id:
            merchant_id_missing = True
            add_signal(
                "missing_merchant_identifiers",
                0.3,
                "Merchant-style payee is missing merchant identifiers (mc/mid/tid/tr).",
            )

        if not query_params:
            errors.append("UPI payload has no query parameters.")
            add_signal("missing_upi_parameters", 0.8, "UPI payload does not include required query parameters.")

        risk_score = self._risk_from_signals(signals)
        warnings = [item.detail for item in sorted(signals, key=lambda sig: sig.weight, reverse=True)[:5]]

        upi_details = {
            "pa": pa,
            "pn": pn,
            "am": am_raw,
            "cu": cu,
            "merchant_identifiers": merchant_fields,
            "validation": {
                "payee_address_valid": payee_valid,
                "prefilled_amount_present": amount_prefilled,
                "amount_value": str(amount_value) if amount_value is not None else None,
                "currency_is_inr": (cu_upper == "INR") if cu else None,
                "merchant_identifiers_missing": merchant_id_missing,
                "merchant_identifiers_suspicious": merchant_id_suspicious,
                "lookalike_or_impersonation_flag": payee_lookalike or bool(brand_in_name),
            },
            "raw_parameters": {key: values[:] for key, values in query_params.items()},
        }

        return QRPayloadAnalysisResult(
            payload_type="upi",
            normalized_payload=payload.strip(),
            risk_score=risk_score,
            warnings=warnings,
            signals=signals,
            upi_parameters=upi_details,
            errors=errors,
        )

    def _analyze_tel_payload(self, payload: str) -> QRPayloadAnalysisResult:
        number = payload[4:].strip() if payload.lower().startswith("tel:") else payload
        digits = "".join(ch for ch in number if ch.isdigit())
        signals: list[PayloadSignal] = []

        if not number:
            signals.append(
                PayloadSignal(
                    code="missing_phone_number",
                    weight=0.65,
                    detail="Telephone payload is missing a phone number.",
                )
            )
        else:
            if len(digits) < 8:
                signals.append(
                    PayloadSignal(
                        code="short_phone_number",
                        weight=0.25,
                        detail="Telephone number appears too short.",
                    )
                )
            if re.search(r"(?i)https?://|upi://", number):
                signals.append(
                    PayloadSignal(
                        code="embedded_link_in_tel",
                        weight=0.45,
                        detail="Telephone payload includes an embedded URL/UPI link.",
                    )
                )

        risk_score = self._risk_from_signals(signals)
        warnings = [item.detail for item in sorted(signals, key=lambda sig: sig.weight, reverse=True)[:4]]
        return QRPayloadAnalysisResult(
            payload_type="tel",
            normalized_payload=payload.strip(),
            risk_score=risk_score,
            warnings=warnings,
            signals=signals,
        )

    def _analyze_sms_payload(self, payload: str) -> QRPayloadAnalysisResult:
        parsed = urlsplit(payload)
        recipient = (parsed.path or parsed.netloc or "").strip()
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        body = _first_query_value(query_params, "body")
        content = f"{recipient} {body}".strip()

        signals: list[PayloadSignal] = []
        if not recipient:
            signals.append(
                PayloadSignal(
                    code="missing_sms_recipient",
                    weight=0.22,
                    detail="SMS payload has no recipient.",
                )
            )
        if body and HTTP_PATTERN.search(body):
            signals.append(
                PayloadSignal(
                    code="sms_contains_link",
                    weight=0.28,
                    detail="SMS body contains an HTTP/HTTPS link.",
                )
            )
        if body and SOCIAL_ENGINEERING_HINT_PATTERN.search(body):
            signals.append(
                PayloadSignal(
                    code="sms_social_engineering_terms",
                    weight=0.3,
                    detail="SMS body contains urgency/support phrasing often used in scams.",
                )
            )
        if len(content) > 300:
            signals.append(
                PayloadSignal(
                    code="sms_unusually_long",
                    weight=0.12,
                    detail="SMS payload is unusually long.",
                )
            )

        risk_score = self._risk_from_signals(signals)
        warnings = [item.detail for item in sorted(signals, key=lambda sig: sig.weight, reverse=True)[:4]]
        return QRPayloadAnalysisResult(
            payload_type="sms",
            normalized_payload=payload.strip(),
            risk_score=risk_score,
            warnings=warnings,
            signals=signals,
        )

    def _analyze_other_payload(self, payload: str) -> QRPayloadAnalysisResult:
        text = payload.strip()
        signals: list[PayloadSignal] = []

        if HTTP_PATTERN.search(text):
            signals.append(
                PayloadSignal(
                    code="embedded_http_link",
                    weight=0.26,
                    detail="Non-standard payload contains an embedded HTTP/HTTPS link.",
                )
            )
        if "upi://" in text.lower():
            signals.append(
                PayloadSignal(
                    code="embedded_upi_link",
                    weight=0.24,
                    detail="Non-standard payload contains an embedded UPI deep link.",
                )
            )
        if SOCIAL_ENGINEERING_HINT_PATTERN.search(text):
            signals.append(
                PayloadSignal(
                    code="social_engineering_terms",
                    weight=0.24,
                    detail="Payload text includes urgency/support wording often seen in scams.",
                )
            )
        if len(text) > 600:
            signals.append(
                PayloadSignal(
                    code="very_long_payload",
                    weight=0.12,
                    detail="Payload is unusually long and hard to verify manually.",
                )
            )

        risk_score = self._risk_from_signals(signals)
        warnings = [item.detail for item in sorted(signals, key=lambda sig: sig.weight, reverse=True)[:4]]
        return QRPayloadAnalysisResult(
            payload_type="other",
            normalized_payload=text,
            risk_score=risk_score,
            warnings=warnings,
            signals=signals,
        )

    @staticmethod
    def _risk_from_signals(signals: list[PayloadSignal]) -> float:
        if not signals:
            return 0.0
        total = sum(max(0.0, signal.weight) for signal in signals)
        score = 1.0 - math.exp(-total)
        return round(max(0.0, min(score, 1.0)), 4)
