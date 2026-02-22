"""URL feature engineering for the static QRShield++ URL ML layer.

This module exposes:
- ``URLFeatureExtractor``: pure-python lexical/statistical feature extraction
- ``URLFeatureTransformer``: scikit-learn compatible transformer that converts
  raw URL strings into numeric feature vectors
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from typing import Any, Iterable, Sequence
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin


class URLFeatureExtractor:
    """Extract lexical + statistical numeric features from URLs."""

    SUSPICIOUS_KEYWORDS: set[str] = {
        "account",
        "bank",
        "billing",
        "confirm",
        "gift",
        "invoice",
        "login",
        "otp",
        "password",
        "pay",
        "payment",
        "recover",
        "reset",
        "secure",
        "signin",
        "unlock",
        "update",
        "urgent",
        "verify",
        "wallet",
    }

    SHORTENER_DOMAINS: set[str] = {
        "bit.ly",
        "cutt.ly",
        "is.gd",
        "ow.ly",
        "rebrand.ly",
        "rb.gy",
        "shorturl.at",
        "t.co",
        "tiny.cc",
        "tinyurl.com",
    }

    LEXICAL_FEATURES: list[str] = [
        "url_length",
        "host_length",
        "path_length",
        "query_length",
        "digit_count",
        "digit_ratio",
        "alpha_count",
        "alpha_ratio",
        "special_count",
        "special_ratio",
        "dot_count",
        "hyphen_count",
        "underscore_count",
        "slash_count",
        "subdomain_count",
        "path_depth",
        "query_param_count",
        "has_at_symbol",
        "has_ip_host",
        "has_port",
        "is_https",
        "is_http",
        "has_punycode",
        "has_percent_encoding",
        "has_double_slash_path",
        "contains_shortener",
        "suspicious_keyword_count",
        "tld_length",
        "host_token_count",
    ]

    STATISTICAL_FEATURES: list[str] = [
        "entropy_url",
        "entropy_host",
        "entropy_path",
        "entropy_query",
        "unique_char_ratio",
        "host_digit_ratio",
        "host_alpha_ratio",
        "max_digit_run",
        "max_alpha_run",
        "max_special_run",
        "max_repeated_char_run",
    ]

    @classmethod
    def feature_names(cls) -> list[str]:
        """Return all feature names in deterministic order."""
        return cls.LEXICAL_FEATURES + cls.STATISTICAL_FEATURES

    @staticmethod
    def canonicalize_url(url: Any) -> str:
        """Normalize URL format so extraction is stable across variants."""
        if url is None:
            return ""

        candidate = str(url).strip()
        if not candidate:
            return ""

        # Add a default scheme for bare domains.
        if not re.match(r"^[A-Za-z][A-Za-z0-9+\-.]*://", candidate):
            candidate = f"http://{candidate}"

        parsed = urlsplit(candidate)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower().strip(".")
        path = parsed.path or ""
        query = parsed.query or ""

        netloc = host

        if parsed.username:
            userinfo = parsed.username
            if parsed.password:
                userinfo = f"{userinfo}:{parsed.password}"
            netloc = f"{userinfo}@{netloc}"

        try:
            port = parsed.port
        except ValueError:
            port = None

        is_default_port = (scheme == "http" and port == 80) or (
            scheme == "https" and port == 443
        )
        if port and not is_default_port:
            netloc = f"{netloc}:{port}"

        # Fragment is removed intentionally for model stability.
        return urlunsplit((scheme, netloc, path, query, ""))

    @classmethod
    def extract_features(cls, url: Any) -> dict[str, float]:
        """Extract one feature dictionary from a URL-like input."""
        canonical = cls.canonicalize_url(url)
        parsed = urlsplit(canonical)
        lower_url = canonical.lower()

        host = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""

        full_len = len(canonical)
        host_len = len(host)
        path_len = len(path)
        query_len = len(query)

        alpha_count = sum(ch.isalpha() for ch in canonical)
        digit_count = sum(ch.isdigit() for ch in canonical)
        special_count = max(full_len - alpha_count - digit_count, 0)

        host_tokens = [token for token in host.split(".") if token]
        host_token_count = len(host_tokens)
        subdomain_count = max(host_token_count - 2, 0)
        tld_length = len(host_tokens[-1]) if host_tokens else 0

        path_depth = len([segment for segment in path.split("/") if segment])
        query_param_count = len(parse_qsl(query, keep_blank_values=True))

        try:
            parsed_port = parsed.port
        except ValueError:
            parsed_port = None

        has_ip_host = cls._is_ip_address(host)
        contains_shortener = int(host in cls.SHORTENER_DOMAINS)
        suspicious_keyword_count = sum(
            keyword in lower_url for keyword in cls.SUSPICIOUS_KEYWORDS
        )

        features: dict[str, float] = {
            # Lexical features
            "url_length": float(full_len),
            "host_length": float(host_len),
            "path_length": float(path_len),
            "query_length": float(query_len),
            "digit_count": float(digit_count),
            "digit_ratio": cls._safe_ratio(digit_count, full_len),
            "alpha_count": float(alpha_count),
            "alpha_ratio": cls._safe_ratio(alpha_count, full_len),
            "special_count": float(special_count),
            "special_ratio": cls._safe_ratio(special_count, full_len),
            "dot_count": float(canonical.count(".")),
            "hyphen_count": float(canonical.count("-")),
            "underscore_count": float(canonical.count("_")),
            "slash_count": float(canonical.count("/")),
            "subdomain_count": float(subdomain_count),
            "path_depth": float(path_depth),
            "query_param_count": float(query_param_count),
            "has_at_symbol": float("@" in canonical),
            "has_ip_host": float(has_ip_host),
            "has_port": float(parsed_port is not None),
            "is_https": float(parsed.scheme.lower() == "https"),
            "is_http": float(parsed.scheme.lower() == "http"),
            "has_punycode": float("xn--" in host),
            "has_percent_encoding": float("%" in canonical),
            "has_double_slash_path": float("//" in path),
            "contains_shortener": float(contains_shortener),
            "suspicious_keyword_count": float(suspicious_keyword_count),
            "tld_length": float(tld_length),
            "host_token_count": float(host_token_count),
            # Statistical features
            "entropy_url": cls._shannon_entropy(canonical),
            "entropy_host": cls._shannon_entropy(host),
            "entropy_path": cls._shannon_entropy(path),
            "entropy_query": cls._shannon_entropy(query),
            "unique_char_ratio": cls._safe_ratio(len(set(canonical)), full_len),
            "host_digit_ratio": cls._safe_ratio(sum(ch.isdigit() for ch in host), host_len),
            "host_alpha_ratio": cls._safe_ratio(sum(ch.isalpha() for ch in host), host_len),
            "max_digit_run": float(cls._max_regex_run(r"\d+", canonical)),
            "max_alpha_run": float(cls._max_regex_run(r"[A-Za-z]+", canonical)),
            "max_special_run": float(
                cls._max_regex_run(r"[^A-Za-z0-9]+", canonical)
            ),
            "max_repeated_char_run": float(cls._max_repeated_char_run(canonical)),
        }

        # Keep feature order stable and explicit.
        return {name: features[name] for name in cls.feature_names()}

    @staticmethod
    def _safe_ratio(numerator: int | float, denominator: int | float) -> float:
        if denominator == 0:
            return 0.0
        return float(numerator) / float(denominator)

    @staticmethod
    def _is_ip_address(host: str) -> bool:
        if not host:
            return False
        candidate = host.strip("[]")
        try:
            ipaddress.ip_address(candidate)
            return True
        except ValueError:
            return False

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        counts = Counter(text)
        text_len = len(text)
        entropy = 0.0
        for count in counts.values():
            prob = count / text_len
            entropy -= prob * math.log2(prob)
        return float(entropy)

    @staticmethod
    def _max_regex_run(pattern: str, text: str) -> int:
        matches = re.findall(pattern, text)
        if not matches:
            return 0
        return max(len(match) for match in matches)

    @staticmethod
    def _max_repeated_char_run(text: str) -> int:
        if not text:
            return 0
        max_run = 1
        run = 1
        for idx in range(1, len(text)):
            if text[idx] == text[idx - 1]:
                run += 1
            else:
                max_run = max(max_run, run)
                run = 1
        max_run = max(max_run, run)
        return max_run


class URLFeatureTransformer(BaseEstimator, TransformerMixin):
    """scikit-learn transformer that maps raw URLs to numeric features."""

    def __init__(self) -> None:
        self._feature_names = URLFeatureExtractor.feature_names()

    def fit(self, X: Sequence[str] | np.ndarray, y: np.ndarray | None = None) -> "URLFeatureTransformer":
        # Stateless transformer; method is implemented for sklearn compatibility.
        return self

    def transform(self, X: Sequence[str] | np.ndarray) -> np.ndarray:
        urls = self._coerce_to_strings(X)
        matrix = np.zeros((len(urls), len(self._feature_names)), dtype=np.float64)

        for row_idx, url in enumerate(urls):
            feat_dict = URLFeatureExtractor.extract_features(url)
            matrix[row_idx, :] = [feat_dict[name] for name in self._feature_names]

        return matrix

    def get_feature_names_out(self, input_features: Iterable[str] | None = None) -> np.ndarray:
        return np.array(self._feature_names, dtype=object)

    @staticmethod
    def _coerce_to_strings(values: Sequence[str] | np.ndarray) -> list[str]:
        if isinstance(values, np.ndarray):
            if values.ndim == 0:
                return [str(values.item())]
            if values.ndim == 2 and values.shape[1] == 1:
                values = values.ravel()
            if values.ndim > 2:
                raise ValueError("URLFeatureTransformer received array with ndim > 2")
            return ["" if val is None else str(val) for val in values.tolist()]

        # Covers Python lists/tuples and pandas Series without importing pandas.
        if isinstance(values, (str, bytes)):
            return [str(values)]

        return ["" if val is None else str(val) for val in values]

