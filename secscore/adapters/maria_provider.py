from __future__ import annotations

import ipaddress
import os
import socket
from copy import deepcopy
from typing import Any, Dict
from urllib.parse import urlsplit

import requests

_PRIVATE_URL_OPT_IN = "SECSCORE_ALLOW_PRIVATE_MARIA_URLS"


def fetch_policy(
    maria_url: str,
    token: str,
    repository_id: str,
    timeout: int = 15,
    policy_url: str | None = None,
) -> Dict[str, Any]:
    if not maria_url:
        raise ValueError("maria_url is required")
    if not token:
        raise ValueError("token is required")
    if not repository_id:
        raise ValueError("repository_id is required")

    resolved_policy_url = _validate_maria_url(policy_url or _derive_policy_url(maria_url))
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": "SecScore/1.0 (+maria-integration)",
    }

    response = requests.get(
        resolved_policy_url,
        params={"repositoryId": repository_id},
        headers=headers,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def build_secscore_policy_from_maria(
    maria_policy: Dict[str, Any],
    base_policy: Dict[str, Any],
) -> Dict[str, Any]:
    policy = deepcopy(base_policy or {})

    thresholds = maria_policy.get("thresholds") or {}
    maria_scoring = maria_policy.get("scoring") or {}
    penalties = maria_scoring.get("penalties") or {}
    risk_weights = maria_scoring.get("risk_weights") or {}
    application_context = maria_scoring.get("application_context")
    risk_profile = maria_scoring.get("risk_profile") or {}
    scoring_model = str(maria_scoring.get("model") or "").strip().lower()

    policy["policy_version"] = str(policy.get("policy_version") or "1.1")
    policy["mode"] = "pull_request"

    decision = policy.get("decision") if isinstance(policy.get("decision"), dict) else {}
    decision["pass_min_score"] = int(thresholds.get("pass_min", decision.get("pass_min_score", 85)))
    decision["review_min_score"] = int(thresholds.get("review_min", decision.get("review_min_score", 51)))
    decision["fail_below_score"] = int(thresholds.get("fail_min", decision.get("fail_below_score", 0)))
    if scoring_model == "maria_riskscore_v1":
        decision["model"] = "risk_score"
        decision["pass_max_score"] = int(thresholds.get("pass_max_risk_score", decision.get("pass_max_score", 49)))
        decision["review_max_score"] = int(thresholds.get("review_max_risk_score", decision.get("review_max_score", 79)))
        decision["fail_min_risk_score"] = int(thresholds.get("fail_min_risk_score", decision.get("fail_min_risk_score", 80)))
    policy["decision"] = decision

    scoring = policy.get("scoring") if isinstance(policy.get("scoring"), dict) else {}
    scoring["base_score"] = int(maria_scoring.get("base_score", scoring.get("base_score", 100)))
    if scoring_model == "maria_riskscore_v1":
        scoring["model"] = scoring_model
        scoring["risk_weights"] = {
            "critical": int(risk_weights.get("critical", 10)),
            "high": int(risk_weights.get("high", 5)),
            "medium": int(risk_weights.get("medium", 2)),
            "low": int(risk_weights.get("low", 1)),
            "internet_exposure": int(risk_weights.get("internet_exposure", 12)),
            "third_party_interaction": int(risk_weights.get("third_party_interaction", 8)),
            "api_exposure": int(risk_weights.get("api_exposure", 6)),
            "pii_data": int(risk_weights.get("pii_data", 10)),
            "no_encryption": int(risk_weights.get("no_encryption", 8)),
            "encryption_bonus": int(risk_weights.get("encryption_bonus", -4)),
            "no_authentication": int(risk_weights.get("no_authentication", 8)),
            "authentication_bonus": int(risk_weights.get("authentication_bonus", -3)),
            "recent_commit": int(risk_weights.get("recent_commit", 2)),
            "no_recent_commit": int(risk_weights.get("no_recent_commit", 5)),
        }
        scoring["application_context"] = application_context if isinstance(application_context, dict) else None
        scoring["risk_profile"] = {
            "enabled": bool(risk_profile.get("enabled", False)),
            "business_multiplier": float(risk_profile.get("business_multiplier", 1.0)),
            "data_multiplier": float(risk_profile.get("data_multiplier", 1.0)),
            "combined_multiplier": float(risk_profile.get("combined_multiplier", 1.0)),
            "max_combined_multiplier": float(risk_profile.get("max_combined_multiplier", 1.8)),
        }

    scoring_penalties = scoring.get("penalties") if isinstance(scoring.get("penalties"), dict) else {}
    scoring_penalties["critical"] = int(penalties.get("critical", scoring_penalties.get("critical", 40)))
    scoring_penalties["high"] = int(penalties.get("high", scoring_penalties.get("high", 20)))
    scoring_penalties["medium"] = int(penalties.get("medium", scoring_penalties.get("medium", 7)))
    scoring_penalties["low"] = int(penalties.get("low", scoring_penalties.get("low", 2)))
    scoring_penalties["info"] = int(scoring_penalties.get("info", 0))
    scoring["penalties"] = scoring_penalties
    policy["scoring"] = scoring

    if bool(thresholds.get("hard_fail_on_critical", False)):
        hard_fails = policy.get("hard_fails")
        if not isinstance(hard_fails, list):
            hard_fails = []

        has_rule = any(
            isinstance(rule, dict) and rule.get("id") == "MARIA_CRITICAL_NEW"
            for rule in hard_fails
        )
        if not has_rule:
            hard_fails.append(
                {
                    "id": "MARIA_CRITICAL_NEW",
                    "when": {"severity_in": ["critical"], "is_new": True},
                    "reason": "M.A.R.I.A policy: new critical finding",
                }
            )
        policy["hard_fails"] = hard_fails

    return policy


def _derive_policy_url(maria_url: str) -> str:
    cleaned = maria_url.strip().rstrip("/")
    if cleaned.endswith("/submissions"):
        return f"{cleaned[:-len('/submissions')]}/policy"
    if cleaned.endswith("/policy"):
        return cleaned
    return f"{cleaned}/policy"


def _validate_maria_url(url: str) -> str:
    parsed = urlsplit(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("M.A.R.I.A URL must use http or https")
    if not parsed.hostname:
        raise ValueError("M.A.R.I.A URL must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("M.A.R.I.A URL must not include embedded credentials")

    if _allow_private_maria_urls():
        return url.strip()

    hostname = parsed.hostname.strip().lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError(
            "M.A.R.I.A URL points to a local host. Set "
            f"{_PRIVATE_URL_OPT_IN}=true only for trusted local development."
        )

    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            addresses = [
                ipaddress.ip_address(info[4][0])
                for info in socket.getaddrinfo(hostname, parsed.port, proto=socket.IPPROTO_TCP)
            ]
        except socket.gaierror as exc:
            raise ValueError(f"Could not resolve M.A.R.I.A URL host: {hostname}") from exc

    for address in addresses:
        if _is_private_network_address(address):
            raise ValueError(
                "M.A.R.I.A URL resolves to a local, private, loopback, or reserved address. "
                f"Set {_PRIVATE_URL_OPT_IN}=true only for trusted local development."
            )

    return url.strip()


def _allow_private_maria_urls() -> bool:
    return os.getenv(_PRIVATE_URL_OPT_IN, "").strip().lower() in {"1", "true", "yes", "on"}


def _is_private_network_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def send_submission(
    maria_url: str,
    token: str,
    submission_payload: Dict[str, Any],
    timeout: int = 15,
) -> None:
    if not maria_url:
        raise ValueError("maria_url is required")
    if not token:
        raise ValueError("token is required")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "SecScore/1.0 (+maria-integration)",
    }

    response = requests.post(
        _validate_maria_url(maria_url),
        json=submission_payload,
        headers=headers,
        timeout=timeout,
    )
    response.raise_for_status()
