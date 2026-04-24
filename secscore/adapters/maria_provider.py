from __future__ import annotations

from typing import Any, Dict

import requests


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
        maria_url,
        json=submission_payload,
        headers=headers,
        timeout=timeout,
    )
    response.raise_for_status()
