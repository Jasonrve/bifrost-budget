from __future__ import annotations

import base64
import binascii
import hashlib
import json
import logging
import os
from typing import Any, Literal

LOGGER_NAME = "bifrost_budget"
DEFAULT_LOG_LEVEL = "INFO"
SAFE_JWT_CLAIM_KEYS = ("iss", "sub", "tid", "tenant", "tenant_id", "org_id")


def configure_logging(level: str | None = None) -> logging.Logger:
    resolved_level_name = (level or os.getenv("BIFROST_LOG_LEVEL", DEFAULT_LOG_LEVEL)).upper()
    resolved_level = getattr(logging, resolved_level_name, logging.INFO)
    logging.basicConfig(level=resolved_level, format="%(message)s")
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(resolved_level)
    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)


def fingerprint_value(value: str | None, *, length: int = 12) -> str | None:
    if value is None:
        return None

    normalized = value.strip()
    if not normalized:
        return None

    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return digest[:length]


def _split_authorization(credential: str) -> tuple[str, str]:
    parts = credential.strip().split(None, 1)
    if len(parts) == 2:
        return parts[0], parts[1].strip()
    return "Bearer", credential.strip()


def _decode_jwt_claims(token: str) -> dict[str, Any] | None:
    parts = token.split(".")
    if len(parts) < 2:
        return None

    payload = parts[1]
    padding = "=" * (-len(payload) % 4)
    try:
        decoded_payload = base64.urlsafe_b64decode(payload + padding)
        claims = json.loads(decoded_payload.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
        return None

    if not isinstance(claims, dict):
        return None

    safe_claims: dict[str, Any] = {}
    for key in SAFE_JWT_CLAIM_KEYS:
        value = claims.get(key)
        if isinstance(value, (str, int, float, bool)) and value not in ("", None):
            safe_claims[key] = value
    return safe_claims or None


def build_credential_trace(
    credential: str | None,
    *,
    auth_source: str,
    credential_mode: Literal["authorization", "virtual_key"],
) -> dict[str, Any]:
    normalized = credential.strip() if isinstance(credential, str) else ""
    trace: dict[str, Any] = {
        "auth_source": auth_source,
        "credential_mode": credential_mode,
        "token_present": bool(normalized),
        "token_fingerprint": fingerprint_value(normalized),
    }

    if credential_mode == "authorization" and normalized:
        scheme, token = _split_authorization(normalized)
        trace["scheme"] = scheme
        trace["token_fingerprint"] = fingerprint_value(token)
        claims = _decode_jwt_claims(token)
        if claims:
            trace["claims"] = claims

    return trace


def log_event(level: int, event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    get_logger().log(level, json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")))
