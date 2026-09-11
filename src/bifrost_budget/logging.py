from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
from importlib.metadata import PackageNotFoundError, version as package_version
from typing import Any, Literal

LOGGER_NAME = "bifrost_budget"
DEFAULT_LOG_LEVEL = "INFO"
SAFE_JWT_CLAIM_KEYS = (
    "iss",
    "sub",
    "tid",
    "tenant",
    "tenant_id",
    "org_id",
    "email",
    "upn",
    "preferred_username",
    "oid",
    "client_id",
    "appid",
    "azp",
    "uid",
    "user_id",
    "name",
)
IDENTITY_CLAIM_PRIORITY = ("name", "preferred_username", "email", "upn", "sub", "uid", "user_id")
_BUILD_ID_PATTERN = re.compile(r"^[0-9a-fA-F]{7,64}$")
_DIAGNOSTIC_KEY = "bifrost-budget-safe-diagnostics-v1"
_SENSITIVE_HEADER_WORDS = ("authorization", "cookie", "credential", "password", "secret", "token", "api-key", "apikey", "proxy-auth")


def configure_logging(level: str | None = None) -> logging.Logger:
    resolved_level_name = (level or os.getenv("BIFROST_LOG_LEVEL", DEFAULT_LOG_LEVEL)).upper()
    resolved_level = getattr(logging, resolved_level_name, logging.INFO)
    logging.basicConfig(level=resolved_level, format="%(message)s")
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(resolved_level)
    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)


def service_version_info() -> dict[str, str]:
    """Return safe package/build identifiers for the one-per-process startup log."""
    try:
        version = package_version("bifrost-budget")
    except PackageNotFoundError:
        version = "unknown"

    build_id = "unknown"
    for variable in ("BIFROST_BUILD_SHA", "GIT_SHA", "SOURCE_COMMIT"):
        candidate = os.getenv(variable, "").strip()
        if _BUILD_ID_PATTERN.fullmatch(candidate):
            build_id = candidate
            break
    return {"version": version, "build_id": build_id}


def fingerprint_value(value: str | None, *, length: int = 12) -> str | None:
    if value is None:
        return None

    normalized = value.strip()
    if not normalized:
        return None

    digest = hmac.new(
        os.getenv("BIFROST_DIAGNOSTIC_FINGERPRINT_KEY", _DIAGNOSTIC_KEY).encode("utf-8"),
        normalized.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:length]


def header_diagnostics(headers: Any) -> list[dict[str, Any]]:
    """Describe inbound headers without retaining or logging their values."""
    if not headers:
        return []
    result = []
    for raw_name, raw_value in headers.items():
        name = str(raw_name).lower()
        value = raw_value if isinstance(raw_value, str) else str(raw_value)
        result.append({
            "name": name,
            "present": bool(value),
            "value_type": type(raw_value).__name__,
            "value_length": len(value),
            "value_fingerprint": fingerprint_value(value),
            "sensitive": any(word in name for word in _SENSITIVE_HEADER_WORDS),
        })
    return sorted(result, key=lambda item: item["name"])


def authorization_diagnostics(authorization: str | None) -> dict[str, Any]:
    """Return exhaustive, value-free metadata for an Authorization header."""
    normalized = authorization.strip() if isinstance(authorization, str) else ""
    scheme, token = _split_authorization(normalized) if normalized else (None, "")
    parts = token.split(".") if token else []
    result: dict[str, Any] = {
        "header_present": bool(normalized), "scheme": scheme,
        "token_length": len(token), "token_fingerprint": fingerprint_value(token),
        "token_segment_count": len(parts), "token_segment_lengths": [len(part) for part in parts],
        "decode_success": False, "decode_failure_reason": None,
        "invalid_json": False, "claim_keys": [], "claim_metadata": [], "duplicate_claim_keys": [],
    }
    if not token:
        result["decode_failure_reason"] = "missing_token"
        return result
    if len(parts) < 2:
        result["decode_failure_reason"] = "insufficient_segments"
        return result
    padding = "=" * (-len(parts[1]) % 4)
    try:
        decoded = base64.urlsafe_b64decode(parts[1] + padding).decode("utf-8")
        pairs: list[tuple[str, Any]] = []
        claims = json.loads(decoded, object_pairs_hook=lambda values: (pairs.extend(values) or dict(values)))
    except (binascii.Error, UnicodeDecodeError):
        result["decode_failure_reason"] = "invalid_base64_or_utf8"
        return result
    except json.JSONDecodeError:
        result["decode_failure_reason"] = "invalid_json"
        result["invalid_json"] = True
        return result
    if not isinstance(claims, dict):
        result["decode_failure_reason"] = "claims_not_object"
        return result
    seen: set[str] = set()
    duplicates: list[str] = []
    for key, value in pairs:
        if key in seen and key not in duplicates:
            duplicates.append(key)
        seen.add(key)
        serialized = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
        result["claim_metadata"].append({
            "key": key, "value_type": type(value).__name__, "value_length": len(serialized),
            "value_fingerprint": fingerprint_value(serialized),
        })
    result.update({"decode_success": True, "claim_keys": sorted(claims), "duplicate_claim_keys": sorted(duplicates)})
    return result


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
        "token_length": len(normalized) if normalized else 0,
    }

    if credential_mode == "authorization" and normalized:
        scheme, token = _split_authorization(normalized)
        trace["scheme"] = scheme
        trace["token_fingerprint"] = fingerprint_value(token)
        trace["token_length"] = len(token)
        trace["authorization_diagnostics"] = authorization_diagnostics(normalized)
        claims = _decode_jwt_claims(token)
        if claims:
            trace["claim_keys"] = sorted(claims)
            trace["claim_fingerprints"] = {
                key: fingerprint_value(str(value)) for key, value in sorted(claims.items())
            }
            trace["claim_lengths"] = {
                key: len(str(value)) for key, value in sorted(claims.items())
            }
            selection = select_identity_claim(claims)
            trace.update(
                {
                    "selected_identity_claim": selection["claim"],
                    "identity_extraction_source": "raw_authorization_jwt",
                    "identity_selection_reason": selection["reason"],
                }
            )
            if selection["identity"]:
                trace["identity_fingerprint"] = fingerprint_value(selection["identity"])

    return trace


def extract_identity_name(claims: dict[str, Any] | None) -> str | None:
    return select_identity_claim(claims)["identity"]


def select_identity_claim(claims: dict[str, Any] | None) -> dict[str, str | None]:
    """Select a caller identity without ever returning it in diagnostics.

    The source is intentionally explicit: only claims decoded from the raw inbound
    Authorization JWT may be used. Middleware metadata is not an identity fallback.
    """
    if not claims:
        return {"identity": None, "claim": None, "reason": "no_decodable_authorization_claims"}
    for key in IDENTITY_CLAIM_PRIORITY:
        value = claims.get(key)
        if isinstance(value, str) and value.strip():
            return {"identity": value.strip(), "claim": key, "reason": f"selected_{key}_claim"}
    return {"identity": None, "claim": None, "reason": "no_supported_identity_claim"}


def extract_identity_from_authorization(authorization: str | None) -> str | None:
    if not authorization:
        return None
    _, token = _split_authorization(authorization)
    return extract_identity_name(_decode_jwt_claims(token))


def log_event(level: int, event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    get_logger().log(level, json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")))
