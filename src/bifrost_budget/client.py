from __future__ import annotations

from datetime import datetime, timezone
import logging
import time
from typing import Any, Literal

import httpx
from mcp.server.mcpserver.exceptions import ToolError

from .logging import build_credential_trace, fingerprint_value, log_event, safe_text_preview
from .normalization import normalize_quota_payload
from .settings import BifrostSettings


class BifrostClient:
    def __init__(self, settings: BifrostSettings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._client = client or httpx.AsyncClient(timeout=settings.timeout_seconds)
        self._owns_client = client is None

    async def __aenter__(self) -> "BifrostClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def fetch_quota(
        self,
        *,
        credential: str,
        credential_mode: Literal["authorization", "virtual_key"],
        auth_source: str,
    ) -> dict[str, Any]:
        started_at = time.perf_counter()
        headers = {"accept": "application/json"}
        if credential_mode == "authorization":
            headers["authorization"] = credential
        else:
            headers["x-bf-vk"] = credential

        credential_identity = build_credential_trace(
            credential,
            auth_source=auth_source,
            credential_mode=credential_mode,
        )
        auth_headers = sorted(name for name in headers if name in {"authorization", "x-bf-vk"})
        log_event(
            logging.INFO,
            "upstream_quota_request",
            quota_url=self.settings.quota_url,
            auth_source=auth_source,
            outbound_auth_mode=credential_mode,
            auth_headers=auth_headers,
            credential_identity=credential_identity,
        )
        response = await self._client.get(self.settings.quota_url, headers=headers)
        duration_ms = round((time.perf_counter() - started_at) * 1000, 2)
        if response.status_code >= 400:
            log_event(
                logging.ERROR,
                "upstream_quota_error",
                quota_url=self.settings.quota_url,
                auth_source=auth_source,
                outbound_auth_mode=credential_mode,
                auth_headers=auth_headers,
                credential_identity=credential_identity,
                status_code=response.status_code,
                response_header_names=sorted(response.headers.keys()),
                response_www_authenticate=response.headers.get("www-authenticate"),
                response_content_type=response.headers.get("content-type"),
                response_body_preview=safe_text_preview(response.text),
                duration_ms=duration_ms,
            )
            raise ToolError(
                f"Bifrost quota lookup failed with HTTP {response.status_code} from {self.settings.quota_url}"
            )

        try:
            payload = response.json()
        except ValueError as exc:  # pragma: no cover - defensive guard
            log_event(
                logging.ERROR,
                "upstream_quota_error",
                quota_url=self.settings.quota_url,
                auth_source=auth_source,
                outbound_auth_mode=credential_mode,
                auth_headers=auth_headers,
                credential_identity=credential_identity,
                error_type=type(exc).__name__,
                duration_ms=duration_ms,
            )
            raise ToolError("Bifrost quota lookup returned invalid JSON") from exc

        report = normalize_quota_payload(
            payload,
            endpoint=self.settings.quota_url,
            auth_source=auth_source,
            queried_at=datetime.now(timezone.utc),
        )
        log_event(
            logging.INFO,
            "upstream_quota_success",
            quota_url=self.settings.quota_url,
            auth_source=auth_source,
            outbound_auth_mode=credential_mode,
            auth_headers=auth_headers,
            credential_identity=credential_identity,
            status_code=response.status_code,
            budget_count=report.summary.budget_count,
            remaining_total=report.summary.remaining_total,
            duration_ms=duration_ms,
        )
        return report.model_dump(mode="json")

    async def fetch_user_usage(self, *, admin_api_key: str, user_identifier: str) -> dict[str, Any]:
        if not admin_api_key.strip():
            raise ToolError("BIFROST_ADMIN_API_KEY must be configured")
        user_lookup_url = self.settings.users_url
        search_trace = {
            "search_identity_fingerprint": fingerprint_value(user_identifier),
            "search_identity_length": len(user_identifier.strip()),
        }
        log_event(
            logging.INFO,
            "governance_user_request",
            request_url=user_lookup_url,
            outbound_auth_mode="admin_api_key",
            inbound_credential="pingidentity_authorization",
            **search_trace,
        )
        response = await self._client.get(
            user_lookup_url,
            headers={"accept": "application/json", "authorization": f"Bearer {admin_api_key}"},
        )
        log_event(
            logging.INFO,
            "governance_user_response",
            request_url=user_lookup_url,
            status_code=response.status_code,
            outbound_auth_mode="admin_api_key",
            **search_trace,
        )
        if response.status_code >= 400:
            raise ToolError(f"Bifrost user lookup failed with HTTP {response.status_code}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise ToolError("Bifrost user lookup returned invalid JSON") from exc
        users = payload.get("users") if isinstance(payload, dict) else None
        users = users if isinstance(users, list) else []
        candidate_diagnostics: list[dict[str, Any]] = []
        matches: list[dict[str, Any]] = []
        for index, user in enumerate(users):
            if not isinstance(user, dict):
                continue
            matched_fields = _matching_fields(user, user_identifier)
            fields = _candidate_identity_fingerprints(user)
            candidate_diagnostics.append({
                "candidate_index": index,
                "identity_fields": sorted(fields),
                "identity_fingerprints": fields,
                "field_metadata": _candidate_field_metadata(user),
                "match": bool(matched_fields),
                "match_reason": "matched" if matched_fields else "no_supported_identity_field_match",
                "match_reason_detail": _candidate_match_reason_detail(user, matched_fields),
                "matched_fields": matched_fields,
            })
            if matched_fields:
                matches.append(user)
        log_event(
            logging.INFO,
            "user_lookup_match",
            request_url=user_lookup_url,
            status_code=response.status_code,
            returned_user_count=len(users),
            match_count=len(matches),
            candidates=candidate_diagnostics,
            **search_trace,
        )
        if not matches:
            raise ToolError("No Bifrost governance user matched the authenticated PingIdentity user")
        budgets: list[dict[str, Any]] = []
        malformed = 0
        profiles = matches[0].get("access_profiles")
        for profile in profiles if isinstance(profiles, list) else []:
            profile_budgets = profile.get("budgets") if isinstance(profile, dict) else None
            for budget in profile_budgets if isinstance(profile_budgets, list) else []:
                if not isinstance(budget, dict) or "current_usage" not in budget:
                    malformed += 1
                    continue
                budgets.append({
                    "name": budget.get("name", "usage"),
                    "consumed": budget.get("current_usage"),
                    "limit": budget.get("limit"),
                    "unit": budget.get("unit"),
                })
        log_event(logging.INFO, "usage_extraction", budget_count=len(budgets), malformed_budget_count=malformed)
        return normalize_quota_payload(
            {"budgets": budgets}, endpoint=user_lookup_url, auth_source="admin_api_key",
            queried_at=datetime.now(timezone.utc),
        ).model_dump(mode="json")


_IDENTITY_FIELDS = ("name", "username", "email", "user_name", "id")


def _candidate_identity_fingerprints(user: dict[str, Any]) -> dict[str, str]:
    return {
        key: fingerprint_value(user[key]) or ""
        for key in _IDENTITY_FIELDS
        if isinstance(user.get(key), str) and user[key].strip()
    }


def _candidate_field_metadata(user: dict[str, Any]) -> list[dict[str, Any]]:
    metadata: list[dict[str, Any]] = []
    for key in _IDENTITY_FIELDS:
        value = user.get(key)
        field: dict[str, Any] = {
            "field": key,
            "present": key in user,
            "value_type": type(value).__name__ if key in user else None,
        }
        if isinstance(value, str) and value.strip():
            field["fingerprint"] = fingerprint_value(value)
            field["length"] = len(value.strip())
        metadata.append(field)
    return metadata


def _candidate_match_reason_detail(user: dict[str, Any], matched_fields: list[str]) -> str:
    if matched_fields:
        return "matched"
    present_fields = [key for key in _IDENTITY_FIELDS if key in user]
    if not present_fields:
        return "field_absent"
    if any(not isinstance(user[key], str) for key in present_fields):
        return "field_non_string"
    return "normalized_mismatch"


def _matching_fields(user: dict[str, Any], identifier: str) -> list[str]:
    needle = identifier.casefold().strip()
    return [
        key
        for key in _IDENTITY_FIELDS
        if isinstance(user.get(key), str) and user[key].casefold().strip() == needle
    ]


def _user_matches(user: dict[str, Any], identifier: str) -> bool:
    return bool(_matching_fields(user, identifier))
