from __future__ import annotations

from datetime import datetime, timezone
import logging
import time
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
from fastmcp.exceptions import ToolError

from .logging import log_event
from .normalization import normalize_quota_payload
from .settings import BifrostSettings, validate_userinfo_url


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

        auth_headers = sorted(name for name in headers if name in {"authorization", "x-bf-vk"})
        log_event(
            logging.DEBUG,
            "upstream_quota_request",
            quota_url=self.settings.quota_url,
            auth_source=auth_source,
            outbound_auth_mode=credential_mode,
            auth_headers=auth_headers,
        )
        try:
            response = await self._client.get(self.settings.quota_url, headers=headers, follow_redirects=False)
        except httpx.RequestError as exc:
            log_event(logging.ERROR, "upstream_quota_error", auth_source=auth_source,
                      outbound_auth_mode=credential_mode, reason_code="request_failed",
                      error_type=type(exc).__name__)
            raise ToolError("Bifrost quota lookup failed (request_failed)") from None
        duration_ms = round((time.perf_counter() - started_at) * 1000, 2)
        if response.status_code >= 300:
            log_event(
                logging.ERROR,
                "upstream_quota_error",
                quota_url=self.settings.quota_url,
                auth_source=auth_source,
                outbound_auth_mode=credential_mode,
                auth_headers=auth_headers,
                status_code=response.status_code,
                response_header_names=sorted(response.headers.keys()),
                response_content_type=response.headers.get("content-type"),
                error_type="upstream_http_error",
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
                error_type=type(exc).__name__,
                duration_ms=duration_ms,
            )
            raise ToolError("Bifrost quota lookup returned invalid JSON") from None

        report = normalize_quota_payload(
            payload,
            endpoint=self.settings.quota_url,
            auth_source=auth_source,
            queried_at=datetime.now(timezone.utc),
        )
        log_event(
            logging.DEBUG,
            "upstream_quota_success",
            quota_url=self.settings.quota_url,
            auth_source=auth_source,
            outbound_auth_mode=credential_mode,
            auth_headers=auth_headers,
            status_code=response.status_code,
            budget_count=report.summary.budget_count,
            remaining_total=report.summary.remaining_total,
            duration_ms=duration_ms,
        )
        return report.model_dump(mode="json")

    async def fetch_user_usage(
        self, *, admin_api_key: str, user_identifier: str,
        exact_id: bool = False,
        correlation: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not admin_api_key.strip():
            raise ToolError("BIFROST_ADMIN_API_KEY must be configured")
        user_lookup_url = _build_governance_users_url(self.settings.users_url, user_identifier)
        request_parts = urlsplit(user_lookup_url)
        query_parameters = dict(parse_qsl(request_parts.query, keep_blank_values=True))
        request_metadata = {
            "request_host": request_parts.netloc,
            "request_path": request_parts.path,
            "request_url": urlunsplit((request_parts.scheme, request_parts.netloc, request_parts.path, "", "")),
            "query_parameter_names": sorted(query_parameters),
            "search_present": bool(query_parameters.get("search")),
            "limit": query_parameters.get("limit"),
        }
        correlation = correlation or {}
        log_event(
            logging.DEBUG,
            "governance_user_request",
            outbound_auth_mode="admin_api_key",
            inbound_credential="verified_bearer",
            **request_metadata,
            **correlation,
        )
        try:
            response = await self._client.get(
                user_lookup_url,
                headers={"accept": "application/json", "authorization": f"Bearer {admin_api_key}"},
                follow_redirects=False,
            )
        except httpx.RequestError as exc:
            log_event(logging.ERROR, "governance_user_error", reason_code="request_failed",
                      error_type=type(exc).__name__, **correlation)
            raise ToolError("Bifrost user lookup failed (request_failed)") from None
        log_event(
            logging.DEBUG,
            "governance_user_response",
            status_code=response.status_code,
            outbound_auth_mode="admin_api_key",
            **request_metadata,
            **correlation,
        )
        if response.status_code >= 300:
            raise ToolError(f"Bifrost user lookup failed with HTTP {response.status_code}")
        try:
            payload = response.json()
        except ValueError as exc:
            raise ToolError("Bifrost user lookup returned invalid JSON") from None
        users = payload.get("users") if isinstance(payload, dict) else None
        users = users if isinstance(users, list) else []
        candidate_diagnostics: list[dict[str, Any]] = []
        matches: list[dict[str, Any]] = []
        for index, user in enumerate(users):
            if not isinstance(user, dict):
                continue
            if exact_id:
                matched_fields = ["id"] if isinstance(user.get("id"), str) and user["id"] == user_identifier else []
            else:
                matched_fields = _matching_fields(user, user_identifier)
            candidate_diagnostics.append({
                "candidate_index": index,
                "match": bool(matched_fields),
                "match_reason": "matched" if matched_fields else "no_supported_identity_field_match",
                "match_reason_detail": _candidate_match_reason_detail(user, matched_fields),
                "matched_fields": matched_fields,
            })
            if matched_fields:
                matches.append(user)
        log_event(
            logging.DEBUG,
            "user_lookup_match",
            status_code=response.status_code,
            returned_user_count=len(users),
            match_count=len(matches),
            candidate_count=len(candidate_diagnostics),
            **request_metadata,
            **correlation,
        )
        if len(matches) != 1:
            raise ToolError("No unique Bifrost governance user matched the authenticated identity")
        budgets: list[dict[str, Any]] = []
        user = matches[0]
        profiles = user.get("access_profiles", [])
        if not isinstance(profiles, list):
            raise ToolError("Bifrost governance access_profiles container is malformed")
        for profile in profiles:
            if not isinstance(profile, dict):
                raise ToolError("Bifrost governance access profile is malformed")
            profile_budgets = profile.get("budgets", [])
            if not isinstance(profile_budgets, list):
                raise ToolError("Bifrost governance budgets container is malformed")
            for budget in profile_budgets:
                if not isinstance(budget, dict) or "current_usage" not in budget:
                    raise ToolError("Bifrost governance budget row is malformed")
                current_usage = _parse_money(budget.get("current_usage"))
                max_limit = _parse_money(budget.get("max_limit", budget.get("limit")))
                if current_usage is None or max_limit is None:
                    raise ToolError("Bifrost governance budget has missing or malformed monetary quota fields")
                if current_usage > max_limit:
                    raise ToolError("Bifrost governance budget current_usage exceeds max_limit")
                budgets.append({
                    "name": budget.get("name", "usage"),
                    "current_usage": current_usage,
                    "max_limit": max_limit,
                    "unit": budget.get("unit"),
                })
        log_event(logging.DEBUG, "usage_extraction", budget_count=len(budgets))
        return normalize_quota_payload(
            {"budgets": budgets}, endpoint=user_lookup_url, auth_source="admin_api_key",
            queried_at=datetime.now(timezone.utc),
        ).model_dump(mode="json")

    async def fetch_userinfo_identity(self, *, authorization: str, expected_subject: str | None = None, correlation: dict[str, Any] | None = None) -> str:
        """Resolve the caller using inbound bearer credentials, never the governance key."""
        try:
            url = validate_userinfo_url(self.settings.userinfo_url)
        except ValueError as exc:
            raise ToolError("BIFROST_USERINFO_URL must be a safe absolute HTTPS URL") from exc
        url_parts = urlsplit(url)
        url_metadata = {"request_host": url_parts.netloc, "request_path": url_parts.path}
        correlation = correlation or {}
        log_event(logging.DEBUG, "userinfo_request", **url_metadata, auth_headers=["authorization"], **correlation)
        try:
            response = await self._client.get(url, headers={"accept": "application/json", "authorization": authorization}, follow_redirects=False)
        except httpx.TimeoutException as exc:
            log_event(logging.ERROR, "userinfo_error", **url_metadata, reason_code="timeout", error_type=type(exc).__name__, **correlation)
            raise ToolError("PingIdentity UserInfo request timed out") from None
        except httpx.RequestError as exc:
            log_event(logging.ERROR, "userinfo_error", **url_metadata, reason_code="request_failed", error_type=type(exc).__name__, **correlation)
            raise ToolError("PingIdentity UserInfo request failed") from None
        if response.status_code >= 300:
            log_event(logging.ERROR, "userinfo_error", **url_metadata, status_code=response.status_code,
                      response_header_names=sorted(response.headers.keys()), reason_code="http_error", **correlation)
            raise ToolError(f"PingIdentity UserInfo lookup failed with HTTP {response.status_code}")
        try:
            payload = response.json()
        except ValueError as exc:
            log_event(logging.ERROR, "userinfo_error", **url_metadata, status_code=response.status_code,
                      decode_success=False, reason_code="invalid_json", error_type=type(exc).__name__, **correlation)
            raise ToolError("PingIdentity UserInfo returned invalid JSON") from None
        if not isinstance(payload, dict):
            log_event(logging.ERROR, "userinfo_error", **url_metadata, status_code=response.status_code,
                      decode_success=True, response_type=type(payload).__name__, reason_code="response_not_object", **correlation)
            raise ToolError("PingIdentity UserInfo response must be a JSON object")
        if not expected_subject or payload.get("sub") != expected_subject:
            raise ToolError("PingIdentity UserInfo subject binding failed")
        log_event(logging.DEBUG, "userinfo_response", **url_metadata, status_code=response.status_code,
                  decode_success=True, response_field_names=[key for key in ("sub", "name", "preferred_username") if key in payload], **correlation)
        for field in ("name", "preferred_username"):
            value = payload.get(field)
            if isinstance(value, str) and value.strip():
                identity = value.strip()
                log_event(logging.DEBUG, "userinfo_identity_selected", **url_metadata,
                          selected_identity_field=field,
                          selected_identity_source=f"userinfo.{field}", reason_code="identity_selected", **correlation)
                return identity
        log_event(logging.ERROR, "userinfo_error", **url_metadata,
                  reason_code="userinfo_identity_missing", selected_identity_field=None, **correlation)
        raise ToolError("PingIdentity UserInfo response has no usable identity (userinfo_identity_missing)")

_IDENTITY_FIELDS = ("name", "username", "email", "user_name", "id")


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


def _build_governance_users_url(base_url: str, user_identifier: str) -> str:
    """Add the selected identity and bounded page size using URL-safe encoding."""
    parts = urlsplit(base_url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query["search"] = user_identifier.strip()
    query["limit"] = "20"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _user_matches(user: dict[str, Any], identifier: str) -> bool:
    return bool(_matching_fields(user, identifier))


def _parse_money(value: Any) -> float | None:
    """Parse a non-negative monetary amount without binary float arithmetic."""
    from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
    if isinstance(value, bool) or value is None:
        return None
    try:
        amount = Decimal(str(value))
        if not amount.is_finite() or amount < 0:
            return None
        return float(amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
    except (InvalidOperation, ValueError, TypeError):
        return None
