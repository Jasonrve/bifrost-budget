from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_http_headers
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .client import BifrostClient
from .auth import AuthenticationError, KeyCache, TokenVerifier
from .logging import fingerprint_value, log_event
from .settings import BifrostSettings

SERVER_NAME = "bifrost-budget"
SERVER_INSTRUCTIONS = (
    "Use the get_quota tool to inspect the caller's own quota information. "
    "This server is strictly read-only and never mutates Bifrost state."
)


def create_server() -> FastMCP:
    server = FastMCP(
        name=SERVER_NAME,
        instructions=SERVER_INSTRUCTIONS,
        version="0.5.0",
    )
    key_caches: dict[tuple[str, str, str, str], KeyCache] = {}

    @server.custom_route("/healthz", ["GET"], include_in_schema=False)
    async def healthz(_: Request) -> Response:
        return JSONResponse({"status": "ok", "service": SERVER_NAME})

    @server.tool(
        name="get_quota",
        title="Get Bifrost quota snapshot",
        description=(
            "Return the authenticated caller's read-only Bifrost quota snapshot. Requires a verified delegated-user bearer token."
        ),
    )
    async def get_quota(
        ctx: Context,
        api_base_url: str | None = None,
    ) -> dict[str, Any]:
        started_at = time.perf_counter()
        try:
            settings = BifrostSettings.from_env()
            if api_base_url is not None and api_base_url.rstrip("/") != settings.api_base_url.rstrip("/"):
                raise ValueError("backend_override_mismatch")
        except ValueError as exc:
            raise ToolError("Authentication or backend configuration is invalid") from exc
        correlation = {"correlation_id_fingerprint": fingerprint_value(str(ctx.request_id or uuid.uuid4()))}
        headers = get_http_headers(include_all=True)
        authorization = headers.get("authorization", "")
        auth_source, credential_mode = "request_header:authorization", "authorization"
        auth_decision = "verified_bearer"
        log_event(
            logging.DEBUG,
            "tool_invocation",
            tool="get_quota",
            auth_source=auth_source,
            auth_decision=auth_decision,
            outbound_auth_mode=credential_mode,
            transport=settings.transport,
            quota_url=settings.quota_url,
            inbound_credential="bearer_token",
            outbound_credential="bifrost_admin_api_key",
            **correlation,
        )
        try:
            async with BifrostClient(settings) as client:
                cache_key = (settings.auth_issuer, settings.auth_audience, settings.auth_discovery_url, settings.auth_jwks_url)
                verifier = TokenVerifier(issuer=settings.auth_issuer, audience=settings.auth_audience,
                    discovery_url=settings.auth_discovery_url, jwks_url=settings.auth_jwks_url, client=client._client,
                    cache=key_caches.setdefault(cache_key, KeyCache()))
                try:
                    claims = await verifier.verify(authorization)
                    identity, identity_source = _validated_identity(claims, settings)
                except AuthenticationError as exc:
                    if settings.auth_provider == "ping" and exc.code == "userinfo_required":
                        identity = await client.fetch_userinfo_identity(
                            authorization=authorization, expected_subject=claims.get("sub"), correlation=correlation
                        )
                        identity_source = "ping_userinfo"
                    else:
                        raise ToolError(f"Authentication failed ({exc.code})") from None
                if not settings.admin_api_key:
                    raise ToolError("BIFROST_ADMIN_API_KEY must be configured")
                result = await client.fetch_user_usage(
                    admin_api_key=settings.admin_api_key,
                    user_identifier=identity,
                    exact_id=settings.auth_provider == "entra",
                    correlation=correlation,
                )
            # The one line every get_quota call produces at the default log level.
            log_event(
                logging.INFO,
                "get_quota_completed",
                tool="get_quota",
                auth_source=auth_source,
                auth_decision=auth_decision,
                outbound_auth_mode=credential_mode,
                budget_count=result.get("summary", {}).get("budget_count"),
                duration_ms=round((time.perf_counter() - started_at) * 1000, 2),
                **correlation,
            )
            return result
        except ToolError as exc:
            log_event(
                logging.ERROR,
                "tool_error",
                tool="get_quota",
                auth_source=auth_source,
                reason_code=type(exc).__name__,
                duration_ms=round((time.perf_counter() - started_at) * 1000, 2),
                **correlation,
            )
            raise

    return server


def _validated_identity(claims: dict[str, Any], settings: BifrostSettings) -> tuple[str, str]:
    if claims.get("idtyp") == "app":
        raise AuthenticationError("app_only_unsupported")
    if settings.auth_provider == "entra":
        import uuid
        if claims.get("ver") != "2.0" or not isinstance(claims.get("scp"), str) or settings.auth_scope not in claims["scp"].split():
            raise AuthenticationError("delegated_scope_required")
        tid, oid = claims.get("tid"), claims.get("oid")
        try:
            if not isinstance(tid, str) or not isinstance(oid, str) or len(tid) != 36 or len(oid) != 36 or str(uuid.UUID(tid)) != tid.lower() or str(uuid.UUID(oid)) != oid.lower():
                raise ValueError
            uuid.UUID(tid); uuid.UUID(oid)
        except (ValueError, TypeError, AttributeError):
            raise AuthenticationError("invalid_user_subject") from None
        if tid.lower() != settings.entra_tenant_id:
            raise AuthenticationError("invalid_user_subject")
        key = f"{tid.lower()}:{oid.lower()}"
        mapping = settings.entra_user_map or {}
        if key not in mapping:
            raise AuthenticationError("user_mapping_missing")
        return mapping[key], "entra_tid_oid_mapping"
    if settings.auth_scope and (not isinstance(claims.get("scope", claims.get("scp")), str) or settings.auth_scope not in claims.get("scope", claims.get("scp", "")).split()):
        raise AuthenticationError("delegated_scope_required")
    display = claims.get("displayname")
    if isinstance(display, str) and display.strip():
        return display.strip(), "ping_jwt_displayname"
    raise AuthenticationError("userinfo_required")


server = create_server()
