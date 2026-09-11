from __future__ import annotations

import logging
import os
import uuid
from typing import Any, Literal

from fastapi.responses import JSONResponse, Response
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.context import Context
from mcp.server.mcpserver.exceptions import ToolError

from .client import BifrostClient
from .logging import (
    _decode_jwt_claims,
    build_credential_trace,
    header_diagnostics,
    log_event,
    raw_header_diagnostics,
    raw_header_logging_enabled,
    extract_displayname_from_authorization,
    fingerprint_value,
)
from .settings import BifrostSettings

SERVER_NAME = "bifrost-budget"
SERVER_TITLE = "Bifrost Budget"
SERVER_DESCRIPTION = "Read-only MCP server for caller Bifrost budget and quota snapshots."
SERVER_INSTRUCTIONS = (
    "Use the get_quota tool to inspect the caller's own quota information. "
    "This server is strictly read-only and never mutates Bifrost state."
)


def create_server() -> MCPServer[object]:
    server = MCPServer(
        name=SERVER_NAME,
        title=SERVER_TITLE,
        description=SERVER_DESCRIPTION,
        instructions=SERVER_INSTRUCTIONS,
        version="0.3.6",
    )

    @server.custom_route("/healthz", ["GET"], include_in_schema=False)
    async def healthz(_: Any) -> Response:
        return JSONResponse({"status": "ok", "service": SERVER_NAME})

    @server.tool(
        name="get_quota",
        title="Get Bifrost quota snapshot",
        description=(
            "Return the caller's Bifrost quota snapshot by calling the configured quota endpoint "
            "with the caller's Authorization header when present. Explicit virtual_key, x-bf-vk, "
            "and BIFROST_VIRTUAL_KEY remain available for local and non-production fallback use."
        ),
        structured_output=True,
    )
    async def get_quota(
        virtual_key: str | None = None,
        api_base_url: str | None = None,
        ctx: Context[object] | None = None,
    ) -> dict[str, Any]:
        settings = BifrostSettings.from_env(api_base_url=api_base_url)
        request_id = getattr(ctx, "request_id", None) if ctx is not None else None
        correlation = {"correlation_id_fingerprint": fingerprint_value(str(request_id or uuid.uuid4()))}
        credential, auth_source, credential_mode, caller_identity = _resolve_credential(virtual_key, ctx, settings, correlation=correlation)
        log_event(
            logging.INFO,
            "tool_invocation",
            tool="get_quota",
            auth_source=auth_source,
            auth_decision=_auth_decision_label(auth_source, credential_mode),
            caller_identity={key: value for key, value in caller_identity.items() if key != "identity"},
            credential_identity=build_credential_trace(
                credential,
                auth_source=auth_source,
                credential_mode=credential_mode,
            ),
            outbound_auth_mode=credential_mode,
            transport=settings.transport,
            quota_url=settings.quota_url,
            inbound_credential="pingidentity_authorization" if credential_mode == "authorization" else "fallback_virtual_key",
            outbound_credential="bifrost_admin_api_key",
            search_identity_fingerprint=caller_identity.get("identity_fingerprint"),
            search_identity_length=len(caller_identity["identity"]),
            selected_identity_claim=caller_identity.get("selected_identity_claim"),
            selected_identity_source=caller_identity.get("selected_identity_source"),
            identity_extraction_source=caller_identity.get("identity_extraction_source"),
            identity_selection_reason=caller_identity.get("identity_selection_reason"),
            name_present=caller_identity.get("name_present"),
            name_usable=caller_identity.get("name_usable"),
            **correlation,
        )
        try:
            async with BifrostClient(settings) as client:
                if credential_mode != "authorization":
                    raise ToolError("An incoming PingIdentity Authorization header is required")
                if not settings.admin_api_key:
                    raise ToolError("BIFROST_ADMIN_API_KEY must be configured")
                identity = caller_identity.get("identity")
                if not identity:
                    try:
                        identity = await client.fetch_userinfo_identity(authorization=credential, correlation=correlation)
                    except TypeError as exc:
                        if "correlation" not in str(exc):
                            raise
                        identity = await client.fetch_userinfo_identity(authorization=credential)
                    identity_source = "userinfo.name_or_preferred_username"
                else:
                    identity_source = "jwt.displayname"
                try:
                    return await client.fetch_user_usage(
                        admin_api_key=settings.admin_api_key,
                        user_identifier=identity,
                        correlation=correlation,
                        inbound_authorization=credential,
                        identity_source=identity_source,
                    )
                except TypeError as exc:
                    if "correlation" not in str(exc):
                        raise
                    return await client.fetch_user_usage(
                        admin_api_key=settings.admin_api_key, user_identifier=identity
                    )
        except ToolError as exc:
            log_event(logging.ERROR, "tool_error", tool="get_quota", auth_source=auth_source,
                      reason_code=type(exc).__name__, error_reason=str(exc), **correlation)
            raise

    return server


def _resolve_credential(
    explicit: str | None,
    ctx: Context[object] | None,
    settings: BifrostSettings,
    correlation: dict[str, Any] | None = None,
) -> tuple[str, str, Literal["authorization", "virtual_key"], dict[str, Any]]:
    correlation = correlation or {}
    if explicit and explicit.strip():
        resolved = explicit.strip()
        identity_trace = build_credential_trace(
            resolved,
            auth_source="tool_argument",
            credential_mode="virtual_key",
        )
        log_event(
            logging.INFO,
            "auth_source_selected",
            source="tool_argument",
            credential_identity=identity_trace, **correlation,
        )
        log_event(
            logging.DEBUG,
            "auth_decision_complete",
            decision="tool_argument",
            auth_source="tool_argument",
            outbound_auth_mode="virtual_key",
            credential_identity=identity_trace, **correlation,
        )
        return resolved, "tool_argument", "virtual_key", identity_trace

    headers = ctx.headers if ctx is not None else None
    if headers:
        request_id = getattr(ctx, "request_id", None)
        log_event(
            logging.INFO,
            "inbound_request_diagnostics",
            transport="streamable-http",
            process_id=os.getpid(),
            method=getattr(ctx, "method", None),
            path=getattr(ctx, "path", None),
            request_id_fingerprint=build_credential_trace(
                str(request_id), auth_source="request_id", credential_mode="virtual_key"
            ).get("token_fingerprint") if request_id else None,
            headers=header_diagnostics(headers),
        )
        if raw_header_logging_enabled():
            log_event(
                logging.WARNING,
                "inbound_request_headers_cleartext",
                transport="streamable-http",
                headers=raw_header_diagnostics(headers),
            )
        authorization = headers.get("authorization") or headers.get("Authorization")
        if authorization and authorization.strip():
            authorization_trace = build_credential_trace(
                authorization,
                auth_source="request_header:authorization",
                credential_mode="authorization",
            )
            log_event(
                logging.INFO,
                "auth_source_selected",
                source="request_header:authorization",
                credential_identity=authorization_trace, **correlation,
            )
            log_event(
                logging.DEBUG,
                "auth_decision_complete",
                decision="authorization_passthrough",
                auth_source="request_header:authorization",
                outbound_auth_mode="authorization",
                credential_identity=authorization_trace, **correlation,
            )
            _, token = authorization.strip().split(None, 1)
            claims = _decode_jwt_claims(token)
            selection = extract_displayname_from_authorization(authorization)
            identity = selection.get("identity") or ""
            authorization_trace["identity_fingerprint"] = build_credential_trace(
                identity, auth_source="identity", credential_mode="virtual_key"
            )["token_fingerprint"]
            authorization_trace.update(
                {
                    "selected_identity_claim": selection["claim"] if selection.get("identity") else None,
                    "selected_identity_source": "jwt.displayname" if selection.get("identity") else None,
                    "identity_extraction_source": "raw_authorization_jwt",
                    "identity_selection_reason": selection["reason"],
                    "name_present": "name" in (claims or {}),
                    "name_usable": isinstance((claims or {}).get("name"), str) and bool((claims or {}).get("name", "").strip()),
                    "identity_length": len(identity),
                    "displayname_present": selection["present"],
                    "displayname_type": selection["value_type"],
                    "displayname_length": selection["length"],
                    "displayname_fingerprint": selection["fingerprint"],
                }
            )
            return authorization, "request_header:authorization", "authorization", {
                **authorization_trace,
                "identity": identity,
            }

        header_value = headers.get("x-bf-vk") or headers.get("X-BF-VK")
        if header_value and header_value.strip():
            credential = header_value.strip()
            identity_trace = build_credential_trace(
                credential,
                auth_source="request_header:x-bf-vk",
                credential_mode="virtual_key",
            )
            log_event(
                logging.INFO,
                "auth_source_selected",
                source="request_header:x-bf-vk",
                credential_identity=identity_trace, **correlation,
            )
            log_event(
                logging.DEBUG,
                "auth_decision_complete",
                decision="request_header:x-bf-vk",
                auth_source="request_header:x-bf-vk",
                outbound_auth_mode="virtual_key",
                credential_identity=identity_trace, **correlation,
            )
            return credential, "request_header:x-bf-vk", "virtual_key", identity_trace

    env_virtual_key = settings.default_virtual_key
    if env_virtual_key:
        identity_trace = build_credential_trace(
            env_virtual_key,
            auth_source="environment:BIFROST_VIRTUAL_KEY",
            credential_mode="virtual_key",
        )
        log_event(
            logging.INFO,
            "auth_source_selected",
            source="environment:BIFROST_VIRTUAL_KEY",
            credential_identity=identity_trace, **correlation,
        )
        log_event(
            logging.DEBUG,
            "auth_decision_complete",
            decision="environment:BIFROST_VIRTUAL_KEY",
            auth_source="environment:BIFROST_VIRTUAL_KEY",
            outbound_auth_mode="virtual_key",
            credential_identity=identity_trace, **correlation,
        )
        return env_virtual_key, "environment:BIFROST_VIRTUAL_KEY", "virtual_key", identity_trace

    log_event(logging.ERROR, "auth_source_missing")
    raise ToolError(
        "No Bifrost credential was provided. Supply virtual_key, send x-bf-vk, send an Authorization header for passthrough, or set BIFROST_VIRTUAL_KEY."
    )


def _auth_decision_label(auth_source: str, credential_mode: Literal["authorization", "virtual_key"]) -> str:
    if auth_source == "request_header:authorization" and credential_mode == "authorization":
        return "authorization_passthrough"
    if auth_source == "request_header:x-bf-vk":
        return "request_header_virtual_key"
    if auth_source == "environment:BIFROST_VIRTUAL_KEY":
        return "environment_virtual_key"
    if auth_source == "tool_argument":
        return "tool_argument"
    return auth_source


server = create_server()
