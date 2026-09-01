from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi.responses import JSONResponse, Response
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.context import Context
from mcp.server.mcpserver.exceptions import ToolError

from .client import BifrostClient
from .logging import build_credential_trace, log_event
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
        version="0.1.0",
    )

    @server.custom_route("/healthz", ["GET"], include_in_schema=False)
    async def healthz(_: Any) -> Response:
        return JSONResponse({"status": "ok", "service": SERVER_NAME})

    @server.tool(
        name="get_quota",
        title="Get Bifrost quota snapshot",
        description=(
            "Return the caller's Bifrost quota snapshot by calling the configured quota endpoint "
            "with an Authorization header when present, then exchange that identity into a "
            "Bifrost-recognized virtual key using BIFROST_AUTH_EXCHANGE_MAP or a configured "
            "BIFROST_VIRTUAL_KEY fallback. Explicit virtual_key and x-bf-vk remain available for "
            "local and non-production use."
        ),
        structured_output=True,
    )
    async def get_quota(
        virtual_key: str | None = None,
        api_base_url: str | None = None,
        ctx: Context[object] | None = None,
    ) -> dict[str, Any]:
        settings = BifrostSettings.from_env(api_base_url=api_base_url)
        credential, auth_source, credential_mode, caller_identity = _resolve_credential(virtual_key, ctx, settings)
        log_event(
            logging.INFO,
            "tool_invocation",
            tool="get_quota",
            auth_source=auth_source,
            caller_identity=caller_identity,
            credential_identity=build_credential_trace(
                credential,
                auth_source=auth_source,
                credential_mode=credential_mode,
            ),
            outbound_auth_mode=credential_mode,
            transport=settings.transport,
            quota_url=settings.quota_url,
        )
        try:
            async with BifrostClient(settings) as client:
                return await client.fetch_quota(
                    credential=credential,
                    credential_mode=credential_mode,
                    auth_source=auth_source,
                )
        except ToolError as exc:
            log_event(logging.ERROR, "tool_error", tool="get_quota", auth_source=auth_source, error=str(exc))
            raise

    return server


def _resolve_credential(
    explicit: str | None,
    ctx: Context[object] | None,
    settings: BifrostSettings,
) -> tuple[str, str, Literal["authorization", "virtual_key"], dict[str, Any]]:
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
            credential_identity=identity_trace,
        )
        return resolved, "tool_argument", "virtual_key", identity_trace

    headers = ctx.headers if ctx is not None else None
    if headers:
        authorization = headers.get("authorization") or headers.get("Authorization")
        if authorization and authorization.strip():
            authorization_trace = build_credential_trace(
                authorization,
                auth_source="request_header:authorization",
                credential_mode="authorization",
            )
            credential = _exchange_authorization_credential(authorization, settings, authorization_trace)
            log_event(
                logging.INFO,
                "auth_source_selected",
                source="request_header:authorization",
                credential_identity=authorization_trace,
            )
            return credential, "request_header:authorization", "virtual_key", authorization_trace

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
                credential_identity=identity_trace,
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
            credential_identity=identity_trace,
        )
        return env_virtual_key, "environment:BIFROST_VIRTUAL_KEY", "virtual_key", identity_trace

    log_event(logging.ERROR, "auth_source_missing")
    raise ToolError(
        "No Bifrost credential was provided. Supply virtual_key, send x-bf-vk, send an Authorization header that maps in BIFROST_AUTH_EXCHANGE_MAP, or set BIFROST_VIRTUAL_KEY."
    )


def _exchange_authorization_credential(
    authorization: str,
    settings: BifrostSettings,
    authorization_trace: dict[str, Any],
) -> str:
    candidates = _authorization_exchange_candidates(authorization_trace)
    for selector in candidates:
        mapped = settings.credential_exchange_map.get(selector)
        if mapped and mapped.strip():
            resolved = mapped.strip()
            log_event(
                logging.INFO,
                "auth_credential_exchanged",
                source="BIFROST_AUTH_EXCHANGE_MAP",
                selector=selector,
                caller_identity=authorization_trace,
                credential_identity=build_credential_trace(
                    resolved,
                    auth_source="request_header:authorization",
                    credential_mode="virtual_key",
                ),
            )
            return resolved

    if settings.default_virtual_key:
        log_event(
            logging.INFO,
            "auth_credential_defaulted",
            source="BIFROST_VIRTUAL_KEY",
            caller_identity=authorization_trace,
            credential_identity=build_credential_trace(
                settings.default_virtual_key,
                auth_source="request_header:authorization",
                credential_mode="virtual_key",
            ),
        )
        return settings.default_virtual_key

    raise ToolError(
        "Authorization header received but no BIFROST_AUTH_EXCHANGE_MAP entry matched its safe claims and no BIFROST_VIRTUAL_KEY fallback is configured."
    )


def _authorization_exchange_candidates(trace: dict[str, Any]) -> list[str]:
    claims = trace.get("claims")
    if not isinstance(claims, dict):
        return []

    candidates: list[str] = []
    sub = claims.get("sub")
    iss = claims.get("iss")
    tenant = claims.get("tenant") or claims.get("tenant_id") or claims.get("tid") or claims.get("org_id")

    if isinstance(iss, (str, int, float, bool)) and isinstance(sub, (str, int, float, bool)):
        candidates.append(f"iss={iss}|sub={sub}")
    if isinstance(sub, (str, int, float, bool)):
        candidates.append(f"sub={sub}")
    if isinstance(tenant, (str, int, float, bool)) and isinstance(sub, (str, int, float, bool)):
        candidates.append(f"tenant={tenant}|sub={sub}")

    return candidates


server = create_server()
