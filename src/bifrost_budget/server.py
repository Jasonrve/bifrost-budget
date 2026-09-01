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
            "with the caller's authenticated Authorization header when present. The server derives "
            "caller identity from safe JWT claims for tracing, and explicit virtual_key, x-bf-vk, and "
            "BIFROST_VIRTUAL_KEY remain available for local and non-production fallback use."
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
            log_event(
                logging.INFO,
                "auth_source_selected",
                source="request_header:authorization",
                credential_identity=authorization_trace,
            )
            return authorization.strip(), "request_header:authorization", "authorization", authorization_trace

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
        "No Bifrost credential was provided. Supply virtual_key, send x-bf-vk, send an Authorization header, or set BIFROST_VIRTUAL_KEY."
    )


server = create_server()
