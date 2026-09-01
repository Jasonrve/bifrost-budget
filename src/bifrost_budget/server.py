from __future__ import annotations

from typing import Any

from fastapi.responses import JSONResponse, Response

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.context import Context
from mcp.server.mcpserver.exceptions import ToolError

from .client import BifrostClient
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
            "with an x-bf-vk header, an Authorization bearer token, or an explicit virtual_key argument."
        ),
        structured_output=True,
    )
    async def get_quota(
        virtual_key: str | None = None,
        api_base_url: str | None = None,
        ctx: Context[object] | None = None,
    ) -> dict[str, Any]:
        settings = BifrostSettings.from_env(api_base_url=api_base_url)
        resolved_virtual_key, auth_source = _resolve_virtual_key(virtual_key, ctx)
        async with BifrostClient(settings) as client:
            return await client.fetch_quota(virtual_key=resolved_virtual_key, auth_source=auth_source)

    return server


def _resolve_virtual_key(
    explicit: str | None,
    ctx: Context[object] | None,
) -> tuple[str, str]:
    if explicit and explicit.strip():
        return explicit.strip(), "tool_argument"

    headers = ctx.headers if ctx is not None else None
    if headers:
        header_value = headers.get("x-bf-vk") or headers.get("X-BF-VK")
        if header_value and header_value.strip():
            return header_value.strip(), "request_header:x-bf-vk"

        authorization = headers.get("authorization") or headers.get("Authorization")
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization.split(None, 1)[1].strip()
            if token:
                return token, "request_header:authorization"

    import os

    env_virtual_key = os.getenv("BIFROST_VIRTUAL_KEY", "").strip()
    if env_virtual_key:
        return env_virtual_key, "environment:BIFROST_VIRTUAL_KEY"

    raise ToolError(
        "No virtual key was provided. Supply virtual_key, send x-bf-vk or Authorization: Bearer in the request, or set BIFROST_VIRTUAL_KEY."
    )


server = create_server()
