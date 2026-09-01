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
AUTH_SELECTOR_PREFIXES = ("iss", "tid", "tenant", "tenant_id", "org_id")
AUTH_SELECTOR_SINGLE_CLAIMS = (
    "sub",
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
            auth_decision=_auth_decision_label(auth_source, credential_mode),
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
        log_event(
            logging.DEBUG,
            "auth_decision_complete",
            decision="tool_argument",
            auth_source="tool_argument",
            outbound_auth_mode="virtual_key",
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
            log_event(
                logging.DEBUG,
                "auth_decision_complete",
                decision="authorization_exchange",
                auth_source="request_header:authorization",
                outbound_auth_mode="virtual_key",
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
            log_event(
                logging.DEBUG,
                "auth_decision_complete",
                decision="request_header:x-bf-vk",
                auth_source="request_header:x-bf-vk",
                outbound_auth_mode="virtual_key",
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
        log_event(
            logging.DEBUG,
            "auth_decision_complete",
            decision="environment:BIFROST_VIRTUAL_KEY",
            auth_source="environment:BIFROST_VIRTUAL_KEY",
            outbound_auth_mode="virtual_key",
            credential_identity=identity_trace,
        )
        return env_virtual_key, "environment:BIFROST_VIRTUAL_KEY", "virtual_key", identity_trace

    log_event(logging.ERROR, "auth_source_missing")
    raise ToolError(
        "No Bifrost credential was provided. Supply virtual_key, send x-bf-vk, send an Authorization header that matches one of the configured safe-claim selectors, or set BIFROST_VIRTUAL_KEY."
    )


def _exchange_authorization_credential(
    authorization: str,
    settings: BifrostSettings,
    authorization_trace: dict[str, Any],
) -> str:
    candidates = _authorization_exchange_candidates(authorization_trace)
    configured_selectors = _redacted_configured_selectors(settings.credential_exchange_map)
    log_event(
        logging.DEBUG,
        "auth_decision_tree",
        caller_identity=authorization_trace,
        configured_selector_keys=configured_selectors,
        attempted_selector_count=len(candidates),
        has_virtual_key_fallback=bool(settings.default_virtual_key),
    )
    for index, (selector, source_fields) in enumerate(candidates, start=1):
        mapped = settings.credential_exchange_map.get(selector)
        log_event(
            logging.DEBUG,
            "auth_selector_attempted",
            selector=selector,
            selector_index=index,
            source_fields=source_fields,
            matched=bool(mapped and mapped.strip()),
        )
        if mapped and mapped.strip():
            resolved = mapped.strip()
            log_event(
                logging.INFO,
                "auth_credential_exchanged",
                source="BIFROST_AUTH_EXCHANGE_MAP",
                selector=selector,
                selector_index=index,
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
            logging.DEBUG,
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

    log_event(
        logging.ERROR,
        "auth_decision_failed",
        caller_identity=authorization_trace,
        configured_selector_keys=configured_selectors,
        attempted_selectors=[selector for selector, _ in candidates],
        has_virtual_key_fallback=False,
    )
    raise ToolError(
        "Authorization header received but no BIFROST_AUTH_EXCHANGE_MAP entry matched its safe claims. "
        f"Attempted selectors: {[selector for selector, _ in candidates] or ['<none>']}. "
        f"Configured selectors: {configured_selectors or ['<none>']}. "
        "No BIFROST_VIRTUAL_KEY fallback is configured."
    )


def _authorization_exchange_candidates(trace: dict[str, Any]) -> list[tuple[str, list[str]]]:
    claims = trace.get("claims")
    if not isinstance(claims, dict):
        return []

    candidates: list[tuple[str, list[str]]] = []

    claim_values = {
        key: value
        for key, value in claims.items()
        if isinstance(value, (str, int, float, bool)) and value not in ("", None)
    }

    identity_fields = [key for key in AUTH_SELECTOR_SINGLE_CLAIMS if key in claim_values]
    for prefix in AUTH_SELECTOR_PREFIXES:
        if prefix not in claim_values:
            continue
        prefix_value = claim_values[prefix]
        for field in identity_fields:
            if field == prefix:
                continue
            candidates.append((f"{prefix}={prefix_value}|{field}={claim_values[field]}", [prefix, field]))

    for field in identity_fields:
        candidates.append((f"{field}={claim_values[field]}", [field]))

    return _dedupe_candidates(candidates)


def _redacted_configured_selectors(exchange_map: dict[str, str]) -> list[str]:
    return [_redact_selector_key(selector) for selector in sorted(exchange_map)]


def _redact_selector_key(selector: str) -> str:
    parts = selector.split("|")
    redacted_parts: list[str] = []
    for part in parts:
        if "=" not in part:
            redacted_parts.append(part)
            continue
        key, _value = part.split("=", 1)
        redacted_parts.append(f"{key}=*")
    return "|".join(redacted_parts)


def _dedupe_candidates(candidates: list[tuple[str, list[str]]]) -> list[tuple[str, list[str]]]:
    seen: set[str] = set()
    deduped: list[tuple[str, list[str]]] = []
    for selector, source_fields in candidates:
        if selector in seen:
            continue
        seen.add(selector)
        deduped.append((selector, source_fields))
    return deduped


def _auth_decision_label(auth_source: str, credential_mode: Literal["authorization", "virtual_key"]) -> str:
    if auth_source == "request_header:authorization" and credential_mode == "virtual_key":
        return "authorization_exchange_map"
    if auth_source == "request_header:x-bf-vk":
        return "request_header_virtual_key"
    if auth_source == "environment:BIFROST_VIRTUAL_KEY":
        return "environment_virtual_key"
    if auth_source == "tool_argument":
        return "tool_argument"
    return auth_source


server = create_server()
