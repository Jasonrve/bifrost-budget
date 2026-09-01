from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Literal, cast

DEFAULT_API_BASE_URL = ""
DEFAULT_QUOTA_PATH = "/api/governance/virtual-keys/quota"
DEFAULT_HOST = "0.0.0.0"
DEFAULT_HTTP_PORT = 8080
DEFAULT_MCP_PATH = "/mcp"
DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_TRANSPORT: Literal["streamable-http", "stdio"] = "streamable-http"


@dataclass(frozen=True, slots=True)
class BifrostSettings:
    """Runtime configuration loaded from the environment and tool overrides."""

    api_base_url: str
    quota_path: str = DEFAULT_QUOTA_PATH
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    transport: Literal["streamable-http", "stdio"] = DEFAULT_TRANSPORT
    host: str = DEFAULT_HOST
    port: int = DEFAULT_HTTP_PORT
    mcp_path: str = DEFAULT_MCP_PATH
    default_virtual_key: str | None = None
    credential_exchange_map: dict[str, str] = field(default_factory=dict)

    @property
    def quota_url(self) -> str:
        return f"{self.api_base_url.rstrip('/')}/{self.quota_path.lstrip('/')}"

    @classmethod
    def from_env(
        cls,
        *,
        api_base_url: str | None = None,
        quota_path: str | None = None,
        timeout_seconds: float | None = None,
        transport: Literal["streamable-http", "stdio"] | None = None,
        host: str | None = None,
        port: int | None = None,
        mcp_path: str | None = None,
    ) -> "BifrostSettings":
        resolved_api_base_url = (api_base_url or os.getenv("BIFROST_API_BASE_URL", "")).strip()
        if not resolved_api_base_url:
            raise ValueError(
                "BIFROST_API_BASE_URL must be configured (for example https://bifrost.example.com)"
            )

        resolved_transport = transport or os.getenv("BIFROST_TRANSPORT", DEFAULT_TRANSPORT)
        if resolved_transport not in {"streamable-http", "stdio"}:
            raise ValueError("BIFROST_TRANSPORT must be 'streamable-http' or 'stdio'")

        transport_value = cast(Literal["streamable-http", "stdio"], resolved_transport)
        resolved_default_virtual_key = os.getenv("BIFROST_VIRTUAL_KEY", "").strip() or None
        resolved_exchange_map = _parse_exchange_map(os.getenv("BIFROST_AUTH_EXCHANGE_MAP", ""))

        return cls(
            api_base_url=resolved_api_base_url,
            quota_path=(quota_path or os.getenv("BIFROST_QUOTA_PATH", DEFAULT_QUOTA_PATH)).strip() or DEFAULT_QUOTA_PATH,
            timeout_seconds=float(timeout_seconds or os.getenv("BIFROST_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)),
            transport=transport_value,
            host=(host or os.getenv("BIFROST_HOST", DEFAULT_HOST)).strip() or DEFAULT_HOST,
            port=int(port or os.getenv("BIFROST_PORT", DEFAULT_HTTP_PORT)),
            mcp_path=(mcp_path or os.getenv("BIFROST_MCP_PATH", DEFAULT_MCP_PATH)).strip() or DEFAULT_MCP_PATH,
            default_virtual_key=resolved_default_virtual_key,
            credential_exchange_map=resolved_exchange_map,
        )


def _parse_exchange_map(raw_value: str) -> dict[str, str]:
    normalized = raw_value.strip()
    if not normalized:
        return {}

    payload = json.loads(normalized)
    if not isinstance(payload, dict):
        raise ValueError("BIFROST_AUTH_EXCHANGE_MAP must be a JSON object mapping claim selectors to virtual keys")

    exchange_map: dict[str, str] = {}
    for key, value in payload.items():
        if not isinstance(key, str) or not key.strip():
            raise ValueError("BIFROST_AUTH_EXCHANGE_MAP keys must be non-empty strings")
        if not isinstance(value, str) or not value.strip():
            raise ValueError("BIFROST_AUTH_EXCHANGE_MAP values must be non-empty strings")
        exchange_map[key.strip()] = value.strip()
    return exchange_map
