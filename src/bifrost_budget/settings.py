from __future__ import annotations

import os
import json
import re
from dataclasses import dataclass
from typing import Literal, cast
from urllib.parse import parse_qsl, urlsplit

DEFAULT_API_BASE_URL = ""
DEFAULT_QUOTA_PATH = "/api/governance/virtual-keys/quota"
DEFAULT_USERS_PATH = "/api/governance/users?limit=20"
DEFAULT_USERINFO_URL = ""
DEFAULT_HOST = "0.0.0.0"
DEFAULT_HTTP_PORT = 8080
DEFAULT_MCP_PATH = "/mcp"
DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_TRANSPORT: Literal["streamable-http", "stdio"] = "streamable-http"
DEFAULT_AUTH_PROVIDER = "entra"

# A dedicated issuer-controlled marker is required; identity/protocol fields are
# not evidence that the issuer authenticated a delegated human subject.
_PING_NON_DELEGATION_CLAIMS = frozenset({
    "displayname", "name", "scope", "scp", "sub", "client_id", "clientid",
    "aud", "iss", "idtyp", "gty", "grant_type", "exp", "nbf", "iat", "tid",
    "oid", "azp", "ver", "email", "upn", "uid", "user_id", "username",
    "preferred_username",
})


def validate_ping_delegation_contract(claim: str, value: str) -> None:
    """Validate configuration only, never infer the issuer's issuance policy."""
    if (not isinstance(claim, str) or not claim or any(c.isspace() for c in claim)
            or claim.lower() in _PING_NON_DELEGATION_CLAIMS
            or not isinstance(value, str) or not value.strip() or value != value.strip()):
        raise ValueError("Ping requires a dedicated non-identity delegated claim/value configuration")


def _auth_config() -> dict[str, object]:
    provider = os.getenv("BIFROST_AUTH_PROVIDER", DEFAULT_AUTH_PROVIDER).strip().lower()
    if provider not in {"entra", "ping"}:
        raise ValueError("BIFROST_AUTH_PROVIDER must be 'entra' or 'ping'")
    if provider == "entra":
        tenant = os.getenv("BIFROST_ENTRA_TENANT_ID", "").strip().lower()
        audience = os.getenv("BIFROST_ENTRA_AUDIENCE", "").strip()
        scope = os.getenv("BIFROST_ENTRA_SCOPE", "").strip()
        if (not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", tenant)
                or not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}", audience)
                or not scope or any(char.isspace() for char in scope)):
            raise ValueError("Entra requires BIFROST_ENTRA_TENANT_ID, BIFROST_ENTRA_AUDIENCE, and BIFROST_ENTRA_SCOPE")
        issuer = os.getenv("BIFROST_ENTRA_ISSUER", "").strip() or f"https://login.microsoftonline.com/{tenant}/v2.0"
        discovery = os.getenv("BIFROST_ENTRA_DISCOVERY_URL", "").strip() or f"https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"
        jwks = os.getenv("BIFROST_ENTRA_JWKS_URL", "").strip()
        mapping = os.getenv("BIFROST_ENTRA_USER_MAP", "").strip()
        if not jwks or not mapping:
            raise ValueError("Entra requires BIFROST_ENTRA_JWKS_URL and BIFROST_ENTRA_USER_MAP")
        try:
            def unique_pairs(items: list[tuple[str, object]]) -> dict[str, object]:
                result: dict[str, object] = {}
                for key, value in items:
                    if key in result:
                        raise ValueError("duplicate_map_key")
                    result[key] = value
                return result
            parsed = json.loads(mapping, object_pairs_hook=unique_pairs)
        except ValueError as exc:
            raise ValueError("BIFROST_ENTRA_USER_MAP must be a JSON object mapping tid:oid to exact Bifrost user IDs") from exc
        guid = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}"
        if not isinstance(parsed, dict) or not parsed or any(
            not isinstance(k, str) or not re.fullmatch(guid + ":" + guid, k)
            or not isinstance(v, str) or not v.strip() or v != v.strip() for k, v in parsed.items()
        ):
            raise ValueError("BIFROST_ENTRA_USER_MAP must map tid:oid keys to non-empty Bifrost user IDs")
        normalized_map = {key.lower(): value for key, value in parsed.items()}
        if len(normalized_map) != len(parsed):
            raise ValueError("BIFROST_ENTRA_USER_MAP contains duplicate tenant/user keys")
        parsed = normalized_map
        from .auth import _https
        if not all(_https(x) for x in (issuer, discovery, jwks)):
            raise ValueError("Entra issuer, discovery, and JWKS URLs must use HTTPS")
        return {"provider": provider, "tenant_id": tenant, "issuer": issuer, "discovery_url": discovery, "jwks_url": jwks,
                "audience": audience, "scope": scope, "user_map": parsed}
    issuer = os.getenv("BIFROST_PING_ISSUER", "").strip()
    audience = os.getenv("BIFROST_PING_AUDIENCE", "").strip()
    discovery = os.getenv("BIFROST_PING_DISCOVERY_URL", "").strip()
    jwks = os.getenv("BIFROST_PING_JWKS_URL", "").strip()
    scope = os.getenv("BIFROST_PING_SCOPE", "").strip()
    delegated_claim = os.getenv("BIFROST_PING_DELEGATED_CLAIM", "").strip()
    delegated_value = os.getenv("BIFROST_PING_DELEGATED_VALUE", "")
    if not all((issuer, audience, discovery, jwks, scope, delegated_claim, delegated_value)) or any(char.isspace() for char in scope):
        raise ValueError("Ping requires issuer, audience, discovery, JWKS, delegated scope, and delegated claim/value configuration")
    validate_ping_delegation_contract(delegated_claim, delegated_value)
    from .auth import _https
    if not all(_https(x) for x in (issuer, discovery, jwks)):
        raise ValueError("Ping issuer, discovery, and JWKS URLs must use HTTPS")
    return {"provider": provider, "issuer": issuer, "discovery_url": discovery, "jwks_url": jwks,
            "audience": audience, "scope": scope, "user_map": {},
            "ping_delegated_claim": delegated_claim, "ping_delegated_value": delegated_value}


def validate_userinfo_url(url: str) -> str:
    """Require a host-only HTTPS UserInfo endpoint without credential-bearing data."""
    value = url.strip()
    parts = urlsplit(value)
    if (parts.scheme != "https" or not parts.hostname or parts.username or parts.password
            or parts.query or parts.fragment):
        raise ValueError("BIFROST_USERINFO_URL must be an absolute HTTPS URL without credentials, query, or fragment")
    return value


@dataclass(frozen=True, slots=True)
class BifrostSettings:
    """Runtime configuration loaded from the environment and tool overrides."""

    api_base_url: str
    quota_path: str = DEFAULT_QUOTA_PATH
    users_path: str = DEFAULT_USERS_PATH
    userinfo_url: str = DEFAULT_USERINFO_URL
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    transport: Literal["streamable-http", "stdio"] = DEFAULT_TRANSPORT
    host: str = DEFAULT_HOST
    port: int = DEFAULT_HTTP_PORT
    mcp_path: str = DEFAULT_MCP_PATH
    admin_api_key: str | None = None
    auth_provider: str = "entra"
    entra_tenant_id: str = ""
    auth_issuer: str = ""
    auth_discovery_url: str = ""
    auth_jwks_url: str = ""
    auth_audience: str = ""
    auth_scope: str = ""
    entra_user_map: dict[str, str] | None = None
    ping_delegated_claim: str = ""
    ping_delegated_value: str = ""

    @property
    def quota_url(self) -> str:
        return f"{self.api_base_url.rstrip('/')}/{self.quota_path.lstrip('/')}"

    @property
    def users_url(self) -> str:
        return f"{self.api_base_url.rstrip('/')}/{self.users_path.lstrip('/')}"

    @classmethod
    def from_env(
        cls,
        *,
        api_base_url: str | None = None,
        quota_path: str | None = None,
        userinfo_url: str | None = None,
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
        parts = urlsplit(resolved_api_base_url)
        local_http = parts.scheme == "http" and parts.hostname in {"localhost", "127.0.0.1", "::1"}
        if (parts.scheme != "https" and not local_http) or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError("BIFROST_API_BASE_URL must be HTTPS without credentials, query, or fragment")

        resolved_transport = transport or os.getenv("BIFROST_TRANSPORT", DEFAULT_TRANSPORT)
        if resolved_transport not in {"streamable-http", "stdio"}:
            raise ValueError("BIFROST_TRANSPORT must be 'streamable-http' or 'stdio'")

        transport_value = cast(Literal["streamable-http", "stdio"], resolved_transport)
        resolved_quota_path = (quota_path or os.getenv("BIFROST_QUOTA_PATH", DEFAULT_QUOTA_PATH)).strip() or DEFAULT_QUOTA_PATH
        resolved_users_path = os.getenv("BIFROST_USERS_PATH", DEFAULT_USERS_PATH).strip() or DEFAULT_USERS_PATH
        quota_parts = urlsplit(resolved_quota_path)
        users_parts = urlsplit(resolved_users_path)
        if (quota_parts.scheme or quota_parts.netloc or quota_parts.path != DEFAULT_QUOTA_PATH
                or quota_parts.query or quota_parts.fragment or ".." in quota_parts.path.split("/")):
            raise ValueError("BIFROST_QUOTA_PATH must be /api/governance/virtual-keys/quota")
        if (users_parts.scheme or users_parts.netloc or users_parts.path != "/api/governance/users"
                or users_parts.fragment or ".." in users_parts.path.split("/")
                or any(key != "limit" or value != "20" for key, value in parse_qsl(users_parts.query, keep_blank_values=True))
                or len(parse_qsl(users_parts.query, keep_blank_values=True)) > 1):
            raise ValueError("BIFROST_USERS_PATH must be /api/governance/users with optional limit=20")
        auth_config = _auth_config()
        resolved_userinfo_url = (userinfo_url if userinfo_url is not None else os.getenv("BIFROST_USERINFO_URL", "")).strip()
        if auth_config["provider"] == "ping" and not resolved_userinfo_url:
            raise ValueError("Ping requires BIFROST_USERINFO_URL for its configured legacy UserInfo fallback")
        if resolved_userinfo_url:
            resolved_userinfo_url = validate_userinfo_url(resolved_userinfo_url)
        return cls(
            api_base_url=resolved_api_base_url,
            quota_path=resolved_quota_path,
            users_path=resolved_users_path,
            userinfo_url=resolved_userinfo_url,
            timeout_seconds=float(timeout_seconds or os.getenv("BIFROST_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)),
            transport=transport_value,
            host=(host or os.getenv("BIFROST_HOST", DEFAULT_HOST)).strip() or DEFAULT_HOST,
            port=int(port or os.getenv("BIFROST_PORT", DEFAULT_HTTP_PORT)),
            mcp_path=(mcp_path or os.getenv("BIFROST_MCP_PATH", DEFAULT_MCP_PATH)).strip() or DEFAULT_MCP_PATH,
            admin_api_key=os.getenv("BIFROST_ADMIN_API_KEY", "").strip() or None,
            **{("auth_provider" if k == "provider" else "entra_user_map" if k == "user_map" else "entra_tenant_id" if k == "tenant_id" else k if k.startswith("ping_") else f"auth_{k}"): v
               for k, v in auth_config.items()},
        )
