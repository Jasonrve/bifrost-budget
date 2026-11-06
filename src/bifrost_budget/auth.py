from __future__ import annotations

import asyncio
import json
import math
import re
import time
from typing import Any
from urllib.parse import urlsplit

import httpx
import jwt
from jwt import PyJWK

_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")


class AuthenticationError(Exception):
    def __init__(self, code: str = "invalid_token") -> None:
        self.code = code
        super().__init__(code)


class KeyCache:
    """Bounded verifier state that outlives individual outbound HTTP clients."""
    def __init__(self) -> None:
        self.keys: dict[str, dict[str, Any]] = {}
        self.metadata_ok = False
        self.expires = 0.0
        self.lock = asyncio.Lock()
        self.last_unknown_refresh = float("-inf")


def _unique_json(data: bytes) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError("json_object_required")
    return value


def _https(url: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme == "https" and bool(parts.hostname) and not parts.username and not parts.password and not parts.query and not parts.fragment


class TokenVerifier:
    """RS256 OIDC verifier with a bounded in-memory JWKS cache."""
    def __init__(self, *, issuer: str, audience: str, discovery_url: str, jwks_url: str, client: httpx.AsyncClient, cache_seconds: int = 300, cache: KeyCache | None = None):
        if not all((_https(issuer), _https(discovery_url), _https(jwks_url))) or not audience:
            raise ValueError("invalid_auth_configuration")
        self.issuer, self.audience = issuer, audience
        self.discovery_url, self.jwks_url, self.client = discovery_url, jwks_url, client
        self.cache_seconds = min(max(cache_seconds, 30), 3600)
        self._cache = cache or KeyCache()

    async def verify(self, authorization: str) -> dict[str, Any]:
        if (not isinstance(authorization, str) or len(authorization) > 16_384
                or not re.fullmatch(r"Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", authorization)):
            raise AuthenticationError("invalid_bearer")
        token = authorization[7:]
        try:
            parts = token.split(".")
            header = _unique_json(jwt.utils.base64url_decode(parts[0].encode()))
            claims = _unique_json(jwt.utils.base64url_decode(parts[1].encode()))
            if (header.get("alg") != "RS256" or not isinstance(header.get("kid"), str) or not header["kid"]
                    or any(key in header for key in ("crit", "jku", "x5u"))):
                raise ValueError("unsupported_header")
        except Exception as exc:
            raise AuthenticationError("invalid_token") from exc
        key = await self._key(header["kid"], force=False)
        if key is None:
            key = await self._key(header["kid"], force=True)
        if key is None:
            raise AuthenticationError("unknown_signing_key")
        try:
            verified = jwt.decode(token, PyJWK.from_dict(key, algorithm="RS256").key,
                                  algorithms=["RS256"], audience=self.audience, issuer=self.issuer,
                                  options={"require": ["exp", "nbf", "iss", "aud", "sub"]}, leeway=30)
        except Exception as exc:
            raise AuthenticationError("invalid_token") from exc
        if verified != claims:
            raise AuthenticationError("invalid_token")
        for name in ("exp", "nbf"):
            value = verified.get(name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise AuthenticationError("invalid_token")
        if verified["exp"] <= verified["nbf"] or not isinstance(verified.get("sub"), str) or not verified["sub"].strip():
            raise AuthenticationError("invalid_token")
        if verified.get("aud") != self.audience:
            raise AuthenticationError("invalid_token")
        return verified

    async def _key(self, kid: str, *, force: bool) -> dict[str, Any] | None:
        cache = self._cache
        async with cache.lock:
            now = time.monotonic()
            if not force and now < cache.expires:
                return cache.keys.get(kid)
            # Unknown kid values are attacker-controlled; throttle forced refreshes globally.
            if force and now - cache.last_unknown_refresh < 15:
                return None
            if force:
                cache.last_unknown_refresh = now
            try:
                if not cache.metadata_ok or now >= cache.expires:
                    metadata_response = await self.client.get(self.discovery_url, follow_redirects=False)
                    metadata_response.raise_for_status()
                    metadata = metadata_response.json()
                    if metadata.get("issuer") != self.issuer or metadata.get("jwks_uri") != self.jwks_url:
                        raise ValueError("metadata_mismatch")
                cache.metadata_ok = True
                response = await self.client.get(self.jwks_url, follow_redirects=False)
                response.raise_for_status()
                keys = response.json().get("keys", [])
                selected: dict[str, dict[str, Any]] = {}
                for item in keys:
                    if (not isinstance(item, dict) or item.get("kty") != "RSA"
                            or item.get("use", "sig") != "sig" or item.get("alg", "RS256") != "RS256"
                            or not isinstance(item.get("kid"), str)):
                        continue
                    if item["kid"] in selected:
                        raise ValueError("duplicate_signing_key_id")
                    selected[item["kid"]] = item
                cache.keys = selected
                cache.expires = time.monotonic() + self.cache_seconds
            except Exception:
                raise AuthenticationError("key_service_unavailable") from None
            return cache.keys.get(kid)
