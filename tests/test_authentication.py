from __future__ import annotations

import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastmcp.exceptions import ToolError

from bifrost_budget.auth import AuthenticationError, TokenVerifier
from bifrost_budget.client import BifrostClient
from bifrost_budget.server import _validated_identity
from bifrost_budget.settings import BifrostSettings

TENANT = "11111111-1111-4111-8111-111111111111"
OID = "33333333-3333-4333-8333-333333333333"
AUDIENCE = "22222222-2222-4222-8222-222222222222"
ISSUER = f"https://issuer.example.test/{TENANT}/v2.0"
DISCOVERY = "https://issuer.example.test/metadata"
JWKS = "https://issuer.example.test/keys"


def _settings(**changes):
    data = dict(api_base_url="https://bifrost.example.test", auth_provider="entra", entra_tenant_id=TENANT,
        auth_issuer=ISSUER, auth_discovery_url=DISCOVERY, auth_jwks_url=JWKS, auth_audience=AUDIENCE,
        auth_scope="Quota.Read", entra_user_map={f"{TENANT}:{OID}": "bifrost-user-7"})
    data.update(changes)
    return BifrostSettings(**data)


def _token(private, **claims):
    now = int(time.time())
    payload = {"iss": ISSUER, "aud": AUDIENCE, "sub": "subject", "exp": now+300, "nbf": now-5,
        "ver": "2.0", "tid": TENANT, "oid": OID, "scp": "Quota.Read", "name": "Mutable Name", **claims}
    return jwt.encode(payload, private, algorithm="RS256", headers={"kid": "key-1"})


@pytest.mark.asyncio
async def test_rs256_verification_uses_pinned_discovery_and_jwks_and_caches_keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update(kid="key-1", use="sig", alg="RS256")
    calls = []
    def response(req):
        calls.append(str(req.url))
        if str(req.url) == DISCOVERY:
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": JWKS})
        if str(req.url) == JWKS:
            return httpx.Response(200, json={"keys": [jwk]})
        return httpx.Response(404)
    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        verifier = TokenVerifier(issuer=ISSUER, audience=AUDIENCE, discovery_url=DISCOVERY, jwks_url=JWKS, client=client)
        claims = await verifier.verify("Bearer " + _token(private))
        assert claims["oid"] == OID
        await verifier.verify("Bearer " + _token(private))
    assert calls.count(DISCOVERY) == 1 and calls.count(JWKS) == 1


def test_entra_identity_comes_only_from_configured_immutable_mapping():
    settings = _settings()
    claims = {"ver": "2.0", "tid": TENANT, "oid": OID, "scp": "Quota.Read", "name": "Mutable Name", "preferred_username": "changed@example.test"}
    assert _validated_identity(claims, settings) == ("bifrost-user-7", "entra_tid_oid_mapping")
    claims["name"] = "Completely Different"
    assert _validated_identity(claims, settings)[0] == "bifrost-user-7"
    for forbidden in ({**claims, "idtyp": "app", "displayname": "Human Looking Name"}, {**claims, "scp": "Other"}, {**claims, "tid": "44444444-4444-4444-8444-444444444444"}, {**claims, "scp": None}, {**claims, "ver": "1.0"}):
        with pytest.raises(AuthenticationError):
            _validated_identity(forbidden, settings)


@pytest.mark.asyncio
async def test_exact_id_governance_match_requires_one_user_and_hides_search_pii(caplog):
    def response(_):
        return httpx.Response(200, json={"users": [{"id": "bifrost-user-7", "name": "mutable", "access_profiles": [{"budgets": [{"name": "daily", "limit": "10.00", "current_usage": "2.25"}]}]}]})
    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        result = await BifrostClient(_settings(), client=client).fetch_user_usage(admin_api_key="admin-secret", user_identifier="bifrost-user-7", exact_id=True)
    assert result["budgets"][0]["consumed"] == 2.25
    log_text = "".join(r.getMessage() for r in caplog.records)
    assert "bifrost-user-7" not in log_text and "mutable" not in log_text
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"users": [{"id": "BIFROST-USER-7"}]}))) as client:
        with pytest.raises(ToolError):
            await BifrostClient(_settings(), client=client).fetch_user_usage(admin_api_key="admin-secret", user_identifier="bifrost-user-7", exact_id=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("budgets", [
    [{"name": "daily", "limit": "12.50"}],
    [{"name": "good", "limit": "12.50", "current_usage": "2.25"}, {"name": "bad", "limit": "8.00"}],
    [{"name": "daily", "current_usage": "2.25"}],
])
async def test_governance_rejects_every_malformed_budget_row(budgets):
    payload = {"users": [{"id": "bifrost-user-7", "access_profiles": [{"budgets": budgets}]}]}
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))) as client:
        with pytest.raises(ToolError):
            await BifrostClient(_settings(), client=client).fetch_user_usage(admin_api_key="admin-secret", user_identifier="bifrost-user-7", exact_id=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("user", [
    {"id": "bifrost-user-7", "access_profiles": "bad"},
    {"id": "bifrost-user-7", "access_profiles": None},
    {"id": "bifrost-user-7", "access_profiles": [{"budgets": "bad"}]},
    {"id": "bifrost-user-7", "access_profiles": [{"budgets": None}]},
    {"id": "bifrost-user-7", "access_profiles": [{"budgets": []}, "bad"]},
    {"id": "bifrost-user-7", "access_profiles": [{"budgets": [{"limit": "10", "current_usage": "2"}]}, "bad"]},
])
async def test_governance_rejects_malformed_profile_and_budget_containers(user):
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"users": [user]}))) as client:
        with pytest.raises(ToolError, match="governance .*malformed"):
            await BifrostClient(_settings(), client=client).fetch_user_usage(admin_api_key="admin-secret", user_identifier="bifrost-user-7", exact_id=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("user", [
    {"id": "bifrost-user-7"},
    {"id": "bifrost-user-7", "access_profiles": []},
    {"id": "bifrost-user-7", "access_profiles": [{"budgets": []}]},
    {"id": "bifrost-user-7", "access_profiles": [{"budgets": []}, {"budgets": []}]},
])
async def test_governance_accepts_omitted_and_empty_profile_collections(user):
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"users": [user]}))) as client:
        result = await BifrostClient(_settings(), client=client).fetch_user_usage(admin_api_key="admin-secret", user_identifier="bifrost-user-7", exact_id=True)
    assert result["budgets"] == []


async def _invoke_tool(server, token: str, api_base_url: str | None = None):
    from fastmcp import Client
    from fastmcp.client.transports import StreamableHttpTransport
    import httpx as httpx_client
    def factory(*, headers=None, auth=None, follow_redirects=True, timeout=None, **_kwargs):
        return httpx_client.AsyncClient(transport=httpx_client.ASGITransport(app=app), base_url="http://test", headers=headers, follow_redirects=follow_redirects)
    app = server.http_app(path="/mcp", stateless_http=True)
    async with app.router.lifespan_context(app):
        transport = StreamableHttpTransport("http://test/mcp", headers={"authorization": token}, httpx_client_factory=factory)
        async with Client(transport) as client:
            args = {"api_base_url": api_base_url} if api_base_url else {}
            return await client.call_tool("get_quota", args, raise_on_error=False)


def _set_env(monkeypatch, mapping=None):
    monkeypatch.setenv("BIFROST_API_BASE_URL", "https://bifrost.example.test")
    monkeypatch.setenv("BIFROST_ADMIN_API_KEY", "admin-secret")
    monkeypatch.setenv("BIFROST_ENTRA_TENANT_ID", TENANT)
    monkeypatch.setenv("BIFROST_ENTRA_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("BIFROST_ENTRA_SCOPE", "Quota.Read")
    monkeypatch.setenv("BIFROST_ENTRA_ISSUER", ISSUER)
    monkeypatch.setenv("BIFROST_ENTRA_DISCOVERY_URL", DISCOVERY)
    monkeypatch.setenv("BIFROST_ENTRA_JWKS_URL", JWKS)
    monkeypatch.setenv("BIFROST_ENTRA_USER_MAP", json.dumps(mapping or {f"{TENANT}:{OID}": "bifrost-user-7"}))


@pytest.mark.asyncio
async def test_full_get_quota_verifies_token_maps_exact_id_and_returns_decimal_snapshot(monkeypatch, caplog):
    import logging
    import importlib
    server_module = importlib.import_module("bifrost_budget.server")
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update(kid="key-1", use="sig", alg="RS256")
    seen = []
    def handler(request):
        seen.append(request)
        if str(request.url) == DISCOVERY:
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": JWKS})
        if str(request.url) == JWKS:
            return httpx.Response(200, json={"keys": [jwk]})
        if request.url.path == "/api/governance/users":
            assert request.headers.get("authorization") == "Bearer admin-secret"
            assert request.url.params.get("search") == "bifrost-user-7"
            return httpx.Response(200, json={"users": [{"id": "bifrost-user-7", "name": "Mutable Name", "email": "different@example.test", "access_profiles": [{"budgets": [{"name": "monthly", "limit": "12.50", "current_usage": "2.25"}]}]}]})
        raise AssertionError(f"unexpected request to {request.url.host}{request.url.path}")
    class MockBifrostClient(BifrostClient):
        def __init__(self, settings):
            super().__init__(settings, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        async def __aexit__(self, *args):
            await self._client.aclose()
    monkeypatch.setattr(server_module, "BifrostClient", MockBifrostClient)
    _set_env(monkeypatch)
    caplog.set_level(logging.DEBUG, logger="bifrost_budget")
    token = "Bearer " + _token(private, name="Different Mutable Name", preferred_username="changed@example.test")
    app_server = server_module.create_server()
    result = await _invoke_tool(app_server, token)
    second_result = await _invoke_tool(app_server, token)
    assert result.is_error is False
    assert second_result.is_error is False
    body = result.structured_content
    assert body["budgets"][0]["current_usage"] == 2.25
    assert body["budgets"][0]["max_limit"] == 12.5
    assert body["budgets"][0]["remaining"] == 10.25
    assert [req.url.host for req in seen] == ["issuer.example.test", "issuer.example.test", "bifrost.example.test", "bifrost.example.test"]
    logs = "\n".join(r.getMessage() for r in caplog.records)
    for secret in ("admin-secret", "Mutable Name", "Different Mutable Name", "changed@example.test", token):
        assert secret not in logs


@pytest.mark.asyncio
async def test_invalid_bearer_and_backend_override_fail_before_governance(monkeypatch):
    import importlib
    server_module = importlib.import_module("bifrost_budget.server")
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update(kid="key-1", use="sig", alg="RS256")
    governance_calls = []
    def handler(request):
        if str(request.url) == DISCOVERY:
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": JWKS})
        if str(request.url) == JWKS:
            return httpx.Response(200, json={"keys": [jwk]})
        governance_calls.append(request)
        return httpx.Response(200, json={"users": []})
    class MockBifrostClient(BifrostClient):
        def __init__(self, settings): super().__init__(settings, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        async def __aexit__(self, *args): await self._client.aclose()
    monkeypatch.setattr(server_module, "BifrostClient", MockBifrostClient)
    _set_env(monkeypatch)
    forged = _token(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    for authorization in ("Basic abc", "Bearer " + forged, "Bearer not-a-jwt"):
        result = await _invoke_tool(server_module.create_server(), authorization)
        assert result.is_error
        assert not governance_calls
    valid = "Bearer " + _token(private)
    result = await _invoke_tool(server_module.create_server(), valid, "https://attacker.example.test")
    assert result.is_error
    assert not governance_calls


@pytest.mark.parametrize("claims", [
    {"tid": "44444444-4444-4444-8444-444444444444"}, {"scp": "Other"}, {"idtyp": "app"}, {"oid": "not-a-guid"},
])
def test_entra_rejects_invalid_security_claims(claims):
    value = {"ver": "2.0", "tid": TENANT, "oid": OID, "scp": "Quota.Read"}
    value.update(claims)
    try:
        _validated_identity(value, _settings())
    except AuthenticationError:
        pass
    else:
        pytest.fail("invalid Entra claims unexpectedly accepted")


@pytest.mark.parametrize("claims", [
    {"ver": None}, {"ver": "1.0"}, {"scp": ""}, {"scp": "Other"},
    {"tid": "11111111111141118111111111111111"}, {"oid": "{33333333-3333-4333-8333-333333333333}"},
])
def test_entra_requires_canonical_guids_version_and_delegated_scope(claims):
    value = {"ver": "2.0", "tid": TENANT, "oid": OID, "scp": "Quota.Read"}
    value.update(claims)
    with pytest.raises(AuthenticationError):
        _validated_identity(value, _settings())


@pytest.mark.parametrize("payload_changes", [
    {"exp": "future"}, {"exp": True}, {"exp": float("inf")}, {"nbf": "past"},
    {"nbf": False}, {"exp": int(time.time()) - 200, "nbf": int(time.time()) - 300},
    {"exp": int(time.time()) + 300, "nbf": int(time.time()) + 200}, {"sub": ""},
])
@pytest.mark.asyncio
async def test_verifier_rejects_invalid_lifetime_and_empty_subject(payload_changes):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update(kid="key-1", use="sig", alg="RS256")
    def response(request):
        return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": JWKS} if str(request.url) == DISCOVERY else {"keys": [jwk]})
    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        verifier = TokenVerifier(issuer=ISSUER, audience=AUDIENCE, discovery_url=DISCOVERY, jwks_url=JWKS, client=client)
        payload = {"iss": ISSUER, "aud": AUDIENCE, "sub": "subject", "exp": int(time.time()) + 300, "nbf": int(time.time()) - 1, **payload_changes}
        token = jwt.encode(payload, private, algorithm="RS256", headers={"kid": "key-1"})
        with pytest.raises(AuthenticationError):
            await verifier.verify("Bearer " + token)


@pytest.mark.parametrize("name,value", [
    ("BIFROST_USERS_PATH", "https://evil.test/api/governance/users?limit=20"),
    ("BIFROST_USERS_PATH", "/api/governance/users?limit=20&token=secret"),
    ("BIFROST_USERS_PATH", "/api/governance/../users?limit=20"),
    ("BIFROST_QUOTA_PATH", "/api/governance/virtual-keys/quota?token=secret"),
])
def test_endpoint_path_allowlists_reject_overrides(monkeypatch, name, value):
    _set_env(monkeypatch)
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        BifrostSettings.from_env()


@pytest.mark.asyncio
@pytest.mark.parametrize("override", [
    {"exp": None}, {"nbf": None}, {"aud": "wrong-api"}, {"iss": "https://evil.example.test"},
])
async def test_verifier_rejects_wrong_signature_expiry_issuer_audience_and_token_type(override):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update(kid="key-1", use="sig", alg="RS256")
    async def response(request):
        if str(request.url) == DISCOVERY:
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": JWKS})
        return httpx.Response(200, json={"keys": [jwk]})
    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        verifier = TokenVerifier(issuer=ISSUER, audience=AUDIENCE, discovery_url=DISCOVERY, jwks_url=JWKS, client=client)
        claims = await verifier.verify("Bearer " + _token(private))
        changed = {"exp": int(time.time()) + 300, "nbf": int(time.time()) - 1, **claims, **override}
        bad = jwt.encode(changed, private, algorithm="RS256", headers={"kid": "key-1"})
        with pytest.raises(AuthenticationError):
            await verifier.verify("Bearer " + bad)


@pytest.mark.asyncio
async def test_missing_required_claim_and_duplicate_json_claim_are_rejected():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update(kid="key-1", use="sig", alg="RS256")
    async def response(request):
        if str(request.url) == DISCOVERY:
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": JWKS})
        return httpx.Response(200, json={"keys": [jwk]})
    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        verifier = TokenVerifier(issuer=ISSUER, audience=AUDIENCE, discovery_url=DISCOVERY, jwks_url=JWKS, client=client)
        payload = {"iss": ISSUER, "aud": AUDIENCE, "sub": "sub", "exp": int(time.time()) + 300, "nbf": int(time.time()) - 1}
        payload.pop("nbf")
        missing = jwt.encode(payload, private, algorithm="RS256", headers={"kid": "key-1"})
        with pytest.raises(AuthenticationError):
            await verifier.verify("Bearer " + missing)
        import base64
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        header = base64.urlsafe_b64encode(b'{"alg":"RS256","kid":"key-1"}').rstrip(b"=").decode()
        body = base64.urlsafe_b64encode(b'{"iss":"x","iss":"y"}').rstrip(b"=").decode()
        signing_input = f"{header}.{body}".encode()
        sig = private.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        encoded_sig = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        with pytest.raises(AuthenticationError):
            await verifier.verify(f"Bearer {header}.{body}.{encoded_sig}")


@pytest.mark.asyncio
async def test_unknown_kid_refresh_is_bounded_and_rotation_is_supported():
    first = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    second = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    active = {"value": first, "kid": "active"}
    key_requests = []
    def as_jwk(key, kid):
        key_data = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
        key_data.update(kid=kid, use="sig", alg="RS256")
        return key_data
    def response(request):
        if str(request.url) == DISCOVERY:
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": JWKS})
        key_requests.append(None)
        return httpx.Response(200, json={"keys": [as_jwk(active["value"], active["kid"])]})
    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        verifier = TokenVerifier(issuer=ISSUER, audience=AUDIENCE, discovery_url=DISCOVERY, jwks_url=JWKS, client=client)
        old_token = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": "s", "exp": int(time.time())+300, "nbf": int(time.time())-1}, first, algorithm="RS256", headers={"kid":"active"})
        await verifier.verify("Bearer " + old_token)
        active["value"] = second
        active["kid"] = "rotated"
        rotated = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": "s", "exp": int(time.time())+300, "nbf": int(time.time())-1}, second, algorithm="RS256", headers={"kid":"rotated"})
        await verifier.verify("Bearer " + rotated)
        count_after_rotation = len(key_requests)
        unknown = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": "s", "exp": int(time.time())+300, "nbf": int(time.time())-1}, second, algorithm="RS256", headers={"kid":"attacker-controlled"})
        with pytest.raises(AuthenticationError):
            await verifier.verify("Bearer " + unknown)
        assert len(key_requests) == count_after_rotation
    assert len(key_requests) == 2


def test_provider_configuration_fails_closed_and_ping_requires_explicit_scope(monkeypatch):
    monkeypatch.setenv("BIFROST_API_BASE_URL", "https://bifrost.example.test")
    for name in ("BIFROST_ENTRA_TENANT_ID", "BIFROST_ENTRA_AUDIENCE", "BIFROST_ENTRA_SCOPE", "BIFROST_ENTRA_JWKS_URL", "BIFROST_ENTRA_USER_MAP"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("BIFROST_AUTH_PROVIDER", "unknown")
    with pytest.raises(ValueError, match="BIFROST_AUTH_PROVIDER"):
        BifrostSettings.from_env()
    monkeypatch.setenv("BIFROST_AUTH_PROVIDER", "ping")
    monkeypatch.setenv("BIFROST_PING_ISSUER", ISSUER)
    monkeypatch.setenv("BIFROST_PING_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("BIFROST_PING_DISCOVERY_URL", DISCOVERY)
    monkeypatch.setenv("BIFROST_PING_JWKS_URL", JWKS)
    monkeypatch.setenv("BIFROST_PING_SCOPE", "quota.read")
    monkeypatch.delenv("BIFROST_USERINFO_URL", raising=False)
    with pytest.raises(ValueError, match="delegated claim/value"):
        BifrostSettings.from_env()
    monkeypatch.setenv("BIFROST_PING_DELEGATED_CLAIM", "displayname")
    monkeypatch.setenv("BIFROST_PING_DELEGATED_VALUE", "human")
    with pytest.raises(ValueError, match="dedicated"):
        BifrostSettings.from_env()
    monkeypatch.setenv("BIFROST_PING_DELEGATED_CLAIM", "delegated_user")
    monkeypatch.setenv("BIFROST_PING_DELEGATED_VALUE", "human")
    with pytest.raises(ValueError, match="BIFROST_USERINFO_URL"):
        BifrostSettings.from_env()
    monkeypatch.setenv("BIFROST_USERINFO_URL", "https://ping.example.test/userinfo")
    settings = BifrostSettings.from_env()
    assert settings.auth_provider == "ping"
    assert settings.auth_scope == "quota.read"


def test_ping_claim_identity_requires_scope_and_never_uses_mutable_claim_fallback():
    from dataclasses import replace
    settings = replace(_settings(), auth_provider="ping", auth_scope="quota.read", ping_delegated_claim="delegated_user", ping_delegated_value="true")
    base = {"scope": "quota.read", "displayname": "Verified Display", "sub": "person-7", "delegated_user": "true"}
    assert _validated_identity(base, settings) == ("Verified Display", "ping_jwt_displayname")
    with pytest.raises(AuthenticationError):
        _validated_identity({**base, "scope": "other"}, settings)
    for changes in ({"delegated_user": ["true"]}, {"delegated_user": True}, {"delegated_user": "false"}, {"sub": ""}, {"idtyp": "app"}, {"gty": "client_credentials"}, {"grant_type": "client-credentials"}, {"client_id": "person-7"}):
        with pytest.raises(AuthenticationError):
            _validated_identity({**base, **changes}, settings)
    with pytest.raises(AuthenticationError):
        _validated_identity({"scope": "quota.read", "displayname": "Verified Display", "sub": "person-7"}, replace(settings, ping_delegated_claim="", ping_delegated_value=""))
    with pytest.raises(AuthenticationError) as error:
        _validated_identity({**base, "name": "Mutable Name", "preferred_username": "mutable@example.test", "displayname": None}, settings)
    assert error.value.code == "userinfo_required"


@pytest.mark.parametrize("claim,value", [
    ("", "human"), ("scope", "human"), ("displayname", "human"),
    ("delegated user", "human"), ("delegated_user", ""),
    ("delegated_user", " human "),
])
def test_ping_direct_settings_path_requires_valid_delegation_contract(claim, value):
    from dataclasses import replace
    with pytest.raises(AuthenticationError) as error:
        _validated_identity({"scope": "quota.read", "sub": "person-7", "delegated_user": "true"}, replace(_settings(), auth_provider="ping", auth_scope="quota.read", ping_delegated_claim=claim, ping_delegated_value=value))
    assert error.value.code == "delegation_contract_invalid"


@pytest.mark.asyncio
async def test_exact_id_duplicate_governance_users_fail_closed():
    payload = {"users": [{"id": "bifrost-user-7"}, {"id": "bifrost-user-7"}]}
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))) as client:
        with pytest.raises(ToolError, match="No unique"):
            await BifrostClient(_settings(), client=client).fetch_user_usage(admin_api_key="admin-secret", user_identifier="bifrost-user-7", exact_id=True)


@pytest.mark.asyncio
async def test_ping_userinfo_must_bind_subject_and_does_not_follow_redirects():
    settings = BifrostSettings(api_base_url="https://bifrost.example.test", userinfo_url="https://ping.example.test/userinfo")
    request_urls = []
    def handler(request):
        request_urls.append(str(request.url))
        return httpx.Response(200, json={"sub": "another-subject", "name": "Wrong User", "preferred_username": "wrong@example.test"})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ToolError, match="subject binding"):
            await BifrostClient(settings, client=client).fetch_userinfo_identity(
                authorization="Bearer already-verified-token", expected_subject="verified-subject")
    assert request_urls == ["https://ping.example.test/userinfo"]


@pytest.mark.asyncio
async def test_missing_provider_configuration_fails_before_client_or_governance(monkeypatch):
    import importlib
    server_module = importlib.import_module("bifrost_budget.server")
    _set_env(monkeypatch)
    monkeypatch.delenv("BIFROST_ENTRA_USER_MAP")
    result = await _invoke_tool(server_module.create_server(), "Bearer opaque")
    assert result.is_error
    messages = [getattr(block, "text", "") for block in result.content]
    assert all("admin-secret" not in message and "tenant-guid" not in message for message in messages)


@pytest.mark.asyncio
async def test_explicit_ping_provider_validates_then_uses_subject_bound_userinfo(monkeypatch):
    import importlib
    server_module = importlib.import_module("bifrost_budget.server")
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update(kid="key-1", use="sig", alg="RS256")
    ping_issuer = "https://ping.example.test/oauth"
    ping_audience = "ping-resource"
    ping_discovery = "https://ping.example.test/metadata"
    ping_jwks = "https://ping.example.test/keys"
    userinfo = "https://ping.example.test/userinfo"
    calls = []
    def handler(request):
        calls.append(request)
        if str(request.url) == ping_discovery:
            return httpx.Response(200, json={"issuer": ping_issuer, "jwks_uri": ping_jwks})
        if str(request.url) == ping_jwks:
            return httpx.Response(200, json={"keys": [jwk]})
        if str(request.url) == userinfo:
            assert request.headers.get("authorization", "").startswith("Bearer ")
            return httpx.Response(200, json={"sub": "ping-subject", "name": "Ping Legacy Name", "preferred_username": "fallback@example.test"})
        if request.url.path == "/api/governance/users":
            assert request.headers.get("authorization") == "Bearer admin-secret"
            assert request.url.params.get("search") == "Ping Legacy Name"
            return httpx.Response(200, json={"users": [{"name": "Ping Legacy Name", "access_profiles": [{"budgets": [{"name": "daily", "limit": "10", "current_usage": "4"}]}]}]})
        raise AssertionError("unexpected outbound request")
    class MockBifrostClient(BifrostClient):
        def __init__(self, settings): super().__init__(settings, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        async def __aexit__(self, *args): await self._client.aclose()
    monkeypatch.setattr(server_module, "BifrostClient", MockBifrostClient)
    monkeypatch.setenv("BIFROST_API_BASE_URL", "https://bifrost.example.test")
    monkeypatch.setenv("BIFROST_ADMIN_API_KEY", "admin-secret")
    monkeypatch.setenv("BIFROST_AUTH_PROVIDER", "ping")
    monkeypatch.setenv("BIFROST_PING_ISSUER", ping_issuer)
    monkeypatch.setenv("BIFROST_PING_AUDIENCE", ping_audience)
    monkeypatch.setenv("BIFROST_PING_DISCOVERY_URL", ping_discovery)
    monkeypatch.setenv("BIFROST_PING_JWKS_URL", ping_jwks)
    monkeypatch.setenv("BIFROST_PING_SCOPE", "quota.read")
    monkeypatch.setenv("BIFROST_PING_DELEGATED_CLAIM", "delegated_user")
    monkeypatch.setenv("BIFROST_PING_DELEGATED_VALUE", "human")
    monkeypatch.setenv("BIFROST_USERINFO_URL", userinfo)
    token = jwt.encode({"iss": ping_issuer, "aud": ping_audience, "sub": "ping-subject", "exp": int(time.time())+300, "nbf": int(time.time())-1, "scope": "quota.read", "delegated_user": "human"}, private, algorithm="RS256", headers={"kid": "key-1"})
    result = await _invoke_tool(server_module.create_server(), "Bearer " + token)
    assert result.is_error is False
    assert result.structured_content["budgets"][0]["remaining"] == 6.0
    assert [request.url.path for request in calls] == ["/metadata", "/keys", "/userinfo", "/api/governance/users"]


@pytest.mark.asyncio
@pytest.mark.parametrize("extra", [
    {"gty": "client-credentials", "client_id": "synthetic-client", "sub": "synthetic-client", "displayname": "Synthetic Human", "delegated_user": None},
    {"scope": "quota.read", "displayname": "Synthetic Human", "delegated_user": None},
    {"delegated_user": ["human"], "displayname": "Synthetic Human"},
    {"delegated_user": True, "displayname": "Synthetic Human"},
    {"delegated_user": "other", "displayname": "Synthetic Human"},
    {"scope": ["quota.read"], "displayname": "Synthetic Human"},
    {"idtyp": "app", "delegated_user": "human", "displayname": "Synthetic Human"},
    {"idtyp": " APP ", "delegated_user": "human", "displayname": "Synthetic Human"},
    {"idtyp": 1, "delegated_user": "human", "displayname": "Synthetic Human"},
    {"idtyp": ["app"], "delegated_user": "human", "displayname": "Synthetic Human"},
    {"idtyp": False, "delegated_user": "human", "displayname": "Synthetic Human"},
    {"idtyp": None, "delegated_user": "human", "displayname": "Synthetic Human"},
    {"gty": "client_credentials", "delegated_user": "human", "displayname": "Synthetic Human"},
    {"gty": " CLIENT_CREDENTIALS ", "delegated_user": "human", "displayname": "Synthetic Human"},
    {"gty": 1, "delegated_user": "human", "displayname": "Synthetic Human"},
    {"gty": ["user"], "delegated_user": "human", "displayname": "Synthetic Human"},
    {"gty": False, "delegated_user": "human", "displayname": "Synthetic Human"},
    {"gty": None, "delegated_user": "human", "displayname": "Synthetic Human"},
    {"grant_type": "client-credentials", "displayname": "Synthetic Human"},
    {"grant_type": "client_credentials", "displayname": "Synthetic Human"},
    {"grant_type": " Client_Credentials ", "delegated_user": "human", "displayname": "Synthetic Human"},
    {"grant_type": 1, "delegated_user": "human", "displayname": "Synthetic Human"},
    {"grant_type": ["authorization_code"], "delegated_user": "human", "displayname": "Synthetic Human"},
    {"grant_type": False, "delegated_user": "human", "displayname": "Synthetic Human"},
    {"grant_type": None, "delegated_user": "human", "displayname": "Synthetic Human"},
    {"client_id": "person-7", "displayname": "Synthetic Human"},
    {"sub": "", "displayname": "Synthetic Human"},
])
async def test_ping_signed_ambiguous_or_client_tokens_never_reach_governance(monkeypatch, extra):
    import importlib
    server_module = importlib.import_module("bifrost_budget.server")
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update(kid="key-1", use="sig", alg="RS256")
    issuer, audience = "https://ping.example.test/oauth", "ping-resource"
    discovery, keys = "https://ping.example.test/metadata", "https://ping.example.test/keys"
    calls = []
    def handler(request):
        calls.append(request)
        if str(request.url) == discovery: return httpx.Response(200, json={"issuer": issuer, "jwks_uri": keys})
        if str(request.url) == keys: return httpx.Response(200, json={"keys": [jwk]})
        if request.url.path == "/api/governance/users": return httpx.Response(200, json={"users": []})
        if str(request.url) == "https://ping.example.test/userinfo": return httpx.Response(200, json={"sub": "person-7", "name": "Synthetic Human"})
        raise AssertionError("unexpected outbound request")
    class MockBifrostClient(BifrostClient):
        def __init__(self, settings): super().__init__(settings, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        async def __aexit__(self, *args): await self._client.aclose()
    monkeypatch.setattr(server_module, "BifrostClient", MockBifrostClient)
    for key, value in {"BIFROST_API_BASE_URL": "https://bifrost.example.test", "BIFROST_ADMIN_API_KEY": "synthetic-admin", "BIFROST_AUTH_PROVIDER": "ping", "BIFROST_PING_ISSUER": issuer, "BIFROST_PING_AUDIENCE": audience, "BIFROST_PING_DISCOVERY_URL": discovery, "BIFROST_PING_JWKS_URL": keys, "BIFROST_PING_SCOPE": "quota.read", "BIFROST_PING_DELEGATED_CLAIM": "delegated_user", "BIFROST_PING_DELEGATED_VALUE": "human", "BIFROST_USERINFO_URL": "https://ping.example.test/userinfo"}.items(): monkeypatch.setenv(key, value)
    now = int(time.time())
    claims = {"iss": issuer, "aud": audience, "sub": "person-7", "exp": now+300, "nbf": now-1, "scope": "quota.read", "delegated_user": "human", **extra}
    if claims.get("delegated_user") is None:
        claims.pop("delegated_user", None)
    token = jwt.encode(claims, private, algorithm="RS256", headers={"kid": "key-1"})
    result = await _invoke_tool(server_module.create_server(), "Bearer " + token)
    assert result.is_error
    assert not any(request.url.path in {"/api/governance/users", "/userinfo"} for request in calls)


@pytest.mark.asyncio
async def test_ping_signed_delegation_marker_allows_legacy_displayname(monkeypatch):
    import importlib
    server_module = importlib.import_module("bifrost_budget.server")
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    jwk.update(kid="key-1", use="sig", alg="RS256")
    issuer, audience = "https://ping.example.test/oauth", "ping-resource"
    discovery, keys = "https://ping.example.test/metadata", "https://ping.example.test/keys"
    seen = []
    def handler(request):
        seen.append(request)
        if str(request.url) == discovery: return httpx.Response(200, json={"issuer": issuer, "jwks_uri": keys})
        if str(request.url) == keys: return httpx.Response(200, json={"keys": [jwk]})
        if request.url.path == "/api/governance/users": return httpx.Response(200, json={"users": [{"name": "Synthetic Human", "access_profiles": [{"budgets": [{"limit": "10", "current_usage": "4"}]}]}]})
        raise AssertionError("unexpected outbound request")
    class MockBifrostClient(BifrostClient):
        def __init__(self, settings): super().__init__(settings, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        async def __aexit__(self, *args): await self._client.aclose()
    monkeypatch.setattr(server_module, "BifrostClient", MockBifrostClient)
    for key, value in {"BIFROST_API_BASE_URL": "https://bifrost.example.test", "BIFROST_ADMIN_API_KEY": "synthetic-admin", "BIFROST_AUTH_PROVIDER": "ping", "BIFROST_PING_ISSUER": issuer, "BIFROST_PING_AUDIENCE": audience, "BIFROST_PING_DISCOVERY_URL": discovery, "BIFROST_PING_JWKS_URL": keys, "BIFROST_PING_SCOPE": "quota.read", "BIFROST_PING_DELEGATED_CLAIM": "delegated_user", "BIFROST_PING_DELEGATED_VALUE": "human", "BIFROST_USERINFO_URL": "https://ping.example.test/userinfo"}.items(): monkeypatch.setenv(key, value)
    now = int(time.time())
    token = jwt.encode({"iss": issuer, "aud": audience, "sub": "person-7", "exp": now+300, "nbf": now-1, "scope": "quota.read", "delegated_user": "human", "displayname": "Synthetic Human"}, private, algorithm="RS256", headers={"kid": "key-1"})
    result = await _invoke_tool(server_module.create_server(), "Bearer " + token)
    assert not result.is_error
    assert result.structured_content["budgets"][0]["remaining"] == 6.0
    assert all(request.url.path != "/userinfo" for request in seen)


@pytest.mark.asyncio
async def test_untrusted_key_url_and_discovery_outage_fail_closed():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    requests = []
    async def response(request):
        requests.append(str(request.url))
        return httpx.Response(503)
    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        verifier = TokenVerifier(issuer=ISSUER, audience=AUDIENCE, discovery_url=DISCOVERY, jwks_url=JWKS, client=client)
        token = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": "s", "exp": int(time.time())+300, "nbf": int(time.time())-1}, private, algorithm="RS256", headers={"kid": "key-1", "jku": "https://attacker.example.test/keys"})
        with pytest.raises(AuthenticationError):
            await verifier.verify("Bearer " + token)
        assert requests == []
        normal_token = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": "s", "exp": int(time.time())+300, "nbf": int(time.time())-1}, private, algorithm="RS256", headers={"kid": "key-1"})
        with pytest.raises(AuthenticationError) as exc:
            await verifier.verify("Bearer " + normal_token)
        assert exc.value.code == "key_service_unavailable"
        assert requests == [DISCOVERY]


def test_configure_logging_suppresses_http_library_urls_and_headers(caplog):
    import logging
    from bifrost_budget.logging import configure_logging
    caplog.set_level(logging.DEBUG)
    configure_logging("DEBUG")
    logging.getLogger("httpx").info("GET https://bifrost.test/users?search=private@example.test")
    logging.getLogger("httpcore").debug("send_request_headers.started headers=authorization:Bearer secret")
    assert "private@example.test" not in caplog.text
    assert "Bearer secret" not in caplog.text
