from __future__ import annotations

from datetime import datetime, timezone
import base64
import importlib
import json
import logging
from importlib.metadata import PackageNotFoundError, version as package_version

import httpx
import httpx2
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.transport_security import TransportSecuritySettings
from mcp.server.mcpserver.exceptions import ToolError

from bifrost_budget.client import BifrostClient
from bifrost_budget.logging import (
    authorization_diagnostics,
    build_credential_trace,
    configure_logging,
    fingerprint_value,
    header_diagnostics,
    raw_header_diagnostics,
    raw_header_logging_enabled,
    service_version_info,
)
from bifrost_budget import __version__
from bifrost_budget.__main__ import main
from bifrost_budget.normalization import normalize_quota_payload
from bifrost_budget.server import _resolve_credential, create_server
from bifrost_budget.settings import BifrostSettings


def _make_jwt(payload: dict[str, object]) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode("utf-8")).rstrip(b"=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=")
    return f"{header.decode('utf-8')}.{body.decode('utf-8')}.signature"


def test_main_emits_service_version_without_sensitive_configuration(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("BIFROST_API_BASE_URL", "https://bifrost.example.com")
    monkeypatch.setenv("BIFROST_ADMIN_API_KEY", "admin-secret")
    monkeypatch.setenv("BIFROST_BUILD_SHA", "abc123deadbeef")
    monkeypatch.setattr("bifrost_budget.__main__.asyncio.run", lambda coroutine: coroutine.close())
    caplog.set_level(logging.INFO, logger="bifrost_budget")

    main()

    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert '"event":"service_version"' in log_text
    assert f'"version":"{package_version("bifrost-budget")}"' in log_text
    assert '"build_id":"abc123deadbeef"' in log_text
    assert "admin-secret" not in log_text
    assert "Authorization" not in log_text
    assert __version__ == "0.3.0"


def test_raw_header_logging_is_explicitly_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    headers = {"Authorization": "Bearer test-token", "X-Debug": "clear-text-value"}

    monkeypatch.delenv("BIFROST_LOG_RAW_HEADERS", raising=False)
    assert raw_header_logging_enabled() is False
    assert raw_header_diagnostics(headers) == {"Authorization": "Bearer test-token", "X-Debug": "clear-text-value"}

    monkeypatch.setenv("BIFROST_LOG_RAW_HEADERS", "true")
    assert raw_header_logging_enabled() is True


def test_service_version_uses_unknown_for_missing_metadata_and_invalid_build_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for variable in ("BIFROST_BUILD_SHA", "GIT_SHA", "SOURCE_COMMIT"):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("BIFROST_BUILD_SHA", "not-a-sha-or-secret")
    monkeypatch.setattr(
        "bifrost_budget.logging.package_version",
        lambda _: (_ for _ in ()).throw(PackageNotFoundError("bifrost-budget")),
    )

    assert service_version_info() == {"version": "unknown", "build_id": "unknown"}


def test_maximal_diagnostics_never_include_header_or_claim_values() -> None:
    token = _make_jwt({"client_id": "client-secret", "iss": "issuer", "sub": "subject", "name": "Alice"})
    authorization = f"Bearer {token}"
    headers = {"Authorization": authorization, "Cookie": "session-cookie", "X-Request-ID": "request-123"}

    header_trace = header_diagnostics(headers)
    auth_trace = authorization_diagnostics(authorization)
    serialized = json.dumps({"headers": header_trace, "authorization": auth_trace})

    assert [item["name"] for item in header_trace] == ["authorization", "cookie", "x-request-id"]
    assert all(set(item) == {"name", "present", "value_type", "value_length", "value_fingerprint", "sensitive"} for item in header_trace)
    assert auth_trace["decode_success"] is True
    assert auth_trace["claim_keys"] == ["client_id", "iss", "name", "sub"]
    assert auth_trace["token_segment_count"] == 3
    for secret in (authorization, token, "client-secret", "issuer", "subject", "Alice", "session-cookie", "request-123"):
        assert secret not in serialized


@pytest.mark.asyncio
async def test_normalize_quota_payload_derives_remaining_values() -> None:
    payload = {
        "budgets": [
            {
                "name": "global",
                "limit": 1000,
                "used": 250,
                "unit": "requests",
                "period": "daily",
                "reset_at": "2026-09-02T00:00:00Z",
            },
            {
                "scope": "team-a",
                "quota": "500",
                "consumed": "125",
                "remaining": 375,
                "window": "hourly",
            },
        ]
    }

    report = normalize_quota_payload(
        payload,
        endpoint="https://bifrost.example.com/api/governance/virtual-keys/quota",
        auth_source="tool_argument",
        queried_at=datetime(2026, 9, 1, tzinfo=timezone.utc),
    )

    assert report.summary.budget_count == 2
    assert report.summary.limit_total == 1500
    assert report.summary.consumed_total == 375
    assert report.summary.remaining_total == 1125
    assert report.budgets[0].remaining == 750
    assert report.budgets[0].derived_remaining is True
    assert report.budgets[1].remaining == 375
    assert report.budgets[1].derived_remaining is False


@pytest.mark.asyncio
async def test_build_credential_trace_redacts_authorization_token_and_extracts_safe_claims() -> None:
    token = _make_jwt({"iss": "https://issuer.example.com", "sub": "user-123", "tenant": "tenant-42"})
    credential = f"Bearer {token}"

    trace = build_credential_trace(
        credential,
        auth_source="request_header:authorization",
        credential_mode="authorization",
    )

    assert trace["auth_source"] == "request_header:authorization"
    assert trace["credential_mode"] == "authorization"
    assert trace["token_present"] is True
    assert trace["scheme"] == "Bearer"
    assert trace["token_fingerprint"] == fingerprint_value(token)
    assert trace["claim_keys"] == ["iss", "sub", "tenant"]
    assert trace["claim_fingerprints"]["sub"] == fingerprint_value("user-123")
    assert trace["claim_lengths"]["sub"] == len("user-123")
    assert trace["token_length"] == len(token)
    assert trace["identity_fingerprint"] == fingerprint_value("user-123")
    assert token not in json.dumps(trace)
    assert "signature" not in json.dumps(trace)


@pytest.mark.asyncio
async def test_client_builds_expected_request_headers_and_url() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["url"] = str(request.url)
        seen["x-bf-vk"] = request.headers.get("x-bf-vk")
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(
            200,
            json={
                "budgets": [
                    {"name": "caller", "limit": 20, "used": 5, "unit": "requests"}
                ]
            },
        )

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport, base_url="https://bifrost.example.com")
    settings = BifrostSettings(api_base_url="https://bifrost.example.com")
    try:
        bifrost = BifrostClient(settings, client=client)
        report = await bifrost.fetch_quota(
            credential="vk-test",
            credential_mode="virtual_key",
            auth_source="tool_argument",
        )
    finally:
        await client.aclose()

    assert seen["method"] == "GET"
    assert seen["url"] == "https://bifrost.example.com/api/governance/virtual-keys/quota"
    assert seen["x-bf-vk"] == "vk-test"
    assert seen["authorization"] is None
    assert report["summary"]["remaining_total"] == 15


@pytest.mark.asyncio
async def test_client_forwards_authorization_header_when_present() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["authorization"] = request.headers.get("authorization")
        seen["x-bf-vk"] = request.headers.get("x-bf-vk")
        return httpx.Response(200, json={"budgets": [{"name": "caller", "limit": 20, "used": 5}]})

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport, base_url="https://bifrost.example.com")
    settings = BifrostSettings(api_base_url="https://bifrost.example.com")
    try:
        bifrost = BifrostClient(settings, client=client)
        report = await bifrost.fetch_quota(
            credential="Bearer auth-token",
            credential_mode="authorization",
            auth_source="request_header:authorization",
        )
    finally:
        await client.aclose()

    assert seen["authorization"] == "Bearer auth-token"
    assert seen["x-bf-vk"] is None
    assert report["summary"]["remaining_total"] == 15


@pytest.mark.asyncio
async def test_client_emits_structured_logs_for_request_and_success(caplog: pytest.LogCaptureFixture) -> None:
    configure_logging("INFO")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"budgets": [{"name": "caller", "limit": 20, "used": 5}]})

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport, base_url="https://bifrost.example.com")
    settings = BifrostSettings(api_base_url="https://bifrost.example.com")
    caplog.set_level(logging.INFO, logger="bifrost_budget")
    token = _make_jwt({"iss": "https://issuer.example.com", "sub": "user-123", "tenant": "tenant-42"})
    credential = f"Bearer {token}"
    try:
        bifrost = BifrostClient(settings, client=client)
        await bifrost.fetch_quota(
            credential=credential,
            credential_mode="authorization",
            auth_source="request_header:authorization",
        )
    finally:
        await client.aclose()

    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert '"event":"upstream_quota_request"' in log_text
    assert '"event":"upstream_quota_success"' in log_text
    assert '"outbound_auth_mode":"authorization"' in log_text
    assert '"auth_headers":["authorization"]' in log_text
    assert token not in log_text
    assert 'user-123' not in log_text


@pytest.mark.asyncio
async def test_client_logs_safe_401_details_before_raising(caplog: pytest.LogCaptureFixture) -> None:
    configure_logging("INFO")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            headers={"www-authenticate": 'Bearer realm="bifrost"', "content-type": "application/json"},
            text=(
                '{"error":"unauthorized","hint":"use mapped virtual key",'
                '"token":"upstream-body-token","authorization":"Bearer upstream-body-auth",'
                '"name":"Alice Admin","email":"alice@example.com","sub":"subject-123",'
                '"admin_key":"upstream-admin-key"}'
            ),
        )

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport, base_url="https://bifrost.example.com")
    settings = BifrostSettings(api_base_url="https://bifrost.example.com")
    caplog.set_level(logging.INFO, logger="bifrost_budget")
    try:
        bifrost = BifrostClient(settings, client=client)
        with pytest.raises(Exception):
            await bifrost.fetch_quota(
                credential="Bearer auth-secret",
                credential_mode="authorization",
                auth_source="request_header:authorization",
            )
    finally:
        await client.aclose()

    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert '"event":"upstream_quota_error"' in log_text
    assert '"status_code":401' in log_text
    assert '"response_header_names":["content-length","content-type","www-authenticate"]' in log_text
    assert '"response_content_type":"application/json"' in log_text
    assert '"error_type":"upstream_http_error"' in log_text
    for secret in (
        "upstream-body-token",
        "upstream-body-auth",
        "Alice Admin",
        "alice@example.com",
        "subject-123",
        "upstream-admin-key",
        "auth-secret",
    ):
        assert secret not in log_text


@pytest.mark.asyncio
async def test_server_exposes_health_route_and_tool_metadata() -> None:
    server = create_server()
    tool_names = {tool.name for tool in await server.list_tools()}
    assert "get_quota" in tool_names

    tool = next(tool for tool in await server.list_tools() if tool.name == "get_quota")
    assert "Authorization header" in (tool.description or "")
    assert "BIFROST_AUTH_EXCHANGE_MAP" not in (tool.description or "")

    app = server.streamable_http_app(streamable_http_path="/mcp", stateless_http=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "bifrost-budget"}


@pytest.mark.asyncio
async def test_streamable_http_tool_path_selects_name_claim(monkeypatch: pytest.MonkeyPatch) -> None:
    name = "Ping User"
    token = _make_jwt(
        {
            "name": name,
            "preferred_username": "ping-user",
            "email": "ping-user@example.com",
            "sub": "subject-123456789012345678901234567890",
            "iss": "https://issuer.example.com",
            "client_id": "client-123",
        }
    )
    seen: dict[str, object] = {}

    class FakeClient:
        def __init__(self, settings: BifrostSettings) -> None:
            pass

        async def __aenter__(self) -> "FakeClient":
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def fetch_user_usage(self, *, admin_api_key: str, user_identifier: str) -> dict[str, object]:
            seen.update(admin_api_key=admin_api_key, user_identifier=user_identifier)
            return {"budgets": [], "summary": {"budget_count": 0}}

    server_module = importlib.import_module("bifrost_budget.server")
    monkeypatch.setattr(server_module, "BifrostClient", FakeClient)
    monkeypatch.setenv("BIFROST_API_BASE_URL", "https://bifrost.example.com")
    monkeypatch.setenv("BIFROST_ADMIN_API_KEY", "admin-secret")
    app = create_server().streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        json_response=True,
        transport_security=TransportSecuritySettings(allowed_hosts=["test"]),
    )
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url="http://test",
            headers={"authorization": f"Bearer {token}"},
        ) as http_client:
            async with streamable_http_client(
                "http://test/mcp", http_client=http_client, terminate_on_close=False
            ) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    result = await session.call_tool("get_quota", {})

    assert result.is_error is False
    assert seen == {"admin_api_key": "admin-secret", "user_identifier": name}

@pytest.mark.asyncio
async def test_virtual_key_resolution_prefers_explicit_argument() -> None:
    class DummyContext:
        headers = {"x-bf-vk": "header-secret", "authorization": "Bearer auth-secret"}

    settings = BifrostSettings(api_base_url="https://bifrost.example.com")
    resolved, source, mode, trace = _resolve_credential("explicit-secret", DummyContext(), settings)
    assert resolved == "explicit-secret"
    assert source == "tool_argument"
    assert mode == "virtual_key"
    assert trace["token_fingerprint"] == fingerprint_value("explicit-secret")


@pytest.mark.asyncio
async def test_resolve_credential_uses_authorization_header_directly(caplog: pytest.LogCaptureFixture) -> None:
    configure_logging("DEBUG")

    class DummyContext:
        headers = {
            "authorization": f"Bearer {_make_jwt({'iss': 'https://issuer.example.com', 'sub': 'user-123', 'tenant': 'tenant-42'})}",
            "x-bf-vk": "header-secret",
        }

    caplog.set_level(logging.DEBUG, logger="bifrost_budget")
    settings = BifrostSettings(api_base_url="https://bifrost.example.com")
    resolved, source, mode, trace = _resolve_credential(None, DummyContext(), settings)

    assert resolved == DummyContext.headers["authorization"]
    assert source == "request_header:authorization"
    assert mode == "authorization"
    assert trace["claim_keys"] == ["iss", "sub", "tenant"]
    assert trace["identity"] == "user-123"
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert '"event":"auth_source_selected"' in log_text
    assert '"event":"auth_decision_complete"' in log_text
    assert '"outbound_auth_mode":"authorization"' in log_text
    assert 'user-123' not in log_text


@pytest.mark.asyncio
async def test_resolve_credential_prefers_name_claim_from_supplied_pingidentity_jwt(
    caplog: pytest.LogCaptureFixture,
) -> None:
    configure_logging("INFO")
    caplog.set_level(logging.INFO, logger="bifrost_budget")
    name = "Ping User"
    token = _make_jwt({
        "name": name,
        "preferred_username": "ping-user",
        "email": "ping-user@example.com",
        "sub": "subject-123456789012345678901234567890",
        "iss": "https://issuer.example.com",
        "client_id": "client-123",
    })

    class DummyContext:
        headers = {"authorization": f"Bearer {token}"}

    settings = BifrostSettings(api_base_url="https://bifrost.example.com")
    resolved, source, mode, trace = _resolve_credential(None, DummyContext(), settings)

    assert resolved == f"Bearer {token}"
    assert source == "request_header:authorization"
    assert mode == "authorization"
    assert trace["claim_keys"] == ["client_id", "email", "iss", "name", "preferred_username", "sub"]
    assert trace["identity_fingerprint"] == fingerprint_value(name)
    assert trace["selected_identity_claim"] == "name"
    assert trace["identity_extraction_source"] == "raw_authorization_jwt"
    assert trace["identity_selection_reason"] == "selected_name_claim"
    assert trace["identity"] == name

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"users": [{
            "name": name,
            "access_profiles": [{"budgets": [{"name": "daily", "limit": 10, "current_usage": 2}]}],
        }]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://bifrost.example.com") as client:
        report = await BifrostClient(settings, client=client).fetch_user_usage(
            admin_api_key="admin-secret",
            user_identifier=trace["identity"],
        )
    assert report["budgets"][0]["consumed"] == 2
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert name not in log_text
    assert "ping-user@example.com" not in log_text
    assert token not in log_text


@pytest.mark.asyncio
async def test_resolve_credential_falls_back_to_virtual_key_header() -> None:
    class DummyContext:
        headers = {"x-bf-vk": "header-secret"}

    settings = BifrostSettings(api_base_url="https://bifrost.example.com")
    resolved, source, mode, trace = _resolve_credential(None, DummyContext(), settings)

    assert resolved == "header-secret"
    assert source == "request_header:x-bf-vk"
    assert mode == "virtual_key"
    assert trace["token_fingerprint"] == fingerprint_value("header-secret")


@pytest.mark.asyncio
async def test_resolve_credential_uses_default_virtual_key_fallback_when_no_headers_exist(caplog: pytest.LogCaptureFixture) -> None:
    configure_logging("INFO")

    class DummyContext:
        headers = {}

    settings = BifrostSettings(api_base_url="https://bifrost.example.com", default_virtual_key="vk-default")
    caplog.set_level(logging.INFO, logger="bifrost_budget")
    resolved, source, mode, trace = _resolve_credential(None, DummyContext(), settings)

    assert resolved == "vk-default"
    assert source == "environment:BIFROST_VIRTUAL_KEY"
    assert mode == "virtual_key"
    assert trace["token_fingerprint"] == fingerprint_value("vk-default")
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert '"event":"auth_source_selected"' in log_text


@pytest.mark.asyncio
async def test_user_usage_uses_admin_key_and_ping_identity_separately() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, json={"users": [{
            "name": "alice@example.com",
            "access_profiles": [{"budgets": [{"name": "daily", "limit": 100, "current_usage": 27}]}],
        }]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://bifrost.example.com")
    try:
        bifrost = BifrostClient(BifrostSettings(api_base_url="https://bifrost.example.com"), client=client)
        report = await bifrost.fetch_user_usage(admin_api_key="admin-secret", user_identifier="alice@example.com")
    finally:
        await client.aclose()

    assert seen["url"] == "https://bifrost.example.com/api/governance/users?limit=20"
    assert seen["authorization"] == "Bearer admin-secret"
    assert report["budgets"][0]["consumed"] == 27
    assert report["summary"]["remaining_total"] == 73


@pytest.mark.asyncio
async def test_user_usage_returns_empty_for_malformed_budget_entries() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"users": [{
            "name": "alice",
            "access_profiles": [{"budgets": [{"name": "missing-usage"}, "not-a-budget"]}],
        }]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://bifrost.example.com")
    try:
        bifrost = BifrostClient(BifrostSettings(api_base_url="https://bifrost.example.com"), client=client)
        report = await bifrost.fetch_user_usage(admin_api_key="admin-secret", user_identifier="alice")
    finally:
        await client.aclose()

    assert report["budgets"] == []
    assert report["summary"]["budget_count"] == 0


@pytest.mark.asyncio
async def test_user_usage_raises_tool_error_when_pingidentity_user_has_no_match(
    caplog: pytest.LogCaptureFixture,
) -> None:
    configure_logging("INFO")
    caplog.set_level(logging.INFO, logger="bifrost_budget")
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, json={"users": [{"name": "different-user@example.com"}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://bifrost.example.com")
    try:
        bifrost = BifrostClient(BifrostSettings(api_base_url="https://bifrost.example.com"), client=client)
        with pytest.raises(ToolError, match="No Bifrost governance user matched the authenticated PingIdentity user"):
            await bifrost.fetch_user_usage(
                admin_api_key="admin-secret",
                user_identifier="pingidentity-user@example.com",
            )
    finally:
        await client.aclose()

    assert seen["url"] == "https://bifrost.example.com/api/governance/users?limit=20"
    assert seen["authorization"] == "Bearer admin-secret"
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert '"event":"user_lookup_match"' in log_text
    assert '"event":"governance_user_request"' in log_text
    assert '"event":"governance_user_response"' in log_text
    assert '"returned_user_count":1' in log_text
    assert '"match_count":0' in log_text
    assert '"match_reason":"no_supported_identity_field_match"' in log_text
    assert '"identity_fields":["name"]' in log_text
    assert '"search_identity_length":29' in log_text
    assert fingerprint_value("different-user@example.com") in log_text
    assert "admin-secret" not in log_text
    assert "pingidentity-user@example.com" not in log_text


@pytest.mark.asyncio
async def test_user_usage_logs_masked_candidate_match_metadata(caplog: pytest.LogCaptureFixture) -> None:
    configure_logging("INFO")
    caplog.set_level(logging.INFO, logger="bifrost_budget")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"users": [{"email": "alice@example.com"}]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://bifrost.example.com")
    try:
        bifrost = BifrostClient(BifrostSettings(api_base_url="https://bifrost.example.com"), client=client)
        await bifrost.fetch_user_usage(admin_api_key="admin-secret", user_identifier="alice@example.com")
    finally:
        await client.aclose()

    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert '"match_reason":"matched"' in log_text
    assert '"matched_fields":["email"]' in log_text
    assert fingerprint_value("alice@example.com") in log_text
    assert "alice@example.com" not in log_text
    assert "admin-secret" not in log_text


@pytest.mark.asyncio
async def test_successful_user_lookup_logs_only_masked_identity_diagnostics(
    caplog: pytest.LogCaptureFixture,
) -> None:
    configure_logging("INFO")
    caplog.set_level(logging.INFO, logger="bifrost_budget")
    email = "alice.sensitive@example.com"
    name = "Alice Sensitive"
    subject = "ping-subject-sensitive"
    token = _make_jwt({"name": name, "email": email, "sub": subject, "iss": "https://issuer.example.com"})
    authorization = f"Bearer {token}"
    seen: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, json={"users": [{
            "name": name,
            "email": email,
            "id": "candidate-id-sensitive",
            "access_profiles": [{"budgets": [{"name": "daily", "limit": 10, "current_usage": 2}]}],
        }]})

    settings = BifrostSettings(api_base_url="https://bifrost.example.com")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://bifrost.example.com") as client:
        bifrost = BifrostClient(settings, client=client)
        report = await bifrost.fetch_user_usage(
            admin_api_key="admin-api-key-sensitive",
            user_identifier=email,
        )

    assert seen == {
        "url": "https://bifrost.example.com/api/governance/users?limit=20",
        "authorization": "Bearer admin-api-key-sensitive",
    }
    assert report["budgets"][0]["consumed"] == 2
    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert '"event":"governance_user_request"' in log_text
    assert '"event":"governance_user_response"' in log_text
    assert '"event":"user_lookup_match"' in log_text
    assert '"request_url":"https://bifrost.example.com/api/governance/users?limit=20"' in log_text
    assert '"status_code":200' in log_text
    assert '"returned_user_count":1' in log_text
    assert '"match_count":1' in log_text
    assert '"match_reason":"matched"' in log_text
    assert '"identity_fields":["email","id","name"]' in log_text
    assert '"search_identity_length":27' in log_text
    email_fingerprint = fingerprint_value(email)
    assert email_fingerprint is not None
    assert email_fingerprint in log_text
    assert email not in log_text
    assert name not in log_text
    assert subject not in log_text
    assert "candidate-id-sensitive" not in log_text
    assert token not in log_text
    assert authorization not in log_text
    assert "admin-api-key-sensitive" not in log_text


@pytest.mark.asyncio
async def test_user_usage_logs_explicit_candidate_field_reasons_without_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    configure_logging("INFO")
    caplog.set_level(logging.INFO, logger="bifrost_budget")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"users": [
            {"username": "other-user"},
            {"email": 12345},
            {"id": "different-user"},
            {"name": "Alice X"},
            {"display_name": "unusable-field"},
        ]})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="https://bifrost.example.com")
    try:
        bifrost = BifrostClient(BifrostSettings(api_base_url="https://bifrost.example.com"), client=client)
        with pytest.raises(ToolError):
            await bifrost.fetch_user_usage(admin_api_key="admin-secret", user_identifier="alice")
    finally:
        await client.aclose()

    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert '"match_reason_detail":"field_non_string"' in log_text
    assert '"match_reason_detail":"field_absent"' in log_text
    assert '"match_reason_detail":"normalized_mismatch"' in log_text
    assert '"field_metadata"' in log_text
    assert "other-user" not in log_text
    assert "different-user" not in log_text
    assert "admin-secret" not in log_text
