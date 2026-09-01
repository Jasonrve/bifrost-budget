from __future__ import annotations

from datetime import datetime, timezone
import logging

import httpx
import pytest

from bifrost_budget.client import BifrostClient
from bifrost_budget.logging import configure_logging
from bifrost_budget.normalization import normalize_quota_payload
from bifrost_budget.server import _resolve_credential, create_server
from bifrost_budget.settings import BifrostSettings


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
async def test_client_emits_structured_logs_for_request_and_success(caplog: pytest.LogCaptureFixture) -> None:
    configure_logging("INFO")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"budgets": [{"name": "caller", "limit": 20, "used": 5}]})

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport, base_url="https://bifrost.example.com")
    settings = BifrostSettings(api_base_url="https://bifrost.example.com")
    caplog.set_level(logging.INFO, logger="bifrost_budget")
    try:
        bifrost = BifrostClient(settings, client=client)
        await bifrost.fetch_quota(
            credential="Bearer auth-secret",
            credential_mode="authorization",
            auth_source="request_header:authorization",
        )
    finally:
        await client.aclose()

    log_text = "\n".join(record.getMessage() for record in caplog.records)
    assert '"event":"upstream_quota_request"' in log_text
    assert '"event":"upstream_quota_success"' in log_text
    assert 'auth-secret' not in log_text


@pytest.mark.asyncio
async def test_server_exposes_health_route_and_tool_metadata() -> None:
    server = create_server()
    tool_names = {tool.name for tool in await server.list_tools()}
    assert "get_quota" in tool_names

    tool = next(tool for tool in await server.list_tools() if tool.name == "get_quota")
    assert "Authorization header" in (tool.description or "")

    app = server.streamable_http_app(streamable_http_path="/mcp", stateless_http=True)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "bifrost-budget"}


@pytest.mark.asyncio
async def test_virtual_key_resolution_prefers_explicit_argument() -> None:
    class DummyContext:
        headers = {"x-bf-vk": "header-secret", "authorization": "Bearer auth-secret"}

    resolved, source, mode = _resolve_credential("explicit-secret", DummyContext())
    assert resolved == "explicit-secret"
    assert source == "tool_argument"
    assert mode == "virtual_key"


@pytest.mark.asyncio
async def test_resolve_credential_prefers_authorization_header(caplog: pytest.LogCaptureFixture) -> None:
    configure_logging("INFO")

    class DummyContext:
        headers = {"authorization": "Bearer auth-secret", "x-bf-vk": "header-secret"}

    caplog.set_level(logging.INFO, logger="bifrost_budget")
    resolved, source, mode = _resolve_credential(None, DummyContext())

    assert resolved == "Bearer auth-secret"
    assert source == "request_header:authorization"
    assert mode == "authorization"
    assert any("auth_source_selected" in record.getMessage() for record in caplog.records)


@pytest.mark.asyncio
async def test_resolve_credential_falls_back_to_virtual_key_header() -> None:
    class DummyContext:
        headers = {"x-bf-vk": "header-secret"}

    resolved, source, mode = _resolve_credential(None, DummyContext())

    assert resolved == "header-secret"
    assert source == "request_header:x-bf-vk"
    assert mode == "virtual_key"
