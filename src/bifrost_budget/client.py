from __future__ import annotations

from datetime import datetime, timezone
import logging
import time
from typing import Any, Literal

import httpx
from mcp.server.mcpserver.exceptions import ToolError

from .logging import build_credential_trace, log_event
from .normalization import normalize_quota_payload
from .settings import BifrostSettings


class BifrostClient:
    def __init__(self, settings: BifrostSettings, client: httpx.AsyncClient | None = None) -> None:
        self.settings = settings
        self._client = client or httpx.AsyncClient(timeout=settings.timeout_seconds)
        self._owns_client = client is None

    async def __aenter__(self) -> "BifrostClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def fetch_quota(
        self,
        *,
        credential: str,
        credential_mode: Literal["authorization", "virtual_key"],
        auth_source: str,
    ) -> dict[str, Any]:
        started_at = time.perf_counter()
        headers = {
            "accept": "application/json",
        }
        if credential_mode == "authorization":
            headers["authorization"] = credential
        else:
            headers["x-bf-vk"] = credential
        log_event(
            logging.INFO,
            "upstream_quota_request",
            quota_url=self.settings.quota_url,
            auth_source=auth_source,
            credential_identity=build_credential_trace(
                credential,
                auth_source=auth_source,
                credential_mode=credential_mode,
            ),
        )
        response = await self._client.get(self.settings.quota_url, headers=headers)
        if response.status_code >= 400:
            log_event(
                logging.ERROR,
                "upstream_quota_error",
                quota_url=self.settings.quota_url,
                auth_source=auth_source,
                credential_identity=build_credential_trace(
                    credential,
                    auth_source=auth_source,
                    credential_mode=credential_mode,
                ),
                status_code=response.status_code,
                duration_ms=round((time.perf_counter() - started_at) * 1000, 2),
            )
            raise ToolError(
                f"Bifrost quota lookup failed with HTTP {response.status_code} from {self.settings.quota_url}"
            )

        try:
            payload = response.json()
        except ValueError as exc:  # pragma: no cover - defensive guard
            log_event(
                logging.ERROR,
                "upstream_quota_error",
                quota_url=self.settings.quota_url,
                auth_source=auth_source,
                credential_identity=build_credential_trace(
                    credential,
                    auth_source=auth_source,
                    credential_mode=credential_mode,
                ),
                error_type=type(exc).__name__,
                duration_ms=round((time.perf_counter() - started_at) * 1000, 2),
            )
            raise ToolError("Bifrost quota lookup returned invalid JSON") from exc

        report = normalize_quota_payload(
            payload,
            endpoint=self.settings.quota_url,
            auth_source=auth_source,
            queried_at=datetime.now(timezone.utc),
        )
        log_event(
            logging.INFO,
            "upstream_quota_success",
            quota_url=self.settings.quota_url,
            auth_source=auth_source,
            credential_identity=build_credential_trace(
                credential,
                auth_source=auth_source,
                credential_mode=credential_mode,
            ),
            status_code=response.status_code,
            budget_count=report.summary.budget_count,
            remaining_total=report.summary.remaining_total,
            duration_ms=round((time.perf_counter() - started_at) * 1000, 2),
        )
        return report.model_dump(mode="json")
