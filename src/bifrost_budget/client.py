from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from mcp.server.mcpserver.exceptions import ToolError

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

    async def fetch_quota(self, *, virtual_key: str, auth_source: str) -> dict[str, Any]:
        headers = {
            "accept": "application/json",
            "x-bf-vk": virtual_key,
        }
        response = await self._client.get(self.settings.quota_url, headers=headers)
        if response.status_code >= 400:
            raise ToolError(
                f"Bifrost quota lookup failed with HTTP {response.status_code} from {self.settings.quota_url}"
            )

        try:
            payload = response.json()
        except ValueError as exc:  # pragma: no cover - defensive guard
            raise ToolError("Bifrost quota lookup returned invalid JSON") from exc

        report = normalize_quota_payload(
            payload,
            endpoint=self.settings.quota_url,
            auth_source=auth_source,
            queried_at=datetime.now(timezone.utc),
        )
        return report.model_dump(mode="json")
