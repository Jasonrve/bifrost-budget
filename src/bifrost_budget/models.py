from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class BudgetItem(BaseModel):
    name: str
    limit: float | int | None = None
    consumed: float | int | None = None
    remaining: float | int | None = None
    unit: str | None = None
    period: str | None = None
    reset_at: datetime | None = None
    source_path: str
    derived_remaining: bool = False
    details: dict[str, Any] = Field(default_factory=dict)


class QuotaSummary(BaseModel):
    budget_count: int
    limit_total: float | int | None = None
    consumed_total: float | int | None = None
    remaining_total: float | int | None = None
    exhausted_budgets: int = 0


class QuotaReport(BaseModel):
    service: str = "bifrost-budget"
    endpoint: str
    auth_source: str
    queried_at: datetime
    budgets: list[BudgetItem]
    summary: QuotaSummary
    raw_payload: dict[str, Any] | list[Any] | str | int | float | bool | None = None
