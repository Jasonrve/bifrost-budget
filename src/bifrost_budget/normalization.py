from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any

from .models import BudgetItem, QuotaReport, QuotaSummary

NAME_KEYS = ("name", "budget", "scope", "kind", "resource", "metric", "type", "label")
LIMIT_KEYS = ("limit", "quota", "cap", "max", "capacity", "allowed", "total")
CONSUMED_KEYS = ("consumed", "used", "usage", "spent", "consumption", "current")
REMAINING_KEYS = ("remaining", "left", "available", "balance")
UNIT_KEYS = ("unit", "units", "metric_unit", "measure")
PERIOD_KEYS = ("period", "window", "interval", "cycle")
RESET_KEYS = ("reset_at", "resets_at", "reset", "refresh_at", "expires_at")
CONTAINER_KEYS = ("budgets", "quota", "quotas", "limits", "allocations", "items", "data")


def normalize_quota_payload(payload: Any, *, endpoint: str, auth_source: str, queried_at: datetime) -> QuotaReport:
    raw_records = _collect_budget_records(payload)
    normalized = [normalize_budget_record(record, source_path=path) for record, path in raw_records]
    summary = build_summary(normalized)
    return QuotaReport(
        endpoint=endpoint,
        auth_source=auth_source,
        queried_at=queried_at,
        budgets=normalized,
        summary=summary,
        raw_payload=payload if isinstance(payload, (dict, list, str, int, float, bool)) or payload is None else repr(payload),
    )


def normalize_budget_record(record: dict[str, Any], *, source_path: str) -> BudgetItem:
    name = _first_str(record, NAME_KEYS) or source_path
    limit = _first_number(record, LIMIT_KEYS)
    consumed = _first_number(record, CONSUMED_KEYS)
    remaining = _first_number(record, REMAINING_KEYS)
    derived_remaining = False
    if remaining is None and limit is not None and consumed is not None:
        remaining = limit - consumed
        derived_remaining = True
    elif remaining is None and limit is not None and consumed is None:
        remaining = limit
        derived_remaining = True

    reset_at = _first_datetime(record, RESET_KEYS)
    details = _strip_known_fields(record)
    return BudgetItem(
        name=name,
        limit=limit,
        consumed=consumed,
        remaining=remaining,
        unit=_first_str(record, UNIT_KEYS),
        period=_first_str(record, PERIOD_KEYS),
        reset_at=reset_at,
        source_path=source_path,
        derived_remaining=derived_remaining,
        details=details,
    )


def build_summary(items: Iterable[BudgetItem]) -> QuotaSummary:
    materialized = list(items)
    limit_values = [item.limit for item in materialized if item.limit is not None]
    consumed_values = [item.consumed for item in materialized if item.consumed is not None]
    remaining_values = [item.remaining for item in materialized if item.remaining is not None]
    exhausted = sum(1 for item in materialized if item.remaining is not None and item.remaining <= 0)
    return QuotaSummary(
        budget_count=len(materialized),
        limit_total=sum(limit_values) if limit_values else None,
        consumed_total=sum(consumed_values) if consumed_values else None,
        remaining_total=sum(remaining_values) if remaining_values else None,
        exhausted_budgets=exhausted,
    )


def _collect_budget_records(payload: Any, *, path: str = "root") -> list[tuple[dict[str, Any], str]]:
    records: list[tuple[dict[str, Any], str]] = []
    if isinstance(payload, dict):
        for key, value in payload.items():
            child_path = f"{path}.{key}"
            if key in CONTAINER_KEYS and isinstance(value, list):
                records.extend(_collect_budget_records(value, path=child_path))
                continue
            if key in CONTAINER_KEYS and isinstance(value, dict):
                records.extend(_collect_budget_records(value, path=child_path))
                continue
        if _looks_like_budget_record(payload):
            records.append((payload, path))
        else:
            for key, value in payload.items():
                if key in CONTAINER_KEYS:
                    continue
                records.extend(_collect_budget_records(value, path=f"{path}.{key}"))
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            records.extend(_collect_budget_records(value, path=f"{path}[{index}]"))
    return records


def _looks_like_budget_record(record: dict[str, Any]) -> bool:
    return any(key in record for key in (*NAME_KEYS, *LIMIT_KEYS, *CONSUMED_KEYS, *REMAINING_KEYS))


def _first_str(record: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _first_number(record: dict[str, Any], keys: tuple[str, ...]) -> float | int | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            return value
        if isinstance(value, str):
            try:
                number = float(value) if "." in value else int(value)
            except ValueError:
                continue
            return number
    return None


def _first_datetime(record: dict[str, Any], keys: tuple[str, ...]) -> datetime | None:
    for key in keys:
        value = record.get(key)
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                continue
    return None


def _strip_known_fields(record: dict[str, Any]) -> dict[str, Any]:
    known = {"name", *NAME_KEYS, *LIMIT_KEYS, *CONSUMED_KEYS, *REMAINING_KEYS, *UNIT_KEYS, *PERIOD_KEYS, *RESET_KEYS}
    return {key: value for key, value in record.items() if key not in known}
