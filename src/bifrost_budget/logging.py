from __future__ import annotations

import json
import logging
import os
from typing import Any


LOGGER_NAME = "bifrost_budget"
DEFAULT_LOG_LEVEL = "INFO"


def configure_logging(level: str | None = None) -> logging.Logger:
    resolved_level_name = (level or os.getenv("BIFROST_LOG_LEVEL", DEFAULT_LOG_LEVEL)).upper()
    resolved_level = getattr(logging, resolved_level_name, logging.INFO)
    logging.basicConfig(level=resolved_level, format="%(message)s")
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(resolved_level)
    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)


def log_event(level: int, event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    get_logger().log(level, json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")))
