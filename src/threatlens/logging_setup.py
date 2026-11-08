"""Structured JSON logging for ThreatLens' own logs.

Each log record becomes one JSON object per line on stderr, so the
container log can itself be ingested by a log pipeline (or by ThreatLens).
"""

from __future__ import annotations

import json
import logging
import logging.config
from datetime import UTC, datetime
from typing import Any

# Attributes every LogRecord has; anything else was passed via ``extra=`` and is kept.
# uvicorn's "color_message" duplicates "msg" with terminal colour codes: drop it.
_STANDARD_ATTRS = frozenset(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()
    | {"message", "asctime", "color_message"}
)


class JsonFormatter(logging.Formatter):
    """Format a log record as a single-line JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def logging_config(level: str) -> dict[str, Any]:
    """A ``logging.config.dictConfig`` mapping, also handed to uvicorn."""
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {"json": {"()": JsonFormatter}},
        "handlers": {
            "stderr": {
                "class": "logging.StreamHandler",
                "formatter": "json",
                "stream": "ext://sys.stderr",
            }
        },
        "root": {"handlers": ["stderr"], "level": level},
        "loggers": {
            "uvicorn": {"handlers": ["stderr"], "level": level, "propagate": False},
            "uvicorn.error": {"handlers": ["stderr"], "level": level, "propagate": False},
            "uvicorn.access": {"handlers": ["stderr"], "level": level, "propagate": False},
        },
    }


def configure_logging(level: str) -> None:
    logging.config.dictConfig(logging_config(level))
