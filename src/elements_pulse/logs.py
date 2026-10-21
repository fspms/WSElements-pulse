"""Structured logging setup (structlog, JSON or console)."""

from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    log_level = logging.getLevelNamesMapping().get(level.upper(), logging.INFO)
    logging.basicConfig(stream=sys.stdout, level=log_level, format="%(message)s")
    # httpx logs full URLs at INFO; keep it quiet, our client logs what matters.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    renderer: structlog.typing.Processor = (
        structlog.processors.JSONRenderer()
        if fmt == "json"
        else structlog.dev.ConsoleRenderer(colors=sys.stdout.isatty())
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.typing.FilteringBoundLogger:
    return structlog.get_logger(name)
