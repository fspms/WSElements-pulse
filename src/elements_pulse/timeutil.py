"""Timestamp helpers. Everything is handled as timezone-aware UTC."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any


def utcnow() -> datetime:
    return datetime.now(UTC)


def parse_ts(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp from the API. Returns None for empty or invalid values."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def fmt_ts(value: datetime) -> str:
    """Format a datetime the way the Elements API expects it (RFC 3339, UTC, millis, 'Z')."""
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def time_windows(
    start: datetime, end: datetime, max_span: timedelta
) -> Iterator[tuple[datetime, datetime]]:
    """Split [start, end) into consecutive windows no longer than max_span."""
    cursor = start
    while cursor < end:
        window_end = min(cursor + max_span, end)
        yield cursor, window_end
        cursor = window_end
