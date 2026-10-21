"""Minimal HTTP health endpoint (GET /healthz) without extra dependencies."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any

from elements_pulse.logs import get_logger

log = get_logger(__name__)

HealthProbe = Callable[[], Awaitable[tuple[bool, dict[str, Any]]]]


async def start_health_server(host: str, port: int, probe: HealthProbe) -> asyncio.Server:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=5)
            # Drain headers.
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                if line in (b"\r\n", b"\n", b""):
                    break
            parts = request_line.decode("latin-1").split()
            path = parts[1] if len(parts) >= 2 else "/"
            if path.split("?")[0] not in ("/healthz", "/health"):
                status_line, body = "404 Not Found", {"error": "not found"}
            else:
                try:
                    healthy, body = await probe()
                except Exception as exc:
                    healthy, body = False, {"error": str(exc)}
                status_line = "200 OK" if healthy else "503 Service Unavailable"
                body = {"status": "ok" if healthy else "unhealthy", **body}
            payload = json.dumps(body, default=str).encode()
            writer.write(
                f"HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\n"
                f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
                + payload
            )
            await writer.drain()
        except (TimeoutError, ConnectionError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, host, port)
    log.info("health_server_listening", host=host, port=port)
    return server
