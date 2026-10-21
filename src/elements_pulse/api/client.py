"""Async HTTP client for the WithSecure Elements API.

Responsibilities:
- OAuth2 client-credentials token handling (read scope only), with caching and refresh.
- Read-only guard: only an explicit allowlist of (method, path) can ever be sent.
- Throttling (minimum delay between requests), retries with exponential backoff + jitter
  on 429/5xx/transport errors, Retry-After support, one re-authentication on 401.
- Request metrics hook (latency/status) used for the collector health dashboard.
"""

from __future__ import annotations

import asyncio
import base64
import random
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from uuid import UUID

import httpx

from elements_pulse.api.errors import AuthenticationError, ElementsApiError, ReadOnlyViolation
from elements_pulse.config import READ_SCOPE, ApiSettings
from elements_pulse.logs import get_logger

log = get_logger(__name__)

TOKEN_PATH = "/as/token.oauth2"  # noqa: S105 - URL path, not a secret

# The ONLY requests this tool is allowed to send. POST is used for the token endpoint and for
# the security events *query* endpoint (a read operation that requires only connect.api.read).
# Anything else (PATCH/DELETE/PUT, response actions, device operations, API keys, ...) is
# refused before it reaches the network.
READ_ONLY_ALLOWLIST: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", TOKEN_PATH),
        ("GET", "/whoami/v1/whoami"),
        ("GET", "/organizations/v1/organizations"),
        ("GET", "/incidents/v1/incidents"),
        ("GET", "/incidents/v1/detections"),
        ("POST", "/security-events/v1/security-events"),
        ("GET", "/devices/v1/devices"),
        ("GET", "/audit-logs/v1/audit-logs"),
    }
)


def assert_read_only(method: str, path: str) -> None:
    if (method.upper(), path) not in READ_ONLY_ALLOWLIST:
        raise ReadOnlyViolation(
            f"Refusing to send {method.upper()} {path}: not on the read-only allowlist"
        )


@dataclass(frozen=True)
class Credentials:
    client_id: str
    client_secret: str = field(repr=False)


@dataclass(frozen=True)
class RequestRecord:
    ts: datetime
    method: str
    endpoint: str
    status: int | None
    duration_ms: int
    attempt: int
    organization_id: UUID | None


@dataclass
class CallCounter:
    calls: int = 0


# Per-task counter so each collector run can report how many API calls it made.
current_call_counter: ContextVar[CallCounter | None] = ContextVar(
    "current_call_counter", default=None
)

RequestHook = Callable[[RequestRecord], Awaitable[None]]


class _Token:
    def __init__(self, value: str, expires_at: float):
        self.value = value
        self.expires_at = expires_at


class ElementsClient:
    def __init__(
        self,
        settings: ApiSettings,
        credentials: Credentials,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        on_request: RequestHook | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        rng: Callable[[], float] = random.random,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._settings = settings
        self._credentials = credentials
        self._on_request = on_request
        self._sleep = sleep
        self._rng = rng
        self._clock = clock
        self._http = httpx.AsyncClient(
            base_url=settings.base_url,
            timeout=settings.timeout_seconds,
            transport=transport,
            follow_redirects=False,
        )
        self._token: _Token | None = None
        self._token_lock = asyncio.Lock()
        self._throttle_lock = asyncio.Lock()
        self._last_request_at: float | None = None

    async def __aenter__(self) -> ElementsClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------ auth

    async def _fetch_token(self) -> _Token:
        basic = base64.b64encode(
            f"{self._credentials.client_id}:{self._credentials.client_secret}".encode()
        ).decode()
        resp = await self._send(
            "POST",
            TOKEN_PATH,
            data={"grant_type": "client_credentials", "scope": READ_SCOPE},
            headers={"Authorization": f"Basic {basic}"},
            authenticated=False,
        )
        payload = _json(resp)
        token = payload.get("access_token")
        if resp.status_code != 200 or not token:
            raise AuthenticationError(
                f"Token request failed: {payload.get('error', 'unknown_error')}: "
                f"{payload.get('error_description', resp.reason_phrase)}",
                status=resp.status_code,
                transaction_id=resp.headers.get("X-Transaction"),
            )
        ttl = float(payload.get("expires_in") or 300)
        # Refresh early: at 80% of the lifetime, and at least 30 s before expiry.
        margin = max(30.0, ttl * 0.2)
        log.info("token_acquired", expires_in=ttl)
        return _Token(token, self._clock() + max(ttl - margin, 1.0))

    async def access_token(self) -> str:
        async with self._token_lock:
            if self._token is None or self._clock() >= self._token.expires_at:
                self._token = await self._fetch_token()
            return self._token.value

    def invalidate_token(self) -> None:
        self._token = None

    # --------------------------------------------------------------- requests

    async def get(
        self, path: str, params: dict[str, Any] | None = None, *, org_id: UUID | None = None
    ) -> dict[str, Any]:
        return await self.request("GET", path, params=params, org_id=org_id)

    async def post_form(
        self,
        path: str,
        data: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
        org_id: UUID | None = None,
    ) -> dict[str, Any]:
        return await self.request("POST", path, data=data, headers=headers, org_id=org_id)

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        org_id: UUID | None = None,
    ) -> dict[str, Any]:
        resp = await self._send(
            method, path, params=params, data=data, headers=headers, org_id=org_id
        )
        if resp.status_code >= 400:
            raise _api_error(resp)
        return _json(resp)

    async def paginate(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        org_id: UUID | None = None,
        max_pages: int = 100_000,
    ) -> AsyncIterator[list[dict[str, Any]]]:
        """Yield one list of items per page, following ``nextAnchor``."""
        anchor: str | None = None
        for _ in range(max_pages):
            if method.upper() == "GET":
                page_params = dict(params or {})
                if anchor:
                    page_params["anchor"] = anchor
                payload = await self.request(
                    method, path, params=page_params, headers=headers, org_id=org_id
                )
            else:
                page_data = dict(data or {})
                if anchor:
                    page_data["anchor"] = anchor
                payload = await self.request(
                    method, path, params=params, data=page_data, headers=headers, org_id=org_id
                )
            items = payload.get("items") or []
            yield items
            next_anchor = payload.get("nextAnchor")
            if not next_anchor or next_anchor == anchor:
                return
            anchor = next_anchor
        log.warning("pagination_limit_reached", path=path, max_pages=max_pages)

    async def _throttle(self) -> None:
        delay = self._settings.request_delay_seconds
        if delay <= 0:
            return
        async with self._throttle_lock:
            now = self._clock()
            if self._last_request_at is not None:
                wait = self._last_request_at + delay - now
                if wait > 0:
                    await self._sleep(wait)
            self._last_request_at = self._clock()

    def _backoff(self, attempt: int) -> float:
        cap = min(
            self._settings.backoff_max_seconds,
            self._settings.backoff_base_seconds * (2**attempt),
        )
        # "Equal jitter": at least half of the exponential delay, plus a random part.
        return cap / 2 + self._rng() * cap / 2

    def _retry_after(self, resp: httpx.Response) -> float | None:
        value = resp.headers.get("Retry-After")
        if not value:
            return None
        try:
            seconds = float(value)
        except ValueError:
            try:
                when = parsedate_to_datetime(value)
            except (TypeError, ValueError):
                return None
            if when.tzinfo is None:
                when = when.replace(tzinfo=UTC)
            seconds = (when - datetime.now(UTC)).total_seconds()
        return max(0.0, min(seconds, self._settings.max_retry_after_seconds))

    async def _send(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        org_id: UUID | None = None,
        authenticated: bool = True,
    ) -> httpx.Response:
        method = method.upper()
        assert_read_only(method, path)
        attempt = 0
        reauthenticated = False
        while True:
            await self._throttle()
            req_headers = {
                "User-Agent": self._settings.user_agent,
                "Accept": "application/json",
                **(headers or {}),
            }
            if authenticated:
                req_headers["Authorization"] = f"Bearer {await self.access_token()}"
            started = time.perf_counter()
            status: int | None = None
            try:
                resp = await self._http.request(
                    method, path, params=_clean(params), data=_clean(data), headers=req_headers
                )
                status = resp.status_code
            except httpx.TransportError as exc:
                await self._record(method, path, None, started, attempt, org_id)
                if attempt >= self._settings.max_retries:
                    raise ElementsApiError(f"{method} {path} failed: {exc!r}") from exc
                delay = self._backoff(attempt)
                log.warning(
                    "api_transport_error_retrying",
                    method=method,
                    path=path,
                    error=repr(exc),
                    attempt=attempt,
                    delay=delay,
                )
                await self._sleep(delay)
                attempt += 1
                continue

            await self._record(method, path, status, started, attempt, org_id)

            if status == 401 and authenticated and not reauthenticated:
                log.info("api_unauthorized_reauthenticating", method=method, path=path)
                self.invalidate_token()
                reauthenticated = True
                continue

            if status == 429 or status >= 500:
                if attempt >= self._settings.max_retries:
                    return resp
                delay = self._retry_after(resp)
                if delay is None:
                    delay = self._backoff(attempt)
                log.warning(
                    "api_retrying",
                    method=method,
                    path=path,
                    status=status,
                    attempt=attempt,
                    delay=round(delay, 2),
                )
                await self._sleep(delay)
                attempt += 1
                continue

            return resp

    async def _record(
        self,
        method: str,
        path: str,
        status: int | None,
        started: float,
        attempt: int,
        org_id: UUID | None,
    ) -> None:
        counter = current_call_counter.get()
        if counter is not None:
            counter.calls += 1
        if self._on_request is None:
            return
        record = RequestRecord(
            ts=datetime.now(UTC),
            method=method,
            endpoint=path,
            status=status,
            duration_ms=int((time.perf_counter() - started) * 1000),
            attempt=attempt,
            organization_id=org_id,
        )
        try:
            await self._on_request(record)
        except Exception as exc:  # metrics must never break collection
            log.warning("request_hook_failed", error=repr(exc))


def _clean(values: dict[str, Any] | None) -> dict[str, Any] | None:
    """Drop None values and render booleans the way the API expects ('true'/'false')."""
    if values is None:
        return None
    cleaned: dict[str, Any] = {}
    for key, value in values.items():
        if value is None:
            continue
        if isinstance(value, bool):
            cleaned[key] = "true" if value else "false"
        elif isinstance(value, UUID):
            cleaned[key] = str(value)
        else:
            cleaned[key] = value
    return cleaned


def _json(resp: httpx.Response) -> dict[str, Any]:
    if not resp.content:
        return {}
    try:
        payload = resp.json()
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {"items": payload}


def _api_error(resp: httpx.Response) -> ElementsApiError:
    payload = _json(resp)
    message = payload.get("message") or resp.reason_phrase or "API error"
    return ElementsApiError(
        f"{resp.request.method} {resp.request.url.path} failed: {message}",
        status=resp.status_code,
        code=payload.get("code"),
        transaction_id=payload.get("transactionId") or resp.headers.get("X-Transaction"),
        details=payload.get("details"),
    )
