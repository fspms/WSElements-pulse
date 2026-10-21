"""Auth, retries, rate limiting and the read-only guard."""

from __future__ import annotations

import base64
from urllib.parse import parse_qs

import httpx
import pytest

from elements_pulse.api import (
    READ_ONLY_ALLOWLIST,
    AuthenticationError,
    Credentials,
    ElementsApiError,
    ElementsClient,
    ReadOnlyViolation,
    assert_read_only,
)
from elements_pulse.config import READ_SCOPE, ApiSettings


async def test_token_request_uses_basic_auth_and_read_scope_only(mock_api, client):
    mock_api.get("/whoami/v1/whoami").respond(200, json={"clientId": "demo", "organizationId": "x"})
    await client.get("/whoami/v1/whoami")

    token_call = mock_api.calls[0].request
    assert token_call.url.path == "/as/token.oauth2"
    expected = base64.b64encode(b"demo-client:demo-secret").decode()
    assert token_call.headers["Authorization"] == f"Basic {expected}"
    assert token_call.headers["User-Agent"].startswith("WSElements-pulse/")
    body = parse_qs(token_call.content.decode())
    assert body == {"grant_type": ["client_credentials"], "scope": [READ_SCOPE]}
    assert READ_SCOPE == "connect.api.read"
    assert "write" not in token_call.content.decode()

    api_call = mock_api.calls[1].request
    assert api_call.headers["Authorization"] == "Bearer fake-token-1"


async def test_token_is_cached(mock_api, client):
    route = mock_api.get("/whoami/v1/whoami").respond(200, json={})
    for _ in range(3):
        await client.get("/whoami/v1/whoami")
    assert mock_api.routes[0].call_count == 1  # token route
    assert route.call_count == 3


async def test_token_refreshed_before_expiry(api_settings, sleeps):
    now = [1000.0]
    with __import__("respx").mock(base_url=api_settings.base_url) as router:
        token = router.post("/as/token.oauth2").respond(
            200, json={"access_token": "t", "expires_in": 100}
        )
        router.get("/whoami/v1/whoami").respond(200, json={})
        async with ElementsClient(
            api_settings, Credentials("a", "b"), sleep=sleeps, clock=lambda: now[0]
        ) as c:
            await c.get("/whoami/v1/whoami")
            now[0] += 60  # < 100 - 30 s margin
            await c.get("/whoami/v1/whoami")
            assert token.call_count == 1
            now[0] += 15  # past refresh point (ttl - 30 s)
            await c.get("/whoami/v1/whoami")
            assert token.call_count == 2


async def test_401_triggers_single_reauthentication(mock_api, client):
    route = mock_api.get("/whoami/v1/whoami")
    route.side_effect = [httpx.Response(401), httpx.Response(200, json={"ok": True})]
    assert await client.get("/whoami/v1/whoami") == {"ok": True}
    assert mock_api.routes[0].call_count == 2  # token fetched twice


async def test_persistent_401_raises(mock_api, client):
    mock_api.get("/whoami/v1/whoami").respond(
        401, json={"message": "Unauthorized.", "code": 401000}
    )
    with pytest.raises(ElementsApiError) as err:
        await client.get("/whoami/v1/whoami")
    assert err.value.status == 401
    assert mock_api.routes[0].call_count == 2  # only one re-authentication


async def test_bad_credentials_raise_authentication_error(api_settings, sleeps):
    with __import__("respx").mock(base_url=api_settings.base_url) as router:
        router.post("/as/token.oauth2").respond(
            401, json={"error": "invalid_client", "error_description": "Invalid credentials"}
        )
        async with ElementsClient(api_settings, Credentials("a", "b"), sleep=sleeps) as c:
            with pytest.raises(AuthenticationError, match="Invalid credentials"):
                await c.access_token()


async def test_429_honours_retry_after(mock_api, client, sleeps):
    route = mock_api.get("/whoami/v1/whoami")
    route.side_effect = [
        httpx.Response(429, headers={"Retry-After": "7"}),
        httpx.Response(200, json={"ok": 1}),
    ]
    assert await client.get("/whoami/v1/whoami") == {"ok": 1}
    assert sleeps.calls == [7.0]


async def test_5xx_exponential_backoff_with_jitter(mock_api, client, sleeps):
    route = mock_api.get("/whoami/v1/whoami")
    route.side_effect = [httpx.Response(503), httpx.Response(502), httpx.Response(200, json={})]
    await client.get("/whoami/v1/whoami")
    # rng=0.5, base=1: attempt0 cap=1 -> 0.75 ; attempt1 cap=2 -> 1.5
    assert sleeps.calls == [0.75, 1.5]


async def test_gives_up_after_max_retries(mock_api, client, sleeps):
    mock_api.get("/whoami/v1/whoami").respond(503, json={"message": "unavailable"})
    with pytest.raises(ElementsApiError) as err:
        await client.get("/whoami/v1/whoami")
    assert err.value.status == 503
    assert len(sleeps.calls) == 3  # max_retries


async def test_transport_errors_are_retried(mock_api, client, sleeps):
    route = mock_api.get("/whoami/v1/whoami")
    route.side_effect = [httpx.ConnectError("boom"), httpx.Response(200, json={"ok": 1})]
    assert await client.get("/whoami/v1/whoami") == {"ok": 1}
    assert len(sleeps.calls) == 1


async def test_4xx_error_details_are_exposed(mock_api, client):
    mock_api.get("/whoami/v1/whoami").respond(
        400,
        json={
            "message": "Invalid request parameter.",
            "code": 400004,
            "transactionId": "0000-demo",
            "details": {"limit": "bad"},
        },
    )
    with pytest.raises(ElementsApiError) as err:
        await client.get("/whoami/v1/whoami")
    assert err.value.code == 400004
    assert err.value.transaction_id == "0000-demo"


async def test_request_delay_is_enforced(sleeps):
    now = [0.0]
    settings = ApiSettings(base_url="https://api.example.test", request_delay_seconds=0.5)
    with __import__("respx").mock(base_url=settings.base_url) as router:
        router.post("/as/token.oauth2").respond(200, json={"access_token": "t", "expires_in": 999})
        router.get("/whoami/v1/whoami").respond(200, json={})
        async with ElementsClient(
            settings, Credentials("a", "b"), sleep=sleeps, clock=lambda: now[0]
        ) as c:
            await c.get("/whoami/v1/whoami")
    # token request then API request at the same fake instant -> one 0.5 s wait
    assert sleeps.calls == [0.5]


async def test_request_metrics_hook(mock_api, client, repo):
    mock_api.get("/whoami/v1/whoami").respond(200, json={})
    await client.get("/whoami/v1/whoami")
    endpoints = [(r.method, r.endpoint, r.status) for r in repo.requests]
    assert endpoints == [("POST", "/as/token.oauth2", 200), ("GET", "/whoami/v1/whoami", 200)]


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("PATCH", "/incidents/v1/incidents"),
        ("POST", "/incidents/v1/comments"),
        ("PATCH", "/devices/v1/devices"),
        ("DELETE", "/devices/v1/devices"),
        ("POST", "/devices/v1/operations"),
        ("POST", "/response-actions/v1/execute/netstat"),
        ("POST", "/api-keys/v1/create"),
        ("GET", "/api-keys/v1/api-keys"),
        ("PUT", "/invitations/v1/invitations"),
        ("POST", "/incidents/v1/incidents"),
    ],
)
async def test_read_only_guard_blocks_writes(mock_api, client, method, path):
    with pytest.raises(ReadOnlyViolation):
        await client.request(method, path)
    assert not mock_api.calls  # nothing reached the network, not even a token request


def test_allowlist_only_contains_reads():
    posts = {path for method, path in READ_ONLY_ALLOWLIST if method == "POST"}
    assert posts == {"/as/token.oauth2", "/security-events/v1/security-events"}
    assert {m for m, _ in READ_ONLY_ALLOWLIST} == {"GET", "POST"}
    assert_read_only("get", "/devices/v1/devices")
