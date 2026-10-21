# Creating a read-only API client in WithSecure Elements

WSElements-pulse authenticates with an Elements **API client** (client ID and secret) using the
OAuth 2.0 client-credentials flow. It only ever requests the `connect.api.read` scope.

> Menu names below describe the Elements Security Center at the time of writing and may change.
> The official WithSecure documentation is the reference.

## 1. Choose the right organization level

- **Single company**: create the API client in that company.
- **Partner / MSP (solution provider)**: create it at the partner level. A partner-level client
  can read the companies under it, and you can then use `organizations.discover: true` or list
  company UUIDs in `organizations.ids`.

## 2. Create the client

1. Sign in to Elements Security Center as an administrator of that organization.
2. Open the organization settings and go to the **API clients** section.
3. Add a new API client, give it a clear description (e.g. `WSElements-pulse read-only`), and
   **keep it read-only**. Don't grant write access: this tool never needs it.
4. Copy the **client ID** and **secret**. The secret is shown only once.

## 3. Configure WSElements-pulse

Put the values in `.env` (never commit it):

```dotenv
ELEMENTS_CLIENT_ID=your-client-id
ELEMENTS_CLIENT_SECRET=your-client-secret
```

or use Docker secrets (see [configuration.md](configuration.md#docker-secrets)).

Then validate:

```bash
docker compose run --rm collector check
```

`check` gets a token with the read scope, calls `/whoami/v1/whoami`, resolves the organizations
to poll, and sends one small request (`limit=1`) to each enabled endpoint:

```text
[OK  ] token                        obtained with scope 'connect.api.read' only
[OK  ] whoami                       client=... org=00000000-0000-4000-8000-000000000001
[OK  ] organizations                00000000-0000-4000-8000-000000000001
[OK  ] incidents                    reachable (1 item)
[OK  ] devices                      reachable (1 item)
[OK  ] audit_logs                   reachable (1 item)
[OK  ] security_events:epp          reachable (1 item)
[OK  ] security_events:edr          reachable (0 item)
[OK  ] database                     reachable
```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `invalid_client: Invalid credentials` | Wrong ID or secret, or the client was deleted. |
| `invalid_scope: Scope not allowed for the client` | The client can't use `connect.api.read`; check its settings. |
| `404` on an endpoint | The organization UUID is outside the client's scope. |
| `403` on an endpoint | The client or subscription doesn't allow this data (e.g. no EDR). Disable the matching collector. |
| Many `429` on *Collector health* | Raise `PULSE_API__REQUEST_DELAY_SECONDS` or the collector intervals. |

## Rotating the secret

Create a new API client (or a new secret), update `.env`, run `docker compose up -d collector`,
then delete the old client in Elements.
