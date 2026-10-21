"""Resolve which organizations to poll (configured, discovered, or the client's default)."""

from __future__ import annotations

from uuid import UUID

from elements_pulse.api.client import ElementsClient
from elements_pulse.collectors.base import as_uuid
from elements_pulse.config import Settings
from elements_pulse.logs import get_logger
from elements_pulse.repository import Repository

log = get_logger(__name__)

WHOAMI_PATH = "/whoami/v1/whoami"
ORGANIZATIONS_PATH = "/organizations/v1/organizations"


async def whoami(client: ElementsClient) -> dict[str, str]:
    return await client.get(WHOAMI_PATH)


async def list_child_companies(
    client: ElementsClient, parent: UUID
) -> list[tuple[UUID, str | None, str | None]]:
    """Companies under ``parent`` (including itself if it is a company)."""
    found: list[tuple[UUID, str | None, str | None]] = []
    params = {"organizationId": parent, "type": "company", "limit": 1000}
    async for items in client.paginate("GET", ORGANIZATIONS_PATH, params=params, org_id=parent):
        for item in items:
            org_id = as_uuid(item.get("id"))
            if org_id:
                found.append((org_id, item.get("name"), item.get("type")))
    return found


async def resolve_organizations(
    client: ElementsClient, repo: Repository | None, settings: Settings
) -> list[UUID]:
    cfg = settings.organizations
    parents = list(cfg.ids)
    if not parents:
        me = await whoami(client)
        default_org = as_uuid(me.get("organizationId"))
        if default_org is None:
            raise RuntimeError("whoami did not return an organizationId")
        parents = [default_org]

    if not cfg.discover:
        if repo is not None:
            await repo.upsert_organizations(((p, None, None) for p in parents), "config")
            # Best effort: fill in names (the endpoint includes the org itself if it is a company).
            for parent in parents:
                try:
                    companies = await list_child_companies(client, parent)
                except Exception as exc:
                    log.debug("organization_name_lookup_failed", error=str(exc))
                    continue
                named = [c for c in companies if c[0] == parent]
                if named:
                    await repo.upsert_organizations(named, "config")
        return parents

    discovered: dict[UUID, tuple[UUID, str | None, str | None]] = {}
    for parent in parents:
        for company in await list_child_companies(client, parent):
            discovered[company[0]] = company
    if not discovered:
        log.warning("discovery_found_no_company", parents=[str(p) for p in parents])
        return parents
    if repo is not None:
        await repo.upsert_organizations(discovered.values(), "discovered")
    log.info("organizations_discovered", count=len(discovered))
    return sorted(discovered)
