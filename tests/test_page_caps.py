"""A list a connector reads only up to its page cap fails the part it is in: the part isn't
taken as read in full, so its agents are left as the last full read saw them, neither gone
nor cleared of findings (agentgov.platforms.base)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from agentgov.platforms import aws, databricks, foundry, google
from agentgov.platforms.base import PlatformError


@pytest.fixture(autouse=True)
def two_pages(monkeypatch) -> None:
    for module in (aws, databricks, foundry, google):
        monkeypatch.setattr(module, "MAX_PAGES", 2)


def endless(key: str, token: str, items: int = 1) -> Any:
    """A page that always says there is another."""
    return lambda *args, **kwargs: {key: [{"name": "x"}] * items, token: "more"}


def last(key: str, token: str) -> Any:
    """Pages that end on the cap's last page: the list was read in full."""
    pages = iter([{key: [{"name": "a"}], token: "more"}, {key: [{"name": "b"}]}])
    return lambda *args, **kwargs: next(pages)


def test_databricks() -> None:
    fake = SimpleNamespace(_get=endless("apps", "next_page_token"))
    with pytest.raises(PlatformError, match=r"more than 2 pages of /api/2\.0/apps"):
        list(databricks.DatabricksConnector._pages(fake, "https://w", "/api/2.0/apps", "apps"))
    fake = SimpleNamespace(_get=last("apps", "next_page_token"))
    assert len(list(databricks.DatabricksConnector._pages(fake, "https://w", "/x", "apps"))) == 2


def test_google() -> None:
    fake = SimpleNamespace(_call=endless("agents", "nextPageToken"))
    with pytest.raises(PlatformError, match="more than 2 pages"):
        list(google.GoogleConnector._pages(fake, "https://g/agents", "agents"))
    fake = SimpleNamespace(_call=last("agents", "nextPageToken"))
    assert len(list(google.GoogleConnector._pages(fake, "https://g/agents", "agents"))) == 2


def test_aws() -> None:
    fake = SimpleNamespace(call=endless("agentSummaries", "nextToken"))
    with pytest.raises(PlatformError, match="more than 2 pages of /agents/"):
        list(aws._Api.pages(fake, "bedrock", "e", "POST", "/agents/", "agentSummaries"))
    quick = SimpleNamespace(call=endless("AgentSummaries", "NextToken"))
    with pytest.raises(PlatformError, match="Amazon Quick's agents"):
        aws._quick(quick, "123456789012", "us-east-1", "part")


def test_foundry() -> None:
    settings = SimpleNamespace(
        azure_management_url="https://management.azure.com", foundry_audience="https://ai"
    )
    fake = SimpleNamespace(settings=settings, _get=endless("value", "nextLink"))
    with pytest.raises(PlatformError, match="more than 2 pages"):
        list(foundry.FoundryConnector._arm(fake, "https://management.azure.com/x"))
    with pytest.raises(PlatformError, match="connections"):
        foundry.FoundryConnector._connections(fake, "https://p/api/projects/r")
    # A list that ends on the cap's last page was read in full.
    fake = SimpleNamespace(settings=settings, _get=last("value", "nextLink"))
    assert len(list(foundry.FoundryConnector._arm(fake, "https://management.azure.com/x"))) == 2
