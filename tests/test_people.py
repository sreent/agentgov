"""Who an agent acts for, from the claims of its token (agentgov.identity.people)."""

from __future__ import annotations

import json

from agentgov.identity import people

ALICE = {
    "subject": "u-alice",
    "username": "alice",
    "email": "alice@example.com",
    "groups": ["/support", "Équipe"],
    "roles": ["default-roles-agentgov"],
}


def test_an_agent_on_its_own_acts_for_no_one() -> None:
    # Keycloak's token for a client's own service account.
    claims = {"subject": "sa-1", "username": "service-account-agent-support-bot", "roles": []}
    assert people.person_of(claims) is None
    assert people.person_of({}) is None
    assert people.person_of({"subject": "sa-1"}) is None  # nothing says it's a person


def test_an_exchanged_token_is_for_its_subject() -> None:
    assert people.person_of(ALICE) == {
        "id": "u-alice",
        "username": "alice",
        "email": "alice@example.com",
        "groups": ["/support", "Équipe"],
        "roles": ["default-roles-agentgov"],
        "via": "exchange",
    }
    # Without a username, an email address still says it's a person.
    assert people.person_of({"subject": "u-bob", "email": "bob@example.com"}) == {
        "id": "u-bob",
        "email": "bob@example.com",
        "groups": [],
        "roles": [],
        "via": "exchange",
    }


def test_a_delegated_token_names_the_agent_it_was_delegated_to() -> None:
    claims = {**ALICE, "act": {"sub": "sa-1", "client_id": "agent-support-bot"}}
    person = people.person_of(claims)
    assert person is not None
    assert (person["via"], person["actor"]) == ("delegation", "agent-support-bot")
    # act is what says so, whatever the username.
    delegated = people.person_of({"subject": "u-carol", "act": {"sub": "sa-2"}})
    assert delegated == {
        "id": "u-carol",
        "groups": [],
        "roles": [],
        "via": "delegation",
        "actor": "sa-2",
    }


def test_a_person_who_signed_in_to_the_agent_themselves() -> None:
    # A public client's token, such as a developer's MCP client's, says so.
    for said in (True, "true"):
        person = people.person_of({**ALICE, "sign_in": said})
        assert person is not None and person["via"] == "sign-in"
    assert people.person_of({**ALICE, "sign_in": False})["via"] == "exchange"
    # A delegation is still a delegation.
    claims = {**ALICE, "sign_in": True, "act": {"sub": "sa-1"}}
    assert people.person_of(claims)["via"] == "delegation"
    # And a service account doesn't become a person.
    service = {"subject": "sa-1", "username": "service-account-agent-x", "sign_in": True}
    assert people.person_of(service) is None


def test_only_names_count_as_groups_and_roles() -> None:
    person = people.person_of({**ALICE, "groups": ["/a", "", 3, None], "roles": "admin"})
    assert person is not None
    assert (person["groups"], person["roles"]) == (["/a"], [])


def test_the_ledger_names_people_by_username_then_email_then_id() -> None:
    assert people.name_of(None) is None
    assert people.name_of({"id": "u-1", "username": "alice", "email": "a@x"}) == "alice"
    assert people.name_of({"id": "u-1", "email": "a@x"}) == "a@x"
    assert people.name_of({"id": "u-1"}) == "u-1"


def test_headers_carry_utf8_and_json() -> None:
    # agentgateway sends UTF-8 bytes; HTTP servers decode header values as Latin-1.
    sent = json.dumps(["/support", "Équipe 日本"], ensure_ascii=False)
    received = sent.encode("utf-8").decode("latin-1")
    assert people.header_json(received) == ["/support", "Équipe 日本"]
    assert people.header_text("Zoë".encode().decode("latin-1")) == "Zoë"
    assert people.header_text("plain") == "plain"
    assert people.header_text(None) is None
    # Not UTF-8 after all: the value as it came.
    assert people.header_text("caf\xe9") == "caf\xe9"
    assert people.header_json("not json") is None
    assert people.header_json(None) is None
