# ADR 0006: React and TypeScript for the admin UI

Status: accepted (2026-10-15)

## Context

The admin UI was one hand-written JavaScript file of about 9,000 lines that built the page
with a small DOM helper, with no build step: the control plane served it as it was. It grew
with each feature: forms whose fields show and hide, bulk actions, dialogs that keep their
state, pages drawn again after every change with the focus and what was typed restored by
hand. Each change risked the rest, with nothing but a reader to check it. More people know
React and TypeScript than that file's conventions.

Moving it needed a safety net first: browser tests of the main flows (`ui/e2e`, Playwright),
written against the old UI and run in CI, which the new one then had to pass.

## Decision

React 19 and TypeScript, built with Vite into the package (`src/agentgov/ui`, not in git).
The image builds it in a Node stage; the control plane serves it as before, under the same
content security policy (scripts from itself only).

Every page moved over one for one: the same addresses, wording, API calls and
accessibility tree, compared page by page and dialog by dialog with the old UI before it
was removed. What the API returns is rendered as text only: React escapes it, and a lint
rule forbids setting HTML.

## Consequences

* Building the UI needs Node.js 22 or later (running AgentGov doesn't): the image's build,
  CI and UI work. A source checkout serves a page saying how to build the UI until it is.
* CI checks the UI's types and lint (with React's rules of hooks), builds it, and runs the
  browser tests against the control plane serving that build.
* Scripts are named after their content and kept by browsers; the page naming them is
  checked on each load, so an upgrade never leaves a browser with scripts that are gone.
* The control plane stays Python and FastAPI ([ADR 0005](0005-python-control-plane.md));
  the UI uses only its public API.
