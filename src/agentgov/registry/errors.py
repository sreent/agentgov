"""Errors raised by the registry service layer (mapped to HTTP codes by the API)."""


class RegistryError(Exception):
    status_code = 400


class ValidationError(RegistryError):
    status_code = 422


class NotFound(RegistryError):
    status_code = 404


class Conflict(RegistryError):
    status_code = 409


class InvalidTransition(Conflict):
    """A lifecycle action is not allowed from the agent's current state."""


class Forbidden(RegistryError):
    """The caller may not do this: their role, the hand-off level, or their part in what it
    is about (who is accountable for an agent doesn't accept its risks)."""

    status_code = 403
