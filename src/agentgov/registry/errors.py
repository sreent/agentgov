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
