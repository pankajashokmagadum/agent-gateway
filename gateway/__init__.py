"""Authorization gateway for AI agents: authenticate, authorize, account."""

__all__ = ["Gateway", "SessionError", "Registry", "RegistryError"]


def __getattr__(name):
    # Imported on first use, so `python -m gateway.audit` and
    # `python -m gateway.approve` run as plain modules.
    if name in ("Gateway", "SessionError"):
        from . import gateway
        return getattr(gateway, name)
    if name in ("Registry", "RegistryError"):
        from . import scopes
        return getattr(scopes, name)
    raise AttributeError(name)
