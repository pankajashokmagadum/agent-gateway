"""Typed parameters.

A model hands the gateway strings. Nothing here trusts them: every value is
checked for type and shape, and anything that names a server, user or service
must resolve to a real row. Values that pass are safe to place into a fixed
argv slot; they are never joined into a shell string.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

HOSTNAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+){1,4}")
USERNAME = re.compile(r"[a-z][a-z0-9-]{1,31}")


class ValidationError(Exception):
    pass


@dataclass(frozen=True)
class Param:
    required: bool = True

    def parse(self, name: str, value: Any, db, values: Mapping[str, Any]) -> Any:
        raise NotImplementedError


@dataclass(frozen=True)
class Choice(Param):
    """One of a fixed set of strings."""
    options: tuple = ()

    def parse(self, name, value, db, values):
        if not isinstance(value, str) or value not in self.options:
            raise ValidationError(f"{name}: must be one of {', '.join(self.options)}")
        return value


@dataclass(frozen=True)
class Flag(Param):
    def parse(self, name, value, db, values):
        if not isinstance(value, bool):
            raise ValidationError(f"{name}: must be true or false")
        return value


@dataclass(frozen=True)
class Text(Param):
    """Free text for search queries. Never used as a command argument."""
    max_len: int = 200

    def parse(self, name, value, db, values):
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{name}: must be a non-empty string")
        if len(value) > self.max_len:
            raise ValidationError(f"{name}: longer than {self.max_len} characters")
        return value.strip()


@dataclass(frozen=True)
class ServerRef(Param):
    """A hostname that exists in the inventory."""

    def parse(self, name, value, db, values):
        if not isinstance(value, str) or not HOSTNAME.fullmatch(value):
            raise ValidationError(f"{name}: not a valid hostname")
        if db.execute("SELECT 1 FROM servers WHERE hostname = ?", (value,)).fetchone() is None:
            raise ValidationError(f"{name}: no such server")
        return value


@dataclass(frozen=True)
class UserRef(Param):
    """A username that exists in the directory."""

    def parse(self, name, value, db, values):
        if not isinstance(value, str) or not USERNAME.fullmatch(value):
            raise ValidationError(f"{name}: not a valid username")
        if db.execute("SELECT 1 FROM users WHERE username = ?", (value,)).fetchone() is None:
            raise ValidationError(f"{name}: no such user")
        return value


@dataclass(frozen=True)
class ServiceOn(Param):
    """A known unit that is actually installed on the server named by `host`."""
    options: tuple = ()
    host: str = "host"

    def parse(self, name, value, db, values):
        if not isinstance(value, str) or value not in self.options:
            raise ValidationError(f"{name}: must be one of {', '.join(self.options)}")
        row = db.execute("SELECT 1 FROM services WHERE hostname = ? AND service = ?",
                         (values[self.host], value)).fetchone()
        if row is None:
            raise ValidationError(f"{name}: {value} is not installed on {values[self.host]}")
        return value


@dataclass
class Validated:
    values: dict = field(default_factory=dict)
    server: Optional[Mapping[str, Any]] = None   # inventory row for the target host
    user: Optional[Mapping[str, Any]] = None     # directory row for the target user


def validate(command, args: Any, db) -> Validated:
    """Check `args` against the command's declared parameters, in order."""
    if not isinstance(args, dict):
        raise ValidationError("arguments must be an object")
    unknown = sorted(set(args) - set(command.params))
    if unknown:
        raise ValidationError(f"unknown parameter: {', '.join(map(str, unknown))[:80]}")

    out = Validated()
    for name, param in command.params.items():
        if name not in args or args[name] is None:
            if param.required:
                raise ValidationError(f"{name}: required")
            continue
        out.values[name] = param.parse(name, args[name], db, out.values)
        if isinstance(param, ServerRef):
            out.server = dict(db.execute("SELECT * FROM servers WHERE hostname = ?",
                                         (out.values[name],)).fetchone())
        elif isinstance(param, UserRef):
            out.user = dict(db.execute("SELECT * FROM users WHERE username = ?",
                                       (out.values[name],)).fetchone())
    return out


def render_argv(command, values: Mapping[str, Any]) -> Optional[list]:
    """Fill the fixed argv template. Each value lands in exactly one argv slot.

    The result is recorded, not run: this project simulates effects. It shows
    what would be executed with shell=False, where a value such as
    "authd; rm -rf /" could only ever be one (rejected) argument.
    """
    if command.argv is None:
        return None
    return [part.format(**values) for part in command.argv]
