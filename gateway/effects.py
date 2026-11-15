"""What an allowed command does.

Reads query the database with bound parameters. Writes are simulated: they
change rows in the demo database and record the argv that would have run.
Nothing here executes a process, so the repository is safe to run anywhere.
"""

from __future__ import annotations

import json

from .config import MIN_OS, READ_LIMIT
from .rules import window_open
from .validate import render_argv

EFFECTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS effects (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    human    TEXT NOT NULL,
    agent    TEXT NOT NULL,
    command  TEXT NOT NULL,
    target   TEXT NOT NULL,
    argv     TEXT
);
"""


def _where(filters):
    clauses = [c for c, _ in filters]
    params = [p for _, p in filters]
    return (" WHERE " + " AND ".join(clauses) if clauses else ""), params


def _rows(db, sql, params):
    return [dict(r) for r in db.execute(sql, params).fetchall()]


def read(db, now: str, command, values: dict, policy_search=None) -> dict:
    name = command.name

    if name == "query_servers":
        f = [(f"{col} = ?", values[col]) for col in ("owner_team", "env", "tier", "status")
             if col in values]
        if "below_min_os" in values:
            f.append(("os_version < ?" if values["below_min_os"] else "os_version >= ?", MIN_OS))
        where, params = _where(f)
        total = db.execute(f"SELECT COUNT(*) FROM servers{where}", params).fetchone()[0]
        by_team = dict(db.execute(
            f"SELECT owner_team, COUNT(*) FROM servers{where} GROUP BY 1 ORDER BY 2 DESC",
            params).fetchall())
        rows = _rows(db, f"SELECT * FROM servers{where} ORDER BY hostname LIMIT {READ_LIMIT}",
                     params)
        return {"total": total, "by_team": by_team, "showing": len(rows), "servers": rows}

    if name == "get_server":
        server = _rows(db, "SELECT * FROM servers WHERE hostname = ?", [values["host"]])[0]
        server["services"] = _rows(
            db, "SELECT service, state, since FROM services WHERE hostname = ? ORDER BY service",
            [values["host"]])
        server["change_window_open"] = window_open(db, server["env"], now)
        return server

    if name == "query_users":
        f = [(f"{col} = ?", values[col]) for col in ("team", "status", "auth_level")
             if col in values]
        if "service_accounts" in values:
            f.append(("is_service_account = ?", int(values["service_accounts"])))
        where, params = _where(f)
        total = db.execute(f"SELECT COUNT(*) FROM users{where}", params).fetchone()[0]
        rows = _rows(db, f"SELECT * FROM users{where} ORDER BY username LIMIT {READ_LIMIT}",
                     params)
        return {"total": total, "showing": len(rows), "users": rows}

    if name == "query_services":
        f = []
        if "host" in values:
            f.append(("sv.hostname = ?", values["host"]))
        for col in ("service", "state"):
            if col in values:
                f.append((f"sv.{col} = ?", values[col]))
        for col in ("owner_team", "env"):
            if col in values:
                f.append((f"s.{col} = ?", values[col]))
        where, params = _where(f)
        base = f"FROM services sv JOIN servers s ON s.hostname = sv.hostname{where}"
        total = db.execute(f"SELECT COUNT(*) {base}", params).fetchone()[0]
        rows = _rows(db, "SELECT sv.hostname, sv.service, sv.state, sv.since, s.env, s.tier, "
                         f"s.owner_team {base} ORDER BY sv.hostname, sv.service "
                         f"LIMIT {READ_LIMIT}", params)
        return {"total": total, "showing": len(rows), "services": rows}

    if name == "list_change_windows":
        f = [("ends_at > ?", now)]
        if "env" in values:
            f.append(("env = ?", values["env"]))
        where, params = _where(f)
        rows = _rows(db, f"SELECT env, starts_at, ends_at FROM change_windows{where} "
                         "ORDER BY starts_at LIMIT 6", params)
        for row in rows:
            row["open_now"] = row["starts_at"] <= now
        return {"now": now, "windows": rows}

    if name == "search_policies":
        if policy_search is None:
            return {"error": "policy search is not configured"}
        return {"query": values["query"], "results": policy_search(values["query"])}

    raise ValueError(f"no reader for {name}")


def apply(db, now: str, command, values: dict, human: str, agent: str) -> dict:
    """Apply a write inside the caller's transaction and describe what changed."""
    name = command.name
    argv = render_argv(command, values)
    result = {"simulated": True, "would_run": argv}

    if name == "restart_service":
        key = (values["host"], values["service"])
        before = db.execute("SELECT state FROM services WHERE hostname = ? AND service = ?",
                            key).fetchone()[0]
        db.execute("UPDATE services SET state = 'active', since = ? "
                   "WHERE hostname = ? AND service = ?", (now, *key))
        result.update(host=key[0], service=key[1], previous_state=before, state="active")
        target = f"{key[0]}:{key[1]}"
    elif name in ("drain_server", "restore_server"):
        status = "draining" if name == "drain_server" else "up"
        db.execute("UPDATE servers SET status = ? WHERE hostname = ?", (status, values["host"]))
        result.update(host=values["host"], status=status)
        target = values["host"]
    elif name == "delete_user":
        db.execute("UPDATE users SET status = 'deleted' WHERE username = ?",
                   (values["username"],))
        result.update(username=values["username"], status="deleted")
        target = values["username"]
    elif name == "erase_data":
        result.update(host=values["host"], dataset=values["dataset"], erased=True)
        target = f"{values['host']}:{values['dataset']}"
    else:
        raise ValueError(f"no effect for {name}")

    db.execute("INSERT INTO effects (ts, human, agent, command, target, argv) "
               "VALUES (?,?,?,?,?,?)", (now, human, agent, name, target, json.dumps(argv)))
    return result
