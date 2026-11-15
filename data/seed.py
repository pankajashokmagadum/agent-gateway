"""Seed the FDE demo database.

Deterministic: a fixed RNG seed means the same database every run, so the
attack suite and the eval numbers are reproducible.

Usage:  python data/seed.py            (writes data/fde.db)
        python data/seed.py /tmp/x.db  (writes somewhere else, e.g. for tests)
"""

import random
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "fde.db"
SEED = 20261110
RNG = random.Random(SEED)
NOW = datetime(2026, 11, 10, 14, 0, tzinfo=timezone.utc)

# Servers below this are out of compliance (policy ops-02).
MIN_OS = "22.04"

REGIONS = ["use1", "use2", "usw2", "euw1"]
TEAMS = ["network-core", "platform", "payments", "checkout", "data-eng", "sre"]
OS_VERSIONS = ["20.04", "22.04", "24.04"]

SCHEMA = """
DROP TABLE IF EXISTS servers;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS change_windows;
DROP TABLE IF EXISTS approvals;
DROP TABLE IF EXISTS services;
DROP TABLE IF EXISTS effects;

CREATE TABLE servers (
    hostname    TEXT PRIMARY KEY,
    env         TEXT NOT NULL,   -- prod | staging | dev
    tier        TEXT NOT NULL,   -- core | edge | access
    os_version  TEXT NOT NULL,
    region      TEXT NOT NULL,
    owner_team  TEXT NOT NULL,
    status      TEXT NOT NULL    -- up | down | draining
);

CREATE TABLE users (
    username            TEXT PRIMARY KEY,
    full_name           TEXT NOT NULL,
    team                TEXT NOT NULL,
    is_service_account  INTEGER NOT NULL,
    status              TEXT NOT NULL,  -- active | disabled | deleted
    auth_level          TEXT NOT NULL   -- viewer | engineer | operator | admin
);

CREATE TABLE change_windows (
    id         INTEGER PRIMARY KEY,
    env        TEXT NOT NULL,
    starts_at  TEXT NOT NULL,
    ends_at    TEXT NOT NULL
);

CREATE TABLE approvals (
    token        TEXT PRIMARY KEY,
    requested_by TEXT NOT NULL,   -- the human the approval was issued to
    approved_by  TEXT NOT NULL,   -- the admin who signed off
    scope        TEXT NOT NULL,   -- exact action, e.g. restart_service:core-use1-02:authd
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    used_at      TEXT             -- NULL until consumed; approvals are single-use
);

CREATE TABLE services (
    hostname  TEXT NOT NULL,
    service   TEXT NOT NULL,
    state     TEXT NOT NULL,      -- active | degraded | failed
    since     TEXT NOT NULL,
    PRIMARY KEY (hostname, service)
);
"""

FIRST = ["Jane", "Marco", "Priya", "Tom", "Lena", "Omar", "Sofia", "Dan",
         "Ava", "Kenji", "Nina", "Raj", "Elena", "Chris", "Mei", "Youssef"]
LAST = ["Chen", "Rios", "Nair", "Okafor", "Vargas", "Haddad", "Rossi", "Kim",
        "Silva", "Tanaka", "Novak", "Patel", "Costa", "Dubois", "Lin", "Ahmed"]


def iso(dt):
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def make_servers():
    rows, seen = [], set()
    for _ in range(300):
        tier = RNG.choices(["core", "edge", "access"], weights=[10, 25, 65])[0]
        env = RNG.choices(["prod", "staging", "dev"], weights=[60, 25, 15])[0]
        region = RNG.choice(REGIONS)
        team = RNG.choice(TEAMS)

        prefix = {"core": "core", "edge": "edge", "access": "app"}[tier]
        for _ in range(50):
            host = f"{prefix}-{region}-{RNG.randint(1, 99):02d}"
            if host not in seen:
                break
        if host in seen:
            continue
        seen.add(host)

        # PLANTED FINDING: payments runs old. Roughly 15% of the fleet sits
        # below MIN_OS, most of it in one team, so "which boxes are out of
        # compliance" returns a real, non-random answer.
        if team == "payments":
            os_v = RNG.choices(OS_VERSIONS, weights=[55, 35, 10])[0]
        else:
            os_v = RNG.choices(OS_VERSIONS, weights=[4, 56, 40])[0]

        rows.append((
            host, env, tier, os_v, region, team,
            RNG.choices(["up", "draining", "down"], weights=[90, 5, 5])[0],
        ))
    return rows


LEVELS  = ["viewer", "engineer", "operator", "admin"]
WEIGHTS = [15, 60, 20, 5]


def make_users():
    rows, seen = [], set()
    for _ in range(130):
        fn, ln = RNG.choice(FIRST), RNG.choice(LAST)
        username = (fn[0] + ln).lower()
        if username in seen:
            continue
        seen.add(username)
        rows.append((username, f"{fn} {ln}", RNG.choice(TEAMS), 0, "active",
                     RNG.choices(LEVELS, weights=WEIGHTS)[0]))

    svc = ["svc-bkp", "svc-deploy", "svc-monitor", "svc-ci",
           "svc-scan", "svc-sync", "svc-log", "svc-mesh",
           "svc-vault", "svc-ingest", "svc-etl", "svc-reaper",
           "svc-cron", "svc-probe", "svc-relay", "svc-cache",
           "svc-gw", "svc-dns", "svc-ntp", "svc-audit"]
    for name in svc:
        seen.add(name)
        # PLANTED FINDING: one service account holds admin it does not need.
        # Over-privileged automation accounts are the most common finding in
        # any real access review.
        level = "admin" if name == "svc-reaper" else \
                RNG.choices(["viewer", "engineer"], weights=[40, 60])[0]
        rows.append((name, name.replace("svc-", "").title() + " Service",
                     RNG.choice(TEAMS), 1, "active", level))

    # Fixed identities the demo, the approvals table and the attack suite
    # refer to by name. Pinned so they always exist with known properties.
    pinned = [
        ("jchen", "Jane Chen",  "network-core", 0, "active",   "admin"),
        # Two more admins, so two-person approval has distinct approvers.
        ("onovak",  "Omar Novak",  "sre",      0, "active", "admin"),
        ("lhaddad", "Lena Haddad", "payments", 0, "active", "admin"),
        ("pnair", "Priya Nair", "platform",     0, "active",   "operator"),
        ("tkim",  "Tom Kim",    "checkout",     0, "active",   "engineer"),
        # PLANTED: holds operator authority but the account is disabled —
        # the gateway must check status, not only auth_level.
        ("mrios", "Marco Rios", "platform",     0, "disabled", "operator"),
    ]
    names = {p[0] for p in pinned}
    rows = [r for r in rows if r[0] not in names]
    rows += pinned
    return rows


def make_change_windows():
    rows = []
    # staging and dev are always open; prod gets scheduled windows.
    far = NOW + timedelta(days=3650)
    rows.append((1, "staging", iso(NOW - timedelta(days=365)), iso(far)))
    rows.append((2, "dev", iso(NOW - timedelta(days=365)), iso(far)))

    # Weekly prod window, Thursday 02:00-06:00 UTC, for the next 10 weeks.
    cursor = NOW - timedelta(days=NOW.weekday()) + timedelta(days=3)
    cursor = cursor.replace(hour=2, minute=0)
    for i in range(10):
        start = cursor + timedelta(weeks=i)
        rows.append((3 + i, "prod", iso(start), iso(start + timedelta(hours=4))))
    return rows


def make_approvals():
    """(token, requested_by, approved_by, scope, created_at, expires_at, used_at)

    An approval is bound to one requester and one exact action, expires, and
    is consumed by the action it authorizes.
    """
    created = iso(NOW - timedelta(minutes=30))
    return [
        # Valid at NOW: the happy path for a core-tier restart.
        ("tok_4c1e", "pnair", "jchen", "restart_service:core-use1-02:authd",
         created, iso(NOW + timedelta(hours=2)), None),
        # PLANTED: already expired. The replay test presents this one.
        ("tok_expired", "pnair", "jchen", "restart_service:core-use1-07:authd",
         iso(NOW - timedelta(hours=6)), iso(NOW - timedelta(hours=3)), None),
        # Valid, but for a different host: proves the gateway matches the
        # exact scope and not merely "this requester holds a token".
        ("tok_9f2a", "pnair", "jchen", "restart_service:app-usw2-31:nginx",
         created, iso(NOW + timedelta(hours=4)), None),
        # Valid, but issued to a different requester: proves an approval
        # cannot be borrowed across sessions.
        ("tok_77ab", "tkim", "jchen", "restart_service:edge-use1-14:nginx",
         created, iso(NOW + timedelta(hours=6)), None),
    ]


TIER_SERVICES = {
    "core":   ["sshd", "node_exporter", "authd"],
    "edge":   ["sshd", "node_exporter", "nginx"],
    "access": ["sshd", "node_exporter", "nginx"],
}
TEAM_SERVICE = {"checkout": "checkout-api", "payments": "payments-api",
                "data-eng": "postgres", "platform": "redis"}

# Service states the demo and the tests rely on.
PINNED_SERVICES = {
    ("core-use1-02", "authd"): "failed",        # the incident root cause
    ("core-use1-07", "authd"): "active",
    ("edge-use1-14", "nginx"): "degraded",
    ("app-usw2-31", "nginx"): "active",
    ("app-usw2-31", "checkout-api"): "degraded",  # the visible symptom
    ("app-usw2-32", "nginx"): "failed",         # staging: fixable without approval
    ("app-usw2-32", "checkout-api"): "active",
}


def make_services(servers):
    rows = {}
    since = iso(NOW - timedelta(days=9))
    for host, _env, tier, _os, _region, team, _status in servers:
        names = list(TIER_SERVICES[tier])
        if tier == "access" and team in TEAM_SERVICE:
            names.append(TEAM_SERVICE[team])
        for name in names:
            state = RNG.choices(["active", "degraded", "failed"],
                                weights=[96, 2, 2])[0]
            rows[(host, name)] = (host, name, state, since)
    recent = iso(NOW - timedelta(minutes=42))
    for (host, name), state in PINNED_SERVICES.items():
        rows[(host, name)] = (host, name, state,
                              since if state == "active" else recent)
    return sorted(rows.values())


def main(db_path=DB_PATH, quiet=False):
    RNG.seed(SEED)   # same data no matter how many times this runs in a process
    con = sqlite3.connect(db_path)
    con.executescript(SCHEMA)

    servers = make_servers()
    users = make_users()

    # Guarantee the hosts the demo and tests name actually exist.
    pinned = {
        "core-use1-02": ("prod", "core", "22.04", "use1", "network-core", "up"),
        "core-use1-07": ("prod", "core", "20.04", "use1", "network-core", "up"),
        "edge-use1-14": ("prod", "edge", "24.04", "use1", "platform", "up"),
        "app-usw2-31": ("prod", "access", "22.04", "usw2", "checkout", "up"),
        "app-usw2-32": ("staging", "access", "22.04", "usw2", "checkout", "draining"),
    }
    servers = [s for s in servers if s[0] not in pinned]
    servers += [(h,) + v for h, v in pinned.items()]

    con.executemany("INSERT INTO servers VALUES (?,?,?,?,?,?,?)", servers)
    con.executemany("INSERT INTO users VALUES (?,?,?,?,?,?)", users)
    con.executemany("INSERT INTO change_windows VALUES (?,?,?,?)", make_change_windows())
    con.executemany("INSERT INTO approvals VALUES (?,?,?,?,?,?,?)", make_approvals())
    services = make_services(servers)
    con.executemany("INSERT INTO services VALUES (?,?,?,?)", services)
    con.commit()

    stale = con.execute(
        "SELECT COUNT(*) FROM servers WHERE os_version < ?", (MIN_OS,)
    ).fetchone()[0]
    if quiet:
        con.close()
        return
    print(f"{db_path}")
    print(f"  servers        {len(servers):>4}   ({stale} below {MIN_OS})")
    print(f"  users          {len(users):>4}   "
          f"({sum(u[3] for u in users)} service accounts, "
          f"{sum(1 for u in users if u[4] == 'disabled')} disabled)")
    print(f"  change_windows {con.execute('SELECT COUNT(*) FROM change_windows').fetchone()[0]:>4}")
    print(f"  approvals      {con.execute('SELECT COUNT(*) FROM approvals').fetchone()[0]:>4}   (1 expired)")
    unhealthy = sum(1 for s in services if s[2] != "active")
    print(f"  services       {len(services):>4}   ({unhealthy} not active)")
    con.close()


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else DB_PATH)
