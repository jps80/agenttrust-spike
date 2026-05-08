"""
registry_ui/storage.py

Persistencia de los agentes dados de alta desde la UI.

Cada alta consta de: agent_id legible, agent_did (did:key derivado de la
clave del agente), datos del mandato, y metadata del flow OID4VCI
(offer_id, status_list_index) para poder mostrar al usuario humano qué
ha pasado y reusar el offer si refresca la página.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager


_LOCK = threading.Lock()


def _db_path() -> str:
    return os.getenv("SQLITE_PATH", "./data/agenttrust.db")


@contextmanager
def _conn():
    path = _db_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with _LOCK:
        c = sqlite3.connect(path)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        finally:
            c.close()


def init_db() -> None:
    with _conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS registered_agents (
                agent_id          TEXT PRIMARY KEY,
                agent_did         TEXT NOT NULL,
                organization_did  TEXT NOT NULL,
                delegator_did     TEXT NOT NULL,
                mandate_json      TEXT NOT NULL,
                offer_id          TEXT,
                credential_offer  TEXT,
                created_at        INTEGER NOT NULL
            );
            """
        )


def save_agent(
    *,
    agent_id: str,
    agent_did: str,
    organization_did: str,
    delegator_did: str,
    mandate_json: dict,
    offer_id: str | None,
    credential_offer: dict | None,
    created_at: int,
) -> None:
    with _conn() as c:
        c.execute(
            """
            INSERT OR REPLACE INTO registered_agents
                (agent_id, agent_did, organization_did, delegator_did,
                 mandate_json, offer_id, credential_offer, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                agent_id,
                agent_did,
                organization_did,
                delegator_did,
                json.dumps(mandate_json),
                offer_id,
                json.dumps(credential_offer) if credential_offer else None,
                created_at,
            ),
        )


def list_agents() -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM registered_agents ORDER BY created_at DESC"
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["mandate"] = json.loads(d.pop("mandate_json"))
        if d.get("credential_offer"):
            d["credential_offer"] = json.loads(d["credential_offer"])
        out.append(d)
    return out


def get_agent(agent_id: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM registered_agents WHERE agent_id=?", (agent_id,)
        ).fetchone()
    if row is None:
        return None
    d = dict(row)
    d["mandate"] = json.loads(d.pop("mandate_json"))
    if d.get("credential_offer"):
        d["credential_offer"] = json.loads(d["credential_offer"])
    return d
