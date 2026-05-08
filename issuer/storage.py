"""
issuer/storage.py

Persistencia del Issuer: ofertas de credencial pendientes, c_nonces, status list.

Es SQLite porque el spike no necesita más; en producción se sustituye por
el backing store del Identfy Connector.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any

from shared.status_list import StatusListState, DEFAULT_STATUS_LIST_SIZE_BITS


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
    """Crea las tablas del issuer si no existen. Idempotente."""
    with _conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS credential_offers (
                offer_id           TEXT PRIMARY KEY,
                pre_authorized_code TEXT NOT NULL UNIQUE,
                agent_did          TEXT NOT NULL,
                mandate_json       TEXT NOT NULL,    -- MandateInput serializado
                status_list_index  INTEGER NOT NULL,
                redeemed           INTEGER NOT NULL DEFAULT 0,
                created_at         INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS access_tokens (
                token              TEXT PRIMARY KEY,
                offer_id           TEXT NOT NULL,
                c_nonce            TEXT NOT NULL,
                expires_at         INTEGER NOT NULL,
                FOREIGN KEY(offer_id) REFERENCES credential_offers(offer_id)
            );

            -- Una sola status list para el spike (id=1)
            CREATE TABLE IF NOT EXISTS status_list (
                id                 INTEGER PRIMARY KEY,
                size_bits          INTEGER NOT NULL,
                bits_blob          BLOB    NOT NULL,
                next_index         INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS issued_credentials (
                jti                TEXT PRIMARY KEY,
                agent_did          TEXT NOT NULL,
                status_list_index  INTEGER NOT NULL,
                issued_at          INTEGER NOT NULL,
                vc_jwt             TEXT NOT NULL
            );
            """
        )
        # Bootstrap del status list si está vacío
        row = c.execute("SELECT id FROM status_list WHERE id=1").fetchone()
        if row is None:
            empty = StatusListState.empty()
            c.execute(
                "INSERT INTO status_list (id, size_bits, bits_blob, next_index) VALUES (1, ?, ?, 0)",
                (empty.size_bits, bytes(empty.bits)),
            )


# ---------------------------------------------------------------------------
# credential offers
# ---------------------------------------------------------------------------

def save_credential_offer(
    *,
    offer_id: str,
    pre_authorized_code: str,
    agent_did: str,
    mandate_json: dict[str, Any],
    status_list_index: int,
    created_at: int,
) -> None:
    with _conn() as c:
        c.execute(
            """
            INSERT INTO credential_offers
                (offer_id, pre_authorized_code, agent_did, mandate_json, status_list_index, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (offer_id, pre_authorized_code, agent_did, json.dumps(mandate_json), status_list_index, created_at),
        )


def get_offer_by_pre_auth_code(pre_authorized_code: str) -> dict | None:
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM credential_offers WHERE pre_authorized_code=?",
            (pre_authorized_code,),
        ).fetchone()
        return dict(row) if row else None


def get_offer_by_id(offer_id: str) -> dict | None:
    with _conn() as c:
        row = c.execute("SELECT * FROM credential_offers WHERE offer_id=?", (offer_id,)).fetchone()
        return dict(row) if row else None


def mark_offer_redeemed(offer_id: str) -> None:
    with _conn() as c:
        c.execute("UPDATE credential_offers SET redeemed=1 WHERE offer_id=?", (offer_id,))


# ---------------------------------------------------------------------------
# access tokens / c_nonces
# ---------------------------------------------------------------------------

def save_access_token(*, token: str, offer_id: str, c_nonce: str, expires_at: int) -> None:
    with _conn() as c:
        c.execute(
            "INSERT INTO access_tokens (token, offer_id, c_nonce, expires_at) VALUES (?, ?, ?, ?)",
            (token, offer_id, c_nonce, expires_at),
        )


def get_access_token(token: str) -> dict | None:
    with _conn() as c:
        row = c.execute("SELECT * FROM access_tokens WHERE token=?", (token,)).fetchone()
        return dict(row) if row else None


def delete_access_token(token: str) -> None:
    with _conn() as c:
        c.execute("DELETE FROM access_tokens WHERE token=?", (token,))


# ---------------------------------------------------------------------------
# status list
# ---------------------------------------------------------------------------

def get_status_list_state() -> StatusListState:
    with _conn() as c:
        row = c.execute("SELECT size_bits, bits_blob FROM status_list WHERE id=1").fetchone()
    return StatusListState(size_bits=row["size_bits"], bits=bytearray(row["bits_blob"]))


def save_status_list_state(state: StatusListState) -> None:
    with _conn() as c:
        c.execute(
            "UPDATE status_list SET size_bits=?, bits_blob=? WHERE id=1",
            (state.size_bits, bytes(state.bits)),
        )


def reserve_status_list_index() -> int:
    """Asigna el siguiente índice libre del bitstring y lo persiste."""
    with _conn() as c:
        row = c.execute("SELECT next_index FROM status_list WHERE id=1").fetchone()
        idx = row["next_index"]
        c.execute("UPDATE status_list SET next_index=? WHERE id=1", (idx + 1,))
        return idx


def revoke_status_list_index(index: int) -> None:
    state = get_status_list_state()
    state.set_bit(index)
    save_status_list_state(state)


# ---------------------------------------------------------------------------
# issued credentials (registro auditable de lo que se ha emitido)
# ---------------------------------------------------------------------------

def record_issued_credential(*, jti: str, agent_did: str, status_list_index: int, issued_at: int, vc_jwt: str) -> None:
    with _conn() as c:
        c.execute(
            """
            INSERT INTO issued_credentials (jti, agent_did, status_list_index, issued_at, vc_jwt)
            VALUES (?, ?, ?, ?, ?)
            """,
            (jti, agent_did, status_list_index, issued_at, vc_jwt),
        )


def find_issued_credential_by_agent(agent_did: str) -> dict | None:
    """Devuelve el VC más reciente emitido a un agente dado."""
    with _conn() as c:
        row = c.execute(
            "SELECT * FROM issued_credentials WHERE agent_did=? ORDER BY issued_at DESC LIMIT 1",
            (agent_did,),
        ).fetchone()
        return dict(row) if row else None
