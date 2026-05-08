"""
verifier/trust_framework.py

Trust framework muy simple: lista de issuers que el verifier acepta como
emisores legítimos de Mandate Credentials.

En producción esto es Identfy ITF (Identfy Trust Framework). En el spike
basta con un fichero JSON o variable de entorno.
"""
from __future__ import annotations

import json
import os
from pathlib import Path


def _trust_path() -> Path:
    return Path(os.getenv("TRUST_FRAMEWORK_PATH", "./data/trust_framework.json"))


def load_trusted_issuers() -> list[str]:
    """Devuelve la lista de DIDs aceptados como issuer."""
    path = _trust_path()
    if not path.exists():
        # En el spike, si no existe el fichero, confiamos en la
        # ORG_DID configurada (auto-trust del propio issuer mock).
        org_did = os.getenv("ORG_DID", "did:web:localhost%3A8000")
        return [org_did]
    return json.loads(path.read_text(encoding="utf-8"))


def is_trusted_issuer(did: str) -> bool:
    return did in load_trusted_issuers()


def add_trusted_issuer(did: str) -> None:
    """Sólo para scripts de bootstrap."""
    path = _trust_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    issuers = load_trusted_issuers() if path.exists() else []
    if did not in issuers:
        issuers.append(did)
        path.write_text(json.dumps(issuers, indent=2), encoding="utf-8")
