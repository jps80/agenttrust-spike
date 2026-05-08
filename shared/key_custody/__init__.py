"""
shared/key_custody — selección de backend según configuración.
"""
from __future__ import annotations

import os

from .base import KeyCustody, SupportedAlgorithm
from .local_file import LocalFileCustody
from .vault import VaultCustody

__all__ = ["KeyCustody", "SupportedAlgorithm", "LocalFileCustody", "VaultCustody", "build_custody"]


def build_custody(key_name: str) -> KeyCustody:
    """
    Factory que lee la variable de entorno `KEY_CUSTODY_BACKEND` y construye
    la implementación correspondiente.

    Valores: "local" (default) | "vault"
    """
    backend = os.getenv("KEY_CUSTODY_BACKEND", "local").lower()

    if backend == "vault":
        return VaultCustody(
            vault_addr=os.getenv("VAULT_ADDR", "http://localhost:8200"),
            vault_token=os.getenv("VAULT_TOKEN", "root-token-spike"),
            key_name=key_name,
            transit_mount=os.getenv("VAULT_TRANSIT_MOUNT", "transit"),
        )

    if backend == "local":
        return LocalFileCustody(
            key_dir=os.getenv("LOCAL_KEY_DIR", "./data/keys"),
            key_name=key_name,
        )

    raise ValueError(
        f"KEY_CUSTODY_BACKEND={backend!r} no soportado. Usa 'local' o 'vault'."
    )
