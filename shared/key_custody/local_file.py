"""
shared/key_custody/local_file.py

Custodia de claves en fichero cifrado simétrico.

Es el backend por defecto del spike: simple, sin dependencias externas,
suficiente para validar el resto de hipótesis sin requerir Vault corriendo.

LIMITACIONES (asumidas en el spike, documentadas como riesgo):
  - La clave de cifrado está en disco junto al fichero — NO es seguridad real.
  - No soporta rotación con periodo de gracia: rotate() descarta la versión
    anterior. En producción se mantienen versiones para validar firmas
    antiguas durante un tiempo.
  - No tiene HSM, no tiene atestación remota, no escala a flota.

Para validar H2 con un KMS de verdad, usar VaultCustody.
"""
from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from .base import KeyCustody, SupportedAlgorithm


class LocalFileCustody(KeyCustody):
    """
    Custodia Ed25519 en fichero. La clave privada está en `<dir>/<name>.priv`
    como bytes raw de 32 bytes (Ed25519 seed).
    """

    def __init__(self, key_dir: str | os.PathLike, key_name: str):
        self._key_dir = Path(key_dir)
        self._key_name = key_name
        self._key_dir.mkdir(parents=True, exist_ok=True)
        self._priv_path = self._key_dir / f"{key_name}.priv"
        self._private_key: Ed25519PrivateKey = self._load_or_create()

    # ------------------------------------------------------------------
    # ciclo de vida
    # ------------------------------------------------------------------

    def _load_or_create(self) -> Ed25519PrivateKey:
        if self._priv_path.exists():
            seed = self._priv_path.read_bytes()
            return Ed25519PrivateKey.from_private_bytes(seed)

        # Genera nueva clave
        priv = Ed25519PrivateKey.generate()
        seed = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # NOTA spike: en producción esto va cifrado o detrás de KMS.
        self._priv_path.write_bytes(seed)
        os.chmod(self._priv_path, 0o600)
        return priv

    # ------------------------------------------------------------------
    # KeyCustody interface
    # ------------------------------------------------------------------

    @property
    def algorithm(self) -> SupportedAlgorithm:
        return "EdDSA"

    @property
    def key_id(self) -> str:
        return f"local::{self._key_name}"

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)

    def get_public_jwk(self) -> dict:
        import base64

        pub: Ed25519PublicKey = self._private_key.public_key()
        raw = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": x}
        # Calculamos el kid desde el JWK ya construido (sin recursión)
        jwk["kid"] = KeyCustody.thumbprint_for(jwk)
        return jwk

    def rotate(self) -> None:
        # Borra la clave actual y genera nueva. El llamador debe republicar
        # el did:web document después.
        if self._priv_path.exists():
            self._priv_path.unlink()
        self._private_key = self._load_or_create()
