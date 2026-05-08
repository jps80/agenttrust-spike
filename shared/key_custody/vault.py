"""
shared/key_custody/vault.py

Custodia de claves en HashiCorp Vault con motor Transit.

Esta es la implementación que valida H2 contra un KMS real: la clave privada
NUNCA sale de Vault. El agente firma llamando a la API HTTP de Vault
(`POST /v1/transit/sign/<key_name>`), nunca tiene los bytes de la privada.

Es el patrón equivalente a AWS KMS / Azure Key Vault / GCP KMS para el spike,
con la ventaja de que se puede levantar localmente:

    docker run -d --name vault-spike -p 8200:8200 \\
      -e 'VAULT_DEV_ROOT_TOKEN_ID=root-token-spike' \\
      hashicorp/vault:latest

    # luego: bash scripts/init_vault.sh

DECISIÓN A REGISTRAR EN EL DOCUMENTO DE H2:
La latencia de cada firma es la latencia de un round-trip HTTP a Vault. Para
flujos OID4VCI/VP que requieren 1-2 firmas no es notable; para flujos masivos
de Action Records (iteración 2) habrá que medir y, si hace falta, cachear
batches de tokens efímeros firmados contra Vault.
"""
from __future__ import annotations

import base64
import os

import hvac

from .base import KeyCustody, SupportedAlgorithm


class VaultCustody(KeyCustody):
    """
    Custodia Ed25519 en Vault Transit. La clave debe haberse creado con
    `vault write -f transit/keys/<key_name> type=ed25519` o equivalente
    (ver scripts/init_vault.sh).
    """

    def __init__(
        self,
        vault_addr: str,
        vault_token: str,
        key_name: str,
        transit_mount: str = "transit",
    ):
        self._client = hvac.Client(url=vault_addr, token=vault_token)
        if not self._client.is_authenticated():
            raise RuntimeError(
                f"No se pudo autenticar contra Vault en {vault_addr}. "
                "Comprueba VAULT_TOKEN."
            )
        self._key_name = key_name
        self._mount = transit_mount

        # Cache de la JWK pública: la consultamos a Vault una vez.
        self._public_jwk: dict | None = None

        self._ensure_key_exists()

    # ------------------------------------------------------------------
    # KeyCustody interface
    # ------------------------------------------------------------------

    def _ensure_key_exists(self) -> None:
        try:
            self._client.secrets.transit.read_key(
                name=self._key_name,
                mount_point=self._mount,
            )
        except Exception:
            self._client.secrets.transit.create_key(
                name=self._key_name,
                key_type="ed25519",
                mount_point=self._mount,
            )

    @property
    def algorithm(self) -> SupportedAlgorithm:
        return "EdDSA"

    @property
    def key_id(self) -> str:
        return f"vault::{self._mount}/{self._key_name}"

    def sign(self, data: bytes) -> bytes:
        """
        Firma vía Vault Transit. Vault devuelve la firma en su propio formato
        (`vault:v1:<base64>`); extraemos los bytes raw de la firma Ed25519.
        """
        b64_input = base64.b64encode(data).decode("ascii")
        result = self._client.secrets.transit.sign_data(
            name=self._key_name,
            hash_input=b64_input,
            mount_point=self._mount,
            # Ed25519 no usa hash previo (Vault lo gestiona internamente)
            prehashed=False,
            # Marshaling Ed25519 estándar
            marshaling_algorithm="jws",
        )

        signature_str: str = result["data"]["signature"]
        # Formato de Vault: "vault:v<N>:<base64-firma>"
        # Solo nos interesa la última parte
        _, _, b64_sig = signature_str.split(":", 2)
        # jws marshaling devuelve base64url SIN padding
        b64_sig_padded = b64_sig + "=" * (-len(b64_sig) % 4)
        return base64.urlsafe_b64decode(b64_sig_padded)

    def get_public_jwk(self) -> dict:
        if self._public_jwk is not None:
            return self._public_jwk

        result = self._client.secrets.transit.read_key(
            name=self._key_name,
            mount_point=self._mount,
        )
        # Vault devuelve un dict de versiones: {"keys": {"1": {"public_key": "<base64>"}}}
        keys_dict = result["data"]["keys"]
        latest_version = max(int(v) for v in keys_dict.keys())
        version_data = keys_dict[str(latest_version)]
        # public_key viene como base64 estándar
        pub_b64 = version_data["public_key"]
        pub_raw = base64.b64decode(pub_b64)

        x = base64.urlsafe_b64encode(pub_raw).rstrip(b"=").decode("ascii")
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": x}
        jwk["kid"] = KeyCustody.thumbprint_for(jwk)
        self._public_jwk = jwk
        return jwk

    def rotate(self) -> None:
        """
        Pide a Vault que rote la clave. Vault mantiene versiones anteriores;
        las firmas con versión vieja siguen verificándose. Para el spike, eso
        es suficiente: cuando el issuer rota, el verifier puede seguir
        validando VCs antiguas hasta que el issuer publique el did:web nuevo.
        """
        self._client.secrets.transit.rotate_key(
            name=self._key_name,
            mount_point=self._mount,
        )
        # Invalida la caché de la JWK pública
        self._public_jwk = None
