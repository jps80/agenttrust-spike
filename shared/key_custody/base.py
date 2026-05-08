"""
shared/key_custody/base.py

Interfaz abstracta de custodia de claves.

Este es el núcleo de H2. La pregunta del spike es: ¿podemos firmar JWTs (proof OID4VCI,
JWT VC, JWT VP) sin que la clave privada salga nunca en claro fuera del componente de
custodia? La respuesta es sí, siempre que toda la pila criptográfica del agente,
issuer y holder use esta interfaz en vez de cargar claves PEM.

Implementaciones:
  - LocalFileCustody  — clave en fichero cifrado, opción por defecto del spike
  - VaultCustody      — HashiCorp Vault Transit engine, valida H2 contra un KMS real
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Literal


# Algoritmos soportados en el spike.
# Ed25519 → JWA "EdDSA". Migrable a ES256 para EUDI Wallet ARF en producción.
SupportedAlgorithm = Literal["EdDSA"]


class KeyCustody(ABC):
    """
    Contrato uniforme para firmar y exponer la clave pública.

    Cualquier código que necesite firmar (issuer firmando una VC, agente firmando
    el proof OID4VCI o un VP) trabaja contra esta interfaz, no contra una librería
    de criptografía concreta. Esto permite intercambiar LocalFile ↔ Vault con un
    cambio de configuración, que es exactamente el aprendizaje que H2 quiere validar.
    """

    @property
    @abstractmethod
    def algorithm(self) -> SupportedAlgorithm:
        """Algoritmo JWA usado por esta custodia (ej. 'EdDSA')."""

    @property
    @abstractmethod
    def key_id(self) -> str:
        """
        Identificador estable de la clave (no es el JWK kid, es el handle interno
        del backend: ruta de fichero, nombre de la clave en Vault, etc.).
        """

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """
        Firma `data` y devuelve los bytes de la firma (no el JWT completo,
        solo la firma raw). El llamador se ocupa del encoding base64url.

        La clave privada NO debe salir en claro de la implementación.
        """

    @abstractmethod
    def get_public_jwk(self) -> dict:
        """
        Devuelve la clave pública en formato JWK (RFC 7517).
        Para Ed25519: {"kty": "OKP", "crv": "Ed25519", "x": "<base64url>"}
        """

    @abstractmethod
    def rotate(self) -> None:
        """
        Rota la clave (genera nueva versión). El backend debe seguir
        permitiendo verificar firmas antiguas durante un periodo de gracia.
        En el spike, rotación = generar nueva clave y descartar la anterior.
        """

    def jwk_thumbprint_kid(self) -> str:
        """
        Calcula el JWK Thumbprint (RFC 7638) como kid del JWK público actual.
        Wrapper de conveniencia que delega en `thumbprint_for`.
        """
        return self.thumbprint_for(self.get_public_jwk())

    @staticmethod
    def thumbprint_for(jwk: dict) -> str:
        """
        Calcula el JWK Thumbprint (RFC 7638) de un JWK dado.

        Es estático y toma el JWK como argumento para que `get_public_jwk()`
        pueda usarlo durante su construcción (sin caer en recursión infinita
        al intentar derivar el `kid`).
        """
        import base64
        import hashlib
        import json

        # RFC 7638: ordenar campos requeridos según el `kty`. NO se incluye kid.
        if jwk.get("kty") == "OKP":
            canonical = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
        elif jwk.get("kty") == "EC":
            canonical = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
        else:
            raise NotImplementedError(f"kty={jwk.get('kty')} no soportado en spike")

        canonical_json = json.dumps(canonical, separators=(",", ":"), sort_keys=False)
        digest = hashlib.sha256(canonical_json.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
