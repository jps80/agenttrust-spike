"""
shared/status_list.py

Implementación de **W3C Bitstring Status List v1.0** para revocación
preservando privacidad.

Por qué importa en AgentTrust:

Cuando una organización despliega 100 agentes y revoca el mandato de uno
de ellos (porque está comprometido, porque ha cumplido su misión, porque
ha cambiado el alcance), la revocación tiene que propagarse a TODOS los
verificadores en tiempo real, sin filtrar a un observador externo cuál
de los 100 agentes ha sido revocado.

Bitstring Status List resuelve esto:
  - El issuer mantiene un bitstring grande (mínimo 16 KB recomendado por W3C).
  - Cada VC tiene un índice asignado dentro del bitstring.
  - Para revocar: poner el bit a 1.
  - El bitstring entero (gzip + base64) se publica como otra VC firmada por
    el issuer, accesible públicamente.
  - Un observador no puede deducir QUÉ credencial corresponde a qué bit.

En el spike, simplificamos el tamaño (1024 entries) para que sea legible.
"""
from __future__ import annotations

import base64
import gzip
from dataclasses import dataclass

from .jwt_utils import sign_jwt, now_iso, now_ts
from .key_custody import KeyCustody


# Tamaño de la status list en BITS. 1024 es suficiente para el spike y produce
# un payload pequeño y depurable. En producción W3C recomienda mínimo 131072.
DEFAULT_STATUS_LIST_SIZE_BITS = 1024


@dataclass
class StatusListState:
    """Estado mutable del bitstring. El issuer la persiste en SQLite."""
    size_bits: int
    bits: bytearray   # bytes ceil(size_bits/8)

    @classmethod
    def empty(cls, size_bits: int = DEFAULT_STATUS_LIST_SIZE_BITS) -> "StatusListState":
        size_bytes = (size_bits + 7) // 8
        return cls(size_bits=size_bits, bits=bytearray(size_bytes))

    @classmethod
    def from_bytes(cls, raw: bytes, size_bits: int) -> "StatusListState":
        # `raw` ya es la decodificación cruda (sin gzip ni base64)
        return cls(size_bits=size_bits, bits=bytearray(raw))

    # ------------------------------------------------------------------
    # operaciones sobre bits
    # ------------------------------------------------------------------

    def is_set(self, index: int) -> bool:
        self._check_index(index)
        byte_idx, bit_idx = divmod(index, 8)
        return bool(self.bits[byte_idx] & (1 << (7 - bit_idx)))  # MSB-first per spec

    def set_bit(self, index: int) -> None:
        self._check_index(index)
        byte_idx, bit_idx = divmod(index, 8)
        self.bits[byte_idx] |= (1 << (7 - bit_idx))

    def clear_bit(self, index: int) -> None:
        self._check_index(index)
        byte_idx, bit_idx = divmod(index, 8)
        self.bits[byte_idx] &= ~(1 << (7 - bit_idx))

    def _check_index(self, index: int) -> None:
        if index < 0 or index >= self.size_bits:
            raise IndexError(f"Index {index} fuera de rango [0, {self.size_bits})")


# ---------------------------------------------------------------------------
# encoding / decoding del bitstring
# ---------------------------------------------------------------------------

def encode_bitstring(state: StatusListState) -> str:
    """
    GZIP + base64url (per spec). Devuelve el string que va dentro de
    `credentialSubject.encodedList`.
    """
    compressed = gzip.compress(bytes(state.bits))
    return base64.urlsafe_b64encode(compressed).rstrip(b"=").decode("ascii")


def decode_bitstring(encoded: str, size_bits: int) -> StatusListState:
    padded = encoded + "=" * (-len(encoded) % 4)
    compressed = base64.urlsafe_b64decode(padded)
    raw = gzip.decompress(compressed)
    return StatusListState.from_bytes(raw, size_bits=size_bits)


# ---------------------------------------------------------------------------
# emisión de la status list como VC firmada por el issuer
# ---------------------------------------------------------------------------

def issue_status_list_vc_jwt(
    *,
    issuer_did: str,
    issuer_key_id: str,
    issuer_custody: KeyCustody,
    status_list_id: str,             # URL pública del status list (ej. http://issuer/status-list/1)
    state: StatusListState,
) -> str:
    """
    Empaqueta el estado actual del bitstring como VC firmada y la devuelve
    como JWT compacto. El verifier hace fetch de esto cada vez que
    necesita comprobar revocación.
    """
    encoded = encode_bitstring(state)

    vc = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
        ],
        "id": status_list_id,
        "type": ["VerifiableCredential", "BitstringStatusListCredential"],
        "issuer": issuer_did,
        "validFrom": now_iso(),
        "credentialSubject": {
            "id": f"{status_list_id}#list",
            "type": "BitstringStatusList",
            "statusPurpose": "revocation",
            "encodedList": encoded,
        },
    }

    payload = {
        "iss": issuer_did,
        "iat": now_ts(),
        "jti": status_list_id,
        "vc": vc,
    }
    header = {
        "alg": issuer_custody.algorithm,
        "typ": "JWT",
        "kid": f"{issuer_did}#{issuer_key_id}",
    }
    return sign_jwt(header, payload, issuer_custody)
