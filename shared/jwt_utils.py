"""
shared/jwt_utils.py

Construcción y verificación de JWS/JWT compatibles con KeyCustody.

Importante: NO usamos PyJWT ni jwcrypto al firmar, porque esas librerías necesitan
el material privado en memoria. Como la clave puede vivir en Vault (o un KMS),
construimos el signing input manualmente y pedimos a KeyCustody que firme los bytes.

Para verificar sí podemos usar la librería estándar de cryptography, ya que la
verificación necesita solo la clave pública (que sí tenemos).
"""
from __future__ import annotations

import base64
import json
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .key_custody import KeyCustody


# ---------------------------------------------------------------------------
# base64url helpers
# ---------------------------------------------------------------------------

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded)


# ---------------------------------------------------------------------------
# firma
# ---------------------------------------------------------------------------

def sign_jwt(header: dict[str, Any], payload: dict[str, Any], custody: KeyCustody) -> str:
    """
    Construye un JWT compacto firmando con `custody`.

    El header debe contener `alg`. Si no lo hace, lo añadimos a partir
    de la custodia. `typ` y `kid` los pone el llamador (tienen significado
    distinto según sea un VC, un VP o un proof OID4VCI).
    """
    if "alg" not in header:
        header = {**header, "alg": custody.algorithm}

    header_json = json.dumps(header, separators=(",", ":"), sort_keys=False)
    payload_json = json.dumps(payload, separators=(",", ":"), sort_keys=False)

    header_b64 = b64url_encode(header_json.encode("utf-8"))
    payload_b64 = b64url_encode(payload_json.encode("utf-8"))

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = custody.sign(signing_input)
    sig_b64 = b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


# ---------------------------------------------------------------------------
# parse
# ---------------------------------------------------------------------------

class JWTParseError(Exception):
    pass


class JWTVerifyError(Exception):
    pass


def parse_jwt_unverified(token: str) -> tuple[dict, dict, bytes, bytes]:
    """
    Decodifica un JWT compacto SIN verificar la firma.
    Devuelve (header, payload, signing_input, signature).
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTParseError(f"JWT mal formado: esperaba 3 partes, hay {len(parts)}")

    header_b64, payload_b64, sig_b64 = parts
    try:
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))
    except (ValueError, json.JSONDecodeError) as e:
        raise JWTParseError(f"No se pudo decodificar header/payload: {e}") from e

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = b64url_decode(sig_b64)
    return header, payload, signing_input, signature


def verify_jwt_with_jwk(token: str, public_jwk: dict) -> dict:
    """
    Verifica un JWT contra una JWK pública dada y devuelve el payload.

    Soporta solo Ed25519 / EdDSA (suficiente para el spike).
    """
    header, payload, signing_input, signature = parse_jwt_unverified(token)

    alg = header.get("alg")
    if alg != "EdDSA":
        raise JWTVerifyError(f"alg={alg} no soportado en spike (solo EdDSA)")

    if public_jwk.get("kty") != "OKP" or public_jwk.get("crv") != "Ed25519":
        raise JWTVerifyError(
            f"JWK incompatible: kty={public_jwk.get('kty')} crv={public_jwk.get('crv')}"
        )

    pub_raw = b64url_decode(public_jwk["x"])
    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_raw)
        pub.verify(signature, signing_input)
    except InvalidSignature as e:
        raise JWTVerifyError("Firma inválida") from e
    except Exception as e:
        raise JWTVerifyError(f"Error verificando: {e}") from e

    return payload


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def now_ts() -> int:
    """Timestamp Unix actual en segundos (campo iat / nbf / exp)."""
    return int(time.time())


def now_iso() -> str:
    """ISO 8601 UTC con sufijo Z (campo validFrom / validUntil de VCDM)."""
    from datetime import datetime, timezone
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
