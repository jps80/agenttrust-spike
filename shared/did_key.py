"""
shared/did_key.py

Generación y resolución de DIDs `did:key` con Ed25519.

`did:key` es el método elegido para el agente porque:
  - No requiere red ni infraestructura: el DID encierra la clave pública.
  - Es trivialmente resoluble offline.
  - Es el método más usado en spikes y demos OID4VC.

Formato (W3C `did:key` v0.7):

    did:key:z<multibase-base58btc>
    └─────┘ └────────┘└─────────────────────────────────────┘
    prefijo  z=base58btc <multicodec-prefix><raw-public-key>

Para Ed25519 el multicodec es 0xed01 (varint), seguido de los 32 bytes raw
de la clave pública. La codificación final es base58btc con prefijo "z".

Resolución → DID Document que describe la clave de verificación.
"""
from __future__ import annotations

import base58

from .key_custody import KeyCustody
from .jwt_utils import b64url_decode


# Multicodec prefix para Ed25519 (0xed01) — codificación varint
ED25519_MULTICODEC_PREFIX = bytes([0xED, 0x01])


# ---------------------------------------------------------------------------
# generación
# ---------------------------------------------------------------------------

def did_key_from_public_jwk(public_jwk: dict) -> str:
    """
    Genera el `did:key` correspondiente a una JWK pública Ed25519.
    """
    if public_jwk.get("kty") != "OKP" or public_jwk.get("crv") != "Ed25519":
        raise ValueError(f"Solo Ed25519 OKP soportado, recibido: {public_jwk}")

    pub_raw = b64url_decode(public_jwk["x"])
    if len(pub_raw) != 32:
        raise ValueError(f"Clave Ed25519 debe ser 32 bytes, son {len(pub_raw)}")

    multicodec_pub = ED25519_MULTICODEC_PREFIX + pub_raw
    encoded = base58.b58encode(multicodec_pub).decode("ascii")
    return f"did:key:z{encoded}"


def did_key_from_custody(custody: KeyCustody) -> str:
    """Atajo: did:key directo desde una custodia."""
    return did_key_from_public_jwk(custody.get_public_jwk())


# ---------------------------------------------------------------------------
# resolución
# ---------------------------------------------------------------------------

def resolve_did_key(did: str) -> dict:
    """
    Resuelve un `did:key` y devuelve un DID Document mínimo.

    El DID Document de did:key es generable a partir del propio DID
    (no requiere fetch de red).
    """
    if not did.startswith("did:key:z"):
        raise ValueError(f"No es un did:key válido: {did}")

    encoded = did[len("did:key:z"):]
    multicodec_pub = base58.b58decode(encoded)

    if not multicodec_pub.startswith(ED25519_MULTICODEC_PREFIX):
        raise ValueError(
            f"Solo Ed25519 soportado en spike. Multicodec encontrado: "
            f"{multicodec_pub[:2].hex()}"
        )

    pub_raw = multicodec_pub[len(ED25519_MULTICODEC_PREFIX):]
    if len(pub_raw) != 32:
        raise ValueError(f"Clave Ed25519 inválida: {len(pub_raw)} bytes")

    import base64

    x = base64.urlsafe_b64encode(pub_raw).rstrip(b"=").decode("ascii")
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": x}
    verification_method_id = f"{did}#{did[len('did:key:'):]}"

    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": verification_method_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": public_jwk,
            }
        ],
        "authentication": [verification_method_id],
        "assertionMethod": [verification_method_id],
    }


def public_jwk_for_did_key(did: str) -> dict:
    """Atajo: extrae la JWK pública de un did:key."""
    doc = resolve_did_key(did)
    return doc["verificationMethod"][0]["publicKeyJwk"]
