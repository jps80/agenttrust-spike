"""
shared/did_web.py

Resolución de DIDs `did:web`.

`did:web` es el método elegido para la organización emisora porque:
  - Es la primera elección recomendada por la EUDI Wallet Architecture
    Reference Framework para Issuers / Relying Parties con dominio público.
  - No requiere infraestructura blockchain.
  - Mapea 1:1 sobre HTTPS, que ya tienen todas las organizaciones.

Resolución (W3C did:web spec):

    did:web:example.com           → https://example.com/.well-known/did.json
    did:web:example.com:user:foo  → https://example.com/user/foo/did.json

NOTA spike: usamos HTTP (no HTTPS) porque corremos en localhost. En producción
es HTTPS obligatorio.
"""
from __future__ import annotations

import urllib.parse

import httpx


def did_web_to_url(did: str) -> str:
    """
    Convierte un did:web en la URL HTTPS donde reside su documento.

    `did:web:localhost%3A8000`        → http(s)://localhost:8000/.well-known/did.json
    `did:web:example.com:user:alice`  → http(s)://example.com/user/alice/did.json
    """
    if not did.startswith("did:web:"):
        raise ValueError(f"No es un did:web válido: {did}")

    rest = did[len("did:web:"):]
    parts = rest.split(":")
    # El primer segmento es el host (puede traer puerto url-encoded como %3A)
    host = urllib.parse.unquote(parts[0])
    path_segments = parts[1:]

    # Para localhost / hosts sin TLS: HTTP. Para todo lo demás: HTTPS.
    scheme = "http" if (host.startswith("localhost") or host.startswith("127.")) else "https"

    if not path_segments:
        return f"{scheme}://{host}/.well-known/did.json"

    return f"{scheme}://{host}/{'/'.join(path_segments)}/did.json"


def resolve_did_web(did: str, *, timeout: float = 5.0) -> dict:
    """
    Hace fetch HTTP del documento DID y lo devuelve como dict.
    """
    url = did_web_to_url(did)
    response = httpx.get(url, timeout=timeout)
    response.raise_for_status()
    doc = response.json()

    if doc.get("id") != did:
        raise ValueError(
            f"Documento DID inconsistente: esperaba id={did}, "
            f"obtuvo id={doc.get('id')}"
        )

    return doc


def public_jwk_for_did_web(did: str, key_id: str | None = None) -> dict:
    """
    Resuelve un did:web y devuelve la JWK pública del verificationMethod indicado.
    Si `key_id` es None, devuelve la primera.
    """
    doc = resolve_did_web(did)
    methods = doc.get("verificationMethod", [])
    if not methods:
        raise ValueError(f"DID {did} sin verificationMethod")

    if key_id is None:
        method = methods[0]
    else:
        # key_id puede ser absoluto (did#fragment) o solo el fragment
        target = key_id if "#" in key_id else f"{did}#{key_id}"
        for m in methods:
            if m.get("id") == target:
                method = m
                break
        else:
            raise ValueError(f"verificationMethod {key_id} no encontrado en {did}")

    if "publicKeyJwk" in method:
        return method["publicKeyJwk"]
    raise ValueError(f"verificationMethod {method.get('id')} sin publicKeyJwk")


def build_did_web_document(did: str, public_jwk: dict) -> dict:
    """
    Construye un did:web document mínimo a partir de una JWK pública.
    Lo usamos en el issuer para servir su propio /.well-known/did.json.
    """
    verification_method_id = f"{did}#key-1"
    # Aseguramos que el JWK incluye el kid (es el que apuntará el JWT del VC)
    jwk = {**public_jwk}
    if "kid" not in jwk:
        jwk["kid"] = "key-1"

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
                "publicKeyJwk": jwk,
            }
        ],
        "authentication": [verification_method_id],
        "assertionMethod": [verification_method_id],
    }
