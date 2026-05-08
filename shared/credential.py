"""
shared/credential.py

Schema y constructor de la **Mandate Credential** — la VC que la organización
emite a su agente para autorizarlo a actuar en su nombre.

Es la pieza conceptual central de AgentTrust. Los campos siguen lo descrito
en el Concept Note (1.2.3, bloque "Agent Mandate Credential"):

    agentDID         — sujeto (el agente). credentialSubject.id
    issuerDID        — emisor (la organización). issuer
    delegatorDID     — quién en la organización autoriza la emisión
                       (humano supervisor). credentialSubject.delegator
    scope            — taxonomía de acciones permitidas
    context          — sistema/proceso al que se aplica
    validFrom        — inicio de validez (ISO 8601)
    validUntil       — fin de validez (ISO 8601)
    constraints      — límites operacionales (max ops/h, read-only, etc.)
    revocationEndpoint
                     — vía W3C Bitstring Status List (credentialStatus)

El formato de envoltorio es JWT (`jwt_vc_json` en OID4VCI), con el claim
`vc` conteniendo el JSON-LD de la VC.
"""
from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field

from .jwt_utils import sign_jwt, parse_jwt_unverified, verify_jwt_with_jwk, now_iso, now_ts
from .key_custody import KeyCustody


# ---------------------------------------------------------------------------
# modelos pydantic
# ---------------------------------------------------------------------------

class MandateConstraints(BaseModel):
    """Límites operacionales que el agente NO puede traspasar."""
    max_operations_per_hour: int | None = Field(default=None)
    read_only: bool = Field(default=False)
    allowed_environments: list[str] | None = Field(default=None)  # ["staging", "prod"]


class MandateInput(BaseModel):
    """Input que viene del Registry UI (H0) para emitir el VC."""
    agent_did: str
    delegator_did: str
    scope: list[str]            # ej. ["read:incidents", "execute:restart_service"]
    context: str                # ej. "incident-management"
    valid_from: str             # ISO 8601
    valid_until: str            # ISO 8601
    constraints: MandateConstraints = Field(default_factory=MandateConstraints)


# ---------------------------------------------------------------------------
# constructor
# ---------------------------------------------------------------------------

# Contexto JSON-LD propio del spike (en producción se publica bajo el
# dominio de Identfy y se incluye en el SDK).
AGENT_MANDATE_CONTEXT_URL = "https://identfy.izertis.com/contexts/agent-mandate/v1"

VC_TYPE = ["VerifiableCredential", "AgentMandateCredential"]


def build_mandate_vc_payload(
    *,
    issuer_did: str,
    mandate: MandateInput,
    status_list_credential_url: str,
    status_list_index: int,
) -> dict[str, Any]:
    """
    Construye el JSON-LD de la VC (payload del JWT, sin firmar todavía).
    Sigue W3C VCDM 2.0.
    """
    vc_id = f"urn:uuid:{uuid.uuid4()}"
    return {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            AGENT_MANDATE_CONTEXT_URL,
        ],
        "id": vc_id,
        "type": VC_TYPE,
        "issuer": issuer_did,
        "validFrom": mandate.valid_from,
        "validUntil": mandate.valid_until,
        "credentialSubject": {
            "id": mandate.agent_did,
            "type": "AIAgent",
            "delegator": mandate.delegator_did,
            "scope": mandate.scope,
            "context": mandate.context,
            "constraints": {
                "maxOperationsPerHour": mandate.constraints.max_operations_per_hour,
                "readOnly": mandate.constraints.read_only,
                "allowedEnvironments": mandate.constraints.allowed_environments,
            },
        },
        "credentialStatus": {
            "id": f"{status_list_credential_url}#{status_list_index}",
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": str(status_list_index),
            "statusListCredential": status_list_credential_url,
        },
    }


def issue_mandate_vc_jwt(
    *,
    issuer_did: str,
    issuer_key_id: str,            # fragment del verificationMethod, ej. "key-1"
    issuer_custody: KeyCustody,
    mandate: MandateInput,
    status_list_credential_url: str,
    status_list_index: int,
) -> tuple[str, dict]:
    """
    Emite la Mandate Credential como JWT (formato `jwt_vc_json`).
    Devuelve (jwt_compacto, payload_json).
    """
    vc = build_mandate_vc_payload(
        issuer_did=issuer_did,
        mandate=mandate,
        status_list_credential_url=status_list_credential_url,
        status_list_index=status_list_index,
    )

    # JWT envelope per VCDM 2.0 / OID4VCI jwt_vc_json
    iat = now_ts()
    payload = {
        "iss": issuer_did,
        "sub": mandate.agent_did,
        "iat": iat,
        "jti": vc["id"],
        "vc": vc,
    }

    header = {
        "alg": issuer_custody.algorithm,
        "typ": "JWT",
        "kid": f"{issuer_did}#{issuer_key_id}",
    }

    jwt = sign_jwt(header, payload, issuer_custody)
    return jwt, payload


# ---------------------------------------------------------------------------
# verificación
# ---------------------------------------------------------------------------

class MandateVerificationError(Exception):
    pass


def verify_mandate_vc_jwt(vc_jwt: str, issuer_public_jwk: dict) -> dict:
    """
    Verifica firma del VC y devuelve el `vc` JSON-LD interno.

    NO comprueba revocación ni vigencia: eso se hace en `verifier/policy.py`,
    porque tiene reglas de negocio específicas. Aquí solo validamos firma + estructura.
    """
    try:
        payload = verify_jwt_with_jwk(vc_jwt, issuer_public_jwk)
    except Exception as e:
        raise MandateVerificationError(f"Firma del VC inválida: {e}") from e

    vc = payload.get("vc")
    if not isinstance(vc, dict):
        raise MandateVerificationError("Payload sin claim 'vc'")

    if "VerifiableCredential" not in vc.get("type", []):
        raise MandateVerificationError(f"type incorrecto: {vc.get('type')}")

    if "AgentMandateCredential" not in vc.get("type", []):
        raise MandateVerificationError(
            "Esta VC no es una AgentMandateCredential — el verifier solo acepta mandatos"
        )

    return vc


def parse_vc_jwt_header(vc_jwt: str) -> dict:
    """Devuelve el header JOSE (sin verificar). Útil para extraer `kid` y resolver el emisor."""
    header, _, _, _ = parse_jwt_unverified(vc_jwt)
    return header
