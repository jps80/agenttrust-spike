"""
issuer/main.py

Mock Business Wallet — Issuer OID4VCI.

Implementa los endpoints OID4VCI Pre-Authorized Code Flow para emitir
**Mandate Credentials** a agentes (sujetos NO humanos). Es el corazón de H1.

Endpoints:
  /.well-known/did.json
        Documento did:web de la organización emisora.
  /.well-known/openid-credential-issuer
        Metadatos OID4VCI (qué credenciales emite, qué endpoints expone).
  POST /admin/credential-offer
        Endpoint interno (Registry UI lo llama tras dar de alta un agente):
        crea una oferta y devuelve el `credential_offer` y el `pre-authorized_code`.
  GET  /credential-offer/{offer_id}
        El agente lo consulta para descubrir endpoints + pre-auth code.
  POST /token
        OAuth2 token endpoint, intercambia pre-auth code por access token.
  POST /credential
        Credential endpoint, devuelve el VC firmado tras validar el proof JWT.
  GET  /status-list/1
        VC de tipo BitstringStatusListCredential (revocación).
  POST /admin/revoke
        Endpoint interno para que la organización revoque un mandato.
"""
from __future__ import annotations

import os
import secrets
import uuid
from contextlib import asynccontextmanager
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Form
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from shared import (
    KeyCustody,
    build_custody,
    build_did_web_document,
    issue_mandate_vc_jwt,
    issue_status_list_vc_jwt,
    MandateInput,
    parse_jwt_unverified,
    public_jwk_for_did_key,
    verify_jwt_with_jwk,
    now_ts,
)
from . import storage


# ---------------------------------------------------------------------------
# configuración global
# ---------------------------------------------------------------------------

load_dotenv()

ORG_DID = os.getenv("ORG_DID", "did:web:localhost%3A8000")
ORG_LEGAL_NAME = os.getenv("ORG_LEGAL_NAME", "Banco de Pruebas SA")
ISSUER_BASE_URL = os.getenv("ISSUER_BASE_URL", "http://localhost:8000")
ISSUER_KEY_NAME = "org-issuer"          # nombre de la clave en el backend de custodia
ISSUER_KEY_FRAGMENT = "key-1"           # fragment del verificationMethod
ACCESS_TOKEN_TTL_SECONDS = 600          # 10 min, suficiente para un flow

# La custodia se inicializa en el lifespan, no a nivel módulo, para
# que los tests puedan sustituirla.
_custody: KeyCustody | None = None


def get_custody() -> KeyCustody:
    if _custody is None:
        raise RuntimeError("Custody no inicializada — falta lifespan startup")
    return _custody


# ---------------------------------------------------------------------------
# lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _custody
    storage.init_db()
    _custody = build_custody(ISSUER_KEY_NAME)
    print(f"[ISSUER] Iniciado como Mock Business Wallet (Issuer OID4VCI)", flush=True)
    print(f"[ISSUER]   DID organización : {ORG_DID}", flush=True)
    print(f"[ISSUER]   Custodia clave   : {_custody.key_id}", flush=True)
    yield


app = FastAPI(title="AgentTrust Mock Business Wallet (Issuer)", lifespan=lifespan)


# ---------------------------------------------------------------------------
# /.well-known/did.json
# ---------------------------------------------------------------------------

@app.get("/.well-known/did.json")
def did_document():
    custody = get_custody()
    pub_jwk = custody.get_public_jwk()
    # En el JWK que sirve did:web, el `kid` es el fragment local
    pub_jwk = {**pub_jwk, "kid": ISSUER_KEY_FRAGMENT}
    return build_did_web_document(ORG_DID, pub_jwk)


# ---------------------------------------------------------------------------
# /.well-known/openid-credential-issuer
# Metadatos OID4VCI per spec
# ---------------------------------------------------------------------------

@app.get("/.well-known/openid-credential-issuer")
def issuer_metadata():
    return {
        "credential_issuer": ISSUER_BASE_URL,
        "credential_endpoint": f"{ISSUER_BASE_URL}/credential",
        "token_endpoint": f"{ISSUER_BASE_URL}/token",
        "display": [
            {"name": ORG_LEGAL_NAME, "locale": "es-ES"}
        ],
        "credential_configurations_supported": {
            "AgentMandateCredential_jwt": {
                "format": "jwt_vc_json",
                "scope": "AgentMandateCredential",
                "cryptographic_binding_methods_supported": ["did:key"],
                "credential_signing_alg_values_supported": ["EdDSA"],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": ["EdDSA"]
                    }
                },
                "credential_definition": {
                    "type": ["VerifiableCredential", "AgentMandateCredential"]
                },
                "display": [
                    {"name": "Agent Mandate", "locale": "es-ES"}
                ],
            }
        },
    }


# ---------------------------------------------------------------------------
# Endpoint interno: Registry UI llama aquí tras dar de alta un agente
# ---------------------------------------------------------------------------

class CreateOfferRequest(BaseModel):
    mandate: MandateInput


class CreateOfferResponse(BaseModel):
    offer_id: str
    pre_authorized_code: str
    credential_offer_uri: str
    credential_offer: dict[str, Any] = Field(
        description="El payload completo de credential_offer per OID4VCI"
    )


@app.post("/admin/credential-offer", response_model=CreateOfferResponse)
def create_credential_offer(req: CreateOfferRequest):
    """
    Crea una oferta OID4VCI Pre-Authorized para un agente. Esto es lo que
    el Registry UI invoca tras guardar el alta del agente.
    """
    offer_id = str(uuid.uuid4())
    pre_authorized_code = secrets.token_urlsafe(32)
    sl_index = storage.reserve_status_list_index()

    storage.save_credential_offer(
        offer_id=offer_id,
        pre_authorized_code=pre_authorized_code,
        agent_did=req.mandate.agent_did,
        mandate_json=req.mandate.model_dump(),
        status_list_index=sl_index,
        created_at=now_ts(),
    )

    credential_offer = {
        "credential_issuer": ISSUER_BASE_URL,
        "credential_configuration_ids": ["AgentMandateCredential_jwt"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": pre_authorized_code,
                # El spike no requiere user PIN — el agente no es un humano
            }
        },
    }

    return CreateOfferResponse(
        offer_id=offer_id,
        pre_authorized_code=pre_authorized_code,
        credential_offer_uri=f"{ISSUER_BASE_URL}/credential-offer/{offer_id}",
        credential_offer=credential_offer,
    )


@app.get("/credential-offer/{offer_id}")
def get_credential_offer(offer_id: str):
    """
    Endpoint público — el agente lo consulta usando la URL recibida en
    su bootstrap para obtener el pre-authorized_code.
    """
    offer = storage.get_offer_by_id(offer_id)
    if offer is None:
        raise HTTPException(status_code=404, detail="offer not found")
    if offer["redeemed"]:
        raise HTTPException(status_code=410, detail="offer already redeemed")

    return {
        "credential_issuer": ISSUER_BASE_URL,
        "credential_configuration_ids": ["AgentMandateCredential_jwt"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": offer["pre_authorized_code"],
            }
        },
    }


# ---------------------------------------------------------------------------
# POST /token — OAuth2 token endpoint (Pre-Authorized Code grant)
# ---------------------------------------------------------------------------

@app.post("/token")
def token_endpoint(
    grant_type: str = Form(...),
    pre_authorized_code: str | None = Form(default=None, alias="pre-authorized_code"),
):
    """
    Implementa el grant `urn:ietf:params:oauth:grant-type:pre-authorized_code`.
    No exigimos PIN porque el holder es un agente bajo control de la organización
    (consent ya se fijó en issuance time, en el Registry UI).
    """
    if grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code":
        raise HTTPException(status_code=400, detail={"error": "unsupported_grant_type"})
    if not pre_authorized_code:
        raise HTTPException(status_code=400, detail={"error": "invalid_request"})

    offer = storage.get_offer_by_pre_auth_code(pre_authorized_code)
    if offer is None:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant"})
    if offer["redeemed"]:
        raise HTTPException(status_code=400, detail={"error": "invalid_grant", "error_description": "already redeemed"})

    access_token = secrets.token_urlsafe(32)
    c_nonce = secrets.token_urlsafe(16)
    expires_at = now_ts() + ACCESS_TOKEN_TTL_SECONDS

    storage.save_access_token(
        token=access_token, offer_id=offer["offer_id"], c_nonce=c_nonce, expires_at=expires_at,
    )

    return JSONResponse(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SECONDS,
            "c_nonce": c_nonce,
            "c_nonce_expires_in": ACCESS_TOKEN_TTL_SECONDS,
        },
        # OAuth2 obliga a estos headers
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


# ---------------------------------------------------------------------------
# POST /credential — el agente intercambia access_token + proof por la VC
# ---------------------------------------------------------------------------

class ProofObject(BaseModel):
    proof_type: str
    jwt: str


class CredentialRequest(BaseModel):
    format: str = "jwt_vc_json"
    credential_definition: dict[str, Any] | None = None
    proof: ProofObject


from fastapi import Header  # noqa: E402


@app.post("/credential")
async def credential_endpoint(
    req: CredentialRequest,
    authorization: str = Header(default=""),
):
    """
    Validaciones:
      1. Bearer token válido y no expirado.
      2. proof_type == "jwt".
      3. Proof JWT firmado por la clave del DID al que se va a emitir el VC.
         Esto es la prueba de posesión: el agente demuestra que controla la
         clave privada vinculada a su DID.
      4. `aud` del proof = ISSUER_BASE_URL.
      5. `nonce` del proof = c_nonce que entregamos en /token.
      6. format / type encajan con la oferta.

    Si todo pasa: emite el VC firmado con la clave del issuer y lo devuelve.
    """
    # 1. Bearer token
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={"error": "invalid_token"})
    access_token = authorization[len("Bearer "):]

    token_row = storage.get_access_token(access_token)
    if token_row is None:
        raise HTTPException(status_code=401, detail={"error": "invalid_token"})
    if token_row["expires_at"] < now_ts():
        storage.delete_access_token(access_token)
        raise HTTPException(status_code=401, detail={"error": "invalid_token", "error_description": "expired"})

    offer = storage.get_offer_by_id(token_row["offer_id"])
    if offer is None or offer["redeemed"]:
        raise HTTPException(status_code=400, detail={"error": "invalid_request"})

    # 2. proof_type
    if req.proof.proof_type != "jwt":
        raise HTTPException(status_code=400, detail={"error": "invalid_or_missing_proof"})

    # 3-5. Verificar el proof JWT
    try:
        proof_header, proof_payload, _, _ = parse_jwt_unverified(req.proof.jwt)
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": "invalid_or_missing_proof", "error_description": str(e)})

    # typ del proof OID4VCI
    if proof_header.get("typ") != "openid4vci-proof+jwt":
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_or_missing_proof", "error_description": "typ debe ser openid4vci-proof+jwt"},
        )

    # kid del proof apunta al DID del holder (el agente)
    kid = proof_header.get("kid", "")
    if not kid.startswith("did:key:"):
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_or_missing_proof", "error_description": "kid debe ser did:key (spike)"},
        )
    # Para did:key con un solo verificationMethod, kid puede ser el did completo
    # o did#fragment; en cualquier caso quitamos el fragment para resolver.
    holder_did = kid.split("#", 1)[0]

    if holder_did != offer["agent_did"]:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_or_missing_proof",
                "error_description": (
                    f"el DID del proof ({holder_did}) no coincide con el del agente "
                    f"registrado ({offer['agent_did']})"
                ),
            },
        )

    # Resolvemos did:key del agente y validamos firma del proof
    holder_jwk = public_jwk_for_did_key(holder_did)
    try:
        verify_jwt_with_jwk(req.proof.jwt, holder_jwk)
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_or_missing_proof", "error_description": f"firma del proof inválida: {e}"},
        )

    # aud / nonce
    if proof_payload.get("aud") != ISSUER_BASE_URL:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_or_missing_proof", "error_description": "aud incorrecto"},
        )
    if proof_payload.get("nonce") != token_row["c_nonce"]:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_or_missing_proof", "error_description": "nonce no coincide con c_nonce"},
        )

    # 6. format
    if req.format != "jwt_vc_json":
        raise HTTPException(status_code=400, detail={"error": "unsupported_credential_format"})

    # ---------------------------------------------------------------- emitir
    import json as _json

    print(f"[ISSUER:EMISIÓN] Proof verificado. Emitiendo Mandate Credential…", flush=True)
    print(f"[ISSUER:EMISIÓN]   Sujeto (agente DID)  : {holder_did}", flush=True)
    print(f"[ISSUER:EMISIÓN]   Firmando con custodia : {get_custody().key_id}", flush=True)

    custody = get_custody()
    mandate = MandateInput(**_json.loads(offer["mandate_json"]))
    status_list_credential_url = f"{ISSUER_BASE_URL}/status-list/1"

    vc_jwt, payload = issue_mandate_vc_jwt(
        issuer_did=ORG_DID,
        issuer_key_id=ISSUER_KEY_FRAGMENT,
        issuer_custody=custody,
        mandate=mandate,
        status_list_credential_url=status_list_credential_url,
        status_list_index=offer["status_list_index"],
    )

    storage.record_issued_credential(
        jti=payload["jti"],
        agent_did=mandate.agent_did,
        status_list_index=offer["status_list_index"],
        issued_at=payload["iat"],
        vc_jwt=vc_jwt,
    )
    storage.mark_offer_redeemed(offer["offer_id"])
    storage.delete_access_token(access_token)

    print(f"[ISSUER:EMISIÓN] ✅ VC emitida y firmada con la clave del issuer", flush=True)
    print(f"[ISSUER:EMISIÓN]   JTI (id único VC)    : {payload['jti']}", flush=True)
    print(f"[ISSUER:EMISIÓN]   Issuer DID            : {ORG_DID}", flush=True)
    print(f"[ISSUER:EMISIÓN]   Scope concedido       : {mandate.scope}", flush=True)
    print(f"[ISSUER:EMISIÓN]   Status list index     : {offer['status_list_index']}", flush=True)

    return {
        "format": "jwt_vc_json",
        "credential": vc_jwt,
    }


# ---------------------------------------------------------------------------
# Status list endpoint — se accede vía /status-list/1
# ---------------------------------------------------------------------------

@app.get("/status-list/{list_id}")
def status_list(list_id: int):
    """
    Devuelve la BitstringStatusListCredential, JWT firmada por el issuer.
    El verifier llama aquí cada vez que comprueba revocación.
    """
    if list_id != 1:
        raise HTTPException(status_code=404, detail="not found")

    custody = get_custody()
    state = storage.get_status_list_state()
    status_jwt = issue_status_list_vc_jwt(
        issuer_did=ORG_DID,
        issuer_key_id=ISSUER_KEY_FRAGMENT,
        issuer_custody=custody,
        status_list_id=f"{ISSUER_BASE_URL}/status-list/{list_id}",
        state=state,
    )
    return {"format": "jwt_vc_json", "credential": status_jwt}


# ---------------------------------------------------------------------------
# Endpoint admin: revocar mandato de un agente
# ---------------------------------------------------------------------------

class RevokeRequest(BaseModel):
    agent_did: str


@app.post("/admin/revoke")
def revoke_agent(req: RevokeRequest):
    record = storage.find_issued_credential_by_agent(req.agent_did)
    if record is None:
        raise HTTPException(status_code=404, detail="no credential for that agent")

    storage.revoke_status_list_index(record["status_list_index"])
    print(f"[ISSUER:REVOCACIÓN] ⛔ Mandato REVOCADO", flush=True)
    print(f"[ISSUER:REVOCACIÓN]   Agente DID          : {req.agent_did}", flush=True)
    print(f"[ISSUER:REVOCACIÓN]   JTI revocado        : {record['jti']}", flush=True)
    print(f"[ISSUER:REVOCACIÓN]   Status list index   : {record['status_list_index']}", flush=True)
    print(f"[ISSUER:REVOCACIÓN]   El verifier lo detectará en la próxima presentación", flush=True)
    return {
        "revoked": True,
        "agent_did": req.agent_did,
        "status_list_index": record["status_list_index"],
        "credential_jti": record["jti"],
    }


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "did": ORG_DID, "custody": get_custody().key_id}
