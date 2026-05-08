"""
agent/holder.py

Lógica de holder del agente: recibe la Mandate Credential vía OID4VCI
Pre-Authorized Code Flow y la presenta vía OID4VP cuando intenta una acción.
"""
from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass

import httpx

from shared import (
    KeyCustody,
    sign_jwt,
    did_key_from_custody,
    now_ts,
)

# ── helpers de log ────────────────────────────────────────────────────────────

def _log(section: str, msg: str) -> None:
    print(f"[AGENTE:{section}] {msg}", flush=True)


# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HeldCredential:
    """La VC tal cual la recibió el agente (sin desempaquetar)."""
    vc_jwt: str
    issuer_did: str
    agent_did: str


class AgentHolder:
    """
    Holder OID4VCI/VP. La identidad del agente es su `did:key`, derivada
    de la clave custodiada por `KeyCustody`.
    """

    def __init__(self, custody: KeyCustody):
        self._custody = custody
        self._did = did_key_from_custody(custody)
        self._held: HeldCredential | None = None

        _log("IDENTIDAD", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        _log("IDENTIDAD", "Se ha asignado una identidad criptográfica al agente")
        _log("IDENTIDAD", f"  DID        : {self._did}")
        _log("IDENTIDAD", f"  Custodia   : {custody.key_id}")
        _log("IDENTIDAD", f"  Algoritmo  : {custody.algorithm}")
        _log("IDENTIDAD", "  La clave privada NUNCA sale del backend de custodia.")
        _log("IDENTIDAD", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    # ------------------------------------------------------------------
    # propiedades
    # ------------------------------------------------------------------

    @property
    def did(self) -> str:
        return self._did

    @property
    def custody(self) -> KeyCustody:
        return self._custody

    @property
    def credential(self) -> HeldCredential | None:
        return self._held

    # ------------------------------------------------------------------
    # H1: recibir la VC vía OID4VCI Pre-Authorized Code Flow
    # ------------------------------------------------------------------

    def fetch_credential(
        self,
        *,
        credential_offer: dict,
        timeout: float = 10.0,
    ) -> HeldCredential:
        """
        Ejecuta el flow OID4VCI Pre-Authorized Code:
          1. Lee el credential_offer (issuer + pre-auth code).
          2. Pide access_token y c_nonce a /token.
          3. Construye el proof JWT firmado con la clave del agente.
          4. POST /credential con Bearer + proof → recibe el VC.
        """
        _log("CREDENCIAL", "")
        _log("CREDENCIAL", "Iniciando flujo OID4VCI Pre-Authorized Code Flow")
        _log("CREDENCIAL", "El agente va a solicitar su Mandate Credential al Issuer")

        issuer_url = credential_offer["credential_issuer"]
        grants = credential_offer["grants"]
        pre_auth_grant = grants.get("urn:ietf:params:oauth:grant-type:pre-authorized_code")
        if not pre_auth_grant:
            raise ValueError("credential_offer sin grant pre-authorized_code")
        pre_auth_code = pre_auth_grant["pre-authorized_code"]

        _log("CREDENCIAL", f"  Issuer URL : {issuer_url}")
        _log("CREDENCIAL", f"  Código PAC : {pre_auth_code[:16]}…  (pre-authorized_code)")

        meta_url = f"{issuer_url}/.well-known/openid-credential-issuer"
        with httpx.Client(timeout=timeout) as client:

            _log("CREDENCIAL", f"[1/4] Descubriendo metadatos del Issuer → GET {meta_url}")
            meta = client.get(meta_url).raise_for_status().json()
            token_endpoint = meta["token_endpoint"]
            credential_endpoint = meta["credential_endpoint"]
            _log("CREDENCIAL", f"       token_endpoint      : {token_endpoint}")
            _log("CREDENCIAL", f"       credential_endpoint : {credential_endpoint}")

            _log("CREDENCIAL", f"[2/4] Intercambiando pre-authorized_code por access_token → POST {token_endpoint}")
            token_response = client.post(
                token_endpoint,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    "pre-authorized_code": pre_auth_code,
                },
            )
            if token_response.status_code != 200:
                raise RuntimeError(f"Token endpoint falló: {token_response.status_code} {token_response.text}")
            token_data = token_response.json()
            access_token = token_data["access_token"]
            c_nonce = token_data["c_nonce"]
            _log("CREDENCIAL", f"       access_token (16c) : {access_token[:16]}…")
            _log("CREDENCIAL", f"       c_nonce            : {c_nonce}  (nonce para el proof)")

            _log("CREDENCIAL", "[3/4] Construyendo proof JWT (demostración de posesión de clave)")
            _log("CREDENCIAL", f"       El agente firma con su clave custodiada en: {self._custody.key_id}")
            proof_jwt = self._build_proof_jwt(audience=issuer_url, nonce=c_nonce)
            _log("CREDENCIAL", f"       proof JWT (24c)    : {proof_jwt[:24]}…")

            _log("CREDENCIAL", f"[4/4] Solicitando la credencial → POST {credential_endpoint}")
            credential_response = client.post(
                credential_endpoint,
                json={
                    "format": "jwt_vc_json",
                    "credential_definition": {
                        "type": ["VerifiableCredential", "AgentMandateCredential"],
                    },
                    "proof": {"proof_type": "jwt", "jwt": proof_jwt},
                },
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if credential_response.status_code != 200:
                raise RuntimeError(
                    f"Credential endpoint falló: {credential_response.status_code} {credential_response.text}"
                )
            cred_data = credential_response.json()

        vc_jwt = cred_data["credential"]
        from shared import parse_jwt_unverified
        _, payload, _, _ = parse_jwt_unverified(vc_jwt)
        issuer_did = payload.get("iss", "")

        held = HeldCredential(vc_jwt=vc_jwt, issuer_did=issuer_did, agent_did=self._did)
        self._held = held

        # Mostrar el contenido de la credencial recibida
        vc_inner = payload.get("vc", {})
        cs = vc_inner.get("credentialSubject", {})
        mandate = cs.get("mandate", {})
        _log("CREDENCIAL", "")
        _log("CREDENCIAL", "✅ Mandate Credential recibida y almacenada por el agente")
        _log("CREDENCIAL", f"   Emisor (issuer DID)  : {issuer_did}")
        _log("CREDENCIAL", f"   Sujeto (agente DID)  : {self._did}")
        _log("CREDENCIAL", f"   Tipo                 : {vc_inner.get('type', [])}")
        _log("CREDENCIAL", f"   JTI (id único VC)    : {payload.get('jti', '-')}")
        _log("CREDENCIAL", f"   Válida desde         : {payload.get('nbf', '-')}")
        _log("CREDENCIAL", f"   Válida hasta         : {payload.get('exp', '-')}")
        if mandate:
            _log("CREDENCIAL", f"   Scope autorizado     : {mandate.get('scope', [])}")
            _log("CREDENCIAL", f"   Contexto             : {mandate.get('context', '-')}")
            _log("CREDENCIAL", f"   Entornos permitidos  : {mandate.get('constraints', {}).get('allowed_environments', [])}")
        _log("CREDENCIAL", f"   VC JWT (primeros 60c): {vc_jwt[:60]}…")

        return held

    def _build_proof_jwt(self, *, audience: str, nonce: str) -> str:
        """Construye el proof JWT que demuestra posesión de la clave del agente."""
        header = {
            "typ": "openid4vci-proof+jwt",
            "alg": self._custody.algorithm,
            "kid": self._did,
        }
        payload = {
            "iss": self._did,
            "aud": audience,
            "iat": now_ts(),
            "nonce": nonce,
        }
        return sign_jwt(header, payload, self._custody)

    # ------------------------------------------------------------------
    # H3: presentar la VC autónomamente vía OID4VP
    # ------------------------------------------------------------------

    def present_for_action(
        self,
        *,
        verifier_url: str,
        action: str,
        context: str,
        resource: str | None = None,
        environment: str | None = None,
        timeout: float = 10.0,
    ) -> dict:
        """
        Presenta la Mandate Credential al verifier para obtener autorización
        para ejecutar una acción. Todo ocurre sin intervención humana.
        """
        if self._held is None:
            raise RuntimeError("El agente no tiene credencial. Llama a fetch_credential() primero.")

        _log("PRESENTACIÓN", "")
        _log("PRESENTACIÓN", f"El agente quiere ejecutar la acción: '{action}'")
        _log("PRESENTACIÓN", f"  Contexto   : {context}")
        _log("PRESENTACIÓN", f"  Entorno    : {environment or '-'}")
        _log("PRESENTACIÓN", f"  Verifier   : {verifier_url}")
        _log("PRESENTACIÓN", "  Iniciando flujo OID4VP para presentar la credencial…")

        with httpx.Client(timeout=timeout) as client:

            _log("PRESENTACIÓN", f"[1/3] Solicitando challenge al verifier → POST {verifier_url}/authorize-action")
            auth_response = client.post(
                f"{verifier_url}/authorize-action",
                json={
                    "action": action, "context": context,
                    "resource": resource, "environment": environment,
                },
            )
            if auth_response.status_code != 200:
                raise RuntimeError(f"authorize-action falló: {auth_response.status_code} {auth_response.text}")
            auth_data = auth_response.json()
            challenge_id = auth_data["challenge_id"]
            nonce = auth_data["nonce"]
            present_endpoint = auth_data["presentation_endpoint"]
            _log("PRESENTACIÓN", f"       challenge_id : {challenge_id}")
            _log("PRESENTACIÓN", f"       nonce        : {nonce}  (anti-replay)")

            _log("PRESENTACIÓN", "[2/3] Construyendo Verifiable Presentation (VP) JWT")
            _log("PRESENTACIÓN", f"       El agente envuelve su VC en un VP firmado con: {self._custody.key_id}")
            vp_jwt = self._build_vp_jwt(audience=verifier_url, nonce=nonce)
            _log("PRESENTACIÓN", f"       VP JWT (24c) : {vp_jwt[:24]}…")

            _log("PRESENTACIÓN", f"[3/3] Enviando VP al verifier → POST {present_endpoint}")
            present_response = client.post(
                present_endpoint,
                json={
                    "challenge_id": challenge_id,
                    "vp_token": vp_jwt,
                    "presentation_submission": {
                        "id": str(uuid.uuid4()),
                        "definition_id": auth_data["presentation_definition"]["id"],
                        "descriptor_map": [
                            {
                                "id": "agent_mandate",
                                "format": "jwt_vc_json",
                                "path": "$.vp.verifiableCredential[0]",
                            }
                        ],
                    },
                },
            )
            result = present_response.json()

        authorized = result.get("authorized", False)
        _log("PRESENTACIÓN", f"   → Decisión del verifier: {'✅ AUTORIZADO' if authorized else '❌ DENEGADO'}")
        _log("PRESENTACIÓN", f"     rule_id     : {result.get('rule_id', '-')}")
        _log("PRESENTACIÓN", f"     reason      : {result.get('reason', '-')}")
        _log("PRESENTACIÓN", f"     decision_id : {result.get('decision_id', '-')}")

        return result

    def _build_vp_jwt(self, *, audience: str, nonce: str) -> str:
        """Construye el VP JWT envolviendo el VC con holder binding."""
        if self._held is None:
            raise RuntimeError("Sin credencial")

        vp_id = f"urn:uuid:{uuid.uuid4()}"
        vp = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": vp_id,
            "type": ["VerifiablePresentation"],
            "holder": self._did,
            "verifiableCredential": [self._held.vc_jwt],
        }
        payload = {
            "iss": self._did,
            "aud": audience,
            "iat": now_ts(),
            "nonce": nonce,
            "jti": vp_id,
            "vp": vp,
        }
        header = {
            "alg": self._custody.algorithm,
            "typ": "JWT",
            "kid": self._did,
        }
        return sign_jwt(header, payload, self._custody)

    # ------------------------------------------------------------------
    # persistencia
    # ------------------------------------------------------------------

    def save_credential(self, path: str) -> None:
        if self._held is None:
            raise RuntimeError("Sin credencial que guardar")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                {"vc_jwt": self._held.vc_jwt, "issuer_did": self._held.issuer_did, "agent_did": self._held.agent_did},
                f,
            )
        _log("CREDENCIAL", f"   VC persistida en disco → {path}")

    def load_credential(self, path: str) -> bool:
        if not os.path.exists(path):
            return False
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if data.get("agent_did") != self._did:
            return False
        self._held = HeldCredential(**data)
        _log("CREDENCIAL", f"   VC cargada desde disco → {path}")
        return True
