"""
agent/peer_client.py

Cliente A2A que usa Agent1 para interactuar con Agent2.

Encapsula el protocolo completo:
  1. identify()         → presentación mutua de credenciales de identidad
  2. request_action()   → solicitar a Agent2 que ejecute una acción con
                          presentación del mandato de Agent1 (OID4VP)
"""
from __future__ import annotations

import uuid
from typing import Any

import httpx

from shared import (
    sign_jwt,
    now_ts,
    public_jwk_for_did_web,
    verify_mandate_vc_jwt,
)
from verifier.trust_framework import is_trusted_issuer


class PeerClient:
    """
    Cliente que Agent1 usa para comunicarse con el peer_server de Agent2.
    """

    def __init__(self, holder, peer_url: str, timeout: float = 10.0):
        """
        holder   : AgentHolder de Agent1 (tiene su DID, custodia y VC)
        peer_url : URL base del peer_server de Agent2 (ej. http://localhost:8010)
        """
        self._holder = holder
        self._peer_url = peer_url.rstrip("/")
        self._timeout = timeout

    # ── Paso 1: identificación mutua ─────────────────────────────────────────

    def identify(self) -> dict[str, Any]:
        """
        Agent1 se presenta a Agent2:
          - Envía su VC JWT y DID.
          - Verifica la VC que Agent2 devuelve.

        Devuelve el resultado de la identificación con los datos de Agent2.
        """
        if self._holder.credential is None:
            raise RuntimeError("Agent1 no tiene credencial. Ejecuta fetch_credential() primero.")

        print(f"[AGENT1:PEER] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", flush=True)
        print(f"[AGENT1:PEER] Iniciando identificación mutua con peer: {self._peer_url}", flush=True)
        print(f"[AGENT1:PEER]   Mi DID     : {self._holder.did}", flush=True)
        print(f"[AGENT1:PEER] [1/2] Enviando mi VC al peer → POST {self._peer_url}/peer/identify", flush=True)

        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(
                f"{self._peer_url}/peer/identify",
                json={
                    "agent_did": self._holder.did,
                    "vc_jwt": self._holder.credential.vc_jwt,
                },
            )
            resp.raise_for_status()
            data = resp.json()

        if not data.get("verified"):
            print(f"[AGENT1:PEER] ❌ El peer rechazó mi identidad: {data.get('message')}", flush=True)
            return data

        peer_did = data.get("agent_did")
        peer_vc_jwt = data.get("vc_jwt")

        print(f"[AGENT1:PEER]   ✓ Peer me ha identificado. DID del peer: {peer_did}", flush=True)
        print(f"[AGENT1:PEER] [2/2] Verificando la VC del peer…", flush=True)

        # Verificar la VC que Agent2 nos devuelve
        peer_verified = False
        if peer_vc_jwt:
            try:
                from shared import parse_jwt_unverified
                vc_header, vc_payload, _, _ = parse_jwt_unverified(peer_vc_jwt)
                issuer_did = vc_payload.get("iss", "")

                if not is_trusted_issuer(issuer_did):
                    print(f"[AGENT1:PEER]   ❌ El issuer del peer ({issuer_did}) no está en trust framework", flush=True)
                else:
                    kid = vc_header.get("kid", "")
                    fragment = kid.split("#", 1)[1] if "#" in kid else None
                    issuer_jwk = public_jwk_for_did_web(issuer_did, key_id=fragment)
                    vc = verify_mandate_vc_jwt(peer_vc_jwt, issuer_jwk)
                    vc_subject = vc.get("credentialSubject", {}).get("id", "")
                    if vc_subject == peer_did:
                        peer_verified = True
                        print(f"[AGENT1:PEER]   ✓ VC del peer verificada — issuer: {issuer_did}", flush=True)
                        mandate = vc.get("credentialSubject", {}).get("mandate", {})
                        print(f"[AGENT1:PEER]   Scope del peer : {mandate.get('scope', [])}", flush=True)
                    else:
                        print(f"[AGENT1:PEER]   ❌ Sujeto de la VC del peer no coincide con su DID", flush=True)
            except Exception as e:
                print(f"[AGENT1:PEER]   ❌ Error verificando VC del peer: {e}", flush=True)

        if peer_verified:
            print(f"[AGENT1:PEER] ✅ Identificación mutua completada. Confiamos en el peer.", flush=True)
        else:
            print(f"[AGENT1:PEER] ⚠ No se pudo verificar la VC del peer.", flush=True)

        return {**data, "peer_vc_verified": peer_verified}

    # ── Paso 2: solicitar acción con presentación de mandato ─────────────────

    def request_action(
        self,
        action: str,
        params: dict[str, Any] | None = None,
        context: str = "incident-management",
        environment: str | None = None,
    ) -> dict[str, Any]:
        """
        Agent1 solicita a Agent2 que ejecute una acción, presentando su mandato:
          1. Pide un challenge (nonce) a Agent2.
          2. Construye un VP JWT que envuelve su Mandate Credential + proof firmado.
          3. Envía el VP a Agent2, que verifica la cadena completa y ejecuta.

        Devuelve la respuesta de Agent2 (authorized, result, …).
        """
        if self._holder.credential is None:
            raise RuntimeError("Agent1 no tiene credencial. Ejecuta fetch_credential() primero.")

        params = params or {}

        print(f"[AGENT1:PEER] ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", flush=True)
        print(f"[AGENT1:PEER] Solicitando acción al peer: '{action}'", flush=True)
        print(f"[AGENT1:PEER]   Peer URL   : {self._peer_url}", flush=True)
        print(f"[AGENT1:PEER]   Contexto   : {context}", flush=True)
        print(f"[AGENT1:PEER]   Parámetros : {params}", flush=True)

        with httpx.Client(timeout=self._timeout) as client:

            # 1. Solicitar challenge
            print(f"[AGENT1:PEER] [1/3] Solicitando challenge → POST {self._peer_url}/peer/action/challenge", flush=True)
            ch_resp = client.post(
                f"{self._peer_url}/peer/action/challenge",
                json={"action": action, "params": params, "context": context, "environment": environment},
            )
            ch_resp.raise_for_status()
            ch_data = ch_resp.json()
            challenge_id = ch_data["challenge_id"]
            nonce = ch_data["nonce"]
            print(f"[AGENT1:PEER]   challenge_id : {challenge_id}", flush=True)
            print(f"[AGENT1:PEER]   nonce        : {nonce}", flush=True)

            # 2. Construir VP JWT (audience = URL de Agent2)
            print(f"[AGENT1:PEER] [2/3] Construyendo VP JWT con mandato (audience={self._peer_url})…", flush=True)
            vp_jwt = self._build_vp_jwt(audience=self._peer_url, nonce=nonce)
            print(f"[AGENT1:PEER]   VP JWT (24c) : {vp_jwt[:24]}…", flush=True)

            # 3. Enviar VP y solicitar ejecución
            print(f"[AGENT1:PEER] [3/3] Enviando VP y solicitando ejecución → POST {self._peer_url}/peer/action/submit", flush=True)
            sub_resp = client.post(
                f"{self._peer_url}/peer/action/submit",
                json={
                    "challenge_id": challenge_id,
                    "vp_token": vp_jwt,
                    "action": action,
                    "params": params,
                },
            )
            result = sub_resp.json()

        authorized = result.get("authorized", False)
        print(f"[AGENT1:PEER] → Respuesta del peer:", flush=True)
        print(f"[AGENT1:PEER]   authorized  : {'✅ SÍ' if authorized else '❌ NO'}", flush=True)
        print(f"[AGENT1:PEER]   reason      : {result.get('reason', '-')}", flush=True)
        print(f"[AGENT1:PEER]   executed_by : {result.get('executed_by', '-')}", flush=True)
        if result.get("result"):
            print(f"[AGENT1:PEER]   resultado   : {result['result']}", flush=True)

        return result

    def _build_vp_jwt(self, *, audience: str, nonce: str) -> str:
        """Construye el VP JWT que envuelve la Mandate Credential con el nonce del peer."""
        held = self._holder.credential
        vp_id = f"urn:uuid:{uuid.uuid4()}"
        vp = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "id": vp_id,
            "type": ["VerifiablePresentation"],
            "holder": self._holder.did,
            "verifiableCredential": [held.vc_jwt],
        }
        payload = {
            "iss": self._holder.did,
            "aud": audience,
            "iat": now_ts(),
            "nonce": nonce,
            "jti": vp_id,
            "vp": vp,
        }
        header = {
            "alg": self._holder.custody.algorithm,
            "typ": "JWT",
            "kid": self._holder.did,
        }
        return sign_jwt(header, payload, self._holder.custody)
