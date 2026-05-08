"""
agent/runtime.py

Runtime del agente: bucle simplificado de "tool calling" donde cada
invocación a una tool se condiciona a una presentación OID4VP autónoma
exitosa.

Esto es lo mínimo necesario para validar H3 end-to-end. En producción,
este módulo se reemplaza por (o se integra como middleware en) un
framework completo (LangChain, AutoGen, MCP). El SDK que ese framework
expondría incluiría exactamente este patrón:

    @before_tool_call
    def require_mandate(tool, args):
        decision = holder.present_for_action(...)
        if not decision["authorized"]:
            raise PermissionDenied(decision["reason"])

Aquí lo escribimos explícito para que sea legible.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .holder import AgentHolder
from .tools import Tool, get_tool


@dataclass
class ExecutionRecord:
    """Lo que queda registrado para auditoría de cada intento de tool call."""
    tool_name: str
    args: dict[str, Any]
    decision_id: str | None
    authorized: bool
    reason: str
    rule_id: str | None
    result: dict[str, Any] | None
    timestamp: float = field(default_factory=time.time)


class AgentRuntime:
    """
    Bucle de ejecución de tools con check OID4VP previo en cada llamada.
    """

    def __init__(self, holder: AgentHolder, verifier_url: str):
        self._holder = holder
        self._verifier_url = verifier_url
        self.history: list[ExecutionRecord] = []

    def call_tool(self, tool_name: str, **kwargs) -> ExecutionRecord:
        """
        Intenta ejecutar una tool. Antes:
          1) Presenta la Mandate Credential al verifier (OID4VP autónomo).
          2) Si autorizado → ejecuta la tool.
          3) Si denegado → no ejecuta y registra el motivo.

        Devuelve siempre un ExecutionRecord (no lanza excepción en denegación).
        """
        tool: Tool = get_tool(tool_name)

        print(f"[AGENTE:TOOL] ────────────────────────────────────────────────", flush=True)
        print(f"[AGENTE:TOOL] Solicitud de ejecución de tool: '{tool_name}'", flush=True)
        print(f"[AGENTE:TOOL]   acción requerida : {tool.action}", flush=True)
        print(f"[AGENTE:TOOL]   contexto         : {tool.context}", flush=True)
        print(f"[AGENTE:TOOL]   argumentos       : {kwargs}", flush=True)
        print(f"[AGENTE:TOOL] Antes de ejecutar → presentando credencial al verifier…", flush=True)

        decision = self._holder.present_for_action(
            verifier_url=self._verifier_url,
            action=tool.action,
            context=tool.context,
            environment=tool.environment,
        )

        if not decision.get("authorized"):
            print(f"[AGENTE:TOOL] ❌ Tool BLOQUEADA — el agente NO ejecuta la acción", flush=True)
            print(f"[AGENTE:TOOL]   motivo : {decision.get('reason', '')}", flush=True)
            record = ExecutionRecord(
                tool_name=tool_name,
                args=kwargs,
                decision_id=decision.get("decision_id"),
                authorized=False,
                reason=decision.get("reason", ""),
                rule_id=decision.get("rule_id"),
                result=None,
            )
            self.history.append(record)
            return record

        print(f"[AGENTE:TOOL] ✅ Tool AUTORIZADA — ejecutando '{tool_name}'…", flush=True)
        try:
            result = tool.run(**kwargs)
        except Exception as e:
            result = {"error": str(e)}

        print(f"[AGENTE:TOOL]   resultado : {result}", flush=True)

        record = ExecutionRecord(
            tool_name=tool_name,
            args=kwargs,
            decision_id=decision.get("decision_id"),
            authorized=True,
            reason=decision.get("reason", "OK"),
            rule_id=decision.get("rule_id"),
            result=result,
        )
        self.history.append(record)
        return record
