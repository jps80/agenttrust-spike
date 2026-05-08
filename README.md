#  AgentAI VC ID — Spike

**Validación técnica end-to-end en 4 hipótesis + protocolo Agent-to-Agent (A2A) + Agentes IA reales con Claude.**
Stack: Python 3.11+, FastAPI, Ed25519, OID4VCI Pre-Authorized Code Flow, OID4VP, W3C VCDM 2.0 (JWT), Bitstring Status List, HashiCorp Vault, Anthropic Claude API.

---

## ¿Qué resuelve este spike?

| H | Pregunta | Componente |
|---|----------|------------|
| **H0** | ¿Podemos registrar un agente con datos mínimos y producir los inputs para emitir su credencial? | `registry_ui/` — mini-UI de alta + persistencia SQLite |
| **H1** | ¿Podemos emitir una VC vía OID4VCI a un sujeto NO humano? | `issuer/` — mock Business Wallet con OID4VCI Pre-Auth Flow |
| **H2** | ¿Cómo custodia el agente sus claves sin Secure Enclave / biometría? | `shared/key_custody/` — interfaz con backends `LocalFile` y `Vault` |
| **H3** | ¿Puede el agente presentar su credencial vía OID4VP de forma autónoma? | `verifier/` + `agent/holder.py` — flow sin humano en el loop |
| **A2A** | ¿Pueden dos agentes identificarse mutuamente y delegar acciones con verificación de mandato? | `agent/peer_server.py` + `agent/peer_client.py` — protocolo Agent-to-Agent |
| **IA** | ¿Funciona el protocolo con agentes IA reales usando LLM? | `agent/agent1_server.py` + `shared/claude_client.py` — Translator (ES→EN) + Expert (Claude Opus 4.7) |

---

## Decisiones técnicas congeladas

- **Algoritmo:** Ed25519 (EdDSA). Más simple que ES256 y soportado por Vault Transit. Migrable a ES256 para EUDI ARF en producción.
- **DID del agente:** `did:key` (autocontenido, sin red).
- **DID de la organización:** `did:web` (resuelve a `/.well-known/did.json` del issuer).
- **Formato de credencial:** W3C VCDM 2.0 + JWT (`jwt_vc_json`).
- **Flow OID4VCI:** Pre-Authorized Code Flow (sin user-agent, encaja con holder no humano).
- **Revocación:** W3C Bitstring Status List 1.0.
- **Trust framework:** lista JSON de issuers de confianza (sustituible por Identfy ITF en producción).
- **LLM:** Claude Opus 4.7 con adaptive thinking para traducción y respuesta de preguntas.

---

## Arquitectura de servicios

```
┌──────────────────┐  ┌──────────────┐  ┌──────────────────┐  ┌──────────────────────┐
│  Registry UI     │  │  Chat UI     │  │  HashiCorp Vault  │  │  Anthropic Claude    │
│  :8002 (H0)      │  │  :8003       │  │  :8200 (Transit)  │  │  API (claude-opus-   │
│  [+ Revocar]     │  │  (preguntas) │  │                   │  │  4-7)                │
└────────┬─────────┘  └──────┬───────┘  └─────────┬─────────┘  └────────┬─────────────┘
         │                   │                     │                     │ IA
         │ registra/revoca   │ POST /ask           │ custodia claves     │
         ▼                   ▼                     ▼                     │
┌──────────────────────────────────────────────┐                │
│  Issuer / Mock Business Wallet               │                │
│  :8000  (H1 — OID4VCI + Status List)         │                │
│  /.well-known/did.json   ← did:web org       │                │
│  /credential-offer/{id} · /token · /credential│               │
│  /status-list/{id}  ← revocación            │                │
└────────────────┬─────────────────────────────┘                │
                 │ emite Mandate VC (OID4VCI)                    │
        ┌────────┴───────────────────┐                          │
        ▼                            ▼                          │
┌────────────────────┐   ┌───────────────────────────────────────────┐
│  Agent1            │   │  Agent2                                   │
│  Translator        │   │  Expert                                   │
│  :8011             │   │  :8010                                    │
│                    │   │                                           │
│  POST /ask         │   │  POST /peer/identify                      │
│  {question: "¿?"} │   │  POST /peer/action/challenge              │
│                    │   │  POST /peer/action/submit                 │
│  1. traduce ES→EN  │   │                                           │
│     (Claude)       │   │  Verifica VP JWT de Agent1:               │
│  2. pide respuesta ├──▶│    [1] challenge válido                  │
│     presenta VP    │   │    [2] firma VP (holder binding)          │
│     (mandato)      │   │    [3] nonce anti-replay                  │
│                    │◀──│    [4] firma VC (issuer de confianza)     │
│  3. traduce EN→ES  │   │    [5] sujeto VC == firmante VP           │
│     (Claude)       │   │    [6] no revocada                        │
│  4. devuelve       │   │    [7] scope: execute:answer_question     │
│     {answer_es}   │   │                                           │
│                    │   │  Si autorizado → Claude responde en EN    │
└────────────────────┘   └───────────────────────────────────────────┘
        │
        │ (para sus propias acciones, presenta VP al verifier central)
        ▼
┌──────────────────────────────────────────────┐
│  Verifier  :8001 (H3 — OID4VP)               │
│  - Valida VP/VC · did:web · Status List      │
│  - Evalúa scope + constraints + validez      │
│  - AUTORIZA / DENIEGA                        │
└──────────────────────────────────────────────┘
```

### Flujo IA (Agent1 → Agent2 con mandato)

```
Usuario                  Agent1 (Translator :8011)           Agent2 (Expert :8010)   Claude API
   │                              │                                   │                  │
   │── POST /ask ────────────────▶│                                   │                  │
   │   {"question": "¿...?"}      │                                   │                  │
   │                              │── translate ES→EN ───────────────────────────────────▶│
   │                              │◀─ "What is...?" ────────────────────────────────────│
   │                              │                                   │                  │
   │                              │── POST /peer/action/challenge ───▶│                  │
   │                              │◀─ {challenge_id, nonce} ──────────│                  │
   │                              │                                   │                  │
   │                              │   build VP JWT                    │                  │
   │                              │   (Mandate VC + firma + nonce)    │                  │
   │                              │                                   │                  │
   │                              │── POST /peer/action/submit ───────▶│                  │
   │                              │   {vp_token, action:             │                  │
   │                              │    execute:answer_question,       │                  │
   │                              │    params: {question: "What?"}}   │                  │
   │                              │                                   │── answer() ─────▶│
   │                              │                                   │◀─ "Paris is..." ─│
   │                              │◀─ {authorized: true,             │                  │
   │                              │    result: {answer: "Paris is…"}} │                  │
   │                              │── translate EN→ES ───────────────────────────────────▶│
   │                              │◀─ "París es..." ────────────────────────────────────│
   │◀─ {answer_es: "París es…"} ──│                                   │                  │
```

### Flujo A2A detallado (protocolo base)

```
Agent1                          Agent2 (peer_server)
  │                                    │
  │── POST /peer/identify ────────────▶│
  │   {agent_did, vc_jwt}              │ verifica firma VC, trust framework,
  │                                    │ revocación
  │◀─ {verified, agent_did, vc_jwt} ───│
  │   Agent1 verifica la VC de Agent2  │
  │                                    │
  │── POST /peer/action/challenge ────▶│
  │   {action, context}                │ genera challenge_id + nonce
  │◀─ {challenge_id, nonce} ───────────│
  │                                    │
  │   construye VP JWT                 │
  │   (envuelve Mandate VC, firma      │
  │    con su clave privada, nonce)    │
  │                                    │
  │── POST /peer/action/submit ───────▶│
  │   {challenge_id, vp_token, action} │ [1] challenge válido
  │                                    │ [2] firma VP (holder binding)
  │                                    │ [3] nonce anti-replay
  │                                    │ [4] firma VC (issuer de confianza)
  │                                    │ [5] sujeto VC == firmante VP
  │                                    │ [6] no revocada
  │                                    │ [7] scope cubre la acción
  │◀─ {authorized, result} ────────────│ ejecuta la acción si todo pasa
```

---

## Prerrequisitos

Antes de empezar, verifica que tienes instalado:

| Herramienta | Versión mínima | Cómo comprobar | Notas |
|---|---|---|---|
| **Python** | 3.11+ | `python3 --version` | Necesario para todos los servicios |
| **pip** | 22+ | `pip --version` | Viene con Python |
| **Docker** | 20+ | `docker --version` | **Solo si usas Vault** (Camino B) o docker-compose |
| **make** | cualquiera | `make --version` | Opcional, los comandos se pueden ejecutar a mano |
| **Git** | cualquiera | `git --version` | Para clonar el repositorio |
| **ANTHROPIC_API_KEY** | — | — | **Solo para los agentes IA**. Obtén en [console.anthropic.com](https://console.anthropic.com/) |

**Sistemas operativos probados:** Linux (Ubuntu 22/24), macOS 13+. En Windows usar WSL2.

---

## Puesta en marcha — Camino A (custodia local, sin Vault)

Este es el camino más rápido. La clave de la organización y del agente se guardan como ficheros en `data/keys/`. Suficiente para validar H0, H1, H3 y la interfaz de H2 (sin KMS real).

### Paso 1: Clonar y entrar al proyecto

```bash
git clone <url-del-repositorio> agenttrust-spike
cd agenttrust-spike
```

### Paso 2: Crear entorno virtual e instalar dependencias

```bash
python3 -m venv .venv
source .venv/bin/activate        # En Linux / macOS
# .venv\Scripts\activate         # En Windows (WSL2 recomendado)

pip install -r requirements.txt
```

Verifica que la instalación fue correcta:

```bash
python3 -c "from shared import build_custody; print('OK')"
```

Debe imprimir `OK` sin errores.

### Paso 3: Crear el fichero de configuración

```bash
cp .env.example .env
```

Para el Camino A no hace falta editar nada salvo si quieres usar los agentes IA (ver más abajo). Los valores por defecto usan custodia local:

```
KEY_CUSTODY_BACKEND=local
LOCAL_KEY_DIR=./data/keys
```

### Paso 4: Bootstrap de la organización

```bash
python3 scripts/bootstrap_org.py
```

Este comando hace tres cosas:
1. Genera la clave Ed25519 de la organización en `data/keys/org-issuer.priv`
2. Imprime el `did:web` y la JWK pública para verificación visual
3. Registra la organización como issuer de confianza en `data/trust_framework.json`

**Salida esperada:**

```
======================================================================
AgentTrust — Bootstrap de la organización emisora
======================================================================
  ORG_DID                = did:web:localhost%3A8000
  KEY_CUSTODY_BACKEND    = local
  ISSUER_KEY_NAME        = org-issuer

  Custody key_id         = local::org-issuer
  Algoritmo              = EdDSA
  Public JWK             = {'kty': 'OKP', 'crv': 'Ed25519', 'x': '...', 'kid': '...'}

  ✓ did:web:localhost%3A8000 añadido al trust framework (./data/trust_framework.json)

Bootstrap completado.
```

### Paso 5: Arrancar los tres servicios base

Abre **tres terminales** (todas con el virtualenv activado y en el directorio del proyecto):

**Terminal 1 — Issuer (mock Business Wallet, puerto 8000):**
```bash
uvicorn issuer.main:app --port 8000 --reload
```

**Terminal 2 — Verifier (puerto 8001):**
```bash
uvicorn verifier.main:app --port 8001 --reload
```

**Terminal 3 — Registry UI (puerto 8002):**
```bash
uvicorn registry_ui.main:app --port 8002 --reload
```

### Paso 6: Verificar que los servicios responden

```bash
curl http://localhost:8000/health
# → {"status":"ok","did":"did:web:localhost%3A8000","custody":"local::org-issuer"}

curl http://localhost:8001/health
# → {"status":"ok"}

curl http://localhost:8002/health
# → {"status":"ok"}
```

### Paso 7: Ejecutar las demos

**Demo H0→H3 (agente individual):**
```bash
python3 scripts/demo.py
```

**Demo A2A (dos agentes interactuando con protocolo de mandato):**
```bash
python3 scripts/demo_a2a.py
```

**Salida esperada (resumen demo.py):**

```
========================================================================
  AgentTrust — Demo end-to-end (H0 → H1 → H2 → H3 → revocación)
========================================================================

→ Comprobando servicios arrancados
  ✓ issuer       http://localhost:8000
  ✓ verifier     http://localhost:8001
  ✓ registry_ui  http://localhost:8002

→ POST http://localhost:8002/api/agents
  ✓ Agente dado de alta
    agent_did              did:key:z6Mkk...

→ Ejecutando OID4VCI Pre-Authorized Code Flow
  ✓ VC recibida del issuer did:web:localhost%3A8000

→ call_tool('restart_service', service_name='auth-api')
  ✓ AUTORIZADA — rule=R0, reason=OK

→ call_tool('escalate_to_human', ...) — no está en el scope
  ✓ DENEGADA correctamente — rule=R3

→ Reintentamos la acción tras revocar el mandato
  ✓ DENEGADA por revocación — el verifier consultó el Bitstring Status List
```

### Paso 8 (opcional): Probar la UI en el navegador

Abre http://localhost:8002/ en tu navegador. Verás el agente `demo-agent-001` ya registrado por el script de demo.

Desde el detalle de cualquier agente puedes **revocar su mandato** con el botón rojo. Al hacerlo, el issuer marca el bit en el Bitstring Status List y cualquier intento posterior del agente de usar su credencial será rechazado — aunque el JWT no haya expirado.

---

## Agentes IA con Claude (hipótesis IA)

Esta es la capa más avanzada del spike: dos agentes con identidad criptográfica real que usan Claude Opus 4.7 para tareas cognitivas reales. El protocolo de mandato sigue siendo el mismo — lo que cambia es que el "trabajo" ahora lo hace un LLM.

### Escenario

- **Agent1 — Translator** (`:8011`): recibe una pregunta en español, la traduce al inglés con Claude, la delega a Agent2 presentando su mandato, recibe la respuesta en inglés y la traduce de vuelta al español.
- **Agent2 — Expert** (`:8010`): acepta peticiones de agentes que tengan `execute:answer_question` en su mandato, verifica la cadena completa y responde la pregunta en inglés con Claude.

### Configuración previa

Añade tu API key de Anthropic en `.env`:

```bash
ANTHROPIC_API_KEY=sk-ant-...
```

Obtén tu clave en [console.anthropic.com](https://console.anthropic.com/).

### Arrancar los agentes IA

Con los tres servicios base ya en marcha (issuer, verifier, registry_ui):

```bash
# Terminal 4 — arranca Agent1 y Agent2 automáticamente
python3 scripts/start_ai_agents.py
# o:
make start-agents
```

El script:
1. Registra ambos agentes en el Registry UI con sus scopes correspondientes
2. Obtiene las Mandate Credentials vía OID4VCI
3. Arranca Agent2 (Expert) en el puerto 8010
4. Arranca Agent1 (Translator) en el puerto 8011

**Salida esperada:**

```
========================================================================
  AgentTrust — Arranque de Agentes IA (Translator + Expert)
========================================================================

→ Registrando Agent1 (Translator) con ID 'translator-001'
  ✓ Agent1 registrado
→ Registrando Agent2 (Expert) con ID 'expert-001'
  ✓ Agent2 registrado

→ Agent1 (translator-001) — OID4VCI…
  ✓ Agent1 tiene su Mandate Credential
    DID del agente           did:key:z6Mk...
    scope autorizado         ['execute:translate', 'execute:answer_question']
→ Agent2 (expert-001) — OID4VCI…
  ✓ Agent2 tiene su Mandate Credential

→ Arrancando Agent2 peer server (puerto 8010)…
  ✓ Agent2 peer server listo en http://localhost:8010
→ Arrancando Agent1 Translator (puerto 8011)…
  ✓ Agent1 Translator listo en http://localhost:8011

========================================================================
  ¡Agentes listos!
========================================================================

  Prueba con curl:

    curl -s -X POST http://localhost:8011/ask \
         -H 'Content-Type: application/json' \
         -d '{"question": "¿Cuál es la capital de Francia?"}' | python3 -m json.tool
```

### Probar con curl

```bash
# Pregunta simple
curl -s -X POST http://localhost:8011/ask \
     -H 'Content-Type: application/json' \
     -d '{"question": "¿Cuál es la capital de Francia?"}' | python3 -m json.tool

# Respuesta:
# {
#   "question_es": "¿Cuál es la capital de Francia?",
#   "question_en": "What is the capital of France?",
#   "answer_en": "The capital of France is Paris.",
#   "answer_es": "La capital de Francia es París."
# }

# Pregunta más compleja (Claude usa adaptive thinking)
curl -s -X POST http://localhost:8011/ask \
     -H 'Content-Type: application/json' \
     -d '{"question": "¿Cuáles son las principales diferencias entre TCP y UDP?"}' | python3 -m json.tool
```

### Chat UI — interfaz web (`:8003`)

Como alternativa al `curl`, puedes usar la interfaz de chat. Con los agentes IA ya en marcha:

```bash
# Terminal 5 — Chat UI
uvicorn chat_ui.main:app --port 8003 --reload
# o:
make run-chat
```

Abre http://localhost:8003/ en el navegador. Escribe la pregunta en español y la UI muestra los 4 pasos del flujo:

1. **AGENT1 · ES→EN** — pregunta traducida al inglés
2. **AGENT2 · CLAUDE** — respuesta en inglés generada por Claude
3. **AGENT1 · EN→ES** — respuesta traducida al español
4. Nota de protocolo: *"Agent2 verificó el VP JWT de Agent1: challenge · firma · nonce · issuer · holder binding · revocación · scope"*

Si el mandato de Agent1 está revocado (desde la Registry UI), la Chat UI muestra el error directamente en pantalla.

### Demostrar revocación con la Chat UI

1. Arranca los agentes IA (`make start-agents`) y la Chat UI (`make run-chat`)
2. Haz una pregunta — funciona correctamente
3. Ve a http://localhost:8002/, abre el agente `translator-001` y pulsa **Revocar mandato**
4. Vuelve a la Chat UI y envía otra pregunta — verás el error de mandato revocado

### Lo que demuestran los logs

Al ejecutar la petición, los logs de los servicios muestran el protocolo completo:

```
[AGENT1:ASK] Nueva pregunta recibida: ¿Cuál es la capital de Francia?
[AGENT1:ASK] [1/3] Traduciendo pregunta ES → EN…
[CLAUDE:TRANSLATE] Spanish → English | texto: ¿Cuál es la capital de Francia?…
[AGENT1:ASK]   Pregunta en inglés: What is the capital of France?
[AGENT1:ASK] [2/3] Solicitando respuesta a Agent2 (execute:answer_question)…
[AGENT1:PEER] [1/3] Solicitando challenge → POST http://localhost:8010/peer/action/challenge
[AGENT2:CHALLENGE] Nuevo challenge para acción 'execute:answer_question': <uuid>
[AGENT1:PEER] [2/3] Construyendo VP JWT con mandato…
[AGENT1:PEER] [3/3] Enviando VP y solicitando ejecución → POST http://localhost:8010/peer/action/submit
[AGENT2:SUBMIT] [1/7] Verificando challenge…           ✓ Challenge válido
[AGENT2:SUBMIT] [2/7] Parseando y verificando firma del VP…  ✓ Firma verificada
[AGENT2:SUBMIT] [3/7] Verificando nonce y audience…    ✓ Anti-replay OK
[AGENT2:SUBMIT] [4/7] Extrayendo VC del VP…
[AGENT2:SUBMIT] [5/7] Verificando issuer y firma de la VC…  ✓ Issuer de confianza
[AGENT2:SUBMIT] [6/7] Verificando holder binding…      ✓ Sujeto == firmante VP
[AGENT2:SUBMIT] [7a/7] Verificando revocación…         ✓ No revocada
[AGENT2:SUBMIT] [7b/7] Evaluando política de mandato… scope tiene execute:answer_question ✓
[AGENT2:SUBMIT] ✅ Mandato válido. Ejecutando acción 'execute:answer_question'…
[CLAUDE:ANSWER] pregunta: What is the capital of France?…
[AGENT1:ASK] [3/3] Traduciendo respuesta EN → ES…
[AGENT1:ASK] ✅ Ciclo completo. Devolviendo al usuario.
```

---

## Puesta en marcha — Camino B (con HashiCorp Vault)

Este camino valida H2 contra un KMS real: la clave privada **nunca sale de Vault**. El agente y el issuer firman llamando a la API HTTP de Vault Transit, nunca tienen los bytes de la clave.

### Pasos 1-3: idénticos al Camino A

Sigue los pasos 1, 2 y 3 del Camino A arriba.

### Paso 4: Levantar Vault en modo dev

```bash
docker run -d --name vault-spike \
  -p 8200:8200 \
  -e 'VAULT_DEV_ROOT_TOKEN_ID=root-token-spike' \
  hashicorp/vault:latest
```

Verifica que arrancó:

```bash
curl http://localhost:8200/v1/sys/health
# → {"initialized":true,"sealed":false, ...}
```

### Paso 5: Inicializar Vault Transit y crear la clave de la organización

```bash
bash scripts/init_vault.sh
```

### Paso 6: Configurar `.env` para usar Vault

Edita `.env` y cambia esta línea:

```bash
KEY_CUSTODY_BACKEND=vault
```

Las variables de conexión a Vault ya vienen configuradas por defecto:

```
VAULT_ADDR=http://localhost:8200
VAULT_TOKEN=root-token-spike
VAULT_TRANSIT_MOUNT=transit
```

### Paso 7: Bootstrap + servicios + demo

```bash
python3 scripts/bootstrap_org.py
# Verás: Custody key_id = vault::transit/org-issuer
```

Luego arranca los tres servicios y ejecuta la demo igual que en el Camino A. La diferencia es que ahora las claves de todos los agentes viven en Vault.

---

## Puesta en marcha — Docker Compose (todo de una vez)

```bash
# Arranca Vault + Issuer + Verifier + Registry UI
docker compose up -d

# Espera ~30s y verifica:
docker compose ps

# Ejecuta la demo H0→H3
docker compose run --rm demo

# Para todo y limpia
docker compose down -v
```

> **Nota:** Los agentes IA (`start_ai_agents.py`) no están en el Docker Compose por la dependencia de `ANTHROPIC_API_KEY`. Úsalos con el Camino A o B local.

---

## Estructura del repositorio

```
agenttrust-spike/
├── README.md                               # Este documento
├── requirements.txt                        # Dependencias Python (incluye anthropic)
├── .env.example                            # Variables de entorno (copiar a .env)
├── .gitignore
├── docker-compose.yml                      # Orquestación opcional
├── Makefile                                # Atajos: make run, make demo, make clean
│
├── shared/                                 # Librería compartida
│   ├── __init__.py                         # Re-exports de todo lo público
│   ├── jwt_utils.py                        # Construcción/validación de JWT con KeyCustody
│   ├── did_key.py                          # Generación y resolución did:key (Ed25519)
│   ├── did_web.py                          # Resolución did:web vía HTTP
│   ├── credential.py                       # Mandate Credential schema y builder
│   ├── status_list.py                      # Bitstring Status List 1.0
│   ├── claude_client.py                    # [IA] Wrapper Anthropic SDK: translate() + answer()
│   └── key_custody/
│       ├── __init__.py                     # Factory build_custody() → LocalFile o Vault
│       ├── base.py                         # Interfaz KeyCustody (sign / public_jwk / rotate)
│       ├── local_file.py                   # Backend de fichero
│       └── vault.py                        # Backend HashiCorp Vault Transit
│
├── issuer/                                 # H1: mock Business Wallet
│   ├── __init__.py
│   ├── main.py                             # FastAPI + endpoints OID4VCI + did.json
│   └── storage.py                          # SQLite: ofertas, tokens, status list
│
├── verifier/                               # H3: verificador OID4VP
│   ├── __init__.py
│   ├── main.py                             # FastAPI + flow OID4VP
│   ├── policy.py                           # Evaluación de mandato (scope, constraints, validez)
│   └── trust_framework.py                  # Lista de issuers de confianza
│
├── agent/                                  # Los agentes
│   ├── __init__.py
│   ├── main.py                             # CLI: subcomandos fetch y run
│   ├── holder.py                           # OID4VCI receiver + OID4VP presenter
│   ├── runtime.py                          # Loop: para cada acción → presentar VP → ejecutar
│   ├── tools.py                            # Tools de ejemplo (read_incident, restart_service, ...)
│   ├── peer_server.py                      # [A2A] FastAPI: Agent2 acepta peticiones de otros agentes
│   ├── peer_client.py                      # [A2A] Cliente HTTP: Agent1 llama a Agent2
│   ├── peer_tools.py                       # [A2A] Acciones que Agent2 puede ejecutar (database_backup, answer_question, …)
│   └── agent1_server.py                    # [IA] FastAPI :8011 — Translator ES↔EN
│
├── registry_ui/                            # H0: mini-UI de alta y revocación de agentes
│   ├── __init__.py
│   ├── main.py                             # FastAPI + Jinja2 + API JSON + POST /agents/{id}/revoke
│   ├── storage.py                          # SQLite: agentes registrados + revoked_at
│   └── templates/
│       ├── base.html                       # Estilos: btn-danger, badge-revoked/active, alert
│       ├── index.html                      # Listado con badge ACTIVO/REVOCADO
│       ├── register.html
│       └── agent_detail.html               # Botón "Revocar mandato" + estado de revocación
│
├── chat_ui/                                # [IA] Interfaz web de chat con Agent1
│   ├── __init__.py
│   ├── main.py                             # FastAPI :8003 — proxy a Agent1 /ask
│   └── templates/
│       └── index.html                      # Chat UI: muestra los 4 pasos ES→EN→respuesta→ES
│
├── scripts/
│   ├── bootstrap_org.py                    # Inicializa identidad de la organización
│   ├── init_vault.sh                       # Setup de Vault Transit + clave org
│   ├── demo.py                             # Demo H0→H1→H2→H3 (agente individual)
│   ├── demo_a2a.py                         # [A2A] Demo Agent-to-Agent end-to-end
│   └── start_ai_agents.py                  # [IA] Arranca Translator (:8011) + Expert (:8010)
│
└── data/                                   # Generado en runtime (en .gitignore)
    └── .gitkeep
    # Tras ejecutar se crea:
    # ├── keys/                             # Claves Ed25519 (solo custodia local)
    # ├── agents/                           # VCs persistidas de los agentes
    # ├── agenttrust.db                     # SQLite compartida
    # └── trust_framework.json              # Lista de issuers de confianza
```

---

## Mapa hipótesis → ficheros (lectura recomendada)

- **H0** → `registry_ui/main.py` + `registry_ui/storage.py` + `scripts/bootstrap_org.py` (revocación: `POST /agents/{id}/revoke`)
- **H1** → `issuer/main.py` + `shared/credential.py` + `agent/holder.py`
- **H2** → `shared/key_custody/base.py` + `local_file.py` + `vault.py`
- **H3** → `verifier/main.py` + `verifier/policy.py` + `agent/holder.py`
- **A2A** → `agent/peer_server.py` + `agent/peer_client.py` + `scripts/demo_a2a.py`
- **IA** → `shared/claude_client.py` + `agent/agent1_server.py` + `agent/peer_tools.py` (execute:answer_question) + `scripts/start_ai_agents.py` + `chat_ui/` (interfaz web)

---

## Atajos con Make

```bash
make install        # pip install + crea .env
make bootstrap      # bootstrap_org.py
make run-issuer     # uvicorn issuer en :8000
make run-verifier   # uvicorn verifier en :8001
make run-registry   # uvicorn registry_ui en :8002
make run-vault      # docker run vault dev mode
make init-vault     # init_vault.sh
make demo           # scripts/demo.py  (H0→H3)
make demo-a2a       # scripts/demo_a2a.py  (A2A)
make start-agents   # scripts/start_ai_agents.py  (Translator :8011 + Expert :8010)
make run-chat       # uvicorn chat_ui en :8003 (interfaz web para preguntas)
make clean          # borra data/
```

---

## Uso manual del agente (sin demo script)

### Registrar un agente y obtener su credencial

```bash
# 1. Registrar vía API del Registry UI
curl -s -X POST http://localhost:8002/api/agents \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_id": "mi-agente",
    "delegator_did": "did:web:localhost%3A8000#supervisor-001",
    "scope": ["read:incidents", "execute:restart_service"],
    "context": "incident-management",
    "valid_from": "2025-01-01T00:00:00Z",
    "valid_until": "2099-01-01T00:00:00Z"
  }' | python3 -m json.tool

# 2. El agente recoge su VC
python3 -m agent.main fetch \
  --agent-id mi-agente \
  --credential-offer-uri http://localhost:8000/credential-offer/<OFFER_ID>
```

### Ejecutar una acción con presentación de credencial

```bash
# Acción dentro del scope (será autorizada)
python3 -m agent.main run \
  --agent-id mi-agente \
  --tool restart_service \
  --arg service_name=auth-api

# Acción fuera del scope (será denegada)
python3 -m agent.main run \
  --agent-id mi-agente \
  --tool escalate_to_human \
  --arg incident_id=INC-999
```

### Revocar el mandato de un agente

```bash
curl -s -X POST http://localhost:8000/admin/revoke \
  -H 'Content-Type: application/json' \
  -d '{"agent_did": "did:key:z6Mkk..."}'
```

Tras la revocación, cualquier intento del agente de presentar su credencial será rechazado.

---

## Troubleshooting

### Error: `ModuleNotFoundError: No module named 'shared'`

```bash
cd agenttrust-spike
source .venv/bin/activate
```

### Error: `Connection refused` al ejecutar demo.py

Los tres servicios deben estar corriendo:

```bash
curl http://localhost:8000/health && echo OK
curl http://localhost:8001/health && echo OK
curl http://localhost:8002/health && echo OK
```

### Error: `ANTHROPIC_API_KEY no está configurada`

```bash
# Añade en .env:
ANTHROPIC_API_KEY=sk-ant-...
# Y recarga el proceso
```

### Error: `VAULT_TOKEN` o `is_authenticated` al arrancar con `KEY_CUSTODY_BACKEND=vault`

```bash
docker ps | grep vault-spike
docker start vault-spike   # si no corre
bash scripts/init_vault.sh
```

### Error: `sqlite3.OperationalError: database is locked`

```bash
make clean
# Luego re-arranca los servicios
```

### Quiero empezar de cero

```bash
make clean
# Después repite desde el Paso 4 (bootstrap)
```

---

## Lo que NO hace este spike (y por qué)

| Elemento | Por qué se difiere |
|----------|-------------------|
| Anclaje on-chain de acciones | No necesario para validar las hipótesis. Iteración 2 |
| Integración con MCP | Alcance del SDK del producto, no del spike |
| ERC-8004 | Referencia conceptual, no implementación |
| Integración real con Identfy Business Wallet | Mock — el spike valida el contrato OID4VCI, no el deploy productivo |
| UI productiva | La de H0 es funcional, no productiva |
| Descubrimiento automático de peers | Los peers se configuran por URL. Service discovery en iteración 2 |
| Streaming de respuesta Claude | Implementable; en el spike se usa respuesta síncrona para simplicidad |

---

## Criterio de cierre

El spike cierra cuando se entrega:

1. **Demo funcional H0→H3** — `python scripts/demo.py` mostrando identidad asignada, credencial recibida, presentación y decisión del verifier
2. **Demo A2A** — `python scripts/demo_a2a.py` mostrando identificación mutua, presentación de mandato y ejecución delegada con revocación
3. **Demo IA** — `python scripts/start_ai_agents.py` + curl mostrando el ciclo completo: pregunta en español → Claude traduce → Agent2 verifica mandato → Claude responde → respuesta en español
4. **Documento de decisión por hipótesis** — go/no-go con evidencia (el README recoge las decisiones de stack)
5. **Lista de hallazgos para iteración 1** — qué se reescribirá, qué se reutilizará
