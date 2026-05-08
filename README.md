#  AgentAI VC ID — Spike

**Validación técnica end-to-end en 4 hipótesis + protocolo Agent-to-Agent (A2A).**
Stack: Python 3.11+, FastAPI, Ed25519, OID4VCI Pre-Authorized Code Flow, OID4VP, W3C VCDM 2.0 (JWT), Bitstring Status List, HashiCorp Vault.

---

## ¿Qué resuelve este spike?

| H | Pregunta | Componente |
|---|----------|------------|
| **H0** | ¿Podemos registrar un agente con datos mínimos y producir los inputs para emitir su credencial? | `registry_ui/` — mini-UI de alta + persistencia SQLite |
| **H1** | ¿Podemos emitir una VC vía OID4VCI a un sujeto NO humano? | `issuer/` — mock Business Wallet con OID4VCI Pre-Auth Flow |
| **H2** | ¿Cómo custodia el agente sus claves sin Secure Enclave / biometría? | `shared/key_custody/` — interfaz con backends `LocalFile` y `Vault` |
| **H3** | ¿Puede el agente presentar su credencial vía OID4VP de forma autónoma? | `verifier/` + `agent/holder.py` — flow sin humano en el loop |
| **A2A** | ¿Pueden dos agentes identificarse mutuamente y delegar acciones con verificación de mandato? | `agent/peer_server.py` + `agent/peer_client.py` — protocolo Agent-to-Agent |

---

## Decisiones técnicas congeladas

- **Algoritmo:** Ed25519 (EdDSA). Más simple que ES256 y soportado por Vault Transit. Migrable a ES256 para EUDI ARF en producción.
- **DID del agente:** `did:key` (autocontenido, sin red).
- **DID de la organización:** `did:web` (resuelve a `/.well-known/did.json` del issuer).
- **Formato de credencial:** W3C VCDM 2.0 + JWT (`jwt_vc_json`).
- **Flow OID4VCI:** Pre-Authorized Code Flow (sin user-agent, encaja con holder no humano).
- **Revocación:** W3C Bitstring Status List 1.0.
- **Trust framework:** lista JSON de issuers de confianza (sustituible por Identfy ITF en producción).

---

## Arquitectura de servicios

```
┌──────────────────┐       ┌──────────────────┐
│  Registry UI     │       │  HashiCorp Vault │
│  :8002 (H0)      │       │  :8200 (Transit) │
└────────┬─────────┘       └─────────┬────────┘
         │                           │
         │ registra agentes          │ custodia claves
         ▼                           ▼
┌──────────────────────────────────────────────┐
│  Issuer / Mock Business Wallet               │
│  :8000  (H1 — OID4VCI + Status List)         │
│  /.well-known/did.json   ← did:web org       │
│  /credential-offer/{id} · /token · /credential│
│  /status-list/{id}  ← revocación            │
└────────────────┬─────────────────────────────┘
                 │ emite Mandate VC a cada agente
        ┌────────┴─────────┐
        ▼                  ▼
┌───────────────┐  ┌───────────────────────────┐
│   Agent1      │  │   Agent2                  │
│  (Incident    │  │  (Infra Operator)         │
│   Manager)    │  │                           │
│  did:key:…    │  │  did:key:…                │
│  Mandate VC   │  │  Mandate VC               │
│               │  │  peer_server :8010        │
│  PeerClient ──┼──┼▶ POST /peer/identify      │
│               │  │    verifica VC de Agent1  │
│               │◀─┼── devuelve VC de Agent2   │
│  verifica VC  │  │                           │
│  de Agent2    │  │                           │
│               │  │                           │
│  PeerClient ──┼──┼▶ POST /peer/action/…      │
│  presenta VP  │  │    verifica mandato       │
│  (mandato)    │  │    ejecuta acción         │
│               │◀─┼── {authorized, result}    │
└───────┬───────┘  └───────────────────────────┘
        │
        │ presenta VP al verifier central
        ▼            (para sus propias acciones)
┌──────────────────────────────────────────────┐
│  Verifier  :8001 (H3 — OID4VP)               │
│  - Valida VP/VC · did:web · Status List      │
│  - Evalúa scope + constraints + validez      │
│  - AUTORIZA / DENIEGA                        │
└──────────────────────────────────────────────┘
```

### Flujo A2A detallado

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

Para el Camino A no hace falta editar nada. Los valores por defecto usan custodia local:

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

### Paso 5: Arrancar los tres servicios

Abre **tres terminales** (todas con el virtualenv activado y en el directorio del proyecto):

**Terminal 1 — Issuer (mock Business Wallet, puerto 8000):**
```bash
cd agenttrust-spike
source .venv/bin/activate
uvicorn issuer.main:app --port 8000 --reload
```

Espera a ver:
```
[issuer] Iniciado. Backend de custodia: local::org-issuer
[issuer] DID de la organización: did:web:localhost%3A8000
INFO:     Uvicorn running on http://127.0.0.1:8000
```

**Terminal 2 — Verifier (puerto 8001):**
```bash
cd agenttrust-spike
source .venv/bin/activate
uvicorn verifier.main:app --port 8001 --reload
```

Espera a ver:
```
[verifier] Iniciado en http://localhost:8001
INFO:     Uvicorn running on http://127.0.0.1:8001
```

**Terminal 3 — Registry UI (puerto 8002):**
```bash
cd agenttrust-spike
source .venv/bin/activate
uvicorn registry_ui.main:app --port 8002 --reload
```

Espera a ver:
```
[registry_ui] iniciado
INFO:     Uvicorn running on http://127.0.0.1:8002
```

### Paso 6: Verificar que los servicios responden

En una **cuarta terminal** (o desde el navegador):

```bash
curl http://localhost:8000/health
# → {"status":"ok","did":"did:web:localhost%3A8000","custody":"local::org-issuer"}

curl http://localhost:8001/health
# → {"status":"ok"}

curl http://localhost:8002/health
# → {"status":"ok"}
```

Si los tres devuelven `"status":"ok"`, todo está listo.

### Paso 7: Ejecutar las demos

**Demo H0→H3 (agente individual):**
```bash
python3 scripts/demo.py
```

**Demo A2A (dos agentes interactuando):**
```bash
python3 scripts/demo_a2a.py
```

**Salida esperada (resumen):**

```
========================================================================
  AgentTrust — Demo end-to-end (H0 → H1 → H2 → H3 → revocación)
========================================================================

→ Comprobando servicios arrancados
  ✓ issuer       http://localhost:8000  → {'status': 'ok', ...}
  ✓ verifier     http://localhost:8001  → {'status': 'ok'}
  ✓ registry_ui  http://localhost:8002  → {'status': 'ok'}

========================================================================
  H0 — Alta del agente desde el Registry UI
========================================================================
→ POST http://localhost:8002/api/agents
  ✓ Agente dado de alta
    agent_id               demo-agent-001
    agent_did              did:key:z6Mkk...
    offer_uri              http://localhost:8000/credential-offer/...

========================================================================
  H1 + H2 — El agente obtiene su Mandate Credential vía OID4VCI
========================================================================
→ Ejecutando OID4VCI Pre-Authorized Code Flow
  ✓ VC recibida del issuer did:web:localhost%3A8000

========================================================================
  H3a — Acción DENTRO del scope (debe AUTORIZARSE)
========================================================================
→ call_tool('restart_service', service_name='auth-api')
  ✓ AUTORIZADA — rule=R0, reason=OK — acción dentro del mandato

========================================================================
  H3b — Acción FUERA del scope (debe DENEGARSE)
========================================================================
→ call_tool('escalate_to_human', ...) — no está en el scope
  ✓ DENEGADA correctamente — rule=R3

========================================================================
  Revocación — el mandato se revoca en caliente
========================================================================
→ Reintentamos la acción que antes estaba autorizada
  ✓ DENEGADA por revocación — el verifier consultó el Bitstring Status List

========================================================================
  Demo completada — las 4 hipótesis ejercitadas end-to-end
========================================================================
```

### Paso 8 (opcional): Probar la UI en el navegador

Abre http://localhost:8002/ en tu navegador. Verás el agente `demo-agent-001` ya registrado por el script de demo.

Para registrar otro agente manualmente:
1. Haz clic en **"Alta de agente"**
2. Rellena el formulario (los campos vienen con valores por defecto razonables)
3. Al enviar, se genera el `did:key` del agente y se crea la oferta OID4VCI
4. En la pantalla de detalle verás el comando exacto para que el agente recoja su credencial

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

**Salida esperada:**

```
=== AgentTrust — Vault Transit setup ===
  VAULT_ADDR   = http://localhost:8200
  MOUNT POINT  = transit
[1/3] Habilitando motor transit en transit...
[2/3] Creando clave Ed25519 'org-issuer'...
[3/3] Verificando...
  ...
✓ Vault listo.
```

### Paso 6: Configurar `.env` para usar Vault

Edita `.env` y cambia esta línea:

```bash
# Antes:
KEY_CUSTODY_BACKEND=local

# Después:
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
# Bootstrap (ahora usará Vault en vez de fichero local)
python3 scripts/bootstrap_org.py

# Verás:
#   Custody key_id         = vault::transit/org-issuer
#   Algoritmo              = EdDSA
```

Luego arranca los tres servicios y ejecuta la demo igual que en el Camino A (pasos 5 a 8). La diferencia es que ahora verás:

```
  H2 — la clave privada NO está en este proceso
    backend custodia       vault::transit/org-issuer
    estado                 la clave reside en Vault, sólo se llama POST /v1/transit/sign
```

---

## Puesta en marcha — Docker Compose (todo de una vez)

Si prefieres no abrir múltiples terminales:

```bash
# Arranca Vault + Issuer + Verifier + Registry UI
docker compose up -d

# Espera ~30s a que los servicios arranquen (pip install dentro del contenedor)
# Verifica:
docker compose ps
# Todos deben estar "running" o "Up"

# Ejecuta la demo
docker compose run --rm demo

# Para todo y limpia
docker compose down -v
```

> **Nota:** Docker Compose usa `python:3.11-slim` y hace `pip install` al arrancar cada contenedor. La primera vez tarda ~60s. Las siguientes arrancan más rápido gracias al volumen compartido.

Para cambiar entre custodia local y Vault en Docker Compose, edita la variable `KEY_CUSTODY_BACKEND` en el entorno:

```bash
KEY_CUSTODY_BACKEND=vault docker compose up -d
```

---

## Estructura del repositorio

```
agenttrust-spike/
├── README.md                               # Este documento
├── requirements.txt                        # Dependencias Python
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
├── agent/                                  # El agente Tipo 3
│   ├── __init__.py
│   ├── main.py                             # CLI: subcomandos fetch y run
│   ├── holder.py                           # OID4VCI receiver + OID4VP presenter
│   ├── runtime.py                          # Loop: para cada acción → presentar VP → ejecutar
│   ├── tools.py                            # Tools de ejemplo (read_incident, restart_service, ...)
│   ├── peer_server.py                      # [A2A] FastAPI: Agent2 acepta peticiones de otros agentes
│   ├── peer_client.py                      # [A2A] Cliente HTTP: Agent1 llama a Agent2
│   └── peer_tools.py                       # [A2A] Acciones que Agent2 puede ejecutar (database_backup, …)
│
├── registry_ui/                            # H0: mini-UI de alta de agentes
│   ├── __init__.py
│   ├── main.py                             # FastAPI + Jinja2 + API JSON
│   ├── storage.py                          # SQLite: agentes registrados
│   └── templates/
│       ├── base.html                       # Layout base
│       ├── index.html                      # Listado de agentes
│       ├── register.html                   # Formulario de alta
│       └── agent_detail.html               # Detalle con credential_offer_uri
│
├── scripts/
│   ├── bootstrap_org.py                    # Inicializa identidad de la organización
│   ├── init_vault.sh                       # Setup de Vault Transit + clave org
│   ├── demo.py                             # Demo H0→H1→H2→H3 (agente individual)
│   └── demo_a2a.py                         # [A2A] Demo Agent-to-Agent end-to-end
│
└── data/                                   # Generado en runtime (en .gitignore)
    └── .gitkeep
    # Tras ejecutar se crea:
    # ├── keys/                             # Claves Ed25519 (solo custodia local)
    # │   ├── org-issuer.priv
    # │   └── agent-demo-agent-001.priv
    # ├── agents/
    # │   └── demo-agent-001.vc.json        # VC persistida del agente
    # ├── agenttrust.db                     # SQLite compartida
    # └── trust_framework.json              # Lista de issuers de confianza
```

**Total: 39 archivos.** Los `__init__.py` son marcadores de paquete Python necesarios para que funcionen los `import`.

---

## Mapa hipótesis → ficheros (lectura recomendada)

- **H0** → `registry_ui/main.py` (formulario + API) + `registry_ui/storage.py` + `scripts/bootstrap_org.py`
- **H1** → `issuer/main.py` (endpoints OID4VCI) + `shared/credential.py` (schema Mandate Credential) + `agent/holder.py` (lado holder del flow)
- **H2** → `shared/key_custody/base.py` (la abstracción) + `local_file.py` y `vault.py` (las dos implementaciones)
- **H3** → `verifier/main.py` (validación completa) + `verifier/policy.py` (reglas R0-R5) + `agent/holder.py` (presentación autónoma)
- **A2A** → `agent/peer_server.py` (servidor de Agent2) + `agent/peer_client.py` (cliente de Agent1) + `scripts/demo_a2a.py`

---

## Uso manual del agente (sin demo script)

Además del script `demo.py`, el agente se puede operar desde la línea de comandos:

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

# → Copia el valor de "credential_offer_uri" del output

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
  --arg incident_id=INC-999 \
  --arg reason=test
```

### Revocar el mandato de un agente

```bash
# Consulta el did:key del agente
curl -s http://localhost:8002/api/agents | python3 -m json.tool | grep agent_did

# Revoca
curl -s -X POST http://localhost:8000/admin/revoke \
  -H 'Content-Type: application/json' \
  -d '{"agent_did": "did:key:z6Mkk..."}'
```

Tras la revocación, cualquier intento del agente de presentar su credencial será rechazado por el verifier.

---

## Troubleshooting

### Error: `ModuleNotFoundError: No module named 'shared'`

Estás ejecutando el comando fuera del directorio del proyecto, o sin el virtualenv activado.

```bash
cd agenttrust-spike
source .venv/bin/activate
```

### Error: `Connection refused` al ejecutar demo.py

Los tres servicios deben estar corriendo. Verifica:

```bash
curl http://localhost:8000/health && echo OK
curl http://localhost:8001/health && echo OK
curl http://localhost:8002/health && echo OK
```

Si alguno no responde, vuelve al Paso 5 y arráncalo.

### Error: `VAULT_TOKEN` o `is_authenticated` al arrancar con `KEY_CUSTODY_BACKEND=vault`

Vault no está corriendo o el token no es válido:

```bash
# ¿Corre Vault?
docker ps | grep vault-spike

# Si no corre:
docker start vault-spike
# O recréalo:
docker run -d --name vault-spike -p 8200:8200 \
  -e 'VAULT_DEV_ROOT_TOKEN_ID=root-token-spike' hashicorp/vault:latest

# Reinicializa Transit
bash scripts/init_vault.sh
```

### Error: `sqlite3.OperationalError: database is locked`

Dos servicios intentan escribir en la misma DB simultáneamente. Es raro pero puede pasar si un servicio no se cerró limpiamente. Solución:

```bash
make clean   # o: rm -f data/agenttrust.db
# Luego re-arranca los servicios
```

### Quiero empezar de cero

```bash
make clean
# O manualmente:
rm -rf data/agents data/keys data/agenttrust.db data/trust_framework.json
```

Después repite desde el Paso 4 (bootstrap).

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
make clean          # borra data/
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

---

## Criterio de cierre

El spike cierra cuando se entrega:

1. **Demo funcional H0→H3** — `python scripts/demo.py` con output legible mostrando identidad asignada, credencial recibida, presentación y decisión del verifier
2. **Demo A2A** — `python scripts/demo_a2a.py` mostrando identificación mutua entre agentes, presentación de mandato y ejecución delegada
3. **Documento de decisión por hipótesis** — go/no-go con evidencia (el README recoge las decisiones de stack)
4. **Lista de hallazgos para iteración 1** — qué se reescribirá, qué se reutilizará
