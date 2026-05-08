# AgentTrust spike — Makefile
# Atajos para tareas habituales. Uso:
#   make install        # instala dependencias
#   make bootstrap      # inicializa identidad de la organización
#   make run-issuer     # arranca el issuer en :8000
#   make run-verifier   # arranca el verifier en :8001
#   make run-registry   # arranca el registry UI en :8002
#   make run-vault      # arranca Vault dev mode en Docker (opcional)
#   make init-vault     # configura Vault Transit y la clave org
#   make demo           # ejecuta demo.py H0→H3 (asume servicios arrancados)
#   make demo-a2a       # ejecuta demo_a2a.py Agent-to-Agent (asume servicios arrancados)
#   make clean          # borra data/ (claves, sqlite, status list)

.PHONY: help install bootstrap run-issuer run-verifier run-registry run-vault init-vault demo demo-a2a start-agents clean

PYTHON ?= python3
PIP ?= pip
ISSUER_PORT ?= 8000
VERIFIER_PORT ?= 8001
REGISTRY_UI_PORT ?= 8002

help:
	@echo "AgentTrust spike — comandos disponibles:"
	@echo "  make install        — pip install requirements"
	@echo "  make bootstrap      — inicializa la org (clave + trust framework)"
	@echo "  make run-issuer     — issuer en :$(ISSUER_PORT)"
	@echo "  make run-verifier   — verifier en :$(VERIFIER_PORT)"
	@echo "  make run-registry   — registry UI en :$(REGISTRY_UI_PORT)"
	@echo "  make run-vault      — Vault dev en Docker"
	@echo "  make init-vault     — Vault Transit + clave org"
	@echo "  make demo           — ejecuta demo H0→H3 (agente individual)"
	@echo "  make demo-a2a       — ejecuta demo Agent-to-Agent"
	@echo "  make start-agents   — arranca agentes IA (Translator + Expert) en :8011/:8010"
	@echo "  make clean          — borra data/ (claves, DB, etc.)"

install:
	$(PIP) install -r requirements.txt
	@if [ ! -f .env ]; then cp .env.example .env; echo "→ creado .env desde .env.example"; fi

bootstrap:
	$(PYTHON) scripts/bootstrap_org.py

run-issuer:
	uvicorn issuer.main:app --port $(ISSUER_PORT) --reload

run-verifier:
	uvicorn verifier.main:app --port $(VERIFIER_PORT) --reload

run-registry:
	uvicorn registry_ui.main:app --port $(REGISTRY_UI_PORT) --reload

run-vault:
	docker run -d --name vault-spike --rm \
		-p 8200:8200 \
		-e 'VAULT_DEV_ROOT_TOKEN_ID=root-token-spike' \
		hashicorp/vault:latest \
		|| echo "(quizá ya está corriendo: docker logs vault-spike)"

init-vault:
	bash scripts/init_vault.sh

demo:
	$(PYTHON) scripts/demo.py

demo-a2a:
	$(PYTHON) scripts/demo_a2a.py

start-agents:
	$(PYTHON) scripts/start_ai_agents.py

clean:
	rm -rf data/agents data/keys data/agenttrust.db data/trust_framework.json
	@echo "→ data/ limpiado"
