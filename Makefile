SHELL := /bin/bash

AZURE_KV_IMAGE ?= jamesgoulddev/azure-keyvault-emulator:2.6.6
AZURE_KV_CERTS_DIR ?= ./scripts/azurekv-certs
AZURE_KV_CERTS_DIR := $(abspath $(AZURE_KV_CERTS_DIR))

export AZURE_KV_IMAGE
export AZURE_KV_CERTS_DIR

E2E_COMPOSE_FILE := scripts/compose.e2e.yml
E2E_ENV_FILE ?= scripts/e2e.env
E2E_ENV_FALLBACK := scripts/e2e.env.example

.PHONY: fmt lint build test run docker e2e-up e2e-seed e2e-test e2e-down e2e

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace --all-targets -- -D warnings

build:
	cargo build --workspace

test:
	cargo test --workspace

run:
	cargo run -p secrets-broker

docker:
	docker build -f deploy/Dockerfile.broker -t secrets-broker:dev .

e2e-up:
	@set -euo pipefail; \
	  mkdir -p "$(AZURE_KV_CERTS_DIR)"; \
	  if [ -f "$(AZURE_KV_CERTS_DIR)/emulator.pfx" ]; then \
	    if ! openssl pkcs12 -in "$(AZURE_KV_CERTS_DIR)/emulator.pfx" -passin pass:emulator -clcerts -nodes >/dev/null 2>&1; then \
	      echo "Existing emulator.pfx has unexpected password; regenerating"; \
	      rm -f "$(AZURE_KV_CERTS_DIR)/emulator.pfx"; \
	    fi; \
	  fi; \
	  if [ ! -f "$(AZURE_KV_CERTS_DIR)/emulator.pfx" ]; then \
	    echo "Generating Azure Key Vault emulator certificate bundle"; \
	    openssl req -x509 -nodes -newkey rsa:2048 \
	      -keyout "$(AZURE_KV_CERTS_DIR)/emulator.key" \
	      -out "$(AZURE_KV_CERTS_DIR)/emulator.crt" \
	      -days 365 \
	      -subj "/CN=localhost"; \
	    openssl pkcs12 -export \
	      -out "$(AZURE_KV_CERTS_DIR)/emulator.pfx" \
	      -inkey "$(AZURE_KV_CERTS_DIR)/emulator.key" \
	      -in "$(AZURE_KV_CERTS_DIR)/emulator.crt" \
	      -passout pass:emulator >/dev/null; \
	    rm -f "$(AZURE_KV_CERTS_DIR)/emulator.key" "$(AZURE_KV_CERTS_DIR)/emulator.crt"; \
	  fi; \
	  if [ ! -f "$(AZURE_KV_CERTS_DIR)/emulator.db" ]; then \
	    echo "Creating Azure Key Vault emulator database"; \
	    AZURE_DB_PATH="$(AZURE_KV_CERTS_DIR)/emulator.db" python3 -c 'import os, sqlite3; sqlite3.connect(os.environ["AZURE_DB_PATH"]).close()'; \
	  fi
	docker compose -f $(E2E_COMPOSE_FILE) up -d --wait

e2e-seed:
	./scripts/seed/aws_localstack.sh
	./scripts/seed/azure_kv.sh
	./scripts/seed/vault.sh

e2e-test:
	@set -euo pipefail; \
	  env_file="$$([ -f "$(E2E_ENV_FILE)" ] && echo "$(E2E_ENV_FILE)" || echo "$(E2E_ENV_FALLBACK)")"; \
	  echo "Using environment file: $$env_file"; \
	  set -a; \
	  source "$$env_file"; \
	  set +a; \
	  cargo run -p greentic-secrets-conformance --features provider-aws,provider-azure,provider-vault

e2e-down:
	-docker compose -f $(E2E_COMPOSE_FILE) down -v

e2e:
	@set -euo pipefail; \
	  cleanup() { $(MAKE) --no-print-directory e2e-down; }; \
	  trap cleanup EXIT; \
	  $(MAKE) --no-print-directory e2e-up; \
	  $(MAKE) --no-print-directory e2e-seed; \
	  $(MAKE) --no-print-directory e2e-test; \
	  trap - EXIT; \
	  cleanup
