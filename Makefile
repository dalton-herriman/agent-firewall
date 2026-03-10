PYTHON := .venv/bin/python
PIP := .venv/bin/pip
PYTEST := .venv/bin/pytest
ALEMBIC := .venv/bin/alembic
UVICORN := .venv/bin/uvicorn

.PHONY: venv install bootstrap test test-integration verify-stack run migrate-up migrate-down services-up services-down

venv:
	python3 -m venv .venv

install:
	$(PIP) install -r requirements-dev.txt
	$(PIP) install -e .

bootstrap:
	$(PYTHON) scripts/bootstrap_dev.py

test:
	$(PYTEST) -q

test-integration:
	$(PYTEST) -q -m integration

verify-stack:
	$(PYTHON) scripts/verify_stack.py

run:
	$(UVICORN) agent_firewall.server:create_server_app --factory --reload

migrate-up:
	$(ALEMBIC) upgrade head

migrate-down:
	$(ALEMBIC) downgrade -1

services-up:
	docker compose up -d postgres redis

services-down:
	docker compose down
