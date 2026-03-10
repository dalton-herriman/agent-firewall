# Development

## Virtual environment

Create the local environment:

```bash
python3 -m venv .venv
```

Activate it in your shell:

```bash
source .venv/bin/activate
```

## Install dependencies

```bash
pip install -r requirements-dev.txt
pip install -e .
```

## Start local services

```bash
docker compose up -d postgres redis
```

## Run migrations

```bash
alembic upgrade head
```

## Run tests

```bash
pytest -q
```

## Run integration tests against real services

Set:

```bash
export AGENT_FIREWALL_RUN_INTEGRATION=1
export AGENT_FIREWALL_TEST_DATABASE_URL=postgresql+asyncpg://agent_firewall:agent_firewall@localhost:5432/agent_firewall
export AGENT_FIREWALL_TEST_REDIS_URL=redis://localhost:6379/0
```

Then run:

```bash
make verify-stack
make test-integration
```

`test-integration` now includes both repository-level and full app-path integration coverage against real Postgres and Redis.

## Run the server

```bash
uvicorn agent_firewall.server:create_server_app --factory --reload
```

## Make targets

```bash
make bootstrap
make install
make build
make services-up
make migrate-up
make test
make run
```
