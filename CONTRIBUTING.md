# Contributing

## Setup

```bash
make bootstrap
make install
make test
```

## Before opening a change

- update docs for behavior changes
- run `make test`
- run `python -m compileall src tests alembic scripts examples`

## Integration coverage

If your change touches Postgres or Redis behavior, run:

```bash
make verify-stack
make test-integration
```

The main CI workflow also runs `pytest -m integration` against GitHub Actions service containers for Postgres and Redis.
