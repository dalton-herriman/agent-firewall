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

## Run tests

```bash
pytest -q
```

## Run the server

```bash
uvicorn agent_firewall.server:create_server_app --factory --reload
```
