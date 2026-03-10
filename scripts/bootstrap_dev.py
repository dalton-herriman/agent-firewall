from __future__ import annotations

import json
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    env_path = root / ".env"
    example_env = root / ".env.example"
    if not env_path.exists():
        env_path.write_text(example_env.read_text())
        print("wrote .env from .env.example")
    else:
        print(".env already exists")

    seed_path = root / "seed" / "dev_seed.json"
    payload = json.loads(seed_path.read_text())
    print(f"seed policies: {len(payload['policies'])}")
    print(f"seed adapters: {len(payload['adapters'])}")
    print(f"seed runtime config: {len(payload['runtime_config'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

