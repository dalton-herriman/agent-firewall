from __future__ import annotations

from dataclasses import dataclass, field
from time import monotonic


@dataclass(slots=True)
class CircuitBreakerState:
    failures: int = 0
    opened_until: float = 0.0


@dataclass(slots=True)
class ReliabilityState:
    circuits: dict[str, CircuitBreakerState] = field(default_factory=dict)
    idempotent_results: dict[str, object] = field(default_factory=dict)

    def is_circuit_open(self, key: str, now: float | None = None) -> bool:
        current = now or monotonic()
        state = self.circuits.get(key)
        return bool(state and state.opened_until > current)

    def record_failure(self, key: str, threshold: int, reset_seconds: int, now: float | None = None) -> None:
        current = now or monotonic()
        state = self.circuits.setdefault(key, CircuitBreakerState())
        state.failures += 1
        if state.failures >= threshold:
            state.opened_until = current + reset_seconds

    def record_success(self, key: str) -> None:
        self.circuits[key] = CircuitBreakerState()

    def cache_result(self, idempotency_key: str, result: object) -> None:
        self.idempotent_results[idempotency_key] = result

    def get_cached_result(self, idempotency_key: str) -> object | None:
        return self.idempotent_results.get(idempotency_key)
