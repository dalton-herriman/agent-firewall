from datetime import datetime, timezone
from uuid import UUID, uuid4


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> UUID:
    return uuid4()

