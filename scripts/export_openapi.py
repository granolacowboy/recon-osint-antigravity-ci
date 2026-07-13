"""Export the deterministic v1 OpenAPI contract consumed by the frontend."""

from __future__ import annotations

import json
from pathlib import Path
import sys

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DESTINATION = REPOSITORY_ROOT / "frontend" / "openapi.json"
sys.path.insert(0, str(REPOSITORY_ROOT))

from app.core.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402


def main() -> None:
    application = create_app(Settings(AUTH_ENABLED=False, _env_file=None))
    serialized = json.dumps(
        application.openapi(), ensure_ascii=False, indent=2, sort_keys=True
    )
    DESTINATION.write_text(f"{serialized}\n", encoding="utf-8")


if __name__ == "__main__":
    main()
