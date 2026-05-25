from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_sources(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return data

