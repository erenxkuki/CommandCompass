from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

CONFIG_PATH = Path.home() / ".commandcompass.toml"


def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        return {}
    try:
        with CONFIG_PATH.open("rb") as f:
            return tomllib.load(f)
    except Exception:
        return {}


def save_config(data: dict[str, Any]) -> None:
    lines = []
    for key, value in data.items():
        if isinstance(value, bool):
            lines.append(f"{key} = {'true' if value else 'false'}")
        elif isinstance(value, str):
            lines.append(f'{key} = "{value}"')
        else:
            lines.append(f"{key} = {value}")
    CONFIG_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def get(key: str, default: Any = None) -> Any:
    return load_config().get(key, default)
