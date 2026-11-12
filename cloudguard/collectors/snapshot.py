"""Offline collector: load normalized resources from a JSON snapshot.

Used for tests, demos, and for scanning inventories exported by another
pipeline (e.g. a nightly job that dumps every account to object storage).
`cloudguard collect --out snap.json` writes this same format.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from ..model import Resource


def load_snapshot(path: str | Path) -> Iterator[Resource]:
    data = json.loads(Path(path).read_text())
    for d in data["resources"] if isinstance(data, dict) else data:
        yield Resource.from_dict(d)


def write_snapshot(resources: list[Resource], path: str | Path) -> None:
    Path(path).write_text(json.dumps({"resources": [r.to_dict() for r in resources]}, indent=2))
