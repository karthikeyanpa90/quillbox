# -*- coding: utf-8 -*-
"""A deterministic digest of a directory of source, shared by the witness job and the adapter.

The witness signs the digest of what it measured; the adapter shows the digest of what it is serving. They are
computed the same way on purpose, so the two can be compared -- but only the witness's is evidence. The adapter's
is a drift tripwire (round 136's real failure: a redeploy served v0 while OWL held v1), and it catches nothing
deliberate, because the party computing it is the party being graded.
"""
import hashlib
from pathlib import Path


def tree_digest(path) -> str:
    """sha256 over the sorted (relative path, file digest) list of a directory. A reader holding the repository
    can recompute it over candidates/<version>/quillbox_app without running anything."""
    path = Path(path)
    if not path.is_dir():
        return ""
    h = hashlib.sha256()
    for f in sorted(p for p in path.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
        h.update(str(f.relative_to(path)).replace("\\", "/").encode("utf-8"))
        h.update(hashlib.sha256(f.read_bytes()).digest())
    return "sha256:" + h.hexdigest()
