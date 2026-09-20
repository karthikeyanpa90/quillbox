# -*- coding: utf-8 -*-
"""Read .deploy-env.yaml, the gitignored file holding system F's keys. Every operator script reads them from here
and none of them hardcodes one: this repository is public.

What may live in this file, after round 140: QB_SID, QB_OWNER_KEY, QB_RUNTIME_KEY, QB_ADAPTER_SECRET,
QB_OWL_BASE_URL. Not the witness's signing keys -- those exist only in Secret Manager and inside the witness job,
and no operator script ever holds one.
"""
import re
from pathlib import Path

ENV_FILE = Path(__file__).parent / ".deploy-env.yaml"
_PAT = re.compile('^(\\w+):\\s*"([^"]*)"', re.MULTILINE)


def read_env(path=ENV_FILE) -> dict:
    return {m.group(1): m.group(2) for m in _PAT.finditer(Path(path).read_text(encoding="utf-8"))}


def write_env(env: dict, path=ENV_FILE) -> None:
    Path(path).write_text("".join('%s: "%s"\n' % (k, v) for k, v in env.items()), encoding="utf-8")
