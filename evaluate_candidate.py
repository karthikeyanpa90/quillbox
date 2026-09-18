# -*- coding: utf-8 -*-
"""Evaluate one candidate's real witness numbers, without ever touching OWL or the live deployed
adapter: swap quillbox_app/ to the named candidate, run witness.py in its own fresh subprocess,
restore whatever was there before. Runs as its own process for the same reason witness.py's
compliance_scan was rewritten to parse files rather than import them (round 132): nothing about a
previous import or a previous candidate is allowed to leak in.

Usage: python evaluate_candidate.py <candidate_name>
"""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent
LIVE = ROOT / "quillbox_app"

if __name__ == "__main__":
    name = sys.argv[1]
    backup = ROOT / f".quillbox_app_backup_{name}"
    shutil.copytree(LIVE, backup)
    try:
        shutil.rmtree(LIVE)
        shutil.copytree(ROOT / "candidates" / name / "quillbox_app", LIVE)
        r = subprocess.run([sys.executable, str(ROOT / "witness.py")], capture_output=True, text=True, cwd=ROOT)
        sys.stdout.write(r.stdout)
        sys.exit(r.returncode)
    finally:
        shutil.rmtree(LIVE)
        shutil.move(str(backup), str(LIVE))
