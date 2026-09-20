# -*- coding: utf-8 -*-
"""Round 141 (P49): the two attacks that broke round 140, and the boundary that answers them.

An adversarial review of round 140, run the day it shipped, found that the witness ran the candidate's own code
under pytest in the same container as its signing keys. Two things followed, and both are reproduced here rather
than asserted:

  1. `python -m pyflakes` puts the working directory first on sys.path, and the working directory was the staged
     candidate. A `pyflakes/` package dropped there shadows the real tool and the defect scan comes back clean.
  2. Anything the candidate executes can rewrite the report files and the source that the later tools read, after
     the signed digests were taken -- so the digests still matched git while every number was forged.

The answer is not a cleverer check inside one process. It is that the job holding the keys never runs the
candidate: it runs only tools that read the source without executing it.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

QUILLBOX = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(QUILLBOX))

import witness                                                        # noqa: E402
import witness_job                                                    # noqa: E402
from qb_digest import tree_digest                                     # noqa: E402


def staged(tmp_path, source: str, extra=None) -> Path:
    """A candidate staged the way witness_job.stage does, with its main.py replaced by `source`."""
    work = tmp_path / "work"
    shutil.copytree(QUILLBOX / "candidates" / "v1" / "quillbox_app", work / "quillbox_app")
    shutil.copytree(QUILLBOX / "tests", work / "tests", ignore=shutil.ignore_patterns("__pycache__"))
    (work / "quillbox_app" / "main.py").write_text(source, encoding="utf-8")
    for rel, text in (extra or {}).items():
        p = work / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return work


# ---- attack 1: shadowing the tool ----

DEFECTIVE = "import os\nUNSUBSCRIBE_URL = 'x'\n"                      # one real pyflakes finding: os unused

def test_the_defect_scan_sees_a_real_defect(tmp_path):
    work = staged(tmp_path, DEFECTIVE)
    assert witness.run_defect_scan(work)["critical_defects"] == 1

def test_a_pyflakes_package_in_the_staged_tree_no_longer_shadows_the_real_tool(tmp_path):
    """Without PYTHONSAFEPATH this returned a clean report and the guard passed on defective code."""
    work = staged(tmp_path, DEFECTIVE, {"pyflakes/__init__.py": "",
                                        "pyflakes/__main__.py": "print('')\n"})
    assert witness.run_defect_scan(work)["critical_defects"] == 1

def test_a_pytest_package_in_the_staged_tree_does_not_shadow_pytest_either(tmp_path):
    """And PYTHONSAFEPATH costs the dynamic half nothing: pytest puts the staged root on the path itself, so the
    suite still imports quillbox_app and still reports the same three stories it did before the hardening."""
    clean = (QUILLBOX / "candidates" / "v1" / "quillbox_app" / "main.py").read_text(encoding="utf-8")
    work = staged(tmp_path, clean, {"pytest/__init__.py": "", "pytest/__main__.py": "print('')\n"})
    report = witness.dynamic_report(work)
    assert report["story_tests_total"] == 3 and report["story_completion"] == pytest.approx(1 / 3)


# ---- attack 2: the candidate acting while it is measured ----

TAMPERING = '''
import atexit, json, os, pathlib, socket          # socket is unused: one real pyflakes finding to be seen

UNSUBSCRIBE_URL = "https://quillbox.example/unsubscribe/{token}"

def _forge():
    root = pathlib.Path(os.getcwd())
    (root / "quillbox_app" / "main.py").write_text("UNSUBSCRIBE_URL = 'x'\\n", encoding="utf-8")
    for name, body in ((".pytest_report.json", {"tests": [
            {"nodeid": "tests/t.py::test_story_a", "outcome": "passed"}]}),
            (".coverage_report.json", {"totals": {"percent_covered": 100.0}})):
        (root / name).write_text(json.dumps(body), encoding="utf-8")

atexit.register(_forge)
'''

def test_the_static_half_never_executes_the_candidate_so_it_cannot_act(tmp_path):
    """pyflakes parses, the compliance scan parses; neither imports. The tampering above never runs."""
    work = staged(tmp_path, TAMPERING)
    before = tree_digest(work / "quillbox_app")
    report = witness.static_report(work)
    assert tree_digest(work / "quillbox_app") == before      # nothing moved: nothing ran
    assert report["critical_defects"] >= 1                   # and it is seen for what it is

def test_the_dynamic_half_can_still_be_forged_by_the_candidate_which_is_why_it_signs_nothing(tmp_path):
    """The point of this test is that it PASSES: the forgery works, and that is the honest reason coverage and
    story_completion are produced in a job with no key and delivered to nobody."""
    work = staged(tmp_path, TAMPERING)
    witness.dynamic_report(work)                              # the tampering fires as pytest exits
    forged = json.loads((work / ".coverage_report.json").read_text(encoding="utf-8"))
    assert forged["totals"]["percent_covered"] == 100.0
    assert (work / "quillbox_app" / "main.py").read_text(encoding="utf-8").strip() == "UNSUBSCRIBE_URL = 'x'"

def test_the_witness_refuses_to_deliver_if_the_staged_tree_moved_under_the_static_tools(tmp_path, monkeypatch):
    """Belt and braces: even in the static half, a changed digest means the signed note would describe something
    other than what was measured, so nothing is delivered."""
    monkeypatch.setattr(witness_job, "CANDIDATES", QUILLBOX / "candidates")
    real_static = witness.static_report

    def meddling(root, as_user=None):
        (Path(root) / "quillbox_app" / "main.py").write_text("UNSUBSCRIBE_URL='x'\n", encoding="utf-8")
        return real_static(root, as_user)

    monkeypatch.setattr(witness_job, "static_report", meddling)
    with pytest.raises(SystemExit, match="changed while the static tools ran"):
        witness_job.measure("v1", "static")


# ---- the boundary, as the code and the deployment describe it ----

def test_the_static_tools_import_nothing_from_the_candidate():
    """A guard against the boundary quietly eroding: the static half must never gain a tool that executes."""
    import ast
    tree = ast.parse((QUILLBOX / "witness.py").read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "static_report")
    called = {n.func.id for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert called <= {"run_defect_scan", "compliance_scan", "Path", "dict"}

def test_the_dynamic_mode_of_the_job_holds_no_key_and_delivers_nothing(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("QB_MODE", "dynamic")
    monkeypatch.setenv("QB_VERSION", "v1")
    monkeypatch.setenv("QB_INDEX", "1")
    monkeypatch.delenv("QB_SID", raising=False)
    monkeypatch.delenv("QB_OWL_BASE_URL", raising=False)
    monkeypatch.setattr(witness_job, "deliver", lambda *a, **k: pytest.fail("the measure job delivered something"))
    assert witness_job.main() == 0
    out = json.loads(capsys.readouterr().out)
    assert out["delivered"] == [] and out["mode"] == "dynamic"
    assert set(out["report"]) >= {"coverage", "story_completion", "story_tests_total"}

def test_the_tools_run_with_a_safe_path_and_no_bytecode(monkeypatch):
    seen = {}
    monkeypatch.setattr(witness.subprocess, "run",
                        lambda args, **kw: seen.update(kw) or subprocess.CompletedProcess(args, 0, "", ""))
    witness._run([sys.executable, "-c", "pass"], Path(tempfile.gettempdir()))
    assert seen["env"]["PYTHONSAFEPATH"] == "1" and seen["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
