# -*- coding: utf-8 -*-
"""System F's witnesses, run for real (owl-build.md): pytest for the acceptance suite and coverage, pyflakes for
defects, a source scan for the one compliance rule. No number here is fabricated or simulated -- each is read from
a real tool's real output against the code actually staged for measurement.

Round 140 (P46) changed where that code comes from, not what is measured. Until then this module ran inside the
Quillbox service -- the same process whose /apply rmtree+copytree'd the very directory it then measured -- so
under OWL's strict rule every one of these numbers was tenant-delivered and none of them could honestly be judged.
Now `root` is passed in: witness_job.py stages one candidate's source into a throwaway directory of its own, in a
separate job the service cannot write to, and measures that. The functions are unchanged in substance; they simply
no longer assume the directory they measure is the one they live in.
"""
import ast
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent


def _run(args, root: Path, as_user: str = None):
    """Every tool runs as a subprocess against `root`.

    PYTHONSAFEPATH is not optional. `python -m pyflakes` puts the working directory at the front of sys.path, and
    the working directory is the staged candidate: a directory named `pyflakes/` sitting there shadows the real
    tool entirely. Reproduced, round 141 -- a two-line package silenced the defect scan and returned a clean
    report. PYTHONSAFEPATH=1 stops the interpreter prepending the directory, and the real tool is found again.
    PYTHONDONTWRITEBYTECODE keeps the staged tree free of __pycache__ so it can be re-digested afterwards.

    `as_user` drops to an unprivileged account where the platform allows it. That is hardening, not a boundary:
    it does not stop the candidate reading anything world-readable in the same container, which is why the keys
    live in a different job now."""
    kwargs = {}
    if as_user:
        kwargs["user"] = as_user                                   # POSIX only; witness_job.py decides whether to pass one
    env = dict(os.environ, PYTHONSAFEPATH="1", PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(args, cwd=root, capture_output=True, text=True, env=env, **kwargs)


def run_tests_and_coverage(root: Path = HERE, as_user: str = None) -> dict:
    """pytest's own JSON report gives per-test pass/fail; coverage.py gives real line coverage.
    story_completion is the pass share of tests named test_story_* (the acceptance suite); everything else
    (test_health_* etc.) counts only toward coverage, not story_completion.

    Collection is scoped to `tests` on purpose (round 140): the witness measures the product's own suite. The
    repository also holds platform_tests/, which test the adapter and this job, and counting those would let work
    on the plumbing move a number about the product."""
    report_path = root / ".pytest_report.json"
    cov_path = root / ".coverage_report.json"
    _run([sys.executable, "-m", "pytest", "tests", "-q", "--json-report", f"--json-report-file={report_path}",
          "--cov=quillbox_app", f"--cov-report=json:{cov_path}"], root, as_user)
    report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {"tests": []}
    story_tests = [t for t in report.get("tests", []) if t["nodeid"].split("::")[-1].startswith("test_story_")]
    story_passed = sum(1 for t in story_tests if t["outcome"] == "passed")
    story_completion = (story_passed / len(story_tests)) if story_tests else 0.0

    coverage = 0.0
    if cov_path.exists():
        coverage = json.loads(cov_path.read_text(encoding="utf-8"))["totals"]["percent_covered"] / 100.0
    return {"story_completion": story_completion, "coverage": coverage,
            "story_tests_total": len(story_tests), "story_tests_passed": story_passed}


def run_defect_scan(root: Path = HERE, as_user: str = None) -> dict:
    """pyflakes: real static analysis, not a mock -- unused imports, undefined names, the usual.

    It fails closed (round 142). pyflakes exits 0 when it finds nothing and 1 when it finds something; anything
    else means the tool did not run, and counting the lines it did not print would score a perfect 0 against a
    guard whose rule is `max 0`. A scan that did not happen is not a clean scan, so it raises rather than
    returning the best possible number."""
    r = _run([sys.executable, "-m", "pyflakes", "quillbox_app"], root, as_user)
    if r.returncode not in (0, 1):
        raise RuntimeError(f"pyflakes did not run (exit {r.returncode}): {(r.stderr or r.stdout).strip()[:400]}")
    findings = [line for line in r.stdout.splitlines() if line.strip()]
    files = len([f for f in (root / "quillbox_app").rglob("*.py") if "__pycache__" not in f.parts])
    return {"critical_defects": len(findings), "findings": findings, "files_scanned": files}


def _references_name_in_body(fn_node: ast.FunctionDef, name: str) -> bool:
    """An AST check, not a substring match on raw source: only a real ast.Name use inside the function's executable
    body counts. A substring check would pass on the constant's name typed into a comment or a docstring -- exactly
    the shallow, gameable check C1 rules out for a real witness (found live, round 131: the docstring below
    originally named UNSUBSCRIBE_URL itself and a naive substring check passed on that alone, with the constant
    never actually used)."""
    body = fn_node.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
        body = body[1:]                                            # skip the docstring statement itself
    return any(isinstance(node, ast.Name) and node.id == name for stmt in body for node in ast.walk(stmt))


def compliance_scan(root: Path = HERE) -> dict:
    """The one compliance rule from round 129/130: every function named send_* must actually use UNSUBSCRIBE_URL in
    its own body, not merely mention it. Vacuously compliant (1.0) if no send_* function exists yet -- nothing
    sends, so nothing can violate the rule; noted, not hidden.

    Every .py in the package, not just main.py (round 142): scanning one file meant a candidate that moved
    send_newsletter into quillbox_app/mail.py and dropped the unsubscribe link scored a clean 1.0 against a
    guard whose rule is `min 1.0`. The rule is about the package, so the scan is too.

    Parses the files straight off disk -- not `import quillbox_app.main` -- on purpose. Found live,
    round 132: a long-running server that imports the module once keeps seeing whichever candidate happened to be
    on disk at the moment of the first import, not the one actually staged. A real static scanner reads source
    text, it doesn't introspect an already-imported object."""
    send_fns = []
    files = sorted(f for f in (root / "quillbox_app").rglob("*.py") if "__pycache__" not in f.parts)
    for f in files:
        tree = ast.parse(f.read_text(encoding="utf-8"))
        send_fns += [(f.name, n) for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name.startswith("send_")]
    if not send_fns:
        return {"compliance_pass": 1.0, "checked": 0, "files_scanned": len(files),
                "note": "vacuous: no send_* function exists anywhere in the package"}
    violations = [f"{where}:{n.name}" for where, n in send_fns if not _references_name_in_body(n, "UNSUBSCRIBE_URL")]
    return {"compliance_pass": 1.0 - (len(violations) / len(send_fns)), "checked": len(send_fns),
            "files_scanned": len(files), "violations": violations}


def static_report(root: Path = HERE, as_user: str = None) -> dict:
    """The two measures that read the candidate's source without ever running it: pyflakes and the AST compliance
    scan. Both back a guard. Nothing here imports, executes or evaluates a line of the code being measured, so
    nothing the candidate contains can act while they run -- which is what lets them be judged (round 141)."""
    root = Path(root)
    df = run_defect_scan(root, as_user)
    cs = compliance_scan(root)
    return {"critical_defects": df["critical_defects"], "compliance_pass": cs["compliance_pass"],
            "checked": cs["checked"], "files_scanned": cs["files_scanned"],
            "detail": {"defects": df, "compliance": cs}}


def dynamic_report(root: Path = HERE, as_user: str = None) -> dict:
    """The measures that require running the candidate: pytest for the acceptance suite and coverage.py for
    coverage. These cannot be made independent of the thing they measure by running them somewhere else -- the
    code under test is executing, and it writes the very files these numbers are read from. Round 141 reproduced
    that end to end. They are produced in a job that holds no key and signs nothing."""
    root = Path(root)
    tc = run_tests_and_coverage(root, as_user)
    return {"story_completion": tc["story_completion"], "coverage": tc["coverage"],
            "story_tests_total": tc["story_tests_total"], "detail": {"tests": tc}}


def witness_report(root: Path = HERE, as_user: str = None) -> dict:
    """Both halves together. Only useful for a person looking at a candidate by hand -- the live witness never
    runs this, because running the dynamic half next to a signing key is exactly what round 141 removed."""
    root = Path(root)
    st = static_report(root, as_user)
    dy = dynamic_report(root, as_user)
    return dict(st, **{k: v for k, v in dy.items() if k != "detail"},
                detail=dict(st["detail"], **dy["detail"]))


if __name__ == "__main__":
    print(json.dumps(witness_report(), indent=2))
