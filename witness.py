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
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).parent


def _run(args, root: Path, as_user: str = None):
    """Every tool runs as a subprocess against `root`. `as_user` drops to an unprivileged account first, where the
    platform allows it: pytest executes the candidate's own code, and that code must not run as the identity that
    can read the provider's signing key."""
    kwargs = {}
    if as_user:
        kwargs["user"] = as_user                                   # POSIX only; witness_job.py decides whether to pass one
    return subprocess.run(args, cwd=root, capture_output=True, text=True, **kwargs)


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
    """pyflakes: real static analysis, not a mock -- unused imports, undefined names, the usual."""
    r = _run([sys.executable, "-m", "pyflakes", "quillbox_app"], root, as_user)
    findings = [line for line in r.stdout.splitlines() if line.strip()]
    return {"critical_defects": len(findings), "findings": findings}


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

    Parses quillbox_app/main.py straight off disk -- not `import quillbox_app.main` -- on purpose. Found live,
    round 132: a long-running server that imports the module once keeps seeing whichever candidate happened to be
    on disk at the moment of the first import, not the one actually staged. A real static scanner reads source
    text, it doesn't introspect an already-imported object."""
    tree = ast.parse((root / "quillbox_app" / "main.py").read_text(encoding="utf-8"))
    send_fns = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name.startswith("send_")]
    if not send_fns:
        return {"compliance_pass": 1.0, "checked": 0, "note": "vacuous: no send_* function exists yet"}
    violations = [n.name for n in send_fns if not _references_name_in_body(n, "UNSUBSCRIBE_URL")]
    return {"compliance_pass": 1.0 - (len(violations) / len(send_fns)), "checked": len(send_fns), "violations": violations}


def witness_report(root: Path = HERE, as_user: str = None) -> dict:
    root = Path(root)
    tc = run_tests_and_coverage(root, as_user)
    df = run_defect_scan(root, as_user)
    cs = compliance_scan(root)
    return {
        "story_completion": tc["story_completion"], "coverage": tc["coverage"],
        "critical_defects": df["critical_defects"], "compliance_pass": cs["compliance_pass"],
        "story_tests_total": tc["story_tests_total"],
        "detail": {"tests": tc, "defects": df, "compliance": cs},
    }


if __name__ == "__main__":
    print(json.dumps(witness_report(), indent=2))
