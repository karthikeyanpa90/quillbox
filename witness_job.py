# -*- coding: utf-8 -*-
"""The Quillbox witness, as its own provider (round 140, P46).

Until now the four numbers OWL judged system F on were produced inside the Quillbox service, by the same process
whose /apply swapped the code being measured, and delivered with shared secrets held in that service's own
environment. Under OWL's strict rule (round 137) those readings are tenant-delivered: showable, never judgeable.
OWL could not catch the lie -- it only auto-detects tenant delivery when a measure's witness kind is `own_store`,
and these are ci_pipeline, sast_scanner, compliance_scanner, acceptance_test_runner -- so declaring them
"independent" without changing anything would have been a false declaration OWL happened not to refuse.

What makes this one independent, concretely, is that it is a different program run by a different identity:

  * a Cloud Run Job, not the service. It has no HTTP surface, so the service cannot call it, and the service's
    own service account holds no Cloud Run or Secret Manager permission with which to run, redeploy or rewrite it.
  * it never reads the live quillbox_app/ directory the service rewrites. It stages one candidate's source out of
    its own immutable image into a throwaway directory of its own and measures that.
  * it holds the five Ed25519 private keys -- one per measure -- mounted as a root-only file, and OWL holds only
    the public halves. The Quillbox service holds no key that can write a reading; it cannot produce a number,
    sign one, or reach the identity that can.
  * it reads the keys only after every tool has finished, and runs the tools as an unprivileged user, because
    pytest executes the candidate's own code and that code must not run as the identity holding the key.

What it does not close, said plainly: which candidate is measured comes from whoever runs the job (the operator's
Quill Agent), not from the code. A reader can check that independently -- `about.code` is a digest of the exact
source measured, inside the signed body, recomputable from git -- but nothing here refuses a run pointed at the
wrong tree. And the acceptance suite is itself a file in the repository, so a shrinking rubric would raise
story_completion; that is why story_tests_total is delivered too, shown and never judged.

Run:  QB_VERSION=v1 QB_INDEX=22 python witness_job.py
"""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import httpx

from qb_digest import tree_digest
from qb_signing import deliver
from witness import witness_report

ROOT = Path(__file__).parent
CANDIDATES = ROOT / "candidates"
JUDGED = ("compliance_pass", "critical_defects", "coverage", "story_completion")
SHOWN_ONLY = ("story_tests_total",)
MEASURES = JUDGED + SHOWN_ONLY


def stage(version: str, work: Path) -> dict:
    """Copy the candidate's source and the acceptance suite out of this job's own image into `work`. Nothing is
    read from the running Quillbox service and nothing is written back into the image."""
    src = CANDIDATES / version / "quillbox_app"
    if not src.is_dir():
        raise SystemExit(f"no such candidate in this image: {version} (have: {sorted(p.name for p in CANDIDATES.iterdir())})")
    shutil.copytree(src, work / "quillbox_app")
    shutil.copytree(ROOT / "tests", work / "tests", ignore=shutil.ignore_patterns("__pycache__"))
    return {"code": tree_digest(work / "quillbox_app"), "suite": tree_digest(work / "tests")}


def sandbox_user() -> str:
    """Drop the tools to `nobody` where the platform allows it -- POSIX, running as root, and the account exists.
    On the operator's Windows machine none of that holds and the tools run as the caller; the job says which
    happened in `about.tools_user`, so a reading made without the sandbox is visible as such on the record rather
    than quietly indistinguishable from one made with it."""
    if os.name != "posix" or os.geteuid() != 0:
        return ""
    name = os.environ.get("QB_SANDBOX_USER", "nobody")
    try:
        import pwd
        pwd.getpwnam(name)
    except (ImportError, KeyError):
        return ""
    return name


def measure(version: str) -> tuple:
    work = Path(tempfile.mkdtemp(prefix="qb-witness-"))
    try:
        digests = stage(version, work)
        user = sandbox_user()
        if user:
            for p in [work] + list(work.rglob("*")):
                os.chmod(p, 0o777 if p.is_dir() else 0o666)        # the sandboxed user writes pytest's and coverage's reports here
        report = witness_report(root=work, as_user=user or None)
        return report, dict(digests, tools_user=user or "same-user")
    finally:
        shutil.rmtree(work, ignore_errors=True)


def keys_from(path: str) -> dict:
    """{measure: private key}. A file, not an environment variable: the environment is inherited by every
    subprocess, and one of those subprocesses runs the code under measurement."""
    keys = json.loads(Path(path).read_text(encoding="utf-8"))
    missing = [m for m in MEASURES if m not in keys]
    if missing:
        raise SystemExit(f"the key file has no key for: {', '.join(missing)}")
    return keys


def main() -> int:
    sid = os.environ["QB_SID"]
    owl_base = os.environ["QB_OWL_BASE_URL"]
    version = os.environ["QB_VERSION"]
    index = int(os.environ["QB_INDEX"])
    key_file = os.environ.get("QB_WITNESS_KEY_FILE", "/secrets/witness-keys.json")

    report, provenance = measure(version)                          # every tool has finished before the keys are opened
    keys = keys_from(key_file)
    about = dict(provenance, build_version=version, witness="job-quillbox-witness",
                 image=os.environ.get("QB_IMAGE", "unknown"))

    owl = httpx.Client(base_url=owl_base, timeout=60.0)
    failed = []
    for m in MEASURES:
        body = {"week": index, "age": 0, "rows": [{"unit": "quillbox", "value": report[m]}], "about": about}
        r = deliver(owl, sid, m, body, keys[m])
        if r.status_code != 200:
            failed.append(f"{m}: {r.status_code} {r.text[:200]}")
    # Printed for a person reading the execution log. Not evidence: what OWL holds is what was signed and
    # accepted, and Quill Agent reads the numbers back from OWL rather than from this output.
    print(json.dumps({"version": version, "index": index, "about": about, "report": report,
                      "delivered": [m for m in MEASURES if not any(f.startswith(m + ":") for f in failed)],
                      "failed": failed}, indent=2))
    if failed:
        print("DELIVERY FAILED -- nothing here counts as a reading", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
