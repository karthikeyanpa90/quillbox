# -*- coding: utf-8 -*-
"""The Quillbox witness, as its own provider (round 140, P46), split in two by what it is allowed to touch
(round 141, P49).

Round 140 moved the witness out of the Quillbox service into a job of its own, with its own identity and its own
Ed25519 keys, measuring source staged out of its own image. An adversarial review of that, run immediately after
it shipped, broke it twice, and both breaks were reproduced rather than argued:

  * `python -m pyflakes` puts the working directory first on sys.path, and the working directory was the staged
    candidate: a directory named `pyflakes/` dropped there shadows the real tool and the defect scan returns
    clean. More generally, the candidate's own code runs inside the witness's pytest process, and it could
    rewrite the report files and the source that the later tools read, so every number the witness signed was
    within reach of the code it was grading -- while the digests, taken before the tools ran, still matched git.
  * the signing keys were mounted as a file with mode 0444, world-readable, in the same container. The candidate's
    code, running as `nobody` under pytest, could simply read all five private keys. Probed on the live job:
    `MODE=0o100444 ... NOBODY_CAN_READ=True`. Dropping to an unprivileged user is hardening, not a boundary.

No arrangement fixes the second one while the same container both runs the candidate and holds a key: any process
in a Cloud Run container can ask the metadata server for the service account's token and fetch the secret itself.
The boundary has to be the job.

  QB_MODE=static   (job-quillbox-witness, holds the keys, service account qb-witness@)
      pyflakes and the AST compliance scan. Neither imports, executes or evaluates a line of the candidate, so
      nothing in the candidate can act while they run. Signs and delivers critical_defects and compliance_pass --
      system F's two guards. Re-digests the staged tree afterwards and refuses to deliver if a byte moved.

  QB_MODE=dynamic  (job-quillbox-measure, holds nothing, service account qb-measure@ with no roles at all)
      pytest and coverage. These require the candidate to run, so their numbers are within the candidate's reach
      by construction. This job mounts no secret, its service account can read none, and it delivers nothing: it
      prints what it found and exits. Making those two measures judgeable needs a measurement taken from outside
      the running code -- black-box, against a deployed instance -- which is P49, not a flag.

Run:  QB_MODE=static QB_VERSION=v1 QB_INDEX=22 python witness_job.py
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
from witness import dynamic_report, static_report

ROOT = Path(__file__).parent
CANDIDATES = ROOT / "candidates"
STATIC = ("compliance_pass", "critical_defects")          # guards; measured without running the candidate
DYNAMIC = ("coverage", "story_completion", "story_tests_total")


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
    happened in `about.tools_user`, so a reading made without it is visible as such on the record. It is a
    hardening measure and nothing more: round 141 established that an unprivileged process in this container can
    still read anything world-readable in it, which is why the static and dynamic halves are different jobs."""
    if os.name != "posix" or os.geteuid() != 0:
        return ""
    name = os.environ.get("QB_SANDBOX_USER", "nobody")
    try:
        import pwd
        pwd.getpwnam(name)
    except (ImportError, KeyError):
        return ""
    return name


def measure(version: str, mode: str) -> tuple:
    work = Path(tempfile.mkdtemp(prefix="qb-witness-"))
    try:
        digests = stage(version, work)
        user = sandbox_user()
        if user:
            for p in [work] + list(work.rglob("*")):
                os.chmod(p, 0o777 if p.is_dir() else 0o666)        # the sandboxed user writes the tools' reports here
        report = (static_report if mode == "static" else dynamic_report)(root=work, as_user=user or None)
        after = {"code": tree_digest(work / "quillbox_app"), "suite": tree_digest(work / "tests")}
        if mode == "static" and after != digests:
            # Nothing in the static half executes the candidate, so nothing should have been able to move a byte.
            # If one moved anyway, the digest in the signed body would no longer describe what was measured.
            raise SystemExit(f"the staged tree changed while the static tools ran: {digests} -> {after}; refusing to deliver")
        return report, dict(digests, tools_user=user or "same-user", mode=mode)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def keys_from(path: str, measures) -> dict:
    """{measure: private key}. A file, not an environment variable -- but note that in this container the file is
    world-readable, which is exactly why no candidate code ever runs in the job that reads it."""
    keys = json.loads(Path(path).read_text(encoding="utf-8"))
    missing = [m for m in measures if m not in keys]
    if missing:
        raise SystemExit(f"the key file has no key for: {', '.join(missing)}")
    return keys


def main() -> int:
    mode = os.environ.get("QB_MODE", "static")
    if mode not in ("static", "dynamic"):
        raise SystemExit("QB_MODE must be 'static' or 'dynamic'")
    version = os.environ["QB_VERSION"]
    index = int(os.environ["QB_INDEX"])

    report, provenance = measure(version, mode)
    about = dict(provenance, build_version=version, index=index,
                 witness="job-quillbox-witness" if mode == "static" else "job-quillbox-measure",
                 image=os.environ.get("QB_IMAGE", "unknown"))

    if mode == "dynamic":
        # Holds no key, signs nothing, delivers nothing. These numbers come from a process running the candidate's
        # own code; printing them is all this job is entitled to do with them.
        print(json.dumps({"mode": mode, "version": version, "index": index, "about": about, "report": report,
                          "delivered": [], "note": "measured by running the candidate; not evidence, not delivered"},
                         indent=2))
        return 0

    sid = os.environ["QB_SID"]
    owl = httpx.Client(base_url=os.environ["QB_OWL_BASE_URL"], timeout=60.0)
    keys = keys_from(os.environ.get("QB_WITNESS_KEY_FILE", "/secrets/witness-keys.json"), STATIC)
    failed = []
    for m in STATIC:
        body = {"week": index, "age": 0, "rows": [{"unit": "quillbox", "value": report[m]}], "about": about}
        r = deliver(owl, sid, m, body, keys[m])
        if r.status_code != 200:
            failed.append(f"{m}: {r.status_code} {r.text[:200]}")
    # Printed for a person reading the execution log. Not evidence: what OWL holds is what was signed and
    # accepted, and Quill Agent reads the numbers back from OWL rather than from this output.
    print(json.dumps({"mode": mode, "version": version, "index": index, "about": about, "report": report,
                      "delivered": [m for m in STATIC if not any(f.startswith(m + ":") for f in failed)],
                      "failed": failed}, indent=2))
    if failed:
        print("DELIVERY FAILED -- nothing here counts as a reading", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
