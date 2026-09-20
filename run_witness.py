# -*- coding: utf-8 -*-
"""The production witness_runner: start one execution of the witness job and wait for it.

This is the whole of Quill Agent's influence over a measurement -- it says which candidate and which index, and
then waits. It holds no signing key, sees no number, and touches nothing the job reports: the readings go from
the job to OWL over the job's own signature, and Quill Agent reads them back out of OWL afterwards.

A failed execution raises. That is deliberate: a measurement that did not happen must not be mistaken for one
that happened and said nothing, and Quill Agent's read-back would then find no reading and refuse anyway.
"""
import shutil
import subprocess

PROJECT = "acresgo-prod"
REGION = "asia-south1"
JOB = "job-quillbox-witness"
GCLOUD = shutil.which("gcloud") or "gcloud"       # on Windows the real entry point is gcloud.cmd


def cloud_run_witness(version: str, index: int, project: str = PROJECT, region: str = REGION, job: str = JOB):
    """`gcloud run jobs execute --wait` with the two per-run values as environment overrides. Everything else --
    the system id, OWL's address, the mounted key file -- is fixed on the job itself, not passed in here."""
    cmd = [GCLOUD, "run", "jobs", "execute", job, "--project", project, "--region", region, "--wait",
           "--update-env-vars", f"QB_VERSION={version},QB_INDEX={index}"]
    r = subprocess.run(cmd, capture_output=True, text=True, shell=False)
    if r.returncode != 0:
        raise RuntimeError(f"the witness job failed ({r.returncode}); nothing was measured.\n{r.stderr.strip()[-2000:]}")
    return {"version": version, "index": index, "stdout": r.stdout.strip()[-2000:]}


def local_witness(version: str, index: int, env: dict = None):
    """The same job, run here rather than on Cloud Run -- for a rehearsal against a throwaway OWL system, with a
    key file on disk. Not how production measures anything: the tools then run as whoever runs this."""
    import os
    import sys
    e = dict(os.environ, QB_VERSION=version, QB_INDEX=str(index), **(env or {}))
    r = subprocess.run([sys.executable, "witness_job.py"], cwd=os.path.dirname(os.path.abspath(__file__)),
                       env=e, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"the witness run failed ({r.returncode}).\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")
    return {"version": version, "index": index, "stdout": r.stdout}
