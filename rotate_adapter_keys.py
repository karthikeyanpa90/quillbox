# -*- coding: utf-8 -*-
"""Round 142: rotate what the adapter holds, and give it less (P50).

The review of round 141 found that the adapter's OWL credentials were plain `--set-env-vars` values, so
`gcloud run services describe quillbox` returns them in full to anything holding `run.services.get` -- which in
this project includes the default compute account, and therefore three other graded tenants. They were also the
wrong credentials: the runtime key is admitted on `POST /cycle/{week}` and `POST /suggestions`, so the graded
application could advance the judge's clock and choose which weeks entered its windows. It cannot produce or
sign a number, but "cannot reach" was too strong.

So: rotate the runtime key (the operator keeps it, for Quill Agent), rotate the proposer token and give the
adapter that instead -- it can read status and nothing else that matters, and `submit_proposal` refuses a
version that changes nothing, which is every version of a one-option lever -- and re-register the adapter for a
fresh secret. All three go into Secret Manager, and the service references them rather than carrying them.

Usage:  .venv/Scripts/python.exe rotate_adapter_keys.py
"""
import json
import shutil
import subprocess
import sys

sys.path.insert(0, r"C:\acresgo\quillbox")

import truststore  # noqa: E402
truststore.inject_into_ssl()
import httpx  # noqa: E402

from qb_env import read_env, write_env  # noqa: E402

PROJECT = "acresgo-prod"
QB_BASE = "https://quillbox-120680828302.asia-south1.run.app"
GCLOUD = shutil.which("gcloud") or "gcloud"


def put_secret(name: str, value: str):
    exists = subprocess.run([GCLOUD, "secrets", "describe", name, "--project", PROJECT],
                            capture_output=True, text=True).returncode == 0
    args = ["secrets", "versions", "add", name] if exists else ["secrets", "create", name]
    r = subprocess.run([GCLOUD] + args + ["--project", PROJECT, "--data-file=-"],
                       input=value, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"{name}: {r.stderr.strip()}")
    print(f"  {name}: {'new version' if exists else 'created'}")


if __name__ == "__main__":
    env = read_env(); sid = env["QB_SID"]
    owl = httpx.Client(base_url=env["QB_OWL_BASE_URL"], timeout=40.0)
    owner = {"Authorization": "Bearer " + env["QB_OWNER_KEY"]}

    runtime = owl.post(f"/v1/systems/{sid}/keys/rotate", json={"role": "runtime"}, headers=owner)
    runtime.raise_for_status(); runtime_key = runtime.json()["key"]
    print(f"runtime key rotated: {runtime.json()['id']} (revoked {runtime.json()['revoked']})")

    proposer = owl.post(f"/v1/systems/{sid}/keys/rotate", json={"role": "proposer"}, headers=owner)
    proposer.raise_for_status(); proposer_token = proposer.json()["key"]
    print(f"proposer token rotated: {proposer.json()['id']} (revoked {proposer.json()['revoked']})")

    adapter = owl.post(f"/v1/systems/{sid}/adapter", json={"base_url": QB_BASE}, headers=owner)
    adapter.raise_for_status(); adapter_secret = adapter.json()["secret"]
    print("adapter re-registered; its secret is new")

    print("into Secret Manager:")
    put_secret("QB_ADAPTER_SECRET", adapter_secret)
    put_secret("QB_PROPOSER_TOKEN", proposer_token)

    write_env({"QB_SID": sid, "QB_OWNER_KEY": env["QB_OWNER_KEY"], "QB_RUNTIME_KEY": runtime_key,
               "QB_ADAPTER_SECRET": adapter_secret, "QB_OWL_BASE_URL": env["QB_OWL_BASE_URL"]})
    print("\n.deploy-env.yaml rewritten. The runtime key stays with the operator; the adapter never sees it again.")
    print("Next:  ./infra/deploy.sh service   (references the secrets; carries no credential of its own)")
    print("       ./infra/deploy.sh keys-backup")
