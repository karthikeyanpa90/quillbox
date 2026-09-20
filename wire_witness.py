# -*- coding: utf-8 -*-
"""Cut system F over to an independent, signed witness (round 140, P46). Run once, by the operator.

Order matters, and the order is not reversible:

  1. `keys`     -- generate one Ed25519 key pair per measure and push the private halves into Secret Manager as a
                   single JSON secret. The private halves never touch this machine's disk: they are piped to
                   gcloud on stdin, and this script keeps only the public halves. One key per measure buys
                   revocation granularity, not isolation -- one job holds all five either way, and this file says
                   so rather than implying more.
  2. `define`   -- PUT the Definition that adds story_tests_total (shown, never judged). Adding a measure changes
                   no lever, so OWL does not reset the loop's state.
  3. `register` -- re-register all five connectors with their public keys, delivered_by="independent". This is
                   the irreversible step: register_connector overwrites the whole entry, so the old shared secret
                   stops working the instant it runs, and the old /check-in path dies with it. Deploy the
                   stripped service first.

Usage:  .venv/Scripts/python.exe wire_witness.py keys|define|register|show
"""
import json
import shutil
import subprocess
import sys

sys.path.insert(0, r"C:\acresgo\quillbox")

import truststore  # noqa: E402
truststore.inject_into_ssl()
import httpx  # noqa: E402

from agent import DEF, STATIC, AWAITING_PROVIDER  # noqa: E402
from qb_env import read_env  # noqa: E402
from qb_signing import new_keypair  # noqa: E402

PROJECT = "acresgo-prod"
SECRET = "QB_WITNESS_KEYS"
MEASURES = STATIC + AWAITING_PROVIDER
KINDS = {"compliance_pass": "compliance_scanner", "critical_defects": "sast_scanner", "coverage": "ci_pipeline",
         "story_completion": "acceptance_test_runner", "story_tests_total": "acceptance_test_runner"}
PUBLIC_FILE = r"C:\acresgo\quillbox\witness-public-keys.json"     # committed: public halves only, so anyone can check


GCLOUD = shutil.which("gcloud") or "gcloud"       # on Windows the real entry point is gcloud.cmd, not gcloud


def gcloud(args, stdin: str = None):
    r = subprocess.run([GCLOUD] + args, capture_output=True, text=True, input=stdin)
    if r.returncode != 0:
        raise SystemExit(f"gcloud {' '.join(args[:3])} failed:\n{r.stderr.strip()}")
    return r.stdout.strip()


def make_keys():
    """Round 141: only the two static measures get a private key that is kept. The three that need the candidate
    to run have no provider that is independent of them (P49), so their key pairs are generated, their public
    halves registered, and their private halves discarded here and now -- nothing can deliver those measures
    until there is a way to measure them from outside the running code. That is a deliberate freeze, not an
    oversight, and it is the reason the measures still appear in the Definition with no readings arriving."""
    pairs = {m: new_keypair() for m in MEASURES}
    private = {m: priv for m, (priv, _) in pairs.items() if m in STATIC}
    public = {m: pub for m, (_, pub) in pairs.items()}
    del pairs
    exists = subprocess.run([GCLOUD, "secrets", "describe", SECRET, "--project", PROJECT],
                            capture_output=True, text=True).returncode == 0
    args = ["secrets", "versions", "add", SECRET] if exists else ["secrets", "create", SECRET]
    gcloud(args + ["--project", PROJECT, "--data-file=-"], stdin=json.dumps(private))
    with open(PUBLIC_FILE, "w", encoding="utf-8") as f:
        json.dump(public, f, indent=2, sort_keys=True)
    print(f"{'new version of' if exists else 'created'} secret {SECRET} in {PROJECT} ({len(private)} keys kept: "
          f"{', '.join(sorted(private))}; discarded unused: {', '.join(sorted(AWAITING_PROVIDER))})")
    print(f"wrote {PUBLIC_FILE} -- public halves only; the private halves are in Secret Manager and nowhere else")


def owl_client(env):
    return httpx.Client(base_url=env["QB_OWL_BASE_URL"], timeout=40.0), {"Authorization": "Bearer " + env["QB_OWNER_KEY"]}


def define():
    """Add story_tests_total to the live Definition, keeping the live lever exactly as it is.

    DEF in agent.py is the *original* Definition, and its build_version lever still says v0 -- every promotion
    since has moved it by replacing that lever's options, which is the whole promotion mechanism here (round
    132). PUTting DEF verbatim therefore silently demotes the system to v0 and, because the levers then differ
    from the stored ones, resets OWL's loop state. Done live, round 140, on the real system: the Definition went
    back to v0 while the adapter was serving v1, and week 21 with counts {keep 0, revert 3} was wiped. The ledger
    was untouched -- it is append-only, and both the promotion and the accident are on it -- but the loop's own
    state does not come back. So the live lever wins, and only the measures change."""
    env = read_env(); owl, owner = owl_client(env)
    live = owl.get(f"/v1/systems/{env['QB_SID']}/definition", headers=owner).json()
    new = dict(DEF, levers=live["levers"]) if live.get("levers") else dict(DEF)
    same = live.get("levers") == new["levers"]
    print(f"keeping the live lever: {json.dumps(new['levers'][0].get('options'))} "
          f"start={new['levers'][0].get('start')!r} -- {'no state reset' if same else 'THIS WILL RESET THE LOOP STATE'}")
    r = owl.put(f"/v1/systems/{env['QB_SID']}/definition", json=new, headers=owner)
    r.raise_for_status()
    print(f"definition accepted: {r.json()}")


def register():
    env = read_env(); owl, owner = owl_client(env)
    public = json.load(open(PUBLIC_FILE, encoding="utf-8"))
    for m in MEASURES:
        r = owl.post(f"/v1/systems/{env['QB_SID']}/connectors",
                     json={"measure": m, "kind": KINDS[m], "public_key": public[m], "delivered_by": "independent"},
                     headers=owner)
        if r.status_code != 200:
            raise SystemExit(f"{m}: {r.status_code} {r.text}")
        print(f"{m}: {r.json()}")
    print("\nthe old shared secrets are dead as of now; only the witness job can deliver a reading")


def show():
    env = read_env(); owl, owner = owl_client(env)
    print(json.dumps(owl.get(f"/v1/systems/{env['QB_SID']}/connectors", headers=owner).json(), indent=2))


if __name__ == "__main__":
    {"keys": make_keys, "define": define, "register": register, "show": show}[
        sys.argv[1] if len(sys.argv) > 1 else "show"]()
