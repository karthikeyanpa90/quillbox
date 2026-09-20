# Quillbox

A solo-creator newsletter tool, built through OWL rather than beside it: the requirement Quill Builder works to
is read from the guards and measures of an OWL system, never from a project board, and nothing is kept on the
builder's own say-so. OWL calls this system F (`instances/owl-build.md` in the book): it judges a build the
instant it finishes — compliance, defects, coverage, stories — long before any real subscriber exists.

## Three identities, split by what each is allowed to touch

| | runs as | holds | can |
|---|---|---|---|
| **the adapter** (`service.py`, Cloud Run service) | `qb-app@`, no project roles | the adapter secret | apply, verify and revert a candidate; prove an inbound call came from OWL |
| **the witness** (`witness_job.py` with `QB_MODE=static`, Cloud Run job) | `qb-witness@`, secret accessor on `QB_WITNESS_KEYS` only | two Ed25519 private keys | read the candidate's source with pyflakes and an AST scan — **never run it** — and deliver two signed readings |
| **the measure job** (`witness_job.py` with `QB_MODE=dynamic`, Cloud Run job) | `qb-measure@`, no roles anywhere | nothing | run the candidate under pytest and coverage, print what it found, deliver nothing |
| **Quill Agent** (`agent.py`, operator's machine) | a person | system F's owner and runtime keys | apply a candidate, ask for a measurement, read readings back from OWL, promote |

The split between the last two is the whole of round 141. A number you get by *reading* source cannot be shaped
by what that source would have done, because nothing of it ever runs. A number you get by *running* it is
produced inside a process the measured code is executing in, and that code can rewrite the files the number is
read from — reproduced, not argued: a candidate with an `atexit` handler forged every reading while the signed
digests still matched git. And a container's credentials are reachable by anything running in it, so the job
that runs the candidate holds no key and its service account opens nothing.

One command is the standing proof:

```bash
./infra/deploy.sh check
```

It prints each identity, the image the witness is pinned to, and whether the measure job holds a secret volume.
If a key, a connector secret or an owner key ever appears where it should not, the claim is no longer true.

## What this does not close

* **System F's goal cannot currently be judged.** `story_completion` and `coverage` are both obtained by running
  the candidate, so no provider of them is independent of what they measure. Nothing delivers them; the keys
  their connectors name were generated and discarded unused. Quill Agent checks the guards, finds them holding,
  and **still does not promote** — a system with no trustworthy reading of what it is climbing towards does not
  climb. Putting it back needs a measurement taken from outside the running code (black-box acceptance against
  the deployed instance), which is P49 in the book, not a flag here.
* **Which candidate is measured comes from whoever runs the job**, not from the code. A reader can check it —
  `about.code` is a digest of the exact source measured, inside the signed body, recomputable with
  `qb_digest.tree_digest` over `candidates/<version>/quillbox_app` — but nothing refuses a run pointed elsewhere.
* **The project is the real boundary.** In `acresgo-prod` the default compute account holds editor and can
  execute the witness job with overridden arguments, and OWL's own runtime account can read secrets
  project-wide. P50.
* **`/status`'s `live_digest` is a drift tripwire, not evidence.** It catches a redeploy serving the wrong
  candidate (which really happened, round 136). It catches nothing deliberate: the party computing it is the
  party being graded.

## Running

```bash
.venv/Scripts/python.exe witness.py                     # both halves, against the working tree, by hand
C:/acresgo/owl/.venv/Scripts/python.exe -m pytest platform_tests -q    # the plumbing, against a real local OWL
.venv/Scripts/python.exe run_checkin.py 1               # one real check-in against the live system
.venv/Scripts/python.exe run_checkin.py promote v2 v1   # apply, measure, and — today — decline to promote
```

`tests/` is the product's own acceptance suite and is what the measure job runs. `platform_tests/` tests this
plumbing and is deliberately excluded from that measurement, so work here cannot move a number about the product.
