# Quillbox

A solo-creator newsletter tool, built through OWL rather than beside it: the requirement Quill Builder works to
is read from the guards and measures of an OWL system, never from a project board, and nothing is kept on the
builder's own say-so. OWL calls this system F (`instances/owl-build.md` in the book): it judges a build the
instant it finishes — compliance, defects, coverage, stories — long before any real subscriber exists.

## Two identities, and only one of them can produce a number

| | runs as | holds | can |
|---|---|---|---|
| **the adapter** (`service.py`, Cloud Run service) | `qb-app@`, no project roles | the adapter secret | apply, verify and revert a candidate; prove an inbound call came from OWL |
| **the witness** (`witness_job.py`, Cloud Run job) | `qb-witness@`, secret accessor on `QB_WITNESS_KEYS` only | five Ed25519 private keys, mounted as a root-only file | measure one candidate's source and deliver five signed readings to OWL |
| **Quill Agent** (`agent.py`, operator's machine) | a person | system F's owner and runtime keys | apply a candidate, ask for a measurement, read the readings back from OWL, promote |

The adapter holds no credential that can write a reading. The witness never asks the adapter anything: it stages
one candidate's source out of its own image and measures that. Quill Agent chooses *which* candidate is measured
— that is the owner's business — and can neither see nor route a reading; it reads them back from OWL and refuses
to decide on one that did not arrive signed by a provider declared independent.

Before round 140 all of this ran in one process: the service that swapped the code also measured it and delivered
the numbers, holding the connector secrets — and the owner key — in its own environment. OWL could not have
caught that, because it only detects tenant delivery when a measure's witness kind is `own_store`. The fix had to
be structural.

One command is the standing proof:

```bash
./infra/deploy.sh check
```

It prints the adapter's service account and every environment variable it holds. If a connector secret, a driver
key or an owner key ever reappears there, the independence claim is no longer true.

## What this does not close

* **Which candidate is measured comes from whoever runs the job**, not from the code. A reader can check it —
  `about.code` is a digest of the exact source measured, inside the signed body, recomputable with
  `qb_digest.tree_digest` over `candidates/<version>/quillbox_app` — but nothing refuses a run pointed elsewhere.
* **The acceptance suite is a file in this repository.** Deleting a failing story raises `story_completion`
  without building anything. `story_tests_total` is delivered alongside it, by the same witness, shown and never
  judged, and Quill Agent refuses a candidate whose suite shrank.
* **`/status`'s `live_digest` is a drift tripwire, not evidence.** It catches a redeploy serving the wrong
  candidate (which really happened, round 136). It catches nothing deliberate: the party computing it is the
  party being graded.

## Running

```bash
.venv/Scripts/python.exe witness.py                     # the real tools against the working tree
C:/acresgo/owl/.venv/Scripts/python.exe -m pytest platform_tests -q    # the plumbing, against a real local OWL
.venv/Scripts/python.exe run_checkin.py 1               # one real check-in against the live system
.venv/Scripts/python.exe run_checkin.py promote v2 v1   # apply, measure, compare, promote or revert
```

`tests/` is the product's own acceptance suite and is what the witness measures. `platform_tests/` tests this
plumbing and is deliberately excluded from that measurement, so work here cannot move a number about the product.
