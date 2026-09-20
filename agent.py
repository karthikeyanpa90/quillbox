# -*- coding: utf-8 -*-
"""Quill Agent (instances/owl-build.md, round 130): the one thing on Quillbox's side that ever calls the OWL API.
It runs on the operator's side, not inside the product, and holds system F's owner and runtime keys.

Its job, each time a candidate is ready:

  1. apply the candidate as the build_version under evaluation on the real deployed adapter (slice is always
     {"everyone": True} -- system F has no live population to slice; round 129's pushback #4 and P31)
  2. ask the witness -- a separate job whose numbers it cannot influence -- to measure exactly that candidate
  3. cycle OWL, then read the readings back out of OWL and check they arrived signed and independent
  4. decide what to hand Quill Builder next, from what is currently unmet or unclimbed -- OWL returns a verdict on
     what already happened, never an instruction for what to build next (round 130's pushback #2)

Round 140 (P46) removed this agent from the number's path. It used to call the Quillbox service's /check-in,
which ran the witness in-process and delivered the readings, and then decided on the JSON that call returned.
Now it triggers a job, and reads what OWL actually holds. It can still choose *which* candidate is measured --
that is the owner's business -- but it can no longer see, touch or route a reading, and it refuses to decide on
one that did not arrive signed by an independent provider.
"""
import hashlib
import hmac
import json

DEF = dict(
    name="quillbox-fast",
    note="system F: judges a Quillbox build_version candidate the instant it finishes -- code "
         "quality, compliance, story completion -- before any real subscriber exists "
         "(instances/owl-build.md, round 129)",
    levers=[
        dict(name="build_version", kind="choice", options=["v0"], start="v0", cls="code", blast_per_step=1),
    ],
    measures=[
        # compliance_pass listed first: unit_scale() (owl/core/definition.py) divides every other
        # measure's threshold by measures[0].base, so it can never be 0 -- found live (round 131/132)
        # when every measure here was left at its honest current reading of 0. 1.0 is the natural
        # reference for a share expected to fully hold, not a claim about what's currently measured.
        dict(name="compliance_pass", label="compliance checks passing", unit="share of required checks passing",
             base=1.0, kind="share", witness=dict(kind="compliance_scanner", description="the unsubscribe-link AST scan")),
        dict(name="critical_defects", label="critical static-analysis findings", unit="count",
             base=0, kind="sum", witness=dict(kind="sast_scanner", description="pyflakes, run against the candidate")),
        dict(name="coverage", label="test coverage", unit="share of lines covered", base=0.0,
             kind="share", witness=dict(kind="ci_pipeline", description="pytest-cov's own report")),
        dict(name="story_completion", label="user stories completed", unit="share of acceptance tests passing",
             base=0.0, kind="share", witness=dict(kind="acceptance_test_runner", description="pytest, tests named test_story_*")),
        # Shown, never judged (round 140). story_completion is a share of the acceptance suite, and the suite is a
        # file in the same repository as the code: the cheapest way to raise it is to delete a failing story. The
        # size of the rubric is therefore delivered alongside it, by the same independent witness, so a shrinking
        # denominator is visible on the record. It is deliberately in neither guards nor goal -- making it a wall
        # would freeze the story list, and OWL judges nothing it is not asked to -- which is exactly why Quill
        # Agent checks it itself in promote_if_better.
        dict(name="story_tests_total", label="acceptance tests in the suite", unit="count", base=3, kind="sum",
             witness=dict(kind="acceptance_test_runner", description="how many test_story_* the suite holds")),
    ],
    guards=[
        dict(measure="critical_defects", limit=0, rule="max"),
        dict(measure="compliance_pass", limit=1.0, rule="min"),
    ],
    goal=[
        dict(measure="story_completion", rel="max"),
        dict(measure="coverage", rel="max"),
    ],
    levers_for=dict(story_completion=["build_version"], coverage=["build_version"],
                     compliance_pass=["build_version"], critical_defects=["build_version"]),
    # max_horizon=1 (round 129/131's first guess) turned out wrong in practice, round 132: a real
    # candidate that genuinely clears every guard and improves the goal still needs the sequential
    # judge's confirm step to run across an actual window, structurally, independent of noise --
    # patience=1 was never the limiting factor. 8 matches every other tenant's own convention.
    # slice_share=10 ("always everyone", rounds 129/131) is refused since round 136 (P36): it leaves no control
    # group. It never mattered for system F -- one build_version option means OWL never trials it, and since
    # round 135 a step that changes nothing isn't a trial at all -- so any valid value serves.
    theta=dict(cycle=1, minimum_effect=0.0, quantile=0.5, plausibility_bound=1.0, max_horizon=8,
               slice_share=5, spillover_bound=6, pre_period_weeks=0, auto_approve=True,
               proposer="lever_map", random_share=0.0, patience=8, sequential=True),
)

JUDGED = ("compliance_pass", "critical_defects", "coverage", "story_completion")
SHOWN_ONLY = ("story_tests_total",)
MEASURES = JUDGED + SHOWN_ONLY


class NotIndependent(Exception):
    """A reading OWL holds did not arrive signed by an independent provider, or is not about the candidate that
    was asked for. Quill Agent refuses to decide on it rather than quietly treating it as evidence."""


class QuillAgent:
    """The OWL-facing identity for system F. `owl` is an httpx.Client already pointed at the live service; `qb` is
    one pointed at the deployed Quillbox adapter; `witness_runner(version, index)` starts the witness job and
    returns when it has finished -- in production a Cloud Run execution (run_witness.py), in a test a local call.
    Whatever it returns is ignored on purpose: the numbers are read back from OWL."""

    def __init__(self, owl, sid=None, owner_key=None, runtime_key=None, qb=None, adapter_secret=None,
                 witness_runner=None):
        self.owl = owl
        self.sid = sid
        self.owner_key = owner_key
        self.runtime_key = runtime_key
        self.qb = qb                          # httpx.Client on the real deployed Quillbox adapter
        self.adapter_secret = adapter_secret   # signs calls to qb's /apply and /revert, as OWL's own actuator would
        self.witness_runner = witness_runner
        self.week = 0

    def _owner_hdr(self):
        return {"Authorization": "Bearer " + self.owner_key}

    def _runtime_hdr(self):
        return {"Authorization": "Bearer " + self.runtime_key}

    def _sign(self, body: bytes) -> str:
        return hmac.new(self.adapter_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

    def _apply_live(self, version: str) -> dict:
        """A real, signed call to the deployed adapter's own /apply -- the same call OWL's actuator would make,
        just issued by Quill Agent directly, since Quill Agent is already standing in for OWL's orchestration role
        here (round 132: OWL's trial mechanism cannot judge a one-unit system, so the decision of when to try
        something moved to Quill Agent already)."""
        body = json.dumps({"version": {"build_version": version}, "slice": {"everyone": True}}).encode("utf-8")
        r = self.qb.post("/apply", content=body, headers={"x-owl-signature": self._sign(body)}); r.raise_for_status()
        return r.json()

    def _revert_live(self, version: str) -> dict:
        body = json.dumps({"version": {"build_version": version}, "slice": {"everyone": True}}).encode("utf-8")
        r = self.qb.post("/revert", content=body, headers={"x-owl-signature": self._sign(body)}); r.raise_for_status()
        return r.json()

    def _read_back(self, version: str, index: int) -> dict:
        """The readings as OWL holds them, not as anyone reported them. Every one must have arrived signed, from a
        provider declared independent, and be about the candidate that was asked for -- otherwise this is not
        evidence and nothing is decided on it."""
        out = {}
        for m in MEASURES:
            r = self.owl.get(f"/v1/systems/{self.sid}/records/{m}?week={index}", headers=self._owner_hdr())
            r.raise_for_status(); rows = r.json()
            if not rows:
                raise NotIndependent(f"OWL holds no reading for {m} at index {index}: the witness did not deliver")
            row = rows[-1]
            if not row.get("signed"):
                raise NotIndependent(f"the reading for {m} at index {index} is unsigned")
            if row.get("delivered_by") != "independent":
                raise NotIndependent(f"the reading for {m} at index {index} was delivered by "
                                     f"{row.get('delivered_by')!r}, not an independent provider")
            about = row.get("about") or {}
            if about.get("build_version") != version:
                raise NotIndependent(f"the reading for {m} at index {index} is about build_version "
                                     f"{about.get('build_version')!r}, not {version!r}")
            out[m] = row["value"]; out.setdefault("_about", about)
        return out

    def measure(self, version: str, index: int) -> dict:
        """Run the witness against `version`, let OWL cycle, and read back what OWL now holds."""
        if self.witness_runner is None:
            raise RuntimeError("no witness_runner: Quill Agent does not measure anything itself (round 140)")
        self.witness_runner(version, index)
        c = self.owl.post(f"/v1/systems/{self.sid}/cycle/{index}", headers=self._runtime_hdr()); c.raise_for_status()
        self.week = index
        return self._read_back(version, index)

    def promote_if_better(self, candidate: str, current: str, n: int) -> dict:
        """OWL's own trial mechanism can't confirm a gain here -- system F has one unit, so there is never a
        control group to compare against (round 132, instances/owl-build.md). Quill Agent's own job, not OWL's:
        apply the candidate for real on the live adapter, have the witness measure it for real, and compare
        against a fresh real measurement of the current version. If the candidate clears every guard and is at
        least as good on every goal, it stays applied and Quill Agent promotes it in OWL's Definition too -- the
        same PUT /definition call that registered the very first version, not a new mechanism. If it doesn't clear
        the bar, it's reverted back to the current version on the live adapter, and OWL's Definition is never
        touched at all.

        Both measurements are delivered to OWL by the witness, honestly, win or lose, before anything is decided
        -- and this method reads them back out of OWL rather than trusting what the witness printed."""
        self._apply_live(current); cur = self.measure(current, n)
        self._apply_live(candidate); cand = self.measure(candidate, n + 1)

        def failing():
            for g in DEF["guards"]:
                m, limit, rule = g["measure"], g["limit"], g["rule"]
                if rule == "max" and cand[m] > limit: return f"{m}={cand[m]} exceeds guard max {limit}"
                if rule == "min" and cand[m] < limit: return f"{m}={cand[m]} below guard min {limit}"
            for r in DEF["goal"]:
                m = r["measure"]
                if r["rel"] == "max" and cand[m] < cur[m]: return f"{m} did not improve: {cand[m]} vs current {cur[m]}"
                if r["rel"] == "min" and cand[m] > cur[m]: return f"{m} did not improve: {cand[m]} vs current {cur[m]}"
            if cand["story_tests_total"] < cur["story_tests_total"]:
                # Shown, never judged -- so OWL will not refuse this, and Quill Agent must. story_completion is a
                # share of the acceptance suite, and a candidate that deletes a failing story raises it without
                # building anything: round 140's cheapest attack on system F's own measure.
                return (f"the acceptance suite shrank: {cand['story_tests_total']} stories against "
                        f"{cur['story_tests_total']} -- story_completion is not comparable across a changed rubric")
            return None

        reason = failing()
        if reason:
            self._revert_live(current)
            return {"promoted": False, "reason": reason, "candidate": cand, "current": cur}

        defn = self.owl.get(f"/v1/systems/{self.sid}/definition", headers=self._owner_hdr()).json()
        lever = next(l for l in defn["levers"] if l["name"] == "build_version")
        lever["options"] = [candidate]; lever["start"] = candidate
        put = self.owl.put(f"/v1/systems/{self.sid}/definition", json=defn, headers=self._owner_hdr())
        put.raise_for_status()
        return {"promoted": True, "candidate": cand, "current": cur, "owl_response": put.json()}

    def next_target(self) -> dict:
        """What's currently unmet or unclimbed, read from status -- not an instruction OWL gives, a decision this
        agent makes from what it reads (round 130's pushback #2)."""
        st = self.owl.get(f"/v1/systems/{self.sid}", headers=self._owner_hdr()).json()
        counts = st.get("counts") or {}
        return {"live_build_version": (st.get("x") or {}).get("build_version"),
                "keeps_so_far": counts.get("keep", 0), "reverts_so_far": counts.get("revert", 0)}
