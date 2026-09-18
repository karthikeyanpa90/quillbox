# -*- coding: utf-8 -*-
"""Quill Agent (instances/owl-build.md, round 130): the one thing on Quillbox's side that ever
calls the OWL API. Holds both of system F's keys. Its job, each time a candidate is ready:

  1. apply the candidate as the build_version under evaluation (slice is always {"everyone": True}
     -- system F has no live population to slice; see round 129's pushback #4 and P31)
  2. run the real witnesses (witness.py) against exactly that candidate
  3. deliver the readings to OWL as records, cycle the system, and read back the verdict
  4. decide what to hand Quill Builder next, from what is currently unmet or unclimbed -- OWL
     returns a verdict on what already happened, never an instruction for what to build next
     (round 130's pushback #2); that choice is this file's own, not read off OWL
"""
import hashlib
import hmac
import json
import time

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


class QuillAgent:
    """The OWL-facing identity for system F. `owl` is an httpx.Client already pointed at the live
    service; `witness_fn` defaults to witness.py's real witness_report, swappable in tests."""

    def __init__(self, owl, sid=None, owner_key=None, runtime_key=None, witness_fn=None,
                 qb=None, adapter_secret=None, driver_key=None):
        self.owl = owl
        self.sid = sid
        self.owner_key = owner_key
        self.runtime_key = runtime_key
        self.witness_fn = witness_fn
        self.connector_secrets = {}
        self.week = 0
        self.qb = qb                          # httpx.Client on the real deployed Quillbox service
        self.adapter_secret = adapter_secret   # signs calls to qb's /apply and /revert, like OWL's own actuator would
        self.driver_key = driver_key           # authorizes calls to qb's /check-in

    def register(self):
        r = self.owl.post("/v1/systems", json={"name": "quillbox-fast"}); r.raise_for_status()
        keys = r.json(); self.sid = keys["id"]; self.owner_key = keys["owner_key"]; self.runtime_key = keys["runtime_key"]
        owner = self._owner_hdr()
        r = self.owl.put(f"/v1/systems/{self.sid}/definition", json=DEF, headers=owner); r.raise_for_status()
        for measure, kind in [("critical_defects", "sast_scanner"), ("coverage", "ci_pipeline"),
                               ("compliance_pass", "compliance_scanner"), ("story_completion", "acceptance_test_runner")]:
            r = self.owl.post(f"/v1/systems/{self.sid}/connectors", json={"measure": measure, "kind": kind}, headers=owner)
            r.raise_for_status(); self.connector_secrets[measure] = r.json()["secret"]
        return keys

    def _owner_hdr(self):
        return {"Authorization": "Bearer " + self.owner_key}

    def _runtime_hdr(self):
        return {"Authorization": "Bearer " + self.runtime_key}

    def run_and_report_week(self, week: int):
        """Run the real witnesses against whatever candidate is currently live, deliver the
        readings, and let OWL cycle. With only one build_version option registered so far there is
        nothing yet for the proposer to try (step_lever on a choice lever with no other option
        returns the same value) -- no adapter is registered, so OWL falls back to NullActuator, and
        this stays honest: system F is observing v0's real baseline, not trialling anything yet.
        A second candidate needs a real adapter (service.py) before OWL has anything to apply."""
        report = self.witness_fn()
        for measure in ("critical_defects", "coverage", "compliance_pass", "story_completion"):
            secret = self.connector_secrets[measure]
            self.owl.post(f"/v1/systems/{self.sid}/records/{measure}",
                           json={"week": week, "age": 0, "rows": [{"unit": "quillbox", "value": report[measure]}],
                                 "secret": secret}).raise_for_status()
        r = self.owl.post(f"/v1/systems/{self.sid}/cycle/{week}", headers=self._runtime_hdr())
        r.raise_for_status()
        self.week = week
        return {"week": week, "report": report, "cycle": r.json()}

    def register_adapter(self, base_url: str):
        r = self.owl.post(f"/v1/systems/{self.sid}/adapter", json={"base_url": base_url}, headers=self._owner_hdr())
        r.raise_for_status()
        return r.json()["secret"]

    def _sign(self, body: bytes) -> str:
        return hmac.new(self.adapter_secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

    def _apply_live(self, version: str) -> dict:
        """A real, signed call to the deployed adapter's own /apply -- the same call OWL's actuator
        would make, just issued by Quill Agent directly, since Quill Agent is already standing in
        for OWL's own orchestration role here (round 132: OWL's trial mechanism cannot judge a
        one-unit system, so the decision of when to try something moved to Quill Agent already)."""
        body = json.dumps({"version": {"build_version": version}, "slice": {"everyone": True}}).encode("utf-8")
        r = self.qb.post("/apply", content=body, headers={"x-owl-signature": self._sign(body)}); r.raise_for_status()
        return r.json()

    def _revert_live(self, version: str) -> dict:
        body = json.dumps({"version": {"build_version": version}, "slice": {"everyone": True}}).encode("utf-8")
        r = self.qb.post("/revert", content=body, headers={"x-owl-signature": self._sign(body)}); r.raise_for_status()
        return r.json()

    def _measure_live(self, n: int) -> dict:
        """Whatever's currently applied on the real deployed adapter, measured for real via its own
        /check-in -- which also delivers the reading to OWL as a real record, honestly, win or
        lose, before this agent has decided anything. n: a sequential check-in index (round 134),
        never a calendar week."""
        r = self.qb.post(f"/check-in/{n}", headers={"Authorization": "Bearer " + self.driver_key})
        r.raise_for_status(); report = r.json()
        c = self.owl.post(f"/v1/systems/{self.sid}/cycle/{n}", headers=self._runtime_hdr()); c.raise_for_status()
        self.week = n
        return report

    def promote_if_better(self, candidate: str, current: str, n: int) -> dict:
        """OWL's own trial mechanism can't confirm a gain here -- system F has one unit, so there
        is never a control group to compare against (round 132, instances/owl-build.md). Quill
        Agent's own job, not OWL's: apply the candidate for real on the live adapter, measure it
        for real, and compare against a fresh real measurement of the current version -- exactly
        the real apply/measure/revert-if-it-doesn't-work-out mechanism every other tenant here
        already uses, just decided by Quill Agent instead of OWL's broken trial math. If the
        candidate clears every guard and is at least as good on every goal, it stays applied and
        Quill Agent promotes it in OWL's Definition too -- the same PUT /definition call that
        registered the very first version, not a new mechanism. If it doesn't clear the bar, it's
        reverted back to the current version on the live adapter, and OWL's Definition is never
        touched at all."""
        self._apply_live(current); cur = self._measure_live(n)
        self._apply_live(candidate); cand = self._measure_live(n + 1)

        def failing():
            for g in DEF["guards"]:
                m, limit, rule = g["measure"], g["limit"], g["rule"]
                if rule == "max" and cand[m] > limit: return f"{m}={cand[m]} exceeds guard max {limit}"
                if rule == "min" and cand[m] < limit: return f"{m}={cand[m]} below guard min {limit}"
            for r in DEF["goal"]:
                m = r["measure"]
                if r["rel"] == "max" and cand[m] < cur[m]: return f"{m} did not improve: {cand[m]} vs current {cur[m]}"
                if r["rel"] == "min" and cand[m] > cur[m]: return f"{m} did not improve: {cand[m]} vs current {cur[m]}"
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
        """What's currently unmet or unclimbed, read from status -- not an instruction OWL gives,
        a decision this agent makes from what it reads (round 130's pushback #2)."""
        st = self.owl.get(f"/v1/systems/{self.sid}", headers=self._owner_hdr()).json()
        counts = st.get("counts") or {}
        return {"live_build_version": (st.get("x") or {}).get("build_version"),
                "keeps_so_far": counts.get("keep", 0), "reverts_so_far": counts.get("revert", 0)}
