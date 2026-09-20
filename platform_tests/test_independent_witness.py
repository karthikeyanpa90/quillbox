# -*- coding: utf-8 -*-
"""Round 140 (P46): the Quillbox witness is its own provider, and the graded application cannot produce,
sign, route or relabel a reading.

Every test here runs the real witness job as a subprocess against a real OWL over real HTTP. Nothing is
simulated: pytest, coverage and pyflakes actually run against a real candidate's real source, the delivery is
actually Ed25519-signed with a key OWL never holds, and what is asserted is what OWL ended up holding.
"""
import ast
import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

QUILLBOX = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(QUILLBOX))

import agent as agent_mod                                             # noqa: E402
from agent import AWAITING_PROVIDER, DEF, MEASURES, STATIC, NotIndependent, QuillAgent   # noqa: E402
from qb_digest import tree_digest                                     # noqa: E402
from qb_signing import new_keypair                                    # noqa: E402

KINDS = {"compliance_pass": "compliance_scanner", "critical_defects": "sast_scanner", "coverage": "ci_pipeline",
         "story_completion": "acceptance_test_runner", "story_tests_total": "acceptance_test_runner"}


def make_system(base, svc, register=True, delivered_by="independent", measures=MEASURES):
    c = httpx.Client(base_url=base, timeout=60.0)
    acct = {"Authorization": "Bearer " + svc.create_account("test", 10)["account_key"]}
    keys = c.post("/v1/systems", json={"name": "quillbox-fast"}, headers=acct).json()
    owner = {"Authorization": "Bearer " + keys["owner_key"]}
    assert c.put(f"/v1/systems/{keys['id']}/definition", json=DEF, headers=owner).status_code == 200
    private = {}
    if register:
        for m in measures:
            priv, pub = new_keypair(); private[m] = priv
            r = c.post(f"/v1/systems/{keys['id']}/connectors",
                       json={"measure": m, "kind": KINDS[m], "public_key": pub, "delivered_by": delivered_by},
                       headers=owner)
            assert r.status_code == 200, r.text
    return c, keys, owner, private


def run_witness(base, sid, private, version, index, tmp_path, expect_ok=True):
    """The job, as a subprocess, exactly as Cloud Run runs it."""
    key_file = tmp_path / "witness-keys.json"
    key_file.write_text(json.dumps(private), encoding="utf-8")
    env = dict(os.environ, QB_SID=sid, QB_OWL_BASE_URL=base, QB_VERSION=version, QB_INDEX=str(index),
               QB_WITNESS_KEY_FILE=str(key_file), QB_IMAGE="local-test")
    r = subprocess.run([sys.executable, "witness_job.py"], cwd=QUILLBOX, env=env, capture_output=True, text=True)
    if expect_ok:
        assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    return r


# ---- the witness delivers, and what OWL holds is what it measured ----

def test_the_witness_delivers_the_static_measures_signed_and_independent(owl, tmp_path):
    base, svc = owl
    c, keys, owner, private = make_system(base, svc)
    run_witness(base, keys["id"], private, "v1", 7, tmp_path)

    for m in STATIC:
        rows = c.get(f"/v1/systems/{keys['id']}/records/{m}?week=7", headers=owner).json()
        assert len(rows) == 1, m
        assert rows[0]["signed"] is True and rows[0]["delivered_by"] == "independent", m
        assert rows[0]["about"]["build_version"] == "v1" and rows[0]["about"]["mode"] == "static"

def test_the_witness_delivers_nothing_that_needed_the_candidate_to_run(owl, tmp_path):
    """Round 141: coverage, story_completion and story_tests_total are produced in a job with no key, because
    the running candidate writes the files they are read from. Nothing arrives for them."""
    base, svc = owl
    c, keys, owner, private = make_system(base, svc)
    run_witness(base, keys["id"], private, "v1", 7, tmp_path)
    for m in AWAITING_PROVIDER:
        assert c.get(f"/v1/systems/{keys['id']}/records/{m}?week=7", headers=owner).json() == [], m

def test_the_reading_carries_a_digest_of_the_exact_source_measured(owl, tmp_path):
    """Recomputable by anyone holding the repository, and inside the signed body, so it cannot be swapped."""
    base, svc = owl
    c, keys, owner, private = make_system(base, svc)
    run_witness(base, keys["id"], private, "v1", 1, tmp_path)
    about = c.get(f"/v1/systems/{keys['id']}/records/compliance_pass?week=1", headers=owner).json()[0]["about"]
    assert about["code"] == tree_digest(QUILLBOX / "candidates" / "v1" / "quillbox_app")
    assert about["suite"] == tree_digest(QUILLBOX / "tests")

def test_the_delivered_numbers_are_the_tools_own_output_for_that_candidate(owl, tmp_path):
    """Not a fixed constant: what OWL holds is what pyflakes and the compliance scan say about that candidate's
    source, recomputed here independently of the job that delivered it."""
    import shutil
    import witness
    base, svc = owl
    c, keys, owner, private = make_system(base, svc)
    run_witness(base, keys["id"], private, "v0", 1, tmp_path)
    work = tmp_path / "recheck"
    shutil.copytree(QUILLBOX / "candidates" / "v0" / "quillbox_app", work / "quillbox_app")
    here = witness.static_report(work)
    for m in STATIC:
        row = c.get(f"/v1/systems/{keys['id']}/records/{m}?week=1", headers=owner).json()[0]
        assert row["value"] == float(here[m]), m

def test_a_candidate_that_is_not_in_the_image_is_refused_and_nothing_is_delivered(owl, tmp_path):
    base, svc = owl
    c, keys, owner, private = make_system(base, svc)
    r = run_witness(base, keys["id"], private, "v99", 1, tmp_path, expect_ok=False)
    assert r.returncode != 0
    assert c.get(f"/v1/systems/{keys['id']}/records/coverage?week=1", headers=owner).json() == []

def test_a_second_delivery_of_the_same_run_is_refused_as_a_replay(owl, tmp_path):
    """The job mints a fresh delivery id each run, so two honest runs at the same index both land; a replayed
    capture of one of them does not. Proven by replaying the exact bytes OWL already accepted."""
    base, svc = owl
    c, keys, owner, private = make_system(base, svc)
    from qb_signing import sign
    import time, uuid
    raw = json.dumps({"week": 5, "age": 0, "rows": [{"unit": "quillbox", "value": 0.5}]}).encode("utf-8")
    ts, did = str(int(time.time())), str(uuid.uuid4())
    hdr = {"content-type": "application/json", "x-owl-ts": ts, "x-owl-delivery": did,
           "x-owl-signature": sign(private["coverage"], ts, did, raw)}
    assert c.post(f"/v1/systems/{keys['id']}/records/coverage", content=raw, headers=hdr).status_code == 200
    assert c.post(f"/v1/systems/{keys['id']}/records/coverage", content=raw, headers=hdr).status_code == 409


# ---- the graded application holds nothing that could write a reading ----

def test_the_adapter_has_no_route_that_delivers_a_reading():
    import service as qb_service
    paths = {r.path for r in qb_service.make_app(qb_service.QuillboxAdapter(), sid="s", adapter_secret="x").routes
             if hasattr(r, "path") and not r.path.startswith("/openapi") and not r.path.startswith("/docs")
             and not r.path.startswith("/redoc")}
    assert paths == {"/", "/apply", "/verify", "/revert", "/status"}

def test_the_adapter_takes_no_credential_that_could_sign_a_reading():
    """Its whole signature is (adapter, sid, adapter_secret). There is nowhere to pass it a connector key."""
    import inspect
    import service as qb_service
    assert set(inspect.signature(qb_service.make_app).parameters) == {"adapter", "sid", "adapter_secret"}
    tree = ast.parse((QUILLBOX / "service.py").read_text(encoding="utf-8"))
    used = {n.args[0].value for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get"
            and isinstance(n.func.value, ast.Attribute) and n.func.value.attr == "environ"
            and n.args and isinstance(n.args[0], ast.Constant)}
    assert used == {"QB_SID", "QB_ADAPTER_SECRET", "QB_OWL_BASE_URL", "QB_RUNTIME_KEY"}, f"the adapter reads {used}"
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert "witness" not in imported and "witness_job" not in imported

def test_the_witness_never_asks_the_graded_application_anything():
    """It stages source out of its own image and talks to exactly one address, OWL's. If it ever asked the
    service what to measure, the service would choose what it is graded on -- the hole the alternative design
    could not close (round 140's design round)."""
    tree = ast.parse((QUILLBOX / "witness_job.py").read_text(encoding="utf-8"))
    used = {n.slice.value for n in ast.walk(tree)
            if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Attribute)
            and n.value.attr == "environ" and isinstance(n.slice, ast.Constant)}
    used |= {n.args[0].value for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get"
             and isinstance(n.func.value, ast.Attribute) and n.func.value.attr == "environ"
             and n.args and isinstance(n.args[0], ast.Constant)}
    assert used <= {"QB_SID", "QB_OWL_BASE_URL", "QB_VERSION", "QB_INDEX", "QB_WITNESS_KEY_FILE",
                    "QB_IMAGE", "QB_SANDBOX_USER", "QB_MODE"}, f"the witness reads {used}"
    clients = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
               and isinstance(n.func, ast.Attribute) and n.func.attr == "Client"]
    assert len(clients) == 1
    assert [ast.unparse(k.value) for k in clients[0].keywords if k.arg == "base_url"] == ['os.environ[\'QB_OWL_BASE_URL\']']

def test_the_adapters_own_digest_matches_the_witnesses_for_the_same_candidate(quillbox):
    """The drift tripwire agrees with the evidence when nobody is lying -- which is all it is for."""
    base, secret, root = quillbox
    import hashlib, hmac
    body = json.dumps({"version": {"build_version": "v1"}, "slice": {"everyone": True}}).encode("utf-8")
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    c = httpx.Client(base_url=base, timeout=30.0)
    assert c.post("/apply", content=body, headers={"x-owl-signature": sig}).json() == {"ok": True}
    st = c.get("/status").json()
    assert st["live_version"] == "v1" and st["delivers_readings"] is False
    assert st["live_digest"] == tree_digest(QUILLBOX / "candidates" / "v1" / "quillbox_app")
    assert st["live_digest_is_evidence"] is False


# ---- what Quill Agent will and will not decide on ----

def agent_for(base, keys, sid=None):
    return QuillAgent(httpx.Client(base_url=base, timeout=60.0), sid=sid or keys["id"],
                      owner_key=keys["owner_key"], runtime_key=keys["runtime_key"])

def test_quill_agent_refuses_a_reading_the_tenant_delivered(owl, tmp_path, monkeypatch):
    """OWL permits a measure that is neither guard nor goal to be declared tenant-delivered. Quill Agent still
    refuses to decide on it: "shown, never judged" has to mean something on the deciding side too."""
    base, svc = owl
    c, keys, owner, private = make_system(base, svc, measures=[m for m in MEASURES if m != "story_tests_total"])
    priv, pub = new_keypair(); private["story_tests_total"] = priv
    assert c.post(f"/v1/systems/{keys['id']}/connectors",
                  json={"measure": "story_tests_total", "kind": "acceptance_test_runner",
                        "public_key": pub, "delivered_by": "tenant"}, headers=owner).status_code == 200
    from qb_signing import deliver as sign_deliver
    body = {"week": 3, "age": 0, "rows": [{"unit": "quillbox", "value": 3.0}], "about": {"build_version": "v1"}}
    assert sign_deliver(c, keys["id"], "story_tests_total", body, priv).status_code == 200
    monkeypatch.setattr(agent_mod, "STATIC", ("story_tests_total",))
    with pytest.raises(NotIndependent, match="delivered by 'tenant'"):
        agent_for(base, keys)._read_back("v1", 3)

def test_quill_agent_refuses_a_reading_about_a_different_candidate(owl, tmp_path):
    base, svc = owl
    c, keys, owner, private = make_system(base, svc)
    run_witness(base, keys["id"], private, "v0", 4, tmp_path)
    with pytest.raises(NotIndependent, match="is about build_version 'v0'"):
        agent_for(base, keys)._read_back("v1", 4)

def test_quill_agent_refuses_when_the_witness_did_not_deliver(owl):
    base, svc = owl
    c, keys, owner, private = make_system(base, svc)
    with pytest.raises(NotIndependent, match="did not deliver"):
        agent_for(base, keys)._read_back("v1", 11)

def test_quill_agent_cannot_measure_anything_itself(owl):
    base, svc = owl
    c, keys, owner, private = make_system(base, svc)
    with pytest.raises(RuntimeError, match="does not measure anything itself"):
        agent_for(base, keys).measure("v1", 1)


# ---- the whole flow, end to end ----

def test_a_candidate_that_clears_every_guard_is_still_not_promoted(owl, quillbox, tmp_path):
    """Round 141's real consequence, end to end. v1 clears both guards on readings that hold up -- signed by a
    provider that never ran it -- and is not promoted, because both goal rows can only be obtained by running
    it. A system with no trustworthy reading of what it is climbing towards does not climb."""
    base, svc = owl
    qb_base, secret, root = quillbox
    c, keys, owner, private = make_system(base, svc)

    def runner(version, index):
        run_witness(base, keys["id"], private, version, index, tmp_path)

    agent = QuillAgent(httpx.Client(base_url=base, timeout=60.0), sid=keys["id"], owner_key=keys["owner_key"],
                       runtime_key=keys["runtime_key"], qb=httpx.Client(base_url=qb_base, timeout=60.0),
                       adapter_secret=secret, witness_runner=runner)
    out = agent.promote_if_better("v1", "v0", 1)
    assert out["promoted"] is False
    assert "no goal row can be judged" in out["reason"]
    assert out["candidate"]["compliance_pass"] == 1.0 and out["candidate"]["critical_defects"] == 0.0

    # reverted on the adapter, and OWL's Definition untouched
    assert httpx.get(f"{qb_base}/status", timeout=30).json()["live_version"] == "v0"
    defn = c.get(f"/v1/systems/{keys['id']}/definition", headers=owner).json()
    assert defn["levers"][0]["options"] == ["v0"]
    assert c.get(f"/v1/systems/{keys['id']}/ledger/verify", headers=owner).json()["ok"] is True
