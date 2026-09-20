# -*- coding: utf-8 -*-
"""System F's real adapter for Quillbox -- apply/verify/revert swap which candidate's real code is checked out as
quillbox_app/, so the witness's next run genuinely reflects whatever was just applied. Slice is always
{"everyone": true} (round 129/131): system F has no live population to partition, so there is nothing to check in
a slice beyond that OWL sent the one it always sends.

Round 140 (P46) took four things out of this file and did not put anything back:

  * the witness. It used to run here, in this process, against the very directory /apply rewrites. It now runs in
    witness_job.py, a separate Cloud Run Job this service cannot call, run or redeploy.
  * the connector secrets (QB_CONNECTOR_SECRETS). This service now holds no credential that can write a reading
    into OWL, so no number OWL judges can originate here.
  * /check-in, which was how a reading got delivered from here.
  * QB_OWNER_KEY, which was in this service's environment and never read by it. With it, the graded application
    could have re-registered every connector to point back at itself.

What is left is what an adapter is for: apply a version, say whether it took, revert it. The one credential it
holds is the adapter secret, which only proves an inbound call came from OWL.

Round 142 took one more thing away. It held QB_RUNTIME_KEY, only ever used to ask OWL what is live at startup
-- but the runtime role is admitted on `POST /cycle/{week}` and `POST /suggestions`, so the graded application
could advance the judge's clock and choose which weeks entered its windows. It now holds the proposer token
instead: enough to read status, and `submit_proposal` refuses a version that changes nothing, which is every
version of a one-option lever. Both it and the adapter secret are Secret Manager references now, not plain
values that `gcloud run services describe` hands to anything with run.services.get.

Configured from the environment:  QB_SID, QB_ADAPTER_SECRET, QB_OWL_BASE_URL, QB_PROPOSER_TOKEN
"""
import hashlib
import hmac
import os
import shutil
import threading
from contextlib import contextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from starlette.concurrency import run_in_threadpool

from qb_digest import tree_digest

ROOT = Path(__file__).parent
CANDIDATES = ROOT / "candidates"
LIVE_APP = ROOT / "quillbox_app"


def sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def verify_signature(secret: str, body: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign(secret, body), signature or "")


class QuillboxAdapter:
    """The applied candidate is real, checked-out code, not a label -- apply() actually copies
    candidates/<name>/quillbox_app/ over the live quillbox_app/ directory."""

    def __init__(self):
        self.live_version = "v0"
        self.applies = []
        self._lock = threading.Lock()

    @contextmanager
    def exclusive(self, wait_seconds: float = 30.0):
        """One operation on quillbox_app/ at a time (P42): apply/revert swap the files with a non-atomic
        rmtree+copytree. Callers queue rather than fail -- OWL's actuator treats a 409 as an unverified apply and
        does not retry it -- and only a caller still waiting after `wait_seconds` is refused."""
        if not self._lock.acquire(timeout=wait_seconds):
            raise HTTPException(409, "quillbox is busy with another apply or revert; try again shortly")
        try: yield
        finally: self._lock.release()

    def _candidate_dir(self, name: str) -> Path:
        d = CANDIDATES / name / "quillbox_app"
        if not d.exists():
            raise HTTPException(422, f"no such candidate on disk: {name}")
        return d

    def apply(self, version: dict, slice_: dict) -> bool:
        name = version["build_version"]
        src = self._candidate_dir(name)
        shutil.rmtree(LIVE_APP, ignore_errors=True)
        shutil.copytree(src, LIVE_APP)
        self.live_version = name
        self.applies.append({"kind": "apply", "version": version, "slice": slice_})
        return True

    def verify(self, version: dict, slice_: dict) -> bool:
        return self.live_version == version["build_version"]

    def revert(self, version: dict, slice_: dict) -> bool:
        ok = self.apply(version, slice_)
        self.applies.append({"kind": "revert", "version": version, "slice": slice_})
        return ok


def make_app(adapter: QuillboxAdapter = None, sid: str = "", adapter_secret: str = "") -> FastAPI:
    ad = adapter or QuillboxAdapter()
    app = FastAPI(title="Quillbox adapter")

    @app.get("/", response_class=HTMLResponse)
    def home():
        return (f"<html><body><h1>Quillbox</h1><p>System F's adapter. Live candidate: "
                f"{ad.live_version}</p></body></html>")

    async def _checked_body(request: Request) -> dict:
        raw = await request.body()
        sig = request.headers.get("x-owl-signature", "")
        if not adapter_secret or not verify_signature(adapter_secret, raw, sig):
            raise HTTPException(401, "bad signature: this call did not come from OWL")
        return await request.json()

    def _exclusively(fn, *args):
        with ad.exclusive(): return fn(*args)

    @app.post("/apply")
    async def apply(request: Request):
        body = await _checked_body(request)            # the lock is waited on in the threadpool, never on the event loop
        return {"ok": await run_in_threadpool(_exclusively, ad.apply, body["version"], body["slice"])}

    @app.post("/verify")
    async def verify(request: Request):
        body = await _checked_body(request)
        return {"ok": await run_in_threadpool(_exclusively, ad.verify, body["version"], body["slice"])}

    @app.post("/revert")
    async def revert(request: Request):
        body = await _checked_body(request)
        return {"ok": await run_in_threadpool(_exclusively, ad.revert, body["version"], body["slice"])}

    @app.get("/status")
    def status():
        """live_digest is a drift tripwire, not evidence. It catches the real historical failure -- round 136's
        redeploy, which served v0 while OWL held v1 -- and catches nothing deliberate, because the party
        computing it is the party being graded. The reading that counts carries the witness's own digest of the
        source it measured, signed with a key this service does not hold."""
        return {"system_id": sid, "live_version": ad.live_version, "synced_from_owl": getattr(ad, "synced", False),
                "live_digest": tree_digest(LIVE_APP), "live_digest_is_evidence": False,
                "delivers_readings": False,
                "applies_received": len(ad.applies), "recent_applies": ad.applies[-5:]}

    return app


def build_app_from_env() -> FastAPI:
    sid = os.environ.get("QB_SID", "")
    ad = QuillboxAdapter()
    sync_from_owl(ad, sid, os.environ.get("QB_OWL_BASE_URL", ""), os.environ.get("QB_PROPOSER_TOKEN", ""))
    return make_app(ad, sid=sid, adapter_secret=os.environ.get("QB_ADAPTER_SECRET", ""))


def sync_from_owl(ad: QuillboxAdapter, sid: str, owl_base: str, read_token: str):
    """A fresh container boots on whatever candidate is baked into the image (v0), while OWL's ledger says what
    was actually promoted. Found live, round 136: after a redeploy, check-ins measured v0 while OWL held v1 live.
    So at startup, ask OWL what's live and apply it -- the same thing every other tenant here does on a cold
    start. If OWL can't be reached, stay on the baked-in version and say so on /status, rather than guess."""
    ad.synced = False
    if not (owl_base and sid and read_token): return
    try:
        r = httpx.get(f"{owl_base}/v1/systems/{sid}", headers={"Authorization": "Bearer " + read_token}, timeout=15.0)
        live = ((r.json() or {}).get("x") or {}).get("build_version") if r.status_code == 200 else None
        if live and live != ad.live_version and (CANDIDATES / live / "quillbox_app").exists():
            ad.apply({"build_version": live}, {"everyone": True})
        ad.synced = live is not None
    except Exception:
        pass


app = build_app_from_env()
