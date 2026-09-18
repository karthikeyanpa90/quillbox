# -*- coding: utf-8 -*-
"""System F's real adapter for Quillbox -- apply/verify/revert swap which candidate's real code is
checked out as quillbox_app/, so witness.py's next run genuinely reflects whatever OWL just applied.
Slice is always {"everyone": true} (round 129/131): system F has no live population to partition,
so there is nothing to check in a slice beyond that OWL sent the one it always sends.

Configured from the environment, matching every other tenant here:
  QB_SID, QB_ADAPTER_SECRET, QB_CONNECTOR_SECRETS, QB_OWL_BASE_URL, QB_DRIVER_KEY, QB_RUNTIME_KEY
"""
import hashlib
import hmac
import json
import os
import shutil
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse

from witness import witness_report

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


def make_app(adapter: QuillboxAdapter = None, sid: str = "", adapter_secret: str = "",
             connector_secrets: dict = None, driver_key: str = "") -> FastAPI:
    ad = adapter or QuillboxAdapter()
    connector_secrets = connector_secrets or {}
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

    @app.post("/apply")
    async def apply(request: Request):
        body = await _checked_body(request)
        return {"ok": ad.apply(body["version"], body["slice"])}

    @app.post("/verify")
    async def verify(request: Request):
        body = await _checked_body(request)
        return {"ok": ad.verify(body["version"], body["slice"])}

    @app.post("/revert")
    async def revert(request: Request):
        body = await _checked_body(request)
        return {"ok": ad.revert(body["version"], body["slice"])}

    @app.post("/check-in/{n}")
    def check_in(n: int, authorization: str = Header(default="")):
        """n: a sequential index of real evaluation events (round 134) -- a routine check that
        nothing has regressed, or one step of a candidate-promotion attempt. Never a calendar
        week; renamed from /run-week once that was formally settled."""
        key = authorization[7:] if authorization.lower().startswith("bearer ") else ""
        if not driver_key or not hmac.compare_digest(key, driver_key):
            raise HTTPException(401, "not the onboarding driver")
        report = witness_report()
        owl_base = os.environ.get("QB_OWL_BASE_URL", "")
        if owl_base and sid:
            owl = httpx.Client(base_url=owl_base, timeout=20.0)
            for measure in ("critical_defects", "coverage", "compliance_pass", "story_completion"):
                secret = connector_secrets.get(measure)
                if not secret:
                    continue
                owl.post(f"/v1/systems/{sid}/records/{measure}",
                         json={"week": n, "age": 0, "rows": [{"unit": "quillbox", "value": report[measure]}],
                               "secret": secret}).raise_for_status()   # "week" here is OWL's own field name (records endpoint), unrenamed -- out of scope
        return report

    @app.get("/status")
    def status():
        return {"system_id": sid, "live_version": ad.live_version, "applies_received": len(ad.applies),
                "recent_applies": ad.applies[-5:]}

    return app


def build_app_from_env() -> FastAPI:
    sid = os.environ.get("QB_SID", "")
    adapter_secret = os.environ.get("QB_ADAPTER_SECRET", "")
    connector_secrets = json.loads(os.environ.get("QB_CONNECTOR_SECRETS", "{}"))
    driver_key = os.environ.get("QB_DRIVER_KEY", "")
    return make_app(sid=sid, adapter_secret=adapter_secret, connector_secrets=connector_secrets, driver_key=driver_key)


app = build_app_from_env()
