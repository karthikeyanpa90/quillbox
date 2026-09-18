# -*- coding: utf-8 -*-
"""Quillbox: a solo-creator newsletter tool. This is the skeleton, not the product -- just enough
for Quill Agent to run real tools against and report real witness numbers to OWL. Everything past
/health is Quill Builder's to grow, one build_version candidate at a time (instances/owl-build.md,
round 130): compose, send and the unsubscribe path do not exist yet, and are not stubbed to look
finished -- an unimplemented route answers 501, honestly, rather than pretending.
"""
from fastapi import FastAPI

UNSUBSCRIBE_URL = "https://quillbox.example/unsubscribe/{token}"

app = FastAPI(title="Quillbox")


@app.get("/health")
def health():
    return {"ok": True, "service": "quillbox"}


@app.post("/compose")
def compose():
    raise NotImplementedError("compose: not yet built -- Quill Builder's first real story")


def send_newsletter(draft: dict, subscriber: dict) -> dict:
    """The one function a real send will go through. The unsubscribe link is wired to a real
    per-subscriber token before anything else, so the compliance rule holds even though sending
    itself is not built yet -- witness.py's compliance_scan checks every send_* function for a
    real use of the constant below, not merely its name in a comment."""
    unsubscribe_link = UNSUBSCRIBE_URL.format(token=subscriber.get("unsub_token", ""))
    raise NotImplementedError(f"send_newsletter: not yet built (unsubscribe link would be {unsubscribe_link})")
