# -*- coding: utf-8 -*-
"""Quillbox v1 -- Quill Builder's first real candidate. Built to the one story that was failing
and nothing else: "a creator can compose a draft" (tests/test_story_compose_and_send.py, read-only
to this builder, never edited to make it pass). send_newsletter is untouched from v0 -- still not
built, still honestly raising NotImplementedError -- so this candidate is exactly one story ahead,
not a rewrite.
"""
import uuid

from fastapi import FastAPI

UNSUBSCRIBE_URL = "https://quillbox.example/unsubscribe/{token}"

app = FastAPI(title="Quillbox")

_drafts: dict = {}


@app.get("/health")
def health():
    return {"ok": True, "service": "quillbox"}


@app.post("/compose")
def compose(body: dict):
    draft_id = str(uuid.uuid4())
    _drafts[draft_id] = {"subject": body.get("subject", ""), "body": body.get("body", "")}
    return {"draft_id": draft_id, **_drafts[draft_id]}


def send_newsletter(draft: dict, subscriber: dict) -> dict:
    """Unchanged from v0: not this candidate's story, still not built."""
    unsubscribe_link = UNSUBSCRIBE_URL.format(token=subscriber.get("unsub_token", ""))
    raise NotImplementedError(f"send_newsletter: not yet built (unsubscribe link would be {unsubscribe_link})")
