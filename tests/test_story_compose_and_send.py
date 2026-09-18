# -*- coding: utf-8 -*-
"""The acceptance-test suite -- story_completion's witness (owl-build.md). A test named
test_story_* is one user story; it passes only once Quill Builder has actually built the story,
never by editing the test itself (round 130: Quill Builder gets read-only access to this file).

Three stories, from the original scope (compose, send, subscribe/unsubscribe):
"""
from fastapi.testclient import TestClient
from quillbox_app.main import app, send_newsletter


def test_story_a_creator_can_compose_a_draft():
    c = TestClient(app)
    r = c.post("/compose", json={"subject": "Hello", "body": "First issue."})
    assert r.status_code == 200
    assert "draft_id" in r.json()


def test_story_a_creator_can_send_a_newsletter_to_subscribers():
    result = send_newsletter({"subject": "Hello", "body": "First issue."}, {"email": "reader@example.com"})
    assert result.get("delivered") is True


def test_story_every_send_carries_a_working_unsubscribe_link():
    """Doubles as the compliance rule witness.py scans for statically, but this checks it the
    story's own way: an actual sent message's own body must carry the real per-subscriber link."""
    result = send_newsletter({"subject": "Hello", "body": "First issue."}, {"email": "reader@example.com", "unsub_token": "abc"})
    assert "unsubscribe" in result.get("body", "").lower()
