# -*- coding: utf-8 -*-
"""A plain unit test, not a story -- coverage's witness, not story_completion's."""
from fastapi.testclient import TestClient
from quillbox_app.main import app


def test_health_reports_ok():
    c = TestClient(app)
    r = c.get("/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True
