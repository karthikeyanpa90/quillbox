# -*- coding: utf-8 -*-
"""Fixtures for the platform tests: a real OWL, over real HTTP, and a real Quillbox adapter beside it.

These tests exercise the plumbing between Quillbox and OWL -- who can deliver a reading, what OWL ends up
holding, and what Quill Agent will and will not decide on. They are deliberately NOT under tests/, which is the
product's own acceptance suite and the thing the witness measures; work on the plumbing must not be able to move
a number about the product (round 140).

They run against the real OWL application, imported from the sibling checkout, not a stand-in for it. A stub that
agreed with Quillbox about what a signature is would prove nothing -- the whole point of the round is that the
provider and the verifier are different parties.

Run with OWL's virtualenv, which has both sides' dependencies:
    C:\\acresgo\\owl\\.venv\\Scripts\\python.exe -m pytest platform_tests -q
"""
import os
import shutil
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

os.environ["OWL_AUTOAPP"] = "0"
QUILLBOX = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(QUILLBOX))
sys.path.insert(0, r"C:\acresgo\owl")

import uvicorn  # noqa: E402
from owl.api.app import make_app  # noqa: E402
from owl.api.service import Service  # noqa: E402
from owl.store.memory import MemoryStore  # noqa: E402


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    return port


def _serve(app, port):
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(200):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close(); return server
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("server did not come up")


@pytest.fixture
def owl():
    """A live OWL on localhost with an in-memory store. Yields (base_url, service)."""
    svc = Service(MemoryStore(), url_check=lambda url: None)      # the adapter under test runs on 127.0.0.1
    port = _free_port(); server = _serve(make_app(svc), port)
    try:
        yield f"http://127.0.0.1:{port}", svc
    finally:
        server.should_exit = True


@pytest.fixture
def quillbox(tmp_path):
    """A live Quillbox adapter on localhost, rooted in a throwaway copy of the repository, so that /apply's
    rmtree+copytree never touches the real working tree. Yields (base_url, adapter_secret, root)."""
    import service as qb_service
    root = tmp_path / "qb"
    root.mkdir()
    shutil.copytree(QUILLBOX / "candidates", root / "candidates", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(QUILLBOX / "quillbox_app", root / "quillbox_app", ignore=shutil.ignore_patterns("__pycache__"))
    old = (qb_service.ROOT, qb_service.CANDIDATES, qb_service.LIVE_APP)
    qb_service.ROOT, qb_service.CANDIDATES, qb_service.LIVE_APP = root, root / "candidates", root / "quillbox_app"
    secret = "adapter-secret-for-the-test"
    port = _free_port()
    server = _serve(qb_service.make_app(qb_service.QuillboxAdapter(), sid="sid", adapter_secret=secret), port)
    try:
        yield f"http://127.0.0.1:{port}", secret, root
    finally:
        server.should_exit = True
        qb_service.ROOT, qb_service.CANDIDATES, qb_service.LIVE_APP = old
