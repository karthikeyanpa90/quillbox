# -*- coding: utf-8 -*-
"""Phase 2: grow system F's Definition to admit v1, register its real adapter against the Cloud
Run URL it will have once deployed (predictable from the service name, same as every other tenant
here), re-derive connector secrets (register_connector is safe to call again -- it just issues a
fresh secret for the same measure), and write the full .deploy-env.yaml the actual deploy needs.
Reads SID/OWNER_KEY/RUNTIME_KEY from the gitignored .deploy-env.yaml register.py already wrote --
never hardcoded here, since this file is meant to be committed and this repo is public.

Usage:  C:\\acresgo\\quillbox\\.venv\\Scripts\\python.exe grow_and_wire.py
"""
import json
import re
import secrets
import sys

sys.path.insert(0, r"C:\acresgo\quillbox")

import truststore  # noqa: E402
truststore.inject_into_ssl()
import httpx  # noqa: E402

from agent import QuillAgent  # noqa: E402

OWL_BASE = "https://owl-120680828302.asia-south1.run.app"
QB_BASE = "https://quillbox-120680828302.asia-south1.run.app"
ENV_FILE = r"C:\acresgo\quillbox\.deploy-env.yaml"


def _read_env_file() -> dict:
    text = open(ENV_FILE, encoding="utf-8").read()
    return {m.group(1): m.group(2) for m in re.finditer(r'^(\w+):\s*"((?:[^"\\]|\\.)*)"', text, re.MULTILINE)}


if __name__ == "__main__":
    existing = _read_env_file()
    SID, OWNER_KEY, RUNTIME_KEY = existing["QB_SID"], existing["QB_OWNER_KEY"], existing["QB_RUNTIME_KEY"]
    owl = httpx.Client(base_url=OWL_BASE, timeout=20.0)
    agent = QuillAgent(owl, sid=SID, owner_key=OWNER_KEY, runtime_key=RUNTIME_KEY)

    grown = agent.grow_build_version("v1")
    print(f"grown: {json.dumps(grown)}")

    adapter_secret = agent.register_adapter(QB_BASE)
    print(f"adapter registered against {QB_BASE}")

    owner = agent._owner_hdr()
    connector_secrets = {}
    for measure, kind in [("critical_defects", "sast_scanner"), ("coverage", "ci_pipeline"),
                           ("compliance_pass", "compliance_scanner"), ("story_completion", "acceptance_test_runner")]:
        r = owl.post(f"/v1/systems/{SID}/connectors", json={"measure": measure, "kind": kind}, headers=owner)
        r.raise_for_status()
        connector_secrets[measure] = r.json()["secret"]
    print(f"connector secrets re-derived for: {list(connector_secrets)}")

    driver_key = "qb_driver_" + secrets.token_urlsafe(24)
    env = {
        "QB_SID": SID, "QB_OWNER_KEY": OWNER_KEY, "QB_RUNTIME_KEY": RUNTIME_KEY,
        "QB_ADAPTER_SECRET": adapter_secret, "QB_CONNECTOR_SECRETS": json.dumps(connector_secrets),
        "QB_OWL_BASE_URL": OWL_BASE, "QB_DRIVER_KEY": driver_key,
    }
    with open(ENV_FILE, "w", encoding="utf-8") as f:
        for k, v in env.items():
            f.write(f'{k}: {json.dumps(v)}\n')
    print(f"wrote {ENV_FILE}")
