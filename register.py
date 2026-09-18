# -*- coding: utf-8 -*-
"""Register system F on the real, live OWL service, then run its first real weeks -- witness.py's
genuine numbers against the v0 skeleton, pushed and cycled for real, no different from how every
other tenant here goes live (see cartway/onboard_live.py for the pattern this mirrors).

Usage:  C:\\acresgo\\quillbox\\.venv\\Scripts\\python.exe register.py
"""
import json
import sys

sys.path.insert(0, r"C:\acresgo\quillbox")

import truststore  # noqa: E402
truststore.inject_into_ssl()
import httpx  # noqa: E402

from agent import QuillAgent  # noqa: E402
from witness import witness_report  # noqa: E402

OWL_BASE = "https://owl-120680828302.asia-south1.run.app"
ENV_FILE = r"C:\acresgo\quillbox\.deploy-env.yaml"

if __name__ == "__main__":
    owl = httpx.Client(base_url=OWL_BASE, timeout=20.0)
    agent = QuillAgent(owl, witness_fn=witness_report)
    keys = agent.register()
    print(f"system id: {agent.sid}")
    print(f"owner_key: {agent.owner_key}")
    print(f"runtime_key: {agent.runtime_key}")

    with open(ENV_FILE, "w", encoding="utf-8") as f:
        f.write(f'QB_SID: "{agent.sid}"\n')
        f.write(f'QB_OWNER_KEY: "{agent.owner_key}"\n')
        f.write(f'QB_RUNTIME_KEY: "{agent.runtime_key}"\n')
    print(f"wrote {ENV_FILE}")

    for week in (1, 2, 3):
        result = agent.run_and_report_week(week)
        print(f"week {week}: report={result['report']}")
        print(f"  cycle: {json.dumps(result['cycle'])}")

    status = owl.get(f"/v1/systems/{agent.sid}", headers=agent._owner_hdr()).json()
    print("\n== status ==")
    print(json.dumps(status, indent=2))
