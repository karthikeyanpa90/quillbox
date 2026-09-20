# -*- coding: utf-8 -*-
"""Run real check-ins against the live system. "Check-in" not "week": n is a sequential index of real evaluation
events, never a calendar unit (round 134, P31).

Replaces run_trial.py, which called the adapter's /check-in -- the endpoint round 140 deleted, because a reading
produced inside the graded application is not evidence. A check-in is now one execution of the witness job.

Usage:  .venv/Scripts/python.exe run_checkin.py [n_checkins]
        .venv/Scripts/python.exe run_checkin.py promote <candidate> <current>
"""
import json
import sys

sys.path.insert(0, r"C:\acresgo\quillbox")

import truststore  # noqa: E402
truststore.inject_into_ssl()
import httpx  # noqa: E402

from agent import QuillAgent  # noqa: E402
from qb_env import read_env  # noqa: E402
from run_witness import cloud_run_witness  # noqa: E402

QB_BASE = "https://quillbox-120680828302.asia-south1.run.app"


def build_agent(env):
    return QuillAgent(httpx.Client(base_url=env["QB_OWL_BASE_URL"], timeout=40.0),
                      sid=env["QB_SID"], owner_key=env["QB_OWNER_KEY"], runtime_key=env["QB_RUNTIME_KEY"],
                      qb=httpx.Client(base_url=QB_BASE, timeout=40.0), adapter_secret=env["QB_ADAPTER_SECRET"],
                      witness_runner=cloud_run_witness)


if __name__ == "__main__":
    env = read_env()
    agent = build_agent(env)
    st0 = agent.owl.get(f"/v1/systems/{env['QB_SID']}", headers=agent._owner_hdr()).json()
    live = (st0.get("x") or {}).get("build_version")
    start = (st0.get("week") or 0) + 1                        # "week" is OWL's own status field name, unrenamed
    print(f"live build_version {live}, starting from check-in {start}, counts: {st0.get('counts')}")

    if len(sys.argv) > 1 and sys.argv[1] == "promote":
        candidate, current = sys.argv[2], sys.argv[3]
        print(json.dumps(agent.promote_if_better(candidate, current, start), indent=2, default=str))
    else:
        for n in range(start, start + (int(sys.argv[1]) if len(sys.argv) > 1 else 1)):
            readings = agent.measure(live, n)
            print(f"check-in {n}: {json.dumps(readings, default=str)}")

    final = agent.owl.get(f"/v1/systems/{env['QB_SID']}", headers=agent._owner_hdr()).json()
    ver = agent.owl.get(f"/v1/systems/{env['QB_SID']}/ledger/verify", headers=agent._owner_hdr()).json()
    print("\n== final status ==")
    print(json.dumps(final, indent=2))
    print(f"ledger verifies: {ver}")
