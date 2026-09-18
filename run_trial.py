# -*- coding: utf-8 -*-
"""Run real check-ins now that the adapter is live: Quillbox's own /check-in reports whatever's
currently applied, OWL's /cycle judges and, with a second build_version option now available,
may apply v1 as a real trial. Reads all keys from .deploy-env.yaml -- nothing hardcoded. "Check-in"
not "week" throughout -- n is a sequential index of real evaluation events, never a calendar unit
(round 134).

Usage:  C:\\acresgo\\quillbox\\.venv\\Scripts\\python.exe run_trial.py [n_checkins]
"""
import json
import sys

sys.path.insert(0, r"C:\acresgo\quillbox")

import truststore  # noqa: E402
truststore.inject_into_ssl()
import httpx  # noqa: E402

from grow_and_wire import _read_env_file  # noqa: E402

if __name__ == "__main__":
    n_checkins = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    env = _read_env_file()
    sid, owner_key, runtime_key, driver_key = env["QB_SID"], env["QB_OWNER_KEY"], env["QB_RUNTIME_KEY"], env["QB_DRIVER_KEY"]
    owl_base, qb_base = env["QB_OWL_BASE_URL"], "https://quillbox-120680828302.asia-south1.run.app"

    owl = httpx.Client(base_url=owl_base, timeout=30.0)
    qb = httpx.Client(base_url=qb_base, timeout=30.0)
    owner_hdr = {"Authorization": "Bearer " + owner_key}
    runtime_hdr = {"Authorization": "Bearer " + runtime_key}
    driver_hdr = {"Authorization": "Bearer " + driver_key}

    st0 = owl.get(f"/v1/systems/{sid}", headers=owner_hdr).json()
    start_n = (st0.get("week") or 0) + 1   # "week" is OWL's own status field name, unrenamed
    print(f"starting from check-in {start_n}, current live x: {st0.get('x')}, counts: {st0.get('counts')}")

    for n in range(start_n, start_n + n_checkins):
        rw = qb.post(f"/check-in/{n}", headers=driver_hdr)
        rw.raise_for_status()
        rc = owl.post(f"/v1/systems/{sid}/cycle/{n}", headers=runtime_hdr)
        rc.raise_for_status()
        qst = qb.get("/status").json()
        print(f"check-in {n}: report={rw.json()}  cycle={rc.json()}  quillbox_live_version={qst['live_version']}")

    final = owl.get(f"/v1/systems/{sid}", headers=owner_hdr).json()
    ver = owl.get(f"/v1/systems/{sid}/ledger/verify", headers=owner_hdr).json()
    print("\n== final status ==")
    print(json.dumps(final, indent=2))
    print(f"ledger verifies: {ver}")
