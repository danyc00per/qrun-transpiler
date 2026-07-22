# QRUN Transpiler Service — takes QASM3 + target gates, returns native QASM3.
# Hardened: optional shared-key auth + input caps (this service is a critical
# link in the IBM run chain — a public unbounded endpoint invites DoS/abuse).
#
# Auth model (progressive rollout, nothing breaks mid-deploy):
#   • If env var TRANSPILER_KEY is set on Render → every /transpile call MUST
#     send header  X-QRUN-KEY: <that value>  (401 otherwise).
#   • If TRANSPILER_KEY is not set → open (legacy behavior).
# Deploy order: 1) this file + the ibm.js that sends the header,
#               2) set IBM_TRANSPILER_KEY on Vercel,
#               3) set TRANSPILER_KEY (same value) on Render → locked.
import os
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from qiskit import transpile
from qiskit.qasm3 import loads, dumps

app = FastAPI()

# IBM Heron native basis gates (works for ibm_fez / kingston / marrakesh)
HERON_BASIS = ["rz", "sx", "x", "cz", "id"]
MAX_QASM_CHARS = 20_000   # a legit QRUN circuit is well under this
MAX_QUBITS = 200          # hard cap after parsing (Heron r2 = 156)
MAX_COUPLING_PAIRS = 2_000  # Heron r2 has ~176 edges; this is generous headroom
ALLOWED_OPT_LEVELS = {0, 1, 2}  # level 3 is pathologically expensive — never needed here


class TranspileRequest(BaseModel):
    qasm: str = Field(max_length=MAX_QASM_CHARS)
    basis_gates: list[str] | None = None
    optimization_level: int = 1
    # Which qubits are physically wired together on the target chip.
    # basis_gates says WHICH gates exist; coupling_map says WHICH PAIRS they can
    # act on. Without it, transpile() assumes an all-to-all machine and happily
    # emits e.g. "cz q[0], q[2]" — which IBM then refuses at submission time:
    #   "the instruction cz on qubits (0, 2) is not supported by the target system"
    # Given the map, Qiskit inserts the SWAPs needed to route onto real wiring.
    # Optional: None → previous behaviour, so this deploys in any order.
    coupling_map: list[list[int]] | None = None


@app.get("/")
def health():
    return {"ok": True, "service": "qrun-transpiler", "status": "alive"}


@app.post("/transpile")
def do_transpile(req: TranspileRequest, x_qrun_key: str | None = Header(default=None)):
    expected = os.environ.get("TRANSPILER_KEY", "").strip()
    # FAIL CLOSED. Previously `if expected and ...`: a missing or mistyped
    # TRANSPILER_KEY silently made this service public, and the repo is public
    # so the endpoint is known. No key configured now means nobody gets in.
    if not expected or (x_qrun_key or "").strip() != expected:
        raise HTTPException(status_code=401, detail="unauthorized")
    try:
        circuit = loads(req.qasm)
        if circuit.num_qubits > MAX_QUBITS:
            return {"ok": False, "error": f"circuit too large ({circuit.num_qubits} qubits > {MAX_QUBITS})"}
        level = req.optimization_level if req.optimization_level in ALLOWED_OPT_LEVELS else 1
        basis = req.basis_gates or HERON_BASIS

        # Same caps philosophy as the QASM: refuse absurd input rather than let
        # Qiskit chew on it. A malformed map is worse than no map — routing onto
        # imaginary wiring produces a circuit the QPU rejects — so we drop it and
        # fall back to the old behaviour instead of guessing.
        coupling = req.coupling_map
        if coupling is not None:
            if len(coupling) > MAX_COUPLING_PAIRS or not all(
                isinstance(p, list) and len(p) == 2 and all(isinstance(q, int) and q >= 0 for q in p)
                for p in coupling
            ):
                coupling = None

        isa = transpile(
            circuit,
            basis_gates=basis,
            coupling_map=coupling,
            optimization_level=level,
        )
        return {
            "ok": True,
            "qasm": dumps(isa),
            "num_qubits": isa.num_qubits,
            "depth": isa.depth(),
            # Lets the caller confirm the map was actually honoured rather than
            # silently ignored — the failure mode this whole change exists to fix.
            "routed": coupling is not None,
        }
    except HTTPException:
        raise
    except Exception as e:
        return {"ok": False, "error": str(e)}
