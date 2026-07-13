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
ALLOWED_OPT_LEVELS = {0, 1, 2}  # level 3 is pathologically expensive — never needed here

class TranspileRequest(BaseModel):
    qasm: str = Field(max_length=MAX_QASM_CHARS)
    basis_gates: list[str] | None = None
    optimization_level: int = 1

@app.get("/")
def health():
    return {"ok": True, "service": "qrun-transpiler", "status": "alive"}

@app.post("/transpile")
def do_transpile(req: TranspileRequest, x_qrun_key: str | None = Header(default=None)):
    expected = os.environ.get("TRANSPILER_KEY", "").strip()
    if expected and (x_qrun_key or "").strip() != expected:
        raise HTTPException(status_code=401, detail="unauthorized")
    try:
        circuit = loads(req.qasm)
        if circuit.num_qubits > MAX_QUBITS:
            return {"ok": False, "error": f"circuit too large ({circuit.num_qubits} qubits > {MAX_QUBITS})"}
        level = req.optimization_level if req.optimization_level in ALLOWED_OPT_LEVELS else 1
        basis = req.basis_gates or HERON_BASIS
        isa = transpile(
            circuit,
            basis_gates=basis,
            optimization_level=level,
        )
        return {
            "ok": True,
            "qasm": dumps(isa),
            "num_qubits": isa.num_qubits,
            "depth": isa.depth(),
        }
    except HTTPException:
        raise
    except Exception as e:
        return {"ok": False, "error": str(e)}
