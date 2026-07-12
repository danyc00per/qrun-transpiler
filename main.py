# QRUN Transpiler Service — takes QASM3 + target gates, returns native QASM3.
from fastapi import FastAPI
from pydantic import BaseModel
from qiskit import transpile
from qiskit.qasm3 import loads, dumps

app = FastAPI()

# IBM Heron native basis gates (works for ibm_fez / kingston / marrakesh)
HERON_BASIS = ["rz", "sx", "x", "cz", "id"]

class TranspileRequest(BaseModel):
    qasm: str
    basis_gates: list[str] | None = None
    optimization_level: int = 1

@app.get("/")
def health():
    return {"ok": True, "service": "qrun-transpiler", "status": "alive"}

@app.post("/transpile")
def do_transpile(req: TranspileRequest):
    try:
        circuit = loads(req.qasm)
        basis = req.basis_gates or HERON_BASIS
        isa = transpile(
            circuit,
            basis_gates=basis,
            optimization_level=req.optimization_level,
        )
        return {
            "ok": True,
            "qasm": dumps(isa),
            "num_qubits": isa.num_qubits,
            "depth": isa.depth(),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}
