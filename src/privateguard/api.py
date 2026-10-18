from __future__ import annotations
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from .service import scan, sanitize_file, encrypt_file
from .audit import verify_audit
from .crypto_service import initialize

app = FastAPI(title="PrivateGuard Local API", version="0.1.0", description="Local-only MVP API; bind to localhost.")

class PathRequest(BaseModel):
    path: str

class TransformRequest(BaseModel):
    path: str
    output_path: str

@app.get("/health")
def health(): return {"status": "ok", "mode": "local"}

@app.post("/init")
def init(): return {"home": str(initialize())}

@app.post("/scan")
def scan_endpoint(body: PathRequest):
    try: return scan(body.path)
    except Exception as exc: raise HTTPException(status_code=400, detail=type(exc).__name__) from exc

@app.post("/sanitize")
def sanitize_endpoint(body: TransformRequest):
    try: return sanitize_file(body.path, body.output_path)
    except Exception as exc: raise HTTPException(status_code=400, detail=type(exc).__name__) from exc

@app.post("/encrypt")
def encrypt_endpoint(body: TransformRequest):
    try: return encrypt_file(body.path, body.output_path)
    except Exception as exc: raise HTTPException(status_code=400, detail=type(exc).__name__) from exc

@app.get("/audit/verify")
def audit_verify(): return verify_audit()
