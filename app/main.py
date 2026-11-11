from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pathlib import Path
from app.crypto_macaroon import MacaroonEngine
from app.agbom_scanner import ASTAgentScanner
from app.dag_enforcer import CallGraphEnforcer
from app.models import ToolCallRequest
import uvicorn

app = FastAPI(title="OWASP ACS Policy Engine", version="1.0.0")

crypto_engine = MacaroonEngine()
scanner = ASTAgentScanner(crypto_engine)
enforcer = CallGraphEnforcer(crypto_engine)

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    html = Path(__file__).parent / "static" / "index.html"
    return html.read_text(encoding="utf-8")

@app.get("/v1/acs/agbom/scan")
async def scan_repo():
    target = Path(__file__).parent.parent / "target_agent_repo"
    manifest = scanner.scan_directory(target)
    return manifest.model_dump()

@app.post("/v1/acs/token/mint")
async def mint_token(session_id: str = "sess-001"):
    return crypto_engine.mint_root_token(session_id, "INIT").model_dump()

@app.post("/v1/acs/dag/evaluate")
async def evaluate_call(req: ToolCallRequest):
    return enforcer.evaluate_call(req)

if __name__ == "__main__":
    print("[*] Starting OWASP ACS Policy Engine on http://127.0.0.1:8081")
    uvicorn.run(app, host="127.0.0.1", port=8081)
