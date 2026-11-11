import ast
from pathlib import Path
from app.models import AgBOMManifest, AgBOMComponent
from app.crypto_macaroon import MacaroonEngine
import base64

class ASTAgentScanner:
    def __init__(self, crypto_engine: MacaroonEngine):
        self.crypto_engine = crypto_engine

    def scan_directory(self, target_dir: Path) -> AgBOMManifest:
        components = []
        for py_file in target_dir.rglob("*.py"):
            try:
                tree = ast.parse(py_file.read_text(encoding='utf-8'))
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        for dec in node.decorator_list:
                            # Catch @tool or @mcp.tool decorators via AST
                            if getattr(dec, 'id', '') == 'tool' or (isinstance(dec, ast.Call) and getattr(dec.func, 'id', '') == 'tool'):
                                components.append(AgBOMComponent(name=node.name, type="tool", properties={"file": py_file.name}))
                            elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr == 'tool':
                                components.append(AgBOMComponent(name=node.name, type="mcp_server_tool", properties={"file": py_file.name}))
            except Exception:
                pass
                
        manifest = AgBOMManifest(agent_name="target_agent_repo", version="1.0.0", components=components)
        payload = manifest.model_dump_json(exclude={"signature"}).encode('utf-8')
        sig = self.crypto_engine.private_key.sign(payload)
        manifest.signature = base64.urlsafe_b64encode(sig).decode('utf-8')
        return manifest
