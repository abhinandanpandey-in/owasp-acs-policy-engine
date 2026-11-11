import networkx as nx
from app.models import ToolCallRequest
from app.crypto_macaroon import MacaroonEngine

class CallGraphEnforcer:
    def __init__(self, crypto_engine: MacaroonEngine):
        self.crypto = crypto_engine
        self.dag = nx.DiGraph()
        self._build_enterprise_policy()

    def _build_enterprise_policy(self):
        # Strict state transitions: INIT -> scan -> approval -> drop_db
        self.dag.add_edge("INIT", "scan_repository")
        self.dag.add_edge("scan_repository", "human_approval_webhook")
        self.dag.add_edge("human_approval_webhook", "delete_database")

    def evaluate_call(self, req: ToolCallRequest) -> dict:
        if not self.crypto.verify_chain(req.token):
            return {"status": "DENIED", "reason": "CRYPTOGRAPHIC_SIGNATURE_INVALID"}
            
        states = [req.token.caveats[0]]
        for cav in req.token.caveats[1:]:
            states.append(cav.split('|')[0])
            
        current_state = states[-1]
        attempted_state = req.tool_name

        if not self.dag.has_node(attempted_state):
            return {"status": "DENIED", "reason": f"TOOL_NOT_IN_DAG: {attempted_state}"}

        if not self.dag.has_edge(current_state, attempted_state):
            expected = list(self.dag.predecessors(attempted_state))
            return {"status": "DENIED", "reason": f"DAG_TRANSITION_VIOLATION: Must transit {expected} before {attempted_state}"}
            
        new_token = self.crypto.attenuate(req.token, attempted_state)
        return {"status": "ALLOWED", "reason": "CRYPTOGRAPHIC_TRANSITION_VALID", "new_token": new_token.model_dump()}
