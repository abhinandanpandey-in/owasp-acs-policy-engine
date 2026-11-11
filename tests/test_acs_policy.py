import pytest
from app.crypto_macaroon import MacaroonEngine
from app.dag_enforcer import CallGraphEnforcer
from app.models import ToolCallRequest

@pytest.fixture
def enforcer():
    crypto = MacaroonEngine()
    return CallGraphEnforcer(crypto), crypto

def test_valid_dag_transit_chain(enforcer):
    enf, crypto = enforcer
    token = crypto.mint_root_token("sess-test", "INIT")
    
    req1 = ToolCallRequest(tool_name="scan_repository", arguments={}, token=token)
    res1 = enf.evaluate_call(req1)
    assert res1["status"] == "ALLOWED"
    
    req2 = ToolCallRequest(tool_name="human_approval_webhook", arguments={}, token=res1["new_token"])
    res2 = enf.evaluate_call(req2)
    assert res2["status"] == "ALLOWED"

def test_business_logic_skip_blocked(enforcer):
    enf, crypto = enforcer
    token = crypto.mint_root_token("sess-test", "INIT")
    
    req = ToolCallRequest(tool_name="delete_database", arguments={}, token=token)
    res = enf.evaluate_call(req)
    assert res["status"] == "DENIED"
    assert "DAG_TRANSITION_VIOLATION" in res["reason"]

def test_forged_cryptographic_token_blocked(enforcer):
    enf, crypto = enforcer
    token = crypto.mint_root_token("sess-test", "INIT")
    
    # Tamper with caveat chain
    token.caveats.append("human_approval_webhook|fake_hmac_hash")
    req = ToolCallRequest(tool_name="delete_database", arguments={}, token=token)
    res = enf.evaluate_call(req)
    
    assert res["status"] == "DENIED"
    assert res["reason"] == "CRYPTOGRAPHIC_SIGNATURE_INVALID"
