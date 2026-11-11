# OWASP ACS Policy Engine (`v1.0.0`)

**Agent Bill of Materials (AgBOM) AST Scanner & Cryptographic Call-Graph Enforcer**

![Architecture](https://img.shields.io/badge/OWASP-Agent_Control_Standard-00ff9d?style=flat-square)
![Cryptography](https://img.shields.io/badge/Tokens-Ed25519_Macaroons-ff3366?style=flat-square)

## Overview
Business Logic Abuse (where an agent is tricked into calling valid APIs out of sequence) is the #1 enterprise failure mode for autonomous systems. Standard WAFs and MCP gateways evaluate tool calls in isolation, completely blind to the state machine.

This engine implements the **OWASP Agent Control Standard (ACS)**:
1. **AST AgBOM Scanner:** Statically analyzes agent repositories via Python's `ast` module to discover shadow tools, models, and MCP bindings, generating a cryptographically signed manifest.
2. **Ed25519 Capability Macaroons:** Replaces static API keys with chained, attenuated tokens. Every state transition appends an HMAC-SHA256 caveat. 
3. **Directed Acyclic Graph (DAG) Enforcer:** Deterministically drops tool calls if the cryptographic proof-of-transit does not match the strict enterprise DAG policy.

---

## Quickstart

```bash
pip install -r requirements.txt

# 1. Run the Cryptographic Exploit & DAG Validation Suite
pytest -v

# 2. Launch the ACS Control Plane
python -m app.main
# Open http://127.0.0.1:8081
```
