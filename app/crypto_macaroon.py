import json
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from app.models import AttenuatedToken

class MacaroonEngine:
    def __init__(self):
        # Generate a real Ed25519 keypair for signing root capabilities
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        # HMAC secret for chaining caveats
        self.caveat_secret = b'static_secret_for_demo_purposes_only'

    def mint_root_token(self, session_id: str, initial_state: str) -> AttenuatedToken:
        payload = f"{session_id}:{initial_state}".encode('utf-8')
        signature = self.private_key.sign(payload)
        return AttenuatedToken(
            root_id=session_id,
            signature=base64.urlsafe_b64encode(signature).decode('utf-8'),
            caveats=[initial_state]
        )

    def attenuate(self, token: AttenuatedToken, next_state: str) -> AttenuatedToken:
        """Appends a state transition caveat using HMAC-SHA256 chain."""
        current_chain = ":".join(token.caveats).encode('utf-8')
        h = hmac.new(self.caveat_secret, current_chain, hashlib.sha256)
        h.update(next_state.encode('utf-8'))
        caveat_proof = base64.urlsafe_b64encode(h.digest()).decode('utf-8')
        
        new_token = AttenuatedToken(
            root_id=token.root_id,
            signature=token.signature,
            caveats=token.caveats.copy()
        )
        new_token.caveats.append(f"{next_state}|{caveat_proof}")
        return new_token

    def verify_chain(self, token: AttenuatedToken) -> bool:
        """Verifies the Ed25519 root signature and the entire HMAC caveat chain."""
        if not token.caveats:
            return False
            
        initial_state = token.caveats[0]
        payload = f"{token.root_id}:{initial_state}".encode('utf-8')
        try:
            sig_bytes = base64.urlsafe_b64decode(token.signature)
            self.public_key.verify(sig_bytes, payload)
        except Exception:
            return False

        current_chain_str = initial_state
        for caveat in token.caveats[1:]:
            parts = caveat.split('|')
            if len(parts) != 2:
                return False
            next_state, proof = parts
            
            h = hmac.new(self.caveat_secret, current_chain_str.encode('utf-8'), hashlib.sha256)
            h.update(next_state.encode('utf-8'))
            expected_proof = base64.urlsafe_b64encode(h.digest()).decode('utf-8')
            
            if not hmac.compare_digest(proof, expected_proof):
                return False
            current_chain_str += f":{caveat}"
            
        return True
