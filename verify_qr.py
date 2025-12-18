import hmac
import hashlib
import json
import re

# Load registry
with open('registry.json') as f:
    registry = json.load(f)

def verify_sealed_qr(qr_content: str) -> dict:
    if not qr_content.startswith("seal:"):
        return {"trusted": False, "level": "unverified", "reason": "No seal prefix"}
    
    try:
        parts = qr_content.split("|", 2)
        if len(parts) != 3:
            return {"trusted": False, "level": "unverified", "reason": "Invalid format"}
        
        seal_part, tag_part, payload = parts
        issuer_id = seal_part.split(":", 1)[1]
        provided_tag = tag_part.split(":", 1)[1]
        
        if issuer_id not in registry:
            return {"trusted": False, "level": "unverified", "reason": "Unknown issuer"}
        
        entry = registry[issuer_id]
        secret = entry["secret"].encode('utf-8')
        data_to_sign = payload.encode('utf-8')
        mac = hmac.new(secret, data_to_sign, hashlib.sha256)
        expected_tag = mac.hexdigest()[:16]
        
        if hmac.compare_digest(expected_tag, provided_tag):
            return {
                "trusted": True,
                "level": "official",
                "issuer_name": entry["display_name"],
                "payload": payload
            }
        else:
            return {"trusted": False, "level": "unverified", "reason": "Invalid tag — possible tampering"}
    
    except Exception as e:
        return {"trusted": False, "level": "unverified", "reason": f"Error: {str(e)}"}

# -----------------------------
# Test with generated examples
# -----------------------------
if __name__ == "__main__":
    # Paste a real QR string here after generating, or test these:
    tests = [
        "seal:starbucks-official|tag:correcttaghere|https://bit.ly/starbucks-menu-2025",  # replace tag with real one from generate output
        "seal:starbucks-official|tag:wrongwrong1234|https://bit.ly/starbucks-menu-2025",  # tampered
        "https://normal-site.com/no-seal",  # unsealed
    ]
    
    for t in tests:
        result = verify_sealed_qr(t)
        print("QR Content:", t)
        print("Result:", result)
        print("-" * 50)
