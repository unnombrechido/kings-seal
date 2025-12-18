import qrcode
from io import BytesIO
import hmac
import hashlib
import json
import base64
import os

# Load registry
with open('registry.json') as f:
    registry = json.load(f)

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "buff.ly", "short.url"]

def has_shortened_url(payload: str) -> bool:
    return any(short in payload.lower() for short in SHORTENERS)

def generate_sealed_qr(issuer_id: str, payload: str, output_folder="examples"):
    if issuer_id not in registry:
        raise ValueError(f"Unknown issuer: {issuer_id}")
    
    entry = registry[issuer_id]
    secret = entry["secret"].encode('utf-8')
    
    data_to_sign = payload.encode('utf-8')
    mac = hmac.new(secret, data_to_sign, hashlib.sha256)
    tag = mac.hexdigest()[:16]  # 64-bit security, tiny size
    
    qr_content = f"seal:{issuer_id}|tag:{tag}|{payload}"
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(qr_content)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    os.makedirs(output_folder, exist_ok=True)
    filename = f"{issuer_id.replace('-', '_')}_{hash(payload) % 10000}.png"
    filepath = os.path.join(output_folder, filename)
    img.save(filepath)
    print(f"Sealed QR saved: {filepath}")
    print(f"   Payload: {payload}")
    print(f"   Trusted issuer: {entry['display_name']}")
    if has_shortened_url(payload):
        print("   (Shortened URL detected — seal enforced)")

# -----------------------------
# Examples — run these
# -----------------------------
if __name__ == "__main__":
    os.makedirs("examples", exist_ok=True)
    
    generate_sealed_qr("starbucks-official", "https://bit.ly/starbucks-menu-2025")
    generate_sealed_qr("mcdonalds-official", "https://mcd.co/happy-meal-promo")
    generate_sealed_qr("my-personal-site", "https://myblog.com/about")
    generate_sealed_qr("starbucks-official", "https://starbucks.com/direct-no-shortener")  # direct link
