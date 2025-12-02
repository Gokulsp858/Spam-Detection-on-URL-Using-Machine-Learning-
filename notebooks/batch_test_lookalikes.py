# notebooks/batch_test_lookalikes.py
# Test lookalike/homograph detection
import requests
import json

API_BASE = "http://localhost:5000"
URLS = [
    "https://www.onlinebanking.example.com/",   # legit pattern
    "https://www.onlinebɑnking.example.com/",  # uses Latin small letter alpha (U+0251) - visually similar
    "http://xn--nlinebanking-2lb.example.com/", # punycode
    "https://paypaI.com",  # capital i vs L
    "https://micros0ft.com", # zero instead of o
    "https://secure-appleid.example.com/login",
]

def check(u):
    try:
        r = requests.post(f"{API_BASE}/check", json={"url": u}, timeout=10)
        return r.json()
    except Exception as e:
        return {"url": u, "error": str(e)}

if __name__ == "__main__":
    for u in URLS:
        res = check(u)
        print(json.dumps({
            "url": u,
            "status": res.get("status"),
            "threat_type": res.get("threat_type"),
            "confidence": res.get("confidence"),
            "risk": res.get("risk"),
            "lookalike": (res.get("details") or {}).get("lookalike"),
            "has_punycode": (res.get("details") or {}).get("has_punycode"),
        }, ensure_ascii=False))