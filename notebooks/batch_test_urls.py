# notebooks/batch_test_urls.py
# Quickly batch-test URLs against the running backend
import os
import json
import requests

API_BASE = os.getenv("API_BASE", "http://localhost:5000")

TEST_URLS = [
    # Safe
    "https://google.com",
    "https://github.com",
    "https://www.reddit.com",
    # Phishing-like
    "http://paypal.security.verify-login.ru",
    "http://secure-amazon.login-page.com",
    "http://login.paypal.verify.ru",
    # Malware-like
    "http://malware.com/download.exe",
    "http://virusfile.host/bad.exe",
    # Shorteners / suspicious
    "http://bit.ly/xyz123abc",
    "http://tinyurl.com/badexe",
    "http://update-now.security-info.zip",
    # Punycode / subdomain tricks
    "http://xn--pple-43d.com",
    "http://very.long.sub.domain.attacker.example.xyz/login",
]


def check(url: str):
    try:
        r = requests.post(f"{API_BASE}/check", json={"url": url}, timeout=10)
        data = r.json()
        return {
            "url": url,
            "status": data.get("status"),
            "threat_type": data.get("threat_type"),
            "confidence": data.get("confidence"),
            "source": data.get("source"),
            "risk": data.get("risk"),
        }
    except Exception as e:
        return {"url": url, "error": str(e)}


if __name__ == "__main__":
    print(f"Testing against backend: {API_BASE}")
    results = [check(u) for u in TEST_URLS]
    for r in results:
        print(json.dumps(r, ensure_ascii=False))