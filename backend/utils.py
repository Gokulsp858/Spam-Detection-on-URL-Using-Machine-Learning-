# backend/utils.py
# pylint: disable=broad-except, global-statement
import os
import re
import atexit
import pickle
import importlib
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

import requests
import skops.io as sio

# === Paths / config ===
MODEL_PATH = 'model.skops'            # existing legacy model (skops)
AI_MODEL_PATH = 'ai_model.pkl'        # new hybrid model saved by train_ai_model.py
EMBEDDER_NAME = 'all-MiniLM-L6-v2'   # transformer embedding model
# Google Safe Browsing config (unchanged)
GOOGLE_API_KEY = "AIzaSyCs1wm3B3PfsS87zp-Lzu4OrHgNYfZqB_s"
SB_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# === Thread pool for model batch predictions ===
_MODEL_EXECUTOR = ThreadPoolExecutor(max_workers=8)
atexit.register(_MODEL_EXECUTOR.shutdown)

# === Load legacy skops model (as before) ===
print(f"🔄 Loading legacy skops model from '{MODEL_PATH}'...")
legacy_model = None
try:
    untrusted_types = sio.get_untrusted_types(file=MODEL_PATH)
    print("🔍 Found untrusted types (safe to trust):", untrusted_types)
    legacy_model = sio.load(MODEL_PATH, trusted=untrusted_types)
    print("✅ Legacy skops model loaded.")
except Exception as e:  # noqa: BLE001
    print(f"⚠️ Could not load legacy model.skops: {e}. Continuing without it.")

# === Try loading AI model (pickle produced by train_ai_model.py) ===
ai_model = None
embedder = None
try:
    if os.path.exists(AI_MODEL_PATH):
        print(f"🔄 Loading AI model from '{AI_MODEL_PATH}' ...")
        with open(AI_MODEL_PATH, 'rb') as f:
            ai_model = pickle.load(f)
        print("✅ AI model loaded.")
    else:
        print(f"ℹ️ AI model file not found at '{AI_MODEL_PATH}'. AI inference disabled (will fallback to legacy model).")
except Exception as e:  # noqa: BLE001
    print(f"⚠️ Failed to load AI model: {e}")
    ai_model = None

# === Load sentence-transformers embedder lazily only if ai_model exists ===
if ai_model is not None:
    try:
        st_module = importlib.import_module("sentence_transformers")
        SentenceTransformer = getattr(st_module, "SentenceTransformer")
        print(f"🔄 Loading embedder '{EMBEDDER_NAME}' ... (this may download weights)")
        embedder = SentenceTransformer(EMBEDDER_NAME)
        print("✅ Embedder ready.")
    except ModuleNotFoundError as e:
        print(f"⚠️ Could not load embedder dependency: {e}. AI model disabled.")
        embedder = None
        ai_model = None   # disable AI model if embedder can't be loaded
    except Exception as e:  # noqa: BLE001
        print(f"⚠️ Could not initialize embedder: {e}. AI model disabled.")
        embedder = None
        ai_model = None


def _disable_ai_model(reason: str):
    """Gracefully disable AI pipeline when incompatibilities are detected."""
    global ai_model, embedder  # noqa: PLW0603
    if ai_model is not None:
        print(f"⚠️ Disabling AI model: {reason}")
    ai_model = None
    embedder = None


def _build_ai_input(urls):
    """
    Return numpy feature matrix for the AI model or None when not available/incompatible.
    Automatically disables AI model if feature dimensionality mismatches.
    """
    if ai_model is None or embedder is None:
        return None

    import numpy as _np
    features = _np.array([extract_features(u) for u in urls], dtype=float)

    try:
        embeddings = embedder.encode(urls, show_progress_bar=False, convert_to_numpy=True)
    except TypeError:
        embeddings = embedder.encode(urls)
    embeddings = _np.array(embeddings, dtype=float)
    if embeddings.ndim == 1:
        embeddings = embeddings.reshape(1, -1)

    if embeddings.shape[0] != features.shape[0]:
        # Safeguard against unexpected embedder output
        embeddings = _np.resize(embeddings, (features.shape[0], embeddings.shape[-1]))

    X = _np.hstack([features, embeddings])
    expected = getattr(ai_model, 'n_features_in_', None)
    if expected is not None and X.shape[1] != expected:
        _disable_ai_model(f"feature mismatch ({X.shape[1]} vs expected {expected}). Falling back to legacy model.")
        return None
    return X

# === Google Safe Browsing functions (unchanged) ===
def google_safe_browsing_check(url):
    payload = {
        "client": {"clientId": "safesurf", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "PHISHING", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(SB_URL, json=payload, params={"key": GOOGLE_API_KEY}, timeout=5)
        if response.status_code == 200:
            matches = response.json().get("matches", [])
            if matches:
                return matches[0]["threatType"].title()
        return "Safe"
    except Exception as e:  # noqa: BLE001
        print(f"⚠️ Google Safe Browsing Error: {e}")
        return "Safe"

MAX_GSB_BATCH = 500
MAX_GSB_CONCURRENCY = 8

def _google_safe_browsing_batch(batch):
    payload = {
        "client": {"clientId": "safesurf", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "PHISHING", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in batch]
        }
    }
    try:
        response = requests.post(SB_URL, json=payload, params={"key": GOOGLE_API_KEY}, timeout=10)
        if response.status_code == 200:
            matches = response.json().get("matches", [])
            return {m['threatEntry']['url']: m['threatType'].title() for m in matches}
    except Exception as e:  # noqa: BLE001
        print(f"⚠️ Batch Google Safe Browsing Error: {e}")
    return {}

def batch_google_check(urls):
    if not urls:
        return []
    results_map = {}
    batches = [urls[i:i + MAX_GSB_BATCH] for i in range(0, len(urls), MAX_GSB_BATCH)]
    with ThreadPoolExecutor(max_workers=MAX_GSB_CONCURRENCY) as executor:
        future_to_batch_index = {executor.submit(_google_safe_browsing_batch, batch): idx for idx, batch in enumerate(batches)}
        for future in as_completed(future_to_batch_index):
            batch_index = future_to_batch_index[future]
            batch = batches[batch_index]
            try:
                threat_map = future.result()
            except Exception as exc:  # noqa: BLE001
                print(f"⚠️ Concurrency error during Google Safe Browsing batch {batch_index}: {exc}")
                threat_map = {}
            for url in batch:
                results_map[url] = threat_map.get(url, "Safe")
    return [results_map.get(url, "Safe") for url in urls]

# === Helper: basic URL validation & categorize/detect as before ===
SUSPICIOUS_CONFIDENCE = 0.55


def is_valid_url(url: str) -> bool:
    """Lightweight URL validation to guard against obvious malformed inputs."""
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False
        # only allow http/https for scoring
        if parsed.scheme.lower() not in ("http", "https"):
            return False
        if " " in url:
            return False
        host_port = parsed.netloc.split("@")[-1]
        _ = parsed.port  # validates malformed ports
        host = host_port.split(":")[0]
        host_lower = host.lower()
        if host_lower == "localhost":
            return True
        if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host):
            try:
                ipaddress.IPv4Address(host)
                return True
            except ipaddress.AddressValueError:
                return False
        invalid_chars = set(' <>#"\'{}|\\^`')
        if any(ch in invalid_chars for ch in host):
            return False
        if host.startswith(".") or host.endswith("."):
            return False
        labels = host.split(".")
        if len(labels) < 2 or any(label == "" for label in labels):
            return False
        tld = labels[-1]
        if not re.fullmatch(r"[A-Za-z]{2,}", tld):
            return False
        for label in labels:
            if not re.fullmatch(r"[A-Za-z0-9-]{1,63}", label):
                return False
            if label.startswith("-") or label.endswith("-"):
                return False
        return True
    except Exception:  # noqa: BLE001
        return False


def adjust_status_for_confidence(status: str, confidence: float, threat: str):
    """Downgrade Malicious predictions with low certainty to Suspicious. Safe predictions stay Safe."""
    if status == "Malicious" and confidence < SUSPICIOUS_CONFIDENCE:
        return "Suspicious", threat
    return status, threat


def categorize_safe(url):
    url_lower = url.lower()
    if 'bank' in url_lower or 'paypal' in url_lower or 'stripe' in url_lower:
        return "Banking"
    if 'shop' in url_lower or 'amazon' in url_lower or 'ebay' in url_lower or 'alibaba' in url_lower:
        return "Shopping"
    if 'login' in url_lower or 'signin' in url_lower or 'auth' in url_lower:
        return "Authentication"
    if 'social' in url_lower or 'facebook' in url_lower or 'twitter' in url_lower or 'instagram' in url_lower:
        return "Social Media"
    if 'news' in url_lower or 'bbc' in url_lower or 'cnn' in url_lower:
        return "News"
    if 'edu' in url_lower or 'school' in url_lower or 'university' in url_lower:
        return "Education"
    return "General"

def detect_malware_type(url):
    url_lower = url.lower()
    if 'phish' in url_lower or 'phishing' in url_lower or 'credential' in url_lower or 'verify-account' in url_lower:
        return "Phishing"
    if 'deface' in url_lower or 'defacement' in url_lower:
        return "Defacement"
    elif 'fake' in url_lower or ('login' in url_lower and 'secure' not in url_lower and 'https' not in url_lower):
        return "Phishing"
    elif 'malware' in url_lower or 'virus' in url_lower or 'exe' in url_lower:
        return "Malware"
    else:
        return "Malware"

# === Feature extraction - keep previous 17 features but also produce a stable numeric array ===
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc or ''
    path = parsed.path or ''
    query = parsed.query or ''

    return [
        len(url),
        url.count('.'),
        url.count('@'),
        url.count('//'),
        url.count('%'),
        url.count('-'),
        url.count('exe'),
        int('https' in url.lower()),
        int('http' in url.lower() and 'https' not in url.lower()),
        len(domain),
        domain.count('.'),
        len(path),
        len(query),
        int(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) is not None),
        int(re.search(r'[0-9]{4}', domain) is not None),
        1 if 'login' in path.lower() or 'signin' in domain.lower() else 0,
        1 if 'secure' in domain.lower() or 'verify' in domain.lower() else 0,
    ]

# === Fast batch prediction using legacy model only (no embeddings for speed) ===
def _predict_chunk_fast(urls):
    """
    Fast batch prediction using legacy model only (features-only, no embeddings).
    This is much faster than AI model for large batches.
    Returns: (predictions, probabilities)
    """
    if legacy_model is not None:
        features = [extract_features(u) for u in urls]
        preds = legacy_model.predict(features)
        try:
            probs = legacy_model.predict_proba(features)
        except Exception:  # noqa: BLE001
            import numpy as _np
            probs = _np.zeros((len(preds), 2))
            for i, p in enumerate(preds):
                probs[i, int(p)] = 1.0
        return preds, probs

    # If no legacy model, raise
    raise RuntimeError("No legacy model available for batch prediction")

# === _predict_chunk: works with either ai_model (features+embeddings) or legacy_model (features-only) ===
def _predict_chunk(urls):
    """
    Predict a chunk of URLs. If ai_model+embedder are available, use fused features+embeddings.
    Otherwise fall back to legacy_model which expects only lexical features.
    Returns: (predictions, probabilities)
    - predictions: list/numpy of predicted labels (0 safe, 1 malicious, maybe other)
    - probabilities: list of probability vectors (n_samples x n_classes)
    """
    # Defensive: if ai_model is available but embedder is not, fallback
    if ai_model is not None and embedder is not None:
        import numpy as _np
        X = _build_ai_input(urls)
        if X is not None:
            preds = ai_model.predict(X)
            try:
                probs = ai_model.predict_proba(X)
            except Exception:  # noqa: BLE001
                # Some sklearn wrappers may not implement predict_proba
                probs = _np.zeros((len(preds), 2))
                for i, p in enumerate(preds):
                    probs[i, int(p)] = 1.0
            return preds, probs

    # Fallback to legacy skops model (features only)
    if legacy_model is not None:
        features = [extract_features(u) for u in urls]
        preds = legacy_model.predict(features)
        try:
            probs = legacy_model.predict_proba(features)
        except Exception:  # noqa: BLE001
            import numpy as _np
            probs = _np.zeros((len(preds), 2))
            for i, p in enumerate(preds):
                probs[i, int(p)] = 1.0
        return preds, probs

    # If no model, raise
    raise RuntimeError("No model available for prediction (ai_model and legacy_model are both unavailable)")

# === Public predict_url function: Google Safe Browsing first, then model ===
def predict_url(url):
    # Basic validation first to catch clearly malformed URLs
    if not isinstance(url, str) or not url.strip():
        return {
            "url": url,
            "status": "Error",
            "threat_type": "Invalid URL",
            "confidence": 0.0,
            "error": "URL is empty or missing",
        }

    if not is_valid_url(url):
        return {
            "url": url,
            "status": "Error",
            "threat_type": "Invalid URL",
            "confidence": 0.0,
            "error": "Provided string is not a valid URL",
        }

    # Step 1: Google Safe Browsing
    google_result = google_safe_browsing_check(url)
    if google_result != "Safe":
        return {
            "url": url,
            "status": "Malicious",
            "threat_type": google_result,
            "confidence": 1.0,
            "source": "Google Safe Browsing",
            "details": {
                "url_length": len(url),
                "uses_http": "http:" in url and "https:" not in url,
                "has_ip": bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', urlparse(url).netloc)),
                "shortened": 1 if any(s in url for s in ['bit.ly', 'tinyurl', 'goo.gl']) else 0
            }
        }

    # Step 2: Use ai_model if available, else fall back to legacy_model
    try:
        # Prepare feature(s)
        if ai_model is not None and embedder is not None:
            import numpy as _np
            X = _build_ai_input([url])
            if X is not None:
                pred = ai_model.predict(X)[0]
                try:
                    proba = ai_model.predict_proba(X)[0]
                except Exception:  # noqa: BLE001
                    # fallback
                    proba = [0.0, 1.0] if pred == 1 else [1.0, 0.0]

                confidence = float(max(proba))
                if int(pred) == 0:
                    status = "Safe"
                    threat = categorize_safe(url)
                else:
                    status = "Malicious"
                    threat = detect_malware_type(url)

                status, threat = adjust_status_for_confidence(status, confidence, threat)

                return {
                    "url": url,
                    "status": status,
                    "threat_type": threat,
                    "confidence": confidence,
                    "source": "AI Hybrid Model",
                    "details": {
                        "url_length": len(url),
                        "uses_http": "http:" in url and "https:" not in url,
                        "has_ip": bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', urlparse(url).netloc)),
                        "shortened": 1 if any(s in url for s in ['bit.ly', 'tinyurl', 'goo.gl']) else 0
                    }
                }

        # else fallback to legacy model (features-only)
        if legacy_model is not None:
            features = [extract_features(url)]
            prediction = legacy_model.predict(features)[0]
            try:
                proba = legacy_model.predict_proba(features)[0]
            except Exception:  # noqa: BLE001
                proba = [0.0, 1.0] if prediction == 1 else [1.0, 0.0]
            confidence = float(max(proba))
            if int(prediction) == 0:
                status = "Safe"
                threat = categorize_safe(url)
            else:
                status = "Malicious"
                threat = detect_malware_type(url)
            status, threat = adjust_status_for_confidence(status, confidence, threat)

            return {
                "url": url,
                "status": status,
                "threat_type": threat,
                "confidence": confidence,
                "source": "Local ML Model",
                "details": {
                    "url_length": len(url),
                    "uses_http": "http:" in url and "https:" not in url,
                    "has_ip": bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', urlparse(url).netloc)),
                    "shortened": 1 if any(s in url for s in ['bit.ly', 'tinyurl', 'goo.gl']) else 0
                }
            }

        # If no model available
        return {
            "url": url,
            "status": "Error",
            "threat_type": "Unknown",
            "confidence": 0.0,
            "error": "No model available"
        }
    except Exception as e:  # noqa: BLE001
        return {
            "url": url,
            "status": "Error",
            "threat_type": "Unknown",
            "confidence": 0.0,
            "error": f"Prediction failed: {str(e)}"
        }
# make legacy model public for import
model = legacy_model
