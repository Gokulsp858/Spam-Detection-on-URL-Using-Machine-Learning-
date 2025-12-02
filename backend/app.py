# backend/app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
from concurrent.futures import as_completed
from utils import predict_url, categorize_safe, detect_malware_type, is_valid_url, adjust_status_for_confidence
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
import csv
import io
import re
from urllib.parse import urlparse

app = Flask(__name__)
# Allow up to 100 MB uploads (adjustable)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
CORS(app)


def log(msg):
    """Helper to print timestamped logs"""
    time = datetime.now().strftime("%H:%M:%S")
    print(f"[{time}] {msg}")


# -------------------
# Basic endpoints
# -------------------
@app.route('/check', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        if not data:
            log("❌ No JSON data received")
            return jsonify({"error": "No JSON data received"}), 400

        url = data.get('url', '').strip()
        if not url:
            log("❌ Error: URL is required")
            return jsonify({"error": "URL is required"}), 400

        log(f"🔍 Scanning URL: {url}")

        # Core prediction using existing utils.predict_url
        try:
            result = predict_url(url)
        except Exception as e:
            log(f"💥 predict_url() failed: {e}")
            result = {"url": url, "status": "Error", "error": str(e), "confidence": 0.0, "threat_type": "Unknown", "source": "Local ML Model"}

        # Return result
        return jsonify(result)
    except Exception as e:
        log(f"🚨 Server Error in /check: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(_):
    log("❌ Uploaded file exceeds size limit")
    return jsonify({"error": "File too large. Maximum supported size is 100 MB."}), 413


# -------------------
# Batch file scanning
# -------------------
@app.route('/check-file', methods=['POST'])
def check_file():
    try:
        if 'file' not in request.files:
            log("❌ No file part in request")
            return jsonify({"error": "No file uploaded. Use form field 'file'"}), 400

        file = request.files['file']
        if file.filename == '':
            log("❌ Empty filename")
            return jsonify({"error": "Empty filename"}), 400

        filename = secure_filename(file.filename)
        try:
            raw = file.read()
        except RequestEntityTooLarge:
            log("❌ Uploaded file exceeds size limit during read")
            return jsonify({"error": "File too large. Maximum supported size is 100 MB."}), 413

        # decode with fallback
        try:
            text = raw.decode('utf-8', errors='ignore')
        except Exception:
            text = raw.decode('latin-1', errors='ignore')

        entries = []
        first_line = text.splitlines()[0] if text.splitlines() else ''
        is_csv = filename.lower().endswith('.csv') or (',' in first_line)

        if is_csv:
            reader = csv.reader(io.StringIO(text))
            rows = list(reader)
            if not rows:
                return jsonify({"error": "Empty CSV"}), 400

            header = [h.strip().lower() for h in rows[0]] if rows else []
            # Accept common synonyms for URL and type
            url_candidates = {'url', 'link', 'address'}
            type_candidates = {'type', 'label', 'category'}
            url_col_idx = None
            type_col_idx = None

            if header:
                for idx, name in enumerate(header):
                    if url_col_idx is None and name in url_candidates:
                        url_col_idx = idx
                    if type_col_idx is None and name in type_candidates:
                        type_col_idx = idx
                data_rows = rows[1:]
            else:
                data_rows = rows

            # default to first column for URL if not found
            if url_col_idx is None:
                url_col_idx = 0

            for r in data_rows:
                if not r:
                    continue
                url_value = (r[url_col_idx] if len(r) > url_col_idx else '').strip()
                if not url_value:
                    continue
                entry = {"url": url_value}
                if type_col_idx is not None and len(r) > type_col_idx:
                    provided_value = r[type_col_idx].strip()
                    if provided_value:
                        entry["provided_type"] = provided_value
                entry["is_invalid"] = not is_valid_url(url_value)
                entries.append(entry)
        else:
            # Plain text: one URL per line
            for line in text.splitlines():
                url_value = line.strip()
                if url_value:
                    entries.append({"url": url_value, "is_invalid": not is_valid_url(url_value)})

        # Protect server from massive uploads - limit to 5000 URLs for faster processing
        MAX_URLS = 5000
        if len(entries) > MAX_URLS:
            log(f"⚠️ File contains {len(entries)} URLs, truncating to {MAX_URLS} for faster processing")
            entries = entries[:MAX_URLS]

        log(f"📄 Processing file '{filename}' with {len(entries)} URLs")
        urls = [item["url"] for item in entries]
        results = [None] * len(urls)
        invalid_indices = [i for i, item in enumerate(entries) if item.get("is_invalid")]
        for idx in invalid_indices:
            meta = entries[idx]
            result_item = {
                "url": meta["url"],
                "status": "Error",
                "threat_type": "Invalid URL",
                "confidence": 0.0,
                "source": "Validation",
                "details": {}
            }
            provided_type = meta.get("provided_type")
            if provided_type:
                result_item["provided_type"] = provided_type
            results[idx] = result_item

        # 1) Skip Google Safe Browsing for batch files to speed up processing (use ML model only)
        google_results = ["Safe"] * len(entries)
        for idx in invalid_indices:
            google_results[idx] = "Invalid URL"

        # Mark google malicious first
        for i, (u, g_res) in enumerate(zip(urls, google_results)):
            if results[i] is not None:
                continue
            if g_res != "Safe":
                meta = entries[i]
                result_item = {
                    "url": u,
                    "status": "Malicious",
                    "threat_type": g_res,
                    "confidence": 1.0,
                    "source": "Google Safe Browsing",
                    "details": {
                        "url_length": len(u),
                        "uses_http": ("http:" in u) and ("https:" not in u),
                        "has_ip": bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', urlparse(u).netloc)),
                        "shortened": 1 if any(s in u for s in ['bit.ly', 'tinyurl', 'goo.gl']) else 0
                    }
                }
                provided_type = meta.get("provided_type")
                if provided_type:
                    result_item["provided_type"] = provided_type
                results[i] = result_item

        # 2) Process 'safe' indices with fast legacy ML model in chunks (no embeddings for speed)
        safe_indices = [i for i, g in enumerate(google_results) if g == "Safe" and results[i] is None]
        if safe_indices:
            import warnings
            from utils import _MODEL_EXECUTOR, _predict_chunk_fast
            chunk_size = 1000  # Larger chunks for faster processing
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=UserWarning)
                futures = {}
                for i in range(0, len(safe_indices), chunk_size):
                    chunk_indices = safe_indices[i:i + chunk_size]
                    chunk_urls = [urls[idx] for idx in chunk_indices]
                    if not chunk_urls:
                        continue
                    futures[_MODEL_EXECUTOR.submit(_predict_chunk_fast, chunk_urls)] = chunk_indices

                if futures:
                    for future in as_completed(futures):
                        chunk_indices = futures[future]
                        try:
                            predictions, probas = future.result()
                        except Exception as e:
                            log(f"⚠️ Chunk prediction failed: {e}")
                            for idx in chunk_indices:
                                u = urls[idx]
                                results[idx] = {
                                    "url": u,
                                    "status": "Error",
                                    "threat_type": "Unknown",
                                    "confidence": 0.0,
                                    "error": f"Batch prediction failed: {str(e)}"
                                }
                            continue

                        for j, idx in enumerate(chunk_indices):
                            u = urls[idx]
                            prediction = predictions[j]
                            proba = probas[j]
                            confidence = round(float(max(proba)), 4)
                            if prediction == 0:
                                status = "Safe"
                                threat = categorize_safe(u)
                            elif prediction == 1:
                                status = "Malicious"
                                threat = detect_malware_type(u)
                            elif prediction == 2:
                                status = "Malicious"
                                threat = detect_malware_type(u)
                            else:
                                status = "Suspicious"
                                threat = "Scam"

                            status, threat = adjust_status_for_confidence(status, confidence, threat)

                            result_item = {
                                "url": u,
                                "status": status,
                                "threat_type": threat,
                                "confidence": confidence,
                                "source": "Local ML Model",
                                "details": {
                                    "url_length": len(u),
                                    "uses_http": ("http:" in u) and ("https:" not in u),
                                    "has_ip": bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', urlparse(u).netloc)),
                                    "shortened": 1 if any(s in u for s in ['bit.ly', 'tinyurl', 'goo.gl']) else 0
                                }
                            }
                            provided_type = entries[idx].get("provided_type")
                            if provided_type:
                                result_item["provided_type"] = provided_type
                            results[idx] = result_item

        # 3) Fill any remaining as errors (rare)
        for i in range(len(results)):
            if results[i] is None:
                result_item = {
                    "url": urls[i],
                    "status": "Error",
                    "threat_type": "Unknown",
                    "confidence": 0.0,
                    "error": "Processing failed"
                }
                provided_type = entries[i].get("provided_type")
                if provided_type:
                    result_item["provided_type"] = provided_type
                results[i] = result_item

        # 4) Summary
        summary = {
            "total": len(results),
            "safe": sum(1 for r in results if r.get('status') == 'Safe'),
            "malicious": sum(1 for r in results if r.get('status') == 'Malicious'),
            "suspicious": sum(1 for r in results if r.get('status') == 'Suspicious'),
            "errors": sum(1 for r in results if r.get('status') == 'Error'),
        }
        log(f"📊 Summary: {summary}")
        return jsonify({"filename": filename, "summary": summary, "results": results})

    except RequestEntityTooLarge:
        log("❌ Uploaded file exceeds server limits")
        return jsonify({"error": "File too large to process."}), 413
    except Exception as e:
        log(f"🚨 File Scan Error: {e}")
        return jsonify({"error": "Internal server error"}), 500


@app.route('/')
def home():
    log("📘 Home visited")
    return "<h1>SafeSurf Backend Running!</h1><p>Use POST /check to scan URLs, or POST /check-file to upload CSV/TXT</p>"


# -------------------
# Optional AI endpoints (safe imports + fallbacks)
# -------------------
# The ai_deep, ai_domain, ai_xai modules are optional helpers.
# If missing, we provide harmless fallbacks so server stays up.

def _safe_import(module_name):
    try:
        return __import__(module_name, fromlist=['*'])
    except Exception as e:
        log(f"⚠️ Optional module '{module_name}' not available: {e}")
        return None

_ai_deep_mod = _safe_import('ai_deep')
_ai_domain_mod = _safe_import('ai_domain')
_ai_xai_mod = _safe_import('ai_xai')

# fallback functions
def _deep_predict(url):
    if _ai_deep_mod and hasattr(_ai_deep_mod, 'deep_predict'):
        try:
            return float(_ai_deep_mod.deep_predict(url))
        except Exception as e:
            log(f"⚠️ deep_predict() error: {e}")
    # fallback: use local predict_url confidence as proxy
    try:
        r = predict_url(url)
        return float(r.get('confidence', 0.0))
    except:
        return 0.0

def _domain_intel(url):
    if _ai_domain_mod and hasattr(_ai_domain_mod, 'domain_intel'):
        try:
            return _ai_domain_mod.domain_intel(url)
        except Exception as e:
            log(f"⚠️ domain_intel() error: {e}")
    # fallback minimal domain info
    parsed = urlparse(url)
    domain = parsed.netloc
    return {"domain": domain, "domain_score": 0.5}

def _get_shap_explanation(url, model):
    if _ai_xai_mod and hasattr(_ai_xai_mod, 'get_shap_explanation'):
        try:
            return _ai_xai_mod.get_shap_explanation(url, model)
        except Exception as e:
            log(f"⚠️ get_shap_explanation() error: {e}")
    return {"explanation": "xAI module not available"}


# reuse local model loaded in utils if needed
from utils import model as local_model

@app.route('/ai-deep', methods=['POST'])
def ai_deep():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    score = _deep_predict(url)
    return jsonify({"url": url, "deep_score": float(score)})


@app.route('/ai-domain', methods=['POST'])
def ai_domain():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    info = _domain_intel(url)
    return jsonify({"url": url, **info})


@app.route('/ai-xai', methods=['POST'])
def ai_xai():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    res = _get_shap_explanation(url, local_model)
    return jsonify({"url": url, **res})


@app.route('/ai-risk', methods=['POST'])
def ai_risk():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    if not url:
        return jsonify({"error": "url required"}), 400

    # gather scores (each may use fallback if module absent)
    deep = _deep_predict(url)
    dom_info = _domain_intel(url)
    dom = dom_info.get('domain_score', 0.5)

    # existing local ML prediction from utils.predict_url
    try:
        base = predict_url(url)
        base_score = float(base.get('confidence', 0.0))
    except Exception as e:
        log(f"⚠️ predict_url in ai-risk failed: {e}")
        base = {"status": "Error", "confidence": 0.0}
        base_score = 0.0

    # combine (tunable weights)
    final = 0.40 * base_score + 0.35 * deep + 0.25 * dom
    return jsonify({
        "url": url,
        "base": base,
        "deep_score": float(round(deep, 4)),
        "domain_score": float(round(dom, 4)),
        "final_risk": float(round(final, 4)),
    })


# -------------------
# Main
# -------------------
if __name__ == '__main__':
    print("🚀 SafeSurf Backend Running on http://localhost:5000")
    app.run(debug=True, port=5000)
