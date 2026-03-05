# ai_deep.py
from sentence_transformers import SentenceTransformer
import joblib
import os
import numpy as np

# Load lightweight embedding model (small and fast)
EMB_MODEL_NAME = 'all-MiniLM-L6-v2'  # small & fast
_emb_model = SentenceTransformer(EMB_MODEL_NAME)

# Path to your trained shallow classifier (train in notebook, save as deep_model.pkl)
DEEP_CLASSIFIER_PATH = os.path.join(os.path.dirname(__file__), 'deep_model.pkl')
_deep_clf = None
if os.path.exists(DEEP_CLASSIFIER_PATH):
    _deep_clf = joblib.load(DEEP_CLASSIFIER_PATH)

def embed_url(url: str):
    # returns a numpy vector
    return _emb_model.encode([url], show_progress_bar=False)[0]

def deep_predict(url: str):
    """Return probability between 0..1 for maliciousness (higher = risk)"""
    vec = embed_url(url).reshape(1, -1)
    if _deep_clf is None:
        # fallback heuristic: embed norm scaled to [0,1] (very rough)
        return float(min(0.99, np.linalg.norm(vec) / 10.0))
    probs = _deep_clf.predict_proba(vec)[0]
    # assume classes [safe, malicious] or [0,1]
    if len(probs) == 2:
        return float(probs[1])
    # if multiclass, map last class as malicious
    return float(max(probs))
