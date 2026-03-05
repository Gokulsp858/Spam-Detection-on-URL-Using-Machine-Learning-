# ai_xai.py
import os
import numpy as np
import joblib
import shap
from utils import extract_features  # reuse your feature extractor

# load the same model you use in utils.py or load from model file
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.skops')  # or model.pkl depending on your project
# For performance, DO NOT init shap explainer per request — do it once on import (may be heavy)
_explainer = None

def init_explainer(model):
    global _explainer
    try:
        _explainer = shap.Explainer(model.predict_proba, masker=None)
    except Exception:
        # fallback using KernelExplainer can be slow
        _explainer = None

def get_shap_explanation(url, model):
    """Return a list of top feature contributions (feature_name, value, contribution)"""
    try:
        feats = extract_features(url)
        if _explainer is None:
            # try to init
            init_explainer(model)
        if _explainer is None:
            return {"error": "Explainer not available"}
        shap_vals = _explainer([feats])
        # shap_vals is complex; extract feature contributions for positive (malicious) class
        # choose index 1 if binary
        contribs = []
        feature_names = ["url_length","dots","ats","slashes","pct","hyphens","exe","https","http_only",
                         "domain_len","domain_dots","path_len","query_len","has_ip","has_4digits","login_token","secure_token"]
        vals = shap_vals.values[0]  # shape (K, num_features) or (num_features,) depending on explainer
        # If multi-dim, pick second class
        if vals.ndim == 2:
            vals = vals[1]  # pick class 1 contributions
        for n, v in zip(feature_names, vals):
            contribs.append((n, float(v)))
        # sort by absolute importance
        contribs_sorted = sorted(contribs, key=lambda x: abs(x[1]), reverse=True)
        return {"explanations": contribs_sorted[:8]}
    except Exception as e:
        return {"error": str(e)}
