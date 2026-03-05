import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
import pickle
import importlib

# ==========================
# 1. Load Dataset
# ==========================

DATASET_PATH = "../datasets/url_dataset.csv" # change name if needed

print("📥 Loading dataset...")
df = pd.read_csv(DATASET_PATH)

# Convert your dataset's label column into numeric y
# "legitimate" → 0
# "phishing" or "malicious" → 1

if "label" in df.columns:
    def label_to_binary(x):
        x = str(x).lower()
        if x == "legitimate":
            return 0
        return 1
    df["y"] = df["label"].apply(label_to_binary)
else:
    raise ValueError(f"No 'label' column found. Found columns: {df.columns.tolist()}")

# Ensure URL exists
if "url" not in df.columns:
    raise ValueError("Dataset must contain a 'url' column")


print("Dataset loaded:", df.shape)

# ==========================
# 2. Clean invalid URLs
# ==========================

print("🧹 Cleaning invalid URLs...")

def is_valid_url(u):
    try:
        parsed = urlparse(u)
        return bool(parsed.netloc) and "." in parsed.netloc
    except ValueError:  # pragma: no cover
        return False

df = df[df["url"].map(type) == str]
df = df[df["url"].str.strip() != ""]
df = df[df["url"].apply(is_valid_url)]

df.reset_index(drop=True, inplace=True)

print("Remaining valid URLs:", df.shape)

# ==========================
# 3. Extract ML Features
# ==========================

print("📊 Extracting URL features...")

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    return {
        "url_length": len(url),
        "num_digits": sum(c.isdigit() for c in url),
        "num_special": sum(c in "-_.?=/" for c in url),
        "num_subdirs": path.count("/"),
        "has_https": 1 if url.startswith("https") else 0,
        "has_ip": 1 if re.search(r'\d+\.\d+\.\d+\.\d+', domain) else 0,
        "domain_length": len(domain),
    }

features = df["url"].apply(extract_features).apply(pd.Series)

print("ML Feature shape:", features.shape)

# ==========================
# 4. Generate AI Embeddings
# ==========================

print("🧠 Loading embedding model (MiniLM)...")
try:
    st_module = importlib.import_module("sentence_transformers")
    SentenceTransformer = getattr(st_module, "SentenceTransformer")
except ModuleNotFoundError as exc:  # pragma: no cover
    raise RuntimeError(
        "sentence_transformers is not installed. "
        "Install it with `pip install sentence-transformers` before training."
    ) from exc

embedder = SentenceTransformer("all-MiniLM-L6-v2")

print("⚙️ Generating embeddings... (may take 1–3 minutes)")
embeddings = np.vstack([embedder.encode(url) for url in df["url"]])

print("Embedding shape:", embeddings.shape)

# ==========================
# 5. Combine ML + AI Features
# ==========================

X_ml = features.values
X_ai = embeddings

X = np.hstack([X_ml, X_ai])
y = df["y"].values

print("Final training shape:", X.shape, y.shape)

# ==========================
# 6. Train Hybrid AI Model
# ==========================

print("🚀 Training hybrid AI model...")
model = RandomForestClassifier(
    n_estimators=350,
    max_depth=28,
    class_weight="balanced",
    n_jobs=-1,
    random_state=42
)

model.fit(X, y)

print("🎉 Training complete!")

# ==========================
# 7. Save Model
# ==========================

SAVE_PATH = "../backend/ai_model.pkl"

with open(SAVE_PATH, "wb") as f:
    pickle.dump(model, f)

print(f"📦 Model saved successfully → {SAVE_PATH}")
