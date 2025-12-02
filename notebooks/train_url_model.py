# notebooks/train_url_model.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import re
from urllib.parse import urlparse
import skops.io as sio  

# === Feature Extraction ===
def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    return [
        len(url), url.count('.'), url.count('@'), url.count('//'), url.count('%'),
        url.count('-'), url.count('exe'), int('https' in url.lower()),
        int('http' in url.lower() and 'https' not in url.lower()),
        len(domain), domain.count('.'), len(path), len(query),
        int(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) is not None),
        int(re.search(r'[0-9]{4}', domain) is not None),
        1 if 'login' in path.lower() or 'signin' in domain.lower() else 0,
        1 if 'secure' in domain.lower() or 'verify' in domain.lower() else 0,
    ]

# === Load Dataset ===
df = pd.read_csv('datasets/url_dataset.csv')
X = df['url'].apply(extract_features).tolist()
y = df['label']

# === Train Model ===
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# === Evaluate ===
y_pred = model.predict(X_test)
print("✅ Training Complete!")
print(f"📊 Accuracy: {accuracy_score(y_test, y_pred):.2f}")

# === Save with skops (Secure & Version-Safe) ===
sio.dump(model, 'backend/model.skops')
print("💾 Model saved as 'model.skops'")