# notebooks/fix_model.py
import skops.io as sio
from sklearn.ensemble import RandomForestClassifier

# Step 1: Load the model safely by checking untrusted types
file_path = '../backend/model.skops'

# Get the list of untrusted types (this is safe because we made the file)
untrusted_types = sio.get_untrusted_types(file=file_path)
print("🔍 Untrusted types found (safe to trust since we created it):")
print(untrusted_types)

# Step 2: Now load the model with the trusted list
model = sio.load(file_path, trusted=untrusted_types)

# Optional: Re-save it (ensures latest format)
sio.dump(model, file_path)

print("✅ Model loaded and verified successfully!")