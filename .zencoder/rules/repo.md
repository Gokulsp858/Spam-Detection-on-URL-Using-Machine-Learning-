# Safe-Surf Repository Info

- Name: Safe Surf
- Backend: Flask app in backend/
- Frontend: React app in frontend/
- Notebooks: Training utilities in notebooks/
- Datasets: datasets/

## Backend
- Entry: backend/app.py
- Prediction: backend/utils.py (loads model.skops or model.pkl)
- Endpoints:
  - GET /health → { status: "ok" }
  - POST /check { url } → prediction result
- Env:
  - HOST, PORT, FLASK_DEBUG
  - FRONTEND_ORIGIN
  - GOOGLE_API_KEY

## Frontend
- Entry: frontend/src/index.js, App.js
- Env: REACT_APP_API_URL (defaults to http://localhost:5000)

## Training
- notebooks/train_url_model.py → saves backend/model.skops

## Notes
- Keep features in train and inference in sync (17 features)
- Prefer model.skops; joblib pickle supported as fallback