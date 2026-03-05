📌 Spam Detection on URL Using Machine Learning

A machine-learning based system that analyzes URLs and predicts whether they are safe or malicious.
The project includes:

⭐ Backend (Python + Flask/FastAPI)
⭐ Frontend (React)
⭐ ML Model for detection
⭐ AI Risk Scoring (deep score + domain score)
⭐ Explainable output (why the URL is risky)

📸 Project Screenshots

<img width="1567" height="949" alt="Screenshot 2025-11-26 103106" src="https://github.com/user-attachments/assets/48488402-816d-4d6c-8626-54a6f8df83f8" />
<img width="1512" height="953" alt="Screenshot 2025-11-26 103153" src="https://github.com/user-attachments/assets/04f30d66-0d38-440e-ae99-a42ebf60b5e9" />
<img width="1401" height="565" alt="Screenshot 2025-11-26 103952" src="https://github.com/user-attachments/assets/e036ef74-dd48-457c-abc7-0e36818e9c1b" />
<img width="1412" height="574" alt="Screenshot 2025-11-26 104021" src="https://github.com/user-attachments/assets/f05dcda5-67c3-4f08-a605-6721b6783f3c" />
<img width="1540" height="936" alt="Screenshot 2025-11-26 103429" src="https://github.com/user-attachments/assets/56a14f02-f4dc-46ba-a382-9015149f31b3" />


🚀 Features
🔹 URL Malware Detection
Predicts if a URL is:
Malicious
Spam
Safe
Malware
🔹 Machine Learning Model
Uses ML algorithms trained on:
URL structur
Special characters
Domain patterns
Query parameters
🔹 AI Risk Scoring
Outputs:
Deep Score (pattern-based risk)
Domain Score (trustworthiness)
Final Combined Risk
🔹 Explainable Output
Shows why the URL is malicious:
Length
Protocol
Hidden patterns
Query structure
Risk indicators
🔹 Frontend (React)
Clean UI to enter URL and show results.
🔹 Backend (Python)
ML model + API handling + risk scoring modules.

📂 Project Structure
safe-surf/
│
├── backend/
│   ├── app.py
│   ├── utils.py
│   ├── ai_model.pkl
│   ├── ai_deep.py
│   ├── ai_domain.py
│   ├── ai_xai.py
│   ├── model.pkl
│   ├── model.skops
│   └── requirements.txt
│
├── frontend/
│   ├── public/
│   └── src/
│       ├── App.js
│       ├── index.js
│       ├── index.css
│       ├── logo.svg
│       └── components (if any)
│
├── datasets/
│   └── url_dataset.csv
│
└── notebooks/
    ├── train_ai_model.py
    ├── train_url_model.py
    ├── batch_test_urls.py
    └── fix_model.py

🧠 Machine Learning Model
Algorithms Used
Logistic Regression / Random Forest
TF-IDF / CountVectorizer (if used)
Custom feature engineering on URL patterns
Features Extracted
URL length
Digit count
Symbol count
HTTP/HTTPS
Subdomain structure
Suspicious keywords
Encoded patterns

🔬 AI Risk Scoring
🔹 Deep Score
Calculated from:
symbol patterns
obfuscation
encoded parts
randomness
suspicious segments
🔹 Domain Score
Based on:
TLD (.ru, .cn, etc.)
Domain age
Popularity
Reputation
Hosting location
🔹 Final Risk Score
final_risk = (ml_confidence + deep_score + domain_score) / 3

⚙️ How to Run the Project
Backend
cd backend
pip install -r requirements.txt
python app.py

Frontend
cd frontend
npm install
npm start

🧪 Model Evaluation Metrics
Accuracy
Precision
Recall
F1-Score

📘 Future Enhancements
LSTM / BiLSTM URL detection
Transformer-based phishing model
Real-time browser extension
Live threat-intel API integration
Advanced XAI visualizations

✨ Contributors
👤 Gokul S P
GitHub: https://github.com/Gokulsp858













