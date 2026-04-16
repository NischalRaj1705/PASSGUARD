# Password Policy Analyzer v2.0

## Features
- Password Analyzer with HIBP leak check
- Password Generator (cryptographically secure)
- Hashing Demo (MD5 vs SHA-1 vs SHA-256 vs bcrypt)
- History Dashboard (SQLite)
- Downloadable PDF Reports

## Local Run
```bash
pip install flask reportlab
python app.py
# Open: http://localhost:5000
```

## Deploy to Render (Free)
1. Push this folder to GitHub
2. Go to render.com → New Web Service
3. Connect GitHub repo
4. Deploy — get a public URL!

## Folder Structure
```
password_app/
├── app.py              ← Flask backend (all logic)
├── requirements.txt    ← Dependencies
├── render.yaml         ← Render deployment config
├── history.db          ← SQLite (auto-created)
└── templates/
    └── index.html      ← Frontend UI
```

# SOME SCREENSHOTS OF THE WEBPAGE
<img width="1109" height="831" alt="image" src="https://github.com/user-attachments/assets/829c3575-6180-4939-9346-d04b66c06203" />
<img width="866" height="818" alt="image" src="https://github.com/user-attachments/assets/4f2070a6-637d-47be-b7f1-93fe6e62fbf1" />
<img width="999" height="787" alt="image" src="https://github.com/user-attachments/assets/f1b6aab0-402c-4791-8295-e04b46a4ff68" />
<img width="859" height="833" alt="image" src="https://github.com/user-attachments/assets/e9d717d0-d5d7-4e2a-b304-e0525760e648" />
<img width="1384" height="643" alt="image" src="https://github.com/user-attachments/assets/dbb83a17-ec3a-4b26-a3a9-a7fb744a347a" />




