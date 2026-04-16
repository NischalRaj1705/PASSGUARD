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
