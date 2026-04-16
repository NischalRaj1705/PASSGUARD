"""
Password Policy Analyzer v2.0
Features: Analyze, Generate, Bcrypt Demo, History, PDF Report, HIBP Check
"""

from flask import Flask, request, jsonify, render_template, send_file
import re, math, hashlib, hmac, os, secrets, string, sqlite3, json
import urllib.request, urllib.error
from datetime import datetime
from io import BytesIO

# ── bcrypt simulation using hashlib (no external lib needed) ──
# We use PBKDF2-HMAC-SHA256 to demonstrate slow hashing concept
# In production: pip install bcrypt and use bcrypt.hashpw()
import hashlib as _hl

def bcrypt_simulate(password, rounds=12):
    """
    Simulates bcrypt behaviour using PBKDF2-HMAC-SHA256.
    Real bcrypt: import bcrypt; bcrypt.hashpw(pwd.encode(), bcrypt.gensalt(rounds))
    We simulate it here since bcrypt pip install may not be available everywhere.
    """
    salt = secrets.token_bytes(16)
    iterations = 2 ** rounds  # bcrypt work factor simulation
    # Cap iterations for speed in demo
    actual_iter = min(iterations, 100000)
    dk = _hl.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, actual_iter)
    salt_hex = salt.hex()
    hash_hex  = dk.hex()
    return f"$pbkdf2-sha256$rounds={actual_iter}${salt_hex}${hash_hex}"

def bcrypt_verify(password, stored_hash):
    """Verify password against stored hash"""
    try:
        parts = stored_hash.split('$')
        rounds_part = parts[2]   # rounds=100000
        salt_hex    = parts[3]
        actual_iter = int(rounds_part.split('=')[1])
        salt        = bytes.fromhex(salt_hex)
        dk          = _hl.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, actual_iter)
        return dk.hex() == parts[4]
    except Exception:
        return False

app = Flask(__name__)

# ── Database setup ─────────────────────────────────────────────
DB = os.path.join(os.path.dirname(__file__), 'history.db')

def init_db():
    con = sqlite3.connect(DB)
    con.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            masked_pw TEXT,
            score     INTEGER,
            rating    TEXT,
            length    INTEGER,
            entropy   REAL,
            crack     TEXT,
            hibp      TEXT,
            breaches  INTEGER,
            has_upper INTEGER,
            has_lower INTEGER,
            has_digit INTEGER,
            has_symbol INTEGER,
            problems  TEXT,
            tips      TEXT
        )
    """)
    con.commit()
    con.close()

init_db()

def mask_password(password):
    """Show first 3 chars + stars. e.g. myPass@123 -> myP*******"""
    if len(password) <= 3:
        return password[0] + '*' * (len(password) - 1)
    return password[:3] + '*' * (len(password) - 3)

def save_result(data):
    con = sqlite3.connect(DB)
    con.execute("""INSERT INTO history
        (timestamp,masked_pw,score,rating,length,entropy,crack,hibp,breaches,
         has_upper,has_lower,has_digit,has_symbol,problems,tips)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        data.get('masked_pw', '***'),
        data['score'], data['rating'], data['length'],
        data['entropy'], data['crack_time'],
        data['hibp_status'], data['breach_count'],
        int(data['has_upper']), int(data['has_lower']),
        int(data['has_digit']), int(data['has_symbol']),
        json.dumps(data['problems']),
        json.dumps(data['tips'])
    ))
    con.commit()
    con.close()

def get_history():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT * FROM history ORDER BY id DESC LIMIT 20"
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]

# ── Core Analysis Logic ────────────────────────────────────────

def calc_entropy(password):
    pool = 0
    if re.search(r'[a-z]', password): pool += 26
    if re.search(r'[A-Z]', password): pool += 26
    if re.search(r'\d',    password): pool += 10
    if re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:,.<>?/`~]', password): pool += 32
    if pool == 0: pool = 1
    return round(len(password) * math.log2(pool), 1)

def crack_time(bits):
    s = (2 ** bits) / 1e10
    if s < 1:          return "Less than a second"
    if s < 60:         return f"{s:.0f} seconds"
    if s < 3600:       return f"{s/60:.1f} minutes"
    if s < 86400:      return f"{s/3600:.1f} hours"
    if s < 31536000:   return f"{s/86400:.1f} days"
    if s < 3.154e9:    return f"{s/31536000:.1f} years"
    if s < 3.154e12:   return f"{s/3.154e9:.1f} thousand years"
    return f"{s/3.154e12:.1f} million+ years"

def find_problems(password):
    problems = []
    if re.search(r'(.)\1{2,}', password):
        problems.append("Repeated characters (e.g. 'aaa')")
    if re.search(r'(012|123|234|345|456|567|678|789|abc|bcd|cde|def)', password.lower()):
        problems.append("Sequential characters (e.g. '123')")
    common = ["password","pass","qwerty","admin","login","welcome",
              "letmein","monkey","dragon","123456","iloveyou"]
    if any(w in password.lower() for w in common):
        problems.append("Contains a common password word")
    if re.search(r'(19|20)\d{2}', password):
        problems.append("Contains a year (easy to guess)")
    for row in ["qwertyuiop","asdfghjkl","zxcvbnm"]:
        for i in range(len(row) - 3):
            if row[i:i+4] in password.lower():
                problems.append("Keyboard pattern detected (e.g. 'qwer')")
                break
    return problems

def check_pwned(password):
    try:
        sha1   = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        url    = f"https://api.pwnedpasswords.com/range/{prefix}"
        req    = urllib.request.Request(url, headers={
            "User-Agent": "PasswordPolicyAnalyzer-v2",
            "Add-Padding": "true"
        })
        resp = urllib.request.urlopen(req, timeout=8)
        body = resp.read().decode('utf-8')
        for line in body.splitlines():
            line = line.strip()
            if not line: continue
            parts = line.split(":")
            if len(parts) >= 2 and parts[0].strip() == suffix:
                return True, int(parts[1].strip()), "found"
        return False, 0, "safe"
    except urllib.error.URLError as e:
        print(f"[HIBP] offline: {e}")
        return False, 0, "offline"
    except Exception as e:
        print(f"[HIBP] error: {e}")
        return False, 0, "error"

def full_analysis(password, policy):
    length     = len(password)
    has_upper  = bool(re.search(r'[A-Z]', password))
    has_lower  = bool(re.search(r'[a-z]', password))
    has_digit  = bool(re.search(r'\d', password))
    has_symbol = bool(re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:,.<>?/`~]', password))
    problems   = find_problems(password)
    bits       = calc_entropy(password)
    crack      = crack_time(bits)
    pwned, breach_count, hibp_status = check_pwned(password)

    score = 0
    if length >= 20:   score += 30
    elif length >= 16: score += 25
    elif length >= 12: score += 18
    elif length >= 8:  score += 10
    else:              score += 3
    if has_upper:  score += 7
    if has_lower:  score += 7
    if has_digit:  score += 7
    if has_symbol: score += 7
    score += (20 - min(len(problems) * 5, 20))
    if policy.get("no_dict"):     score += 4
    if policy.get("no_personal"): score += 4
    if policy.get("no_repeat"):   score += 3
    if policy.get("no_seq"):      score += 3
    if policy.get("unique"):      score += 4
    if policy.get("mfa"):         score += 4
    if hibp_status == "found":    score -= 40
    score = max(0, min(score, 100))

    mismatches = []
    if policy.get("upper")     and not has_upper:  mismatches.append("Declared uppercase — none found")
    if policy.get("lower")     and not has_lower:  mismatches.append("Declared lowercase — none found")
    if policy.get("digits")    and not has_digit:  mismatches.append("Declared digits — none found")
    if policy.get("symbols")   and not has_symbol: mismatches.append("Declared symbols — none found")
    if policy.get("no_repeat") and re.search(r'(.)\1{2,}', password):
        mismatches.append("Declared no repeats — repeats found")

    tips = []
    if hibp_status == "found":
        tips.append(f"URGENT: Change this password — found in {breach_count:,} breaches!")
    if length < 12:               tips.append("Use at least 12 characters (16+ recommended)")
    if not has_upper:             tips.append("Add uppercase letters [A-Z]")
    if not has_lower:             tips.append("Add lowercase letters [a-z]")
    if not has_digit:             tips.append("Include numbers [0-9]")
    if not has_symbol:            tips.append("Add special symbols like !@#$%")
    if problems:                  tips.append("Remove predictable patterns")
    if not policy.get("no_dict"):     tips.append("Avoid common words")
    if not policy.get("unique"):      tips.append("Use unique password per account")
    if not policy.get("mfa"):         tips.append("Enable 2FA for extra security")

    if score < 25:   rating = "Very Weak"
    elif score < 45: rating = "Weak"
    elif score < 60: rating = "Moderate"
    elif score < 78: rating = "Strong"
    else:            rating = "Very Strong"

    return {
        "score": score, "rating": rating,
        "length": length, "entropy": bits, "crack_time": crack,
        "has_upper": has_upper, "has_lower": has_lower,
        "has_digit": has_digit, "has_symbol": has_symbol,
        "problems": problems, "mismatches": mismatches, "tips": tips,
        "hibp_status": hibp_status, "breach_count": breach_count, "pwned": pwned,
        "masked_pw":   mask_password(password),
        "sha1_prefix": hashlib.sha1(password.encode()).hexdigest().upper()[:5],
        "sha1_full":   hashlib.sha1(password.encode()).hexdigest().upper(),
        "policy_checks": {
            "Avoids common words":      policy.get("no_dict", False),
            "Avoids personal info":     policy.get("no_personal", False),
            "No repeated characters":   policy.get("no_repeat", False),
            "No sequential patterns":   policy.get("no_seq", False),
            "Used on one account only": policy.get("unique", False),
            "2FA is enabled":           policy.get("mfa", False),
            "Not in any data breach":   hibp_status == "safe",
        }
    }

# ── Routes ─────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    data     = request.json or {}
    password = data.get("password", "")
    policy   = data.get("policy", {})
    if not password:
        return jsonify({"error": "No password"}), 400
    result = full_analysis(password, policy)
    save_result(result)
    return jsonify(result)

@app.route("/generate", methods=["POST"])
def generate():
    data    = request.json or {}
    length  = max(8, min(64, int(data.get("length", 16))))
    use_upper   = data.get("upper", True)
    use_lower   = data.get("lower", True)
    use_digits  = data.get("digits", True)
    use_symbols = data.get("symbols", True)

    charset = ""
    guaranteed = []
    if use_lower:   charset += string.ascii_lowercase;  guaranteed.append(secrets.choice(string.ascii_lowercase))
    if use_upper:   charset += string.ascii_uppercase;  guaranteed.append(secrets.choice(string.ascii_uppercase))
    if use_digits:  charset += string.digits;           guaranteed.append(secrets.choice(string.digits))
    if use_symbols:
        syms = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        charset += syms
        guaranteed.append(secrets.choice(syms))
    if not charset:
        charset = string.ascii_letters + string.digits

    remaining = [secrets.choice(charset) for _ in range(length - len(guaranteed))]
    pwd_list  = guaranteed + remaining
    secrets.SystemRandom().shuffle(pwd_list)
    password  = "".join(pwd_list)

    bits   = calc_entropy(password)
    return jsonify({
        "password":   password,
        "length":     len(password),
        "entropy":    bits,
        "crack_time": crack_time(bits),
        "strength":   "Very Strong" if bits > 80 else "Strong" if bits > 60 else "Moderate"
    })

@app.route("/bcrypt-demo", methods=["POST"])
def bcrypt_demo():
    data     = request.json or {}
    password = data.get("password", "")
    rounds   = int(data.get("rounds", 10))
    if not password:
        return jsonify({"error": "No password"}), 400
    rounds = max(4, min(12, rounds))

    # SHA-1 (fast — bad for storage)
    sha1_hash = hashlib.sha1(password.encode()).hexdigest()
    # MD5 (very fast — very bad)
    md5_hash  = hashlib.md5(password.encode()).hexdigest()
    # SHA-256 (fast — still bad for passwords)
    sha256    = hashlib.sha256(password.encode()).hexdigest()
    # PBKDF2 simulation of bcrypt (slow — good)
    import time
    t0 = time.time()
    bcrypt_hash = bcrypt_simulate(password, rounds=rounds)
    bcrypt_time = round((time.time() - t0) * 1000, 1)

    # Verify demo
    verified = bcrypt_verify(password, bcrypt_hash)

    return jsonify({
        "password":    password,
        "md5":         md5_hash,
        "sha1":        sha1_hash,
        "sha256":      sha256,
        "bcrypt":      bcrypt_hash,
        "bcrypt_time_ms": bcrypt_time,
        "verified":    verified,
        "rounds":      rounds,
        "explanation": {
            "md5":    "32 chars. BROKEN — cracked instantly. Never use.",
            "sha1":   "40 chars. Weak — billions/sec on GPU. Only for HIBP format.",
            "sha256": "64 chars. Fast — good for files, bad for passwords.",
            "bcrypt": f"Slow by design — work factor 2^{rounds}. This is correct for passwords."
        }
    })

@app.route("/history")
def history():
    return jsonify(get_history())

@app.route("/history/clear", methods=["POST"])
def clear_history():
    con = sqlite3.connect(DB)
    con.execute("DELETE FROM history")
    con.commit()
    con.close()
    return jsonify({"ok": True})

@app.route("/report/<int:rid>")
def report(rid):
    """Generate downloadable PDF report for a result"""
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM history WHERE id=?", (rid,)).fetchone()
    con.close()
    if not row:
        return jsonify({"error": "Not found"}), 404

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
            leftMargin=18*mm, rightMargin=18*mm,
            topMargin=14*mm, bottomMargin=14*mm)

        DARK  = colors.HexColor("#0f172a")
        BLUE  = colors.HexColor("#3b82f6")
        GREEN = colors.HexColor("#22c55e")
        RED   = colors.HexColor("#ef4444")
        YELL  = colors.HexColor("#f59e0b")
        LIGHT = colors.HexColor("#f1f5f9")
        MID   = colors.HexColor("#e2e8f0")
        W     = colors.white
        CW    = A4[0] - 36*mm

        def ps(name, **kw): return ParagraphStyle(name, **kw)
        h1  = ps("h1", fontName="Helvetica-Bold", fontSize=22, textColor=W, alignment=TA_CENTER, leading=28)
        h2  = ps("h2", fontName="Helvetica-Bold", fontSize=13, textColor=BLUE, spaceBefore=8, spaceAfter=3)
        bod = ps("bd", fontName="Helvetica", fontSize=10, textColor=DARK, spaceAfter=4, leading=14)
        cod = ps("cd", fontName="Courier",   fontSize=9,  textColor=BLUE, spaceAfter=3, leading=13)

        def HR(): return HRFlowable(width="100%", thickness=1, color=MID, spaceAfter=4, spaceBefore=4)
        def SP(h=4): return Spacer(1, h*mm)

        score = row['score']
        color = GREEN if score >= 78 else BLUE if score >= 60 else YELL if score >= 45 else RED

        story = []

        # Header
        hdr = Table([[Paragraph("Password Policy Analyzer", h1),
                      Paragraph(f"Report #{rid}", ps("sub", fontName="Helvetica", fontSize=10,
                                textColor=colors.HexColor("#94a3b8"), alignment=TA_CENTER))]],
                    colWidths=[CW*0.75, CW*0.25])
        hdr.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),DARK),
            ("TOPPADDING",(0,0),(-1,-1),16),("BOTTOMPADDING",(0,0),(-1,-1),16),
            ("LEFTPADDING",(0,0),(-1,-1),14),("RIGHTPADDING",(0,0),(-1,-1),14),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ]))
        story.append(hdr)
        story.append(SP(4))

        # Score box
        score_tbl = Table([[
            Paragraph(f"{score}", ps("sc", fontName="Helvetica-Bold", fontSize=36,
                      textColor=color, alignment=TA_CENTER)),
            Paragraph(f"/ 100\n{row['rating']}", ps("rt", fontName="Helvetica-Bold", fontSize=14,
                      textColor=DARK, alignment=TA_CENTER, leading=18))
        ]], colWidths=[30*mm, CW-30*mm])
        score_tbl.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,-1),LIGHT),
            ("TOPPADDING",(0,0),(-1,-1),12),("BOTTOMPADDING",(0,0),(-1,-1),12),
            ("LEFTPADDING",(0,0),(-1,-1),14),("RIGHTPADDING",(0,0),(-1,-1),14),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ("LINEAFTER",(0,0),(0,-1),2,color),
        ]))
        story.append(score_tbl)
        story.append(SP(3))

        # Meta
        story.append(Paragraph("Analysis Details", h2))
        story.append(HR())
        masked = row['masked_pw'] if row['masked_pw'] else '***'
        meta = Table([
            [Paragraph("Password",       ps("mk",fontName="Helvetica-Bold",fontSize=9,textColor=colors.HexColor("#64748b"))),
             Paragraph(masked,             ps("pw",fontName="Courier-Bold",fontSize=11,textColor=BLUE,spaceAfter=4,leading=14))],
            [Paragraph("Analyzed On",    ps("mk",fontName="Helvetica-Bold",fontSize=9,textColor=colors.HexColor("#64748b"))),
             Paragraph(row['timestamp'], bod)],
            [Paragraph("Length",         ps("mk",fontName="Helvetica-Bold",fontSize=9,textColor=colors.HexColor("#64748b"))),
             Paragraph(f"{row['length']} characters", bod)],
            [Paragraph("Entropy",        ps("mk",fontName="Helvetica-Bold",fontSize=9,textColor=colors.HexColor("#64748b"))),
             Paragraph(f"{row['entropy']} bits", bod)],
            [Paragraph("Crack Time",     ps("mk",fontName="Helvetica-Bold",fontSize=9,textColor=colors.HexColor("#64748b"))),
             Paragraph(row['crack'], bod)],
            [Paragraph("HIBP Status",    ps("mk",fontName="Helvetica-Bold",fontSize=9,textColor=colors.HexColor("#64748b"))),
             Paragraph(f"{row['hibp'].upper()} — {row['breaches']:,} breaches" if row['hibp']=='found' else row['hibp'].upper(), bod)],
        ], colWidths=[35*mm, CW-35*mm])
        meta.setStyle(TableStyle([
            ("ROWBACKGROUNDS",(0,0),(-1,-1),[W, LIGHT]),
            ("GRID",(0,0),(-1,-1),0.4,MID),
            ("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
            ("LEFTPADDING",(0,0),(-1,-1),8),("RIGHTPADDING",(0,0),(-1,-1),8),
        ]))
        story.append(meta)
        story.append(SP(3))

        # Char check
        story.append(Paragraph("Character Composition", h2))
        story.append(HR())
        chars = [
            ("Uppercase [A-Z]", bool(row['has_upper'])),
            ("Lowercase [a-z]", bool(row['has_lower'])),
            ("Numbers [0-9]",   bool(row['has_digit'])),
            ("Special Symbols", bool(row['has_symbol'])),
        ]
        for name, found in chars:
            ic = GREEN if found else RED
            st = "FOUND" if found else "MISSING"
            story.append(Table([[
                Paragraph(f"{'✔' if found else '✘'}  {name}", ps("ci",fontName="Helvetica",fontSize=10,textColor=ic)),
                Paragraph(st, ps("cb",fontName="Helvetica-Bold",fontSize=9,textColor=ic,alignment=TA_CENTER))
            ]], colWidths=[CW-22*mm, 22*mm]))
            story.append(SP(1))

        story.append(SP(2))
        # Problems
        problems = json.loads(row['problems'] or '[]')
        story.append(Paragraph("Problems Detected", h2))
        story.append(HR())
        if problems:
            for p in problems:
                story.append(Paragraph(f"  ✘  {p}", ps("pr",fontName="Helvetica",fontSize=10,
                             textColor=RED,spaceAfter=3,leading=14)))
        else:
            story.append(Paragraph("  ✔  No problems detected.", ps("ok",fontName="Helvetica",
                         fontSize=10,textColor=GREEN,spaceAfter=3)))

        story.append(SP(2))
        # Tips
        tips = json.loads(row['tips'] or '[]')
        story.append(Paragraph("Improvement Tips", h2))
        story.append(HR())
        for i, t in enumerate(tips, 1):
            story.append(Paragraph(f"  {i}. {t}", ps("tp",fontName="Helvetica",fontSize=10,
                         textColor=DARK,spaceAfter=4,leading=14)))

        # Footer
        story.append(SP(4))
        ft = Table([[Paragraph("Generated by Password Policy Analyzer v2.0 — Student Project",
                    ps("ft",fontName="Helvetica",fontSize=8,textColor=colors.HexColor("#94a3b8"),
                    alignment=TA_CENTER))]], colWidths=[CW])
        ft.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),DARK),
            ("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8)]))
        story.append(ft)

        doc.build(story)
        buf.seek(0)
        return send_file(buf, mimetype='application/pdf',
                         as_attachment=True,
                         download_name=f'password_report_{rid}.pdf')
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/hibp-test")
def hibp_test():
    pwned, count, status = check_pwned("password123")
    return jsonify({"test": "password123", "status": status,
                    "pwned": pwned, "count": count})

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
