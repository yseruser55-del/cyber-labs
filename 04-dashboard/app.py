"""
Cyber Labs Dashboard
--------------------
3 төслийг (Password Analyzer, File Integrity Checker, Secure File Tool)
нэг вэб интерфейсээр нэгтгэсэн локал дашбоард.

Зөвхөн localhost дээр, таны өөрийн компьютер дээр ажиллана.
Байгууллагын систем, өгөгдөлд хандахгүй.

Ажиллуулах:
    pip install flask cryptography zxcvbn
    python app.py
    -> browser дээр http://127.0.0.1:5000 нээнэ

Зогсоох: терминал дээр Ctrl+C
"""

import os
import sys
import io
import json
import hashlib
from datetime import datetime

from flask import Flask, request, render_template_string, send_file, redirect, url_for, flash

# --- Сайжруулсан: сестэр фолдеруудаас модулиудыг импортлох ---
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "01-password"))
sys.path.insert(0, os.path.join(BASE, "03-crypto"))

from password_analyzer import analyze          # noqa: E402
from secure_file import encrypt_bytes, decrypt_bytes  # noqa: E402

app = Flask(__name__)
app.secret_key = "cyber-labs-local-only"  # зөвхөн flash мессежид, локал орчин

BASELINE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline.json")


# ============ Нийтлэг HTML layout ============
BASE_HTML = """
<!doctype html>
<html lang="mn">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cyber Labs Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:#0a0e16; --bg2:#0e1420; --card:rgba(22,28,40,0.72); --border:rgba(255,255,255,0.08);
    --fg:#e8edf5; --muted:#8894a8; --accent:#6366f1; --accent2:#a855f7;
    --ok:#22c55e; --warn:#f59e0b; --danger:#ef4444;
    --grad:linear-gradient(135deg,#6366f1 0%,#a855f7 50%,#ec4899 100%);
  }
  * { box-sizing:border-box; }
  html { scroll-behavior:smooth; }
  body { margin:0; font-family:'Inter',system-ui,sans-serif; color:var(--fg);
         background:var(--bg); min-height:100vh;
         background-image:radial-gradient(900px circle at 10% -10%, rgba(99,102,241,0.18), transparent 45%),
                          radial-gradient(800px circle at 100% 0%, rgba(168,85,247,0.14), transparent 40%); }
  code, .mono { font-family:'JetBrains Mono',monospace; }

  header { position:sticky; top:0; z-index:10; backdrop-filter:blur(14px);
           background:rgba(10,14,22,0.7); border-bottom:1px solid var(--border); }
  .hwrap { max-width:960px; margin:0 auto; padding:16px 20px; display:flex;
           align-items:center; justify-content:space-between; gap:16px; }
  .brand { display:flex; align-items:center; gap:12px; font-weight:800; font-size:18px; letter-spacing:-0.3px; }
  .logo { width:34px; height:34px; border-radius:10px; background:var(--grad);
          display:grid; place-items:center; font-size:18px; box-shadow:0 6px 20px rgba(99,102,241,0.4); }
  .live { font-size:12px; color:var(--muted); display:flex; align-items:center; gap:6px; }
  .dot { width:8px; height:8px; border-radius:50%; background:var(--ok); box-shadow:0 0 0 0 rgba(34,197,94,0.6); animation:pulse 2s infinite; }
  @keyframes pulse { 0%{box-shadow:0 0 0 0 rgba(34,197,94,0.5);} 70%{box-shadow:0 0 0 8px rgba(34,197,94,0);} 100%{box-shadow:0 0 0 0 rgba(34,197,94,0);} }

  .wrap { max-width:960px; margin:0 auto; padding:28px 20px 60px; }
  nav { display:flex; gap:8px; margin-bottom:28px; flex-wrap:wrap; }
  nav a { padding:9px 16px; border:1px solid var(--border); border-radius:999px;
          color:var(--muted); text-decoration:none; font-size:14px; font-weight:500; transition:all .2s; }
  nav a:hover { color:var(--fg); border-color:rgba(255,255,255,0.2); transform:translateY(-1px); }
  nav a.active { color:#fff; background:var(--grad); border-color:transparent; box-shadow:0 6px 18px rgba(99,102,241,0.35); }

  .card { background:var(--card); border:1px solid var(--border); border-radius:18px;
          padding:26px; margin-bottom:22px; backdrop-filter:blur(12px);
          box-shadow:0 10px 40px rgba(0,0,0,0.35); animation:rise .4s ease both; }
  @keyframes rise { from{opacity:0; transform:translateY(10px);} to{opacity:1; transform:translateY(0);} }
  .card h2 { margin:0 0 6px; font-size:19px; font-weight:700; letter-spacing:-0.3px; }
  .card p.desc { color:var(--muted); margin:0 0 18px; font-size:14px; line-height:1.55; }

  .hero h2 { font-size:30px; background:var(--grad); -webkit-background-clip:text;
             background-clip:text; -webkit-text-fill-color:transparent; margin-bottom:8px; }

  label { display:block; margin:14px 0 7px; font-size:13px; font-weight:500; color:var(--muted); }
  input[type=text], input[type=password], input[type=file], textarea {
      width:100%; padding:12px 14px; background:rgba(10,14,22,0.6); border:1px solid var(--border);
      border-radius:12px; color:var(--fg); font-size:14px; transition:all .2s; font-family:inherit; }
  input:focus, textarea:focus { outline:none; border-color:var(--accent);
      box-shadow:0 0 0 3px rgba(99,102,241,0.18); }
  input[type=file]::file-selector-button { background:var(--border); color:var(--fg); border:none;
      padding:7px 12px; border-radius:8px; margin-right:10px; cursor:pointer; font-family:inherit; }
  button { margin-top:18px; padding:12px 22px; background:var(--grad); color:#fff;
           border:none; border-radius:12px; font-size:14px; font-weight:600; cursor:pointer;
           transition:all .2s; box-shadow:0 6px 18px rgba(99,102,241,0.3); }
  button:hover { transform:translateY(-2px); box-shadow:0 10px 26px rgba(99,102,241,0.45); }
  button.alt { background:rgba(255,255,255,0.06); box-shadow:none; border:1px solid var(--border); }
  button.alt:hover { background:rgba(255,255,255,0.1); }

  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:18px; }
  .grid a { text-decoration:none; color:inherit; }
  .tool { position:relative; overflow:hidden; transition:all .25s; cursor:pointer; margin:0; height:100%; }
  .tool:hover { transform:translateY(-4px); border-color:rgba(99,102,241,0.5); }
  .tool .ico { width:46px; height:46px; border-radius:13px; display:grid; place-items:center;
               font-size:22px; margin-bottom:14px; background:rgba(99,102,241,0.14); }
  .tool .arrow { position:absolute; top:22px; right:24px; color:var(--muted); transition:all .2s; }
  .tool:hover .arrow { color:var(--accent); transform:translate(3px,-3px); }

  .meter { height:12px; background:rgba(10,14,22,0.7); border-radius:999px; overflow:hidden;
           border:1px solid var(--border); margin:12px 0; }
  .meter > div { height:100%; border-radius:999px; transition:width .6s cubic-bezier(.2,.8,.2,1); }
  .tag { display:inline-block; padding:5px 14px; border-radius:999px; font-size:12px; font-weight:700; letter-spacing:.3px; }
  .big { font-size:34px; font-weight:800; letter-spacing:-1px; }

  table { width:100%; border-collapse:collapse; margin-top:14px; font-size:14px; }
  th, td { text-align:left; padding:11px 10px; border-bottom:1px solid var(--border); }
  th { color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.5px; }
  tr:last-child td { border-bottom:none; }

  .flash { padding:13px 16px; border-radius:12px; margin-bottom:18px; font-size:14px; font-weight:500;
           display:flex; align-items:center; gap:10px; animation:rise .3s ease both; }
  .flash.ok { background:rgba(34,197,94,0.12); border:1px solid rgba(34,197,94,0.4); color:#86efac; }
  .flash.err { background:rgba(239,68,68,0.12); border:1px solid rgba(239,68,68,0.4); color:#fca5a5; }
  code { background:rgba(10,14,22,0.7); padding:3px 8px; border-radius:6px; font-size:13px; border:1px solid var(--border); }
  .muted { color:var(--muted); font-size:13px; line-height:1.6; }
  hr { border:none; border-top:1px solid var(--border); margin:22px 0; }
  ul { margin:6px 0; padding-left:20px; }
  li { margin:4px 0; }
  .split { display:grid; grid-template-columns:1fr 1fr; gap:18px; }
  @media (max-width:560px){ .split{grid-template-columns:1fr;} }
</style>
</head>
<body>
<header>
  <div class="hwrap">
    <div class="brand"><span class="logo">🛡️</span> Cyber Labs</div>
    <div class="live"><span class="dot"></span> Локал · 127.0.0.1</div>
  </div>
</header>
<div class="wrap">
  <nav>
    <a href="/" class="{{ 'active' if page=='home' }}">Нүүр</a>
    <a href="/password" class="{{ 'active' if page=='password' }}">🔑 Нууц үг</a>
    <a href="/integrity" class="{{ 'active' if page=='integrity' }}">🧾 Бүрэн бүтэн байдал</a>
    <a href="/crypto" class="{{ 'active' if page=='crypto' }}">🔐 Шифрлэлт</a>
  </nav>
  {% with msgs = get_flashed_messages(with_categories=true) %}
    {% for cat, m in msgs %}<div class="flash {{cat}}">{{ '✓' if cat=='ok' else '⚠' }} {{ m }}</div>{% endfor %}
  {% endwith %}
  {{ body|safe }}
</div>
</body>
</html>
"""


def page(body_html, **ctx):
    return render_template_string(BASE_HTML, body=render_template_string(body_html, **ctx), **ctx)


# ============ Нүүр ============
@app.route("/")
def home():
    body = """
    <div class="card hero">
      <h2>Кибер аюулгүй байдлын хэрэгслүүд</h2>
      <p class="desc">Бие даан хийсэн 3 төслийг нэгтгэсэн дашбоард. Бүгд зөвхөн таны компьютер дээр,
      локалд ажиллана — байгууллагын систем, өгөгдөлд хандахгүй.</p>
    </div>
    <div class="grid">
      <a href="/password"><div class="card tool">
        <span class="arrow">↗</span>
        <div class="ico">🔑</div>
        <h2>Password Analyzer</h2>
        <p class="desc">Нууц үгийн урт, нийлмэл байдал, түгээмэл загварыг шалгаж оноо, зөвлөмж гаргана.</p>
        <span class="muted mono">Python · regex · zxcvbn</span>
      </div></a>
      <a href="/integrity"><div class="card tool">
        <span class="arrow">↗</span>
        <div class="ico">🧾</div>
        <h2>File Integrity</h2>
        <p class="desc">SHA-256 hash-аар файл өөрчлөгдсөн, нэмэгдсэн, устсан эсэхийг илрүүлнэ.</p>
        <span class="muted mono">Python · hashlib</span>
      </div></a>
      <a href="/crypto"><div class="card tool">
        <span class="arrow">↗</span>
        <div class="ico">🔐</div>
        <h2>Secure File</h2>
        <p class="desc">Файлыг нууц үгээр AES-256-GCM ашиглан шифрлэх, задлах.</p>
        <span class="muted mono">Python · cryptography</span>
      </div></a>
    </div>
    """
    return page(body, page="home")


# ============ 1. Нууц үг ============
@app.route("/password", methods=["GET", "POST"])
def password():
    result = None
    if request.method == "POST":
        pw = request.form.get("pw", "")
        if pw:
            score, rating, tips = analyze(pw)
            color = "#3fb950" if score >= 80 else ("#d29922" if score >= 50 else "#f85149")
            result = {"score": score, "rating": rating, "tips": tips, "color": color}
    body = """
    <div class="card">
      <h2>🔑 Password Strength Analyzer</h2>
      <p class="desc">Нууц үгээ оруулж хүчийг шалга. Нууц үг сервер рүү хадгалагдахгүй.</p>
      <form method="post">
        <label>Нууц үг</label>
        <input type="password" name="pw" autofocus placeholder="нууц үгээ бич...">
        <button type="submit">Шалгах</button>
      </form>
      {% if result %}
      <hr>
      <div style="display:flex;justify-content:space-between;align-items:flex-end">
        <span class="big" style="color:{{result.color}}">{{ result.score }}<span style="font-size:16px;color:var(--muted)">/100</span></span>
        <span class="tag" style="background:{{result.color}}22;color:{{result.color}}">{{ result.rating }}</span>
      </div>
      <div class="meter"><div style="width:{{result.score}}%;background:{{result.color}}"></div></div>
      {% if result.tips %}
        <p class="muted">Сайжруулах зөвлөмж:</p>
        <ul class="muted">{% for t in result.tips %}<li>{{ t }}</li>{% endfor %}</ul>
      {% else %}<p class="muted">Гайхалтай! Нэмж сайжруулах зүйлгүй.</p>{% endif %}
      {% endif %}
    </div>
    """
    return page(body, page="password", result=result)


# ============ 2. File Integrity ============
def sha256_of_file(path, chunk=65536):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk)
            if not data:
                break
            h.update(data)
    return h.hexdigest()


def scan_folder(folder):
    result = {}
    for root, _dirs, files in os.walk(folder):
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, folder)
            try:
                result[rel] = sha256_of_file(full)
            except OSError:
                pass
    return result


@app.route("/integrity", methods=["GET", "POST"])
def integrity():
    report = None
    folder = request.form.get("folder", "") if request.method == "POST" else ""
    action = request.form.get("action", "")

    if request.method == "POST":
        if not folder or not os.path.isdir(folder):
            flash("Фолдер олдсонгүй. Бүтэн зам оруул.", "err")
        elif action == "init":
            hashes = scan_folder(folder)
            with open(BASELINE_FILE, "w", encoding="utf-8") as f:
                json.dump({"folder": folder, "created": datetime.now().isoformat(timespec="seconds"),
                           "files": hashes}, f, indent=2, ensure_ascii=False)
            flash(f"Baseline үүслээ: {len(hashes)} файл.", "ok")
        elif action == "check":
            if not os.path.exists(BASELINE_FILE):
                flash("Baseline алга. Эхлээд 'Baseline үүсгэх' дар.", "err")
            else:
                with open(BASELINE_FILE, encoding="utf-8") as f:
                    baseline = json.load(f)
                old, new = baseline["files"], scan_folder(folder)
                ok, nk = set(old), set(new)
                report = {
                    "changed": sorted(k for k in (ok & nk) if old[k] != new[k]),
                    "added": sorted(nk - ok),
                    "removed": sorted(ok - nk),
                    "unchanged": len((ok & nk)) - len([k for k in (ok & nk) if old[k] != new[k]]),
                    "created": baseline.get("created", "?"),
                }
    body = """
    <div class="card">
      <h2>🧾 File Integrity Checker</h2>
      <p class="desc">Фолдерын файлуудын SHA-256-г тэмдэглэж, дараа нь өөрчлөлтийг илрүүлнэ.</p>
      <form method="post">
        <label>Фолдерын бүтэн зам</label>
        <input type="text" name="folder" value="{{ folder }}" placeholder="C:\\Users\\...\\testdir">
        <button type="submit" name="action" value="init">1) Baseline үүсгэх</button>
        <button type="submit" name="action" value="check" class="alt">2) Шалгах</button>
      </form>
      {% if report %}
      <hr>
      <p class="muted">Baseline огноо: <code>{{ report.created }}</code></p>
      {% if not report.changed and not report.added and not report.removed %}
        <div class="flash ok">OK — Өөрчлөлт илрээгүй. Бүх файл бүрэн бүтэн.</div>
      {% else %}
      <table><tr><th>Төлөв</th><th>Файл</th></tr>
        {% for k in report.changed %}<tr><td style="color:var(--warn)">~ ӨӨРЧЛӨГДСӨН</td><td>{{k}}</td></tr>{% endfor %}
        {% for k in report.added %}<tr><td style="color:var(--ok)">+ НЭМЭГДСЭН</td><td>{{k}}</td></tr>{% endfor %}
        {% for k in report.removed %}<tr><td style="color:var(--accent)">- УСТСАН</td><td>{{k}}</td></tr>{% endfor %}
      </table>
      {% endif %}
      <p class="muted">Өөрчлөгдөөгүй: {{ report.unchanged }} файл</p>
      {% endif %}
    </div>
    """
    return page(body, page="integrity", folder=folder, report=report)


# ============ 3. Шифрлэлт ============
@app.route("/crypto", methods=["GET"])
def crypto():
    body = """
    <div class="card">
      <h2>🔐 Secure File Tool (AES-256-GCM)</h2>
      <p class="desc">Файлаа оруулж нууц үгээр шифрлэ эсвэл задал. Бүгд локал дээр боловсруулагдана.</p>
      <div class="split">
        <form method="post" action="/crypto/encrypt" enctype="multipart/form-data">
          <strong>🔒 Шифрлэх</strong>
          <label>Файл сонгох</label><input type="file" name="file" required>
          <label>Нууц үг</label><input type="password" name="pw" required>
          <button type="submit">Шифрлэх & татах</button>
        </form>
        <form method="post" action="/crypto/decrypt" enctype="multipart/form-data">
          <strong>🔓 Задлах</strong>
          <label>.enc файл сонгох</label><input type="file" name="file" required>
          <label>Нууц үг</label><input type="password" name="pw" required>
          <button type="submit" class="alt">Задлах & татах</button>
        </form>
      </div>
      <p class="muted" style="margin-top:18px">🛡️ Буруу нууц үгээр задлах оролдлого амжилтгүй болно (GCM tamper detection).</p>
    </div>
    """
    return page(body, page="crypto")


@app.route("/crypto/encrypt", methods=["POST"])
def crypto_encrypt():
    f = request.files.get("file")
    pw = request.form.get("pw", "")
    if not f or not pw:
        flash("Файл болон нууц үг хэрэгтэй.", "err")
        return redirect(url_for("crypto"))
    blob = encrypt_bytes(f.read(), pw)
    return send_file(io.BytesIO(blob), as_attachment=True,
                     download_name=f.filename + ".enc", mimetype="application/octet-stream")


@app.route("/crypto/decrypt", methods=["POST"])
def crypto_decrypt():
    f = request.files.get("file")
    pw = request.form.get("pw", "")
    if not f or not pw:
        flash("Файл болон нууц үг хэрэгтэй.", "err")
        return redirect(url_for("crypto"))
    try:
        plain = decrypt_bytes(f.read(), pw)
    except ValueError as e:
        flash(f"Задлах амжилтгүй: {e}", "err")
        return redirect(url_for("crypto"))
    name = f.filename[:-4] if f.filename.endswith(".enc") else f.filename + ".dec"
    return send_file(io.BytesIO(plain), as_attachment=True,
                     download_name=name, mimetype="application/octet-stream")


if __name__ == "__main__":
    print("Dashboard: http://127.0.0.1:5000  (зогсоох: Ctrl+C)")
    app.run(debug=True, port=5000)
