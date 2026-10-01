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
<style>
  :root { --bg:#0d1117; --card:#161b22; --border:#30363d; --fg:#e6edf3;
          --muted:#8b949e; --accent:#f85149; --ok:#3fb950; --warn:#d29922; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--fg); }
  header { background:#010409; border-bottom:1px solid var(--border); padding:16px 24px; }
  header h1 { margin:0; font-size:20px; display:flex; align-items:center; gap:10px; }
  .wrap { max-width:900px; margin:0 auto; padding:24px 16px; }
  nav { display:flex; gap:8px; margin-bottom:24px; flex-wrap:wrap; }
  nav a { padding:8px 14px; border:1px solid var(--border); border-radius:8px;
          color:var(--fg); text-decoration:none; font-size:14px; }
  nav a:hover, nav a.active { background:var(--card); border-color:var(--accent); }
  .card { background:var(--card); border:1px solid var(--border); border-radius:12px;
          padding:20px; margin-bottom:20px; }
  .card h2 { margin:0 0 6px; font-size:18px; }
  .card p.desc { color:var(--muted); margin:0 0 16px; font-size:14px; }
  label { display:block; margin:12px 0 6px; font-size:14px; color:var(--muted); }
  input[type=text], input[type=password], input[type=file], textarea {
      width:100%; padding:10px; background:#0d1117; border:1px solid var(--border);
      border-radius:8px; color:var(--fg); font-size:14px; }
  button { margin-top:14px; padding:10px 18px; background:var(--accent); color:#fff;
           border:none; border-radius:8px; font-size:14px; cursor:pointer; }
  button:hover { opacity:0.9; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:16px; }
  .grid a { text-decoration:none; }
  .meter { height:14px; background:#0d1117; border-radius:7px; overflow:hidden; border:1px solid var(--border); margin:8px 0; }
  .meter > div { height:100%; transition:width .3s; }
  .tag { display:inline-block; padding:3px 10px; border-radius:20px; font-size:12px; font-weight:600; }
  table { width:100%; border-collapse:collapse; margin-top:12px; font-size:14px; }
  th, td { text-align:left; padding:8px; border-bottom:1px solid var(--border); }
  th { color:var(--muted); font-weight:600; }
  .flash { padding:10px 14px; border-radius:8px; margin-bottom:16px; font-size:14px; }
  .flash.ok { background:#1a2f1a; border:1px solid var(--ok); }
  .flash.err { background:#2f1a1a; border:1px solid var(--accent); }
  code { background:#0d1117; padding:2px 6px; border-radius:4px; font-size:13px; }
  .muted { color:var(--muted); font-size:13px; }
</style>
</head>
<body>
<header><h1>🛡️ Cyber Labs Dashboard</h1></header>
<div class="wrap">
  <nav>
    <a href="/" class="{{ 'active' if page=='home' }}">Нүүр</a>
    <a href="/password" class="{{ 'active' if page=='password' }}">🔑 Нууц үг</a>
    <a href="/integrity" class="{{ 'active' if page=='integrity' }}">🧾 Файл бүрэн бүтэн</a>
    <a href="/crypto" class="{{ 'active' if page=='crypto' }}">🔐 Шифрлэлт</a>
  </nav>
  {% with msgs = get_flashed_messages(with_categories=true) %}
    {% for cat, m in msgs %}<div class="flash {{cat}}">{{ m }}</div>{% endfor %}
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
    <div class="card">
      <h2>Кибер аюулгүй байдлын дадлагын хэрэгслүүд</h2>
      <p class="desc">3 бие даан хийсэн төслийг нэг дашбоардаар. Бүгд локал дээр ажиллана.</p>
      <div class="grid">
        <a href="/password"><div class="card" style="margin:0">
          <h2>🔑 Password Analyzer</h2>
          <p class="desc">Нууц үгийн хүчийг шалгаж оноо, зөвлөмж гаргана.</p></div></a>
        <a href="/integrity"><div class="card" style="margin:0">
          <h2>🧾 File Integrity</h2>
          <p class="desc">SHA-256-аар файл өөрчлөгдсөн эсэхийг илрүүлнэ.</p></div></a>
        <a href="/crypto"><div class="card" style="margin:0">
          <h2>🔐 Secure File</h2>
          <p class="desc">Файлыг AES-256-GCM-ээр шифрлэх / задлах.</p></div></a>
      </div>
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
      <hr style="border-color:var(--border);margin:20px 0">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <strong style="font-size:22px">{{ result.score }}/100</strong>
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
        <button type="submit" name="action" value="check" style="background:#1f6feb">2) Шалгах</button>
      </form>
      {% if report %}
      <hr style="border-color:var(--border);margin:20px 0">
      <p class="muted">Baseline огноо: {{ report.created }}</p>
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
      <div class="grid">
        <form method="post" action="/crypto/encrypt" enctype="multipart/form-data">
          <strong>Шифрлэх</strong>
          <label>Файл сонгох</label><input type="file" name="file" required>
          <label>Нууц үг</label><input type="password" name="pw" required>
          <button type="submit">Шифрлэх & татах</button>
        </form>
        <form method="post" action="/crypto/decrypt" enctype="multipart/form-data">
          <strong>Задлах</strong>
          <label>.enc файл сонгох</label><input type="file" name="file" required>
          <label>Нууц үг</label><input type="password" name="pw" required>
          <button type="submit" style="background:#1f6feb">Задлах & татах</button>
        </form>
      </div>
      <p class="muted" style="margin-top:16px">Буруу нууц үгээр задлах оролдлого амжилтгүй болно (GCM tamper detection).</p>
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
