"""
CyberSentinel AI — Cyber Labs Dashboard
---------------------------------------
Premium dark-mode cybersecurity workspace (Flask).
3 баганат shell: зүүн навигаци + үндсэн ажлын талбар + баруун context panel.

Ажилладаг модулиуд (бодит):
  - Home / SOC Dashboard (demo metrics + alerts)
  - Password Analyzer
  - File Integrity
  - Crypto Lab (hash, salt, encode, caesar, AES file)
Бусад модулиуд: цэвэр "хөгжүүлэлтэд байна" empty state (хуурамч агуулгагүй).

Ажиллуулах:
    pip install flask cryptography zxcvbn
    python app.py
    -> http://127.0.0.1:5000

Зогсоох: Ctrl+C.  Зөвхөн localhost дээр ажиллана.
"""

import os
import sys
import io
import re
import json
import hashlib
import base64
from collections import Counter
from datetime import datetime

from flask import Flask, request, render_template_string, send_file, redirect, url_for, flash

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "01-password"))
sys.path.insert(0, os.path.join(BASE, "03-crypto"))

from password_analyzer import analyze                   # noqa: E402
from secure_file import encrypt_bytes, decrypt_bytes    # noqa: E402

app = Flask(__name__)
app.secret_key = "cyber-sentinel-local-only"

BASELINE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline.json")


# ====================================================================
# Helpers
# ====================================================================
def hashes_of(text):
    b = text.encode("utf-8")
    return {
        "MD5": (hashlib.md5(b).hexdigest(), "⚠ эвдэрсэн — бүү ашигла"),
        "SHA-1": (hashlib.sha1(b).hexdigest(), "⚠ сул — зөвлөдөггүй"),
        "SHA-256": (hashlib.sha256(b).hexdigest(), "✓ найдвартай"),
        "SHA-512": (hashlib.sha512(b).hexdigest(), "✓ найдвартай"),
    }


def caesar(text, shift):
    out = []
    for c in text:
        if c.isupper():
            out.append(chr((ord(c) - 65 + shift) % 26 + 65))
        elif c.islower():
            out.append(chr((ord(c) - 97 + shift) % 26 + 97))
        else:
            out.append(c)
    return "".join(out)


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


# --- Log Analyzer: SSH failed-login parsing (LAB-008 логик) ---
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
ACCEPT_RE = re.compile(r"Accepted password for")


def analyze_log(text, threshold=5):
    by_ip, by_user = Counter(), Counter()
    failed = accepted = 0
    for line in text.splitlines():
        m = FAILED_RE.search(line)
        if m:
            failed += 1
            by_ip[m.group("ip")] += 1
            by_user[m.group("user")] += 1
        elif ACCEPT_RE.search(line):
            accepted += 1
    suspects = [ip for ip, c in by_ip.items() if c >= threshold]
    return {
        "failed": failed, "accepted": accepted,
        "unique_ips": len(by_ip),
        "top_ips": by_ip.most_common(8),
        "top_users": by_user.most_common(8),
        "suspects": suspects, "threshold": threshold,
    }


# --- Network Scanner: Nmap output parsing ---
NMAP_HOST_RE = re.compile(r"Nmap scan report for (?P<host>.+)")
NMAP_PORT_RE = re.compile(r"(?P<port>\d+)/(?P<proto>tcp|udp)\s+(?P<state>open|closed|filtered)\s+(?P<svc>\S+)")


def parse_nmap(text):
    hosts = []
    cur = None
    for line in text.splitlines():
        mh = NMAP_HOST_RE.search(line)
        if mh:
            cur = {"host": mh.group("host").strip(), "ports": []}
            hosts.append(cur)
            continue
        mp = NMAP_PORT_RE.search(line)
        if mp and cur is not None:
            cur["ports"].append({
                "port": mp.group("port"), "proto": mp.group("proto"),
                "state": mp.group("state"), "svc": mp.group("svc"),
            })
    return hosts


# ====================================================================
# Application shell (sidebar + topbar + right panel)
# ====================================================================
SHELL = """
<!doctype html>
<html lang="mn">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberSentinel AI</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#070a12; --bg2:#0b0f1a; --panel:rgba(20,26,40,0.66); --panel2:rgba(28,35,54,0.6);
    --border:rgba(255,255,255,0.08); --border2:rgba(139,124,247,0.25);
    --fg:#e9edf6; --muted:#8b95ab; --faint:#5e6880;
    --indigo:#6366f1; --purple:#a855f7; --blue:#38bdf8;
    --crit:#ef4444; --high:#fb7185; --med:#f59e0b; --low:#38bdf8; --ok:#22c55e;
    --grad:linear-gradient(135deg,#6366f1,#a855f7 55%,#ec4899);
    --glow:0 0 0 1px rgba(139,124,247,0.25),0 8px 30px rgba(99,102,241,0.18);
  }
  *{box-sizing:border-box;}
  html{scroll-behavior:smooth;}
  body{margin:0;font-family:'Inter',system-ui,sans-serif;color:var(--fg);background:var(--bg);
       background-image:radial-gradient(1000px circle at 12% -8%,rgba(99,102,241,0.16),transparent 42%),
                        radial-gradient(900px circle at 100% 0%,rgba(168,85,247,0.12),transparent 40%);}
  .mono,code{font-family:'JetBrains Mono',monospace;}
  a{color:inherit;text-decoration:none;}

  .app{display:grid;grid-template-columns:252px 1fr 326px;min-height:100vh;}

  /* ---- Sidebar ---- */
  .sidebar{border-right:1px solid var(--border);background:rgba(7,10,18,0.6);backdrop-filter:blur(16px);
           padding:18px 14px;position:sticky;top:0;height:100vh;overflow-y:auto;}
  .brand{display:flex;align-items:center;gap:11px;padding:6px 8px 18px;}
  .brand .logo{width:38px;height:38px;border-radius:11px;background:var(--grad);display:grid;place-items:center;
               font-size:19px;box-shadow:0 6px 22px rgba(99,102,241,0.45);}
  .brand b{font-size:15px;font-weight:800;letter-spacing:-0.3px;}
  .brand span{display:block;font-size:11px;color:var(--muted);font-weight:500;}
  .navgroup{font-size:10.5px;letter-spacing:1.2px;color:var(--faint);font-weight:700;margin:16px 10px 6px;text-transform:uppercase;}
  .navitem{display:flex;align-items:center;gap:11px;padding:9px 11px;border-radius:11px;color:var(--muted);
           font-size:13.5px;font-weight:500;margin:2px 0;border:1px solid transparent;transition:all .15s;}
  .navitem .ic{width:18px;text-align:center;font-size:15px;opacity:.9;}
  .navitem:hover{color:var(--fg);background:rgba(255,255,255,0.04);}
  .navitem.active{color:#fff;background:linear-gradient(135deg,rgba(99,102,241,0.22),rgba(168,85,247,0.14));
                  border-color:var(--border2);box-shadow:var(--glow);}
  .navitem.soon{opacity:.62;}
  .navitem .dot{margin-left:auto;width:6px;height:6px;border-radius:50%;background:var(--faint);}

  /* ---- Topbar ---- */
  .topbar{display:flex;align-items:center;gap:16px;padding:14px 26px;border-bottom:1px solid var(--border);
          background:rgba(7,10,18,0.55);backdrop-filter:blur(16px);position:sticky;top:0;z-index:20;}
  .crumb{font-size:13px;color:var(--muted);}.crumb b{color:var(--fg);font-weight:600;}
  .search{flex:1;max-width:460px;display:flex;align-items:center;gap:9px;padding:9px 14px;border-radius:11px;
          background:rgba(10,14,22,0.7);border:1px solid var(--border);color:var(--muted);font-size:13px;}
  .search input{flex:1;background:none;border:none;color:var(--fg);outline:none;font-family:inherit;font-size:13px;}
  .kbd{font-size:11px;border:1px solid var(--border);border-radius:6px;padding:1px 6px;color:var(--faint);}
  .ai-status{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--muted);padding:6px 12px;
             border:1px solid var(--border2);border-radius:999px;background:rgba(99,102,241,0.08);}
  .pulse{width:8px;height:8px;border-radius:50%;background:var(--ok);animation:pulse 2s infinite;}
  @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(34,197,94,.5);}70%{box-shadow:0 0 0 7px rgba(34,197,94,0);}100%{box-shadow:0 0 0 0 rgba(34,197,94,0);}}
  .avatar{width:34px;height:34px;border-radius:50%;background:var(--grad);display:grid;place-items:center;font-weight:700;font-size:14px;}
  .btn-new{padding:8px 15px;border-radius:10px;background:var(--grad);color:#fff;font-size:13px;font-weight:600;
           border:none;cursor:pointer;box-shadow:0 6px 18px rgba(99,102,241,.3);}

  /* ---- Main ---- */
  .main{padding:28px;min-width:0;}
  .page-h{font-size:13px;color:var(--purple);font-weight:600;letter-spacing:.3px;}
  .page-t{font-size:27px;font-weight:800;letter-spacing:-0.6px;margin:2px 0 6px;}
  .page-s{color:var(--muted);font-size:14px;max-width:640px;line-height:1.55;margin:0 0 22px;}

  .card{background:var(--panel);border:1px solid var(--border);border-radius:18px;padding:22px;margin-bottom:20px;
        backdrop-filter:blur(12px);box-shadow:0 10px 36px rgba(0,0,0,.34);animation:rise .4s ease both;}
  @keyframes rise{from{opacity:0;transform:translateY(10px);}to{opacity:1;transform:translateY(0);}}
  .card h2{margin:0 0 6px;font-size:17px;font-weight:700;}
  .card p.desc{color:var(--muted);font-size:13.5px;margin:0 0 16px;line-height:1.55;}

  .metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:22px;}
  .metric{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:18px;backdrop-filter:blur(12px);
          transition:all .2s;}
  .metric:hover{transform:translateY(-3px);border-color:var(--border2);box-shadow:var(--glow);}
  .metric .ic{width:40px;height:40px;border-radius:11px;display:grid;place-items:center;font-size:19px;margin-bottom:12px;background:rgba(99,102,241,.14);}
  .metric .val{font-size:28px;font-weight:800;letter-spacing:-1px;}
  .metric .lab{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-top:2px;}
  .metric .trend{font-size:11.5px;margin-top:8px;}

  .demo-tag{display:inline-block;font-size:10px;letter-spacing:.5px;color:var(--med);border:1px solid rgba(245,158,11,.35);
            background:rgba(245,158,11,.1);border-radius:999px;padding:2px 9px;vertical-align:middle;margin-left:8px;}

  /* AI hero */
  .ai-hero{background:linear-gradient(135deg,rgba(99,102,241,.12),rgba(168,85,247,.08));border:1px solid var(--border2);
           border-radius:20px;padding:24px;margin-bottom:22px;box-shadow:var(--glow);}
  .ai-box{display:flex;gap:10px;align-items:center;background:rgba(7,10,18,.6);border:1px solid var(--border);
          border-radius:14px;padding:6px 6px 6px 16px;margin:14px 0;}
  .ai-box input{flex:1;background:none;border:none;color:var(--fg);outline:none;font-size:14px;font-family:inherit;padding:10px 0;}
  .ai-send{padding:10px 18px;border-radius:10px;background:var(--grad);color:#fff;border:none;font-weight:600;cursor:pointer;}
  .chips{display:flex;flex-wrap:wrap;gap:8px;}
  .chip{padding:7px 13px;border-radius:999px;background:rgba(255,255,255,.05);border:1px solid var(--border);
        font-size:12.5px;color:var(--muted);cursor:pointer;transition:all .15s;}
  .chip:hover{color:#fff;border-color:var(--border2);}

  /* forms */
  label{display:block;margin:12px 0 6px;font-size:12.5px;color:var(--muted);font-weight:500;}
  input[type=text],input[type=password],input[type=file]{width:100%;padding:11px 13px;background:rgba(7,10,18,.6);
       border:1px solid var(--border);border-radius:11px;color:var(--fg);font-size:14px;font-family:inherit;transition:all .15s;}
  input:focus{outline:none;border-color:var(--indigo);box-shadow:0 0 0 3px rgba(99,102,241,.18);}
  input[type=file]::file-selector-button{background:var(--border);color:var(--fg);border:none;padding:7px 12px;border-radius:8px;margin-right:10px;cursor:pointer;font-family:inherit;}
  button{margin-top:14px;padding:11px 20px;background:var(--grad);color:#fff;border:none;border-radius:11px;font-size:13.5px;
         font-weight:600;cursor:pointer;transition:all .2s;box-shadow:0 6px 18px rgba(99,102,241,.3);}
  button:hover{transform:translateY(-2px);box-shadow:0 10px 26px rgba(99,102,241,.45);}
  button.alt{background:rgba(255,255,255,.06);box-shadow:none;border:1px solid var(--border);}
  .split{display:grid;grid-template-columns:1fr 1fr;gap:16px;}@media(max-width:560px){.split{grid-template-columns:1fr;}}

  /* tables + badges */
  table{width:100%;border-collapse:collapse;font-size:13.5px;}
  th,td{text-align:left;padding:11px 10px;border-bottom:1px solid var(--border);}
  th{color:var(--faint);font-size:11px;text-transform:uppercase;letter-spacing:.6px;font-weight:600;}
  tr:last-child td{border-bottom:none;}
  .badge{display:inline-block;padding:3px 11px;border-radius:999px;font-size:11.5px;font-weight:700;}
  .b-crit{background:rgba(239,68,68,.15);color:#fca5a5;}.b-high{background:rgba(251,113,133,.15);color:#fda4af;}
  .b-med{background:rgba(245,158,11,.15);color:#fcd34d;}.b-low{background:rgba(56,189,248,.15);color:#7dd3fc;}
  .b-new{background:rgba(99,102,241,.16);color:#c7d2fe;}.b-inv{background:rgba(245,158,11,.15);color:#fcd34d;}
  .b-open{background:rgba(239,68,68,.14);color:#fca5a5;}

  .meter{height:10px;background:rgba(7,10,18,.7);border-radius:999px;overflow:hidden;border:1px solid var(--border);margin:8px 0;}
  .meter>div{height:100%;border-radius:999px;background:var(--grad);transition:width .6s cubic-bezier(.2,.8,.2,1);}
  .big{font-size:32px;font-weight:800;letter-spacing:-1px;}
  .tag{display:inline-block;padding:4px 12px;border-radius:999px;font-size:12px;font-weight:700;}
  .muted{color:var(--muted);font-size:13px;line-height:1.6;}
  .flash{padding:12px 15px;border-radius:12px;margin-bottom:16px;font-size:13.5px;font-weight:500;}
  .flash.ok{background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.4);color:#86efac;}
  .flash.err{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.4);color:#fca5a5;}
  hr{border:none;border-top:1px solid var(--border);margin:20px 0;}
  ul{margin:6px 0;padding-left:20px;}li{margin:4px 0;}
  .grid2{display:grid;grid-template-columns:1fr 1fr;gap:18px;}@media(max-width:720px){.grid2{grid-template-columns:1fr;}}

  /* ---- Right panel ---- */
  .rightpanel{border-left:1px solid var(--border);background:rgba(7,10,18,.5);backdrop-filter:blur(16px);
              padding:22px 18px;position:sticky;top:0;height:100vh;overflow-y:auto;}
  .widget{background:var(--panel2);border:1px solid var(--border);border-radius:15px;padding:16px;margin-bottom:16px;}
  .widget h4{margin:0 0 12px;font-size:11px;letter-spacing:1px;color:var(--faint);text-transform:uppercase;font-weight:700;}
  .cap{display:flex;align-items:center;gap:8px;font-size:12.5px;color:var(--muted);margin:5px 0;}
  .task{display:flex;align-items:center;gap:9px;font-size:12.5px;margin:7px 0;color:var(--muted);}
  .task.done{color:var(--fg);}.task .box{width:15px;height:15px;border-radius:4px;border:1.5px solid var(--faint);flex:none;}
  .task.done .box{background:var(--ok);border-color:var(--ok);}
  .rp-mini{height:7px;background:rgba(7,10,18,.7);border-radius:999px;overflow:hidden;border:1px solid var(--border);margin:5px 0 10px;}
  .rp-mini>div{height:100%;background:var(--grad);}
  .streak{display:flex;gap:5px;margin-top:8px;}
  .streak i{width:22px;height:22px;border-radius:6px;background:rgba(99,102,241,.5);display:block;}
  .streak i.off{background:rgba(255,255,255,.06);}

  /* empty state */
  .empty{text-align:center;padding:70px 20px;}
  .empty .big-ic{font-size:46px;margin-bottom:14px;}
  .empty h2{font-size:20px;margin:0 0 8px;}

  @media(max-width:1200px){.app{grid-template-columns:252px 1fr;}.rightpanel{display:none;}.metrics{grid-template-columns:repeat(2,1fr);}}
  @media(max-width:820px){.app{grid-template-columns:1fr;}.sidebar{position:static;height:auto;display:flex;gap:6px;overflow-x:auto;}
    .sidebar .navgroup,.sidebar .brand span{display:none;}.navitem{white-space:nowrap;}}
</style>
</head>
<body>
<div class="app">
  <!-- SIDEBAR -->
  <aside class="sidebar">
    <div class="brand">
      <div class="logo">🛡️</div>
      <div><b>CyberSentinel</b><span>AI Workspace</span></div>
    </div>
    <a class="navitem {{ 'active' if active=='home' }}" href="/"><span class="ic">🏠</span> Home</a>

    <div class="navgroup">Operations</div>
    <a class="navitem soon" href="/soon?m=SOC Dashboard"><span class="ic">📊</span> SOC Dashboard<span class="dot"></span></a>
    <a class="navitem soon" href="/soon?m=Assets"><span class="ic">🖥️</span> Assets<span class="dot"></span></a>
    <a class="navitem soon" href="/soon?m=Events"><span class="ic">📡</span> Events<span class="dot"></span></a>
    <a class="navitem soon" href="/soon?m=Alerts"><span class="ic">🚨</span> Alerts<span class="dot"></span></a>
    <a class="navitem soon" href="/soon?m=Incidents"><span class="ic">🔥</span> Incidents<span class="dot"></span></a>
    <a class="navitem soon" href="/soon?m=Threat Intel"><span class="ic">🌐</span> Threat Intel<span class="dot"></span></a>

    <div class="navgroup">Analysis</div>
    <a class="navitem {{ 'active' if active=='log' }}" href="/log-analyzer"><span class="ic">📄</span> Log Analyzer</a>
    <a class="navitem {{ 'active' if active=='scanner' }}" href="/scanner"><span class="ic">📶</span> Network Scanner</a>
    <a class="navitem {{ 'active' if active=='integrity' }}" href="/integrity"><span class="ic">🧾</span> File Integrity</a>
    <a class="navitem {{ 'active' if active=='crypto' }}" href="/crypto"><span class="ic">🔐</span> Crypto Lab</a>
    <a class="navitem {{ 'active' if active=='password' }}" href="/password"><span class="ic">🔑</span> Password Analyzer</a>
    <a class="navitem soon" href="/soon?m=PCAP Analyzer"><span class="ic">🔎</span> PCAP Analyzer<span class="dot"></span></a>

    <div class="navgroup">Learning</div>
    <a class="navitem soon" href="/soon?m=Roadmap"><span class="ic">🗺️</span> Roadmap<span class="dot"></span></a>
    <a class="navitem soon" href="/soon?m=Knowledge Base"><span class="ic">📚</span> Knowledge Base<span class="dot"></span></a>
    <a class="navitem soon" href="/soon?m=CTF"><span class="ic">🚩</span> CTF<span class="dot"></span></a>
    <a class="navitem soon" href="/soon?m=Projects"><span class="ic">📦</span> Projects<span class="dot"></span></a>
    <a class="navitem soon" href="/soon?m=Skills"><span class="ic">🎯</span> Skills<span class="dot"></span></a>

    <div class="navgroup">Planning</div>
    <a class="navitem soon" href="/soon?m=Calendar"><span class="ic">📅</span> Calendar<span class="dot"></span></a>
    <a class="navitem soon" href="/soon?m=Weekly Sprint"><span class="ic">🏃</span> Weekly Sprint<span class="dot"></span></a>
    <a class="navitem soon" href="/soon?m=Daily Scrum"><span class="ic">☀️</span> Daily Scrum<span class="dot"></span></a>

    <div class="navgroup">System</div>
    <a class="navitem {{ 'active' if active=='help' }}" href="/help"><span class="ic">❓</span> Хэрхэн ашиглах</a>
    <a class="navitem soon" href="/soon?m=Reports"><span class="ic">📑</span> Reports<span class="dot"></span></a>
    <a class="navitem soon" href="/soon?m=Settings"><span class="ic">⚙️</span> Settings<span class="dot"></span></a>
  </aside>

  <!-- MAIN COLUMN -->
  <div style="min-width:0;">
    <div class="topbar">
      <div class="crumb">Home / <b>{{ crumb }}</b></div>
      <div class="search"><span>🔍</span><input placeholder="Search assets, alerts, labs, notes..."><span class="kbd">⌘K</span></div>
      <button class="btn-new">+ New Lab</button>
      <div class="ai-status"><span class="pulse"></span> AI Analyst Online</div>
      <div class="avatar">Y</div>
    </div>
    <main class="main">
      {% with msgs = get_flashed_messages(with_categories=true) %}
        {% for cat,m in msgs %}<div class="flash {{cat}}">{{ '✓' if cat=='ok' else '⚠' }} {{ m }}</div>{% endfor %}
      {% endwith %}
      {{ main|safe }}
    </main>
  </div>

  <!-- RIGHT PANEL -->
  <aside class="rightpanel">
    <div class="widget">
      <h4>AI Analyst</h4>
      <div class="cap" style="color:var(--ok)"><span class="pulse"></span> Online · Security Assistant</div>
      <div class="cap">✓ Log Analysis</div>
      <div class="cap">✓ Alert Explanation</div>
      <div class="cap">✓ PCAP Summary</div>
      <div class="cap">✓ Security Learning</div>
      <div class="cap" style="color:var(--faint);font-size:11px;margin-top:8px">* демо — дүрэмд суурилсан туслах</div>
    </div>
    <div class="widget">
      <h4>Today</h4>
      <div class="muted" style="font-size:12px;margin-bottom:4px">Daily Progress · 3 / 5</div>
      <div class="rp-mini"><div style="width:60%"></div></div>
      <div class="task done"><span class="box"></span> Review TCP/IP</div>
      <div class="task done"><span class="box"></span> Complete Nmap lab</div>
      <div class="task done"><span class="box"></span> Analyze PCAP</div>
      <div class="task"><span class="box"></span> Write lab report</div>
      <div class="task"><span class="box"></span> Daily review</div>
    </div>
    <div class="widget">
      <h4>Current Lab</h4>
      <div style="font-weight:700;font-size:14px">LAB-005</div>
      <div class="muted" style="font-size:12.5px;margin-bottom:6px">TCP Traffic Analysis</div>
      <div class="rp-mini"><div style="width:70%"></div></div>
      <div class="muted" style="font-size:11.5px">Progress 70%</div>
    </div>
    <div class="widget">
      <h4>Roadmap</h4>
      <div class="muted" style="font-size:12px">TCP/IP</div><div class="rp-mini"><div style="width:70%"></div></div>
      <div class="muted" style="font-size:12px">Linux</div><div class="rp-mini"><div style="width:60%"></div></div>
      <div class="muted" style="font-size:12px">Blue Team</div><div class="rp-mini"><div style="width:40%"></div></div>
    </div>
    <div class="widget">
      <h4>Weekly Streak · 5 days</h4>
      <div class="streak"><i></i><i></i><i></i><i></i><i></i><i class="off"></i><i class="off"></i></div>
    </div>
  </aside>
</div>
</body>
</html>
"""


def shell(main_html, active, crumb, **ctx):
    rendered = render_template_string(main_html, **ctx)
    return render_template_string(SHELL, main=rendered, active=active, crumb=crumb)


# ====================================================================
# Home / SOC Dashboard
# ====================================================================
@app.route("/")
def home():
    alerts = [
        ("Medium", "b-med", "Multiple SSH authentication failures", "ubuntu-server-01", "2 min ago", "Investigating", "b-inv"),
        ("High", "b-high", "File integrity change detected", "ubuntu-server-01", "5 min ago", "Open", "b-open"),
        ("Medium", "b-med", "New service detected on host", "192.168.56.20", "8 min ago", "New", "b-new"),
        ("Low", "b-low", "Unusual outbound connection", "windows-lab-01", "21 min ago", "New", "b-new"),
    ]
    main = """
    <div class="page-h">Good morning</div>
    <div class="page-t">Cybersecurity Workspace <span class="demo-tag">DEMO DATA</span></div>
    <p class="page-s">Лабораторио хянах, аюулгүй байдлын үйл явдлыг шинжлэх, сурах аяллаа үргэлжлүүл.
    Доорх үзүүлэлтүүд нь интерфейсийг бүрэн харуулах жишээ өгөгдөл. Ажиллах хэрэгслүүд: Password, File Integrity, Crypto Lab.</p>

    <div class="metrics">
      <div class="metric"><div class="ic">🖥️</div><div class="val">5</div><div class="lab">Assets</div><div class="trend" style="color:var(--muted)">лабораторийн хостууд</div></div>
      <div class="metric"><div class="ic">📡</div><div class="val">1,284</div><div class="lab">Security Events</div><div class="trend" style="color:var(--ok)">+28 (24h)</div></div>
      <div class="metric"><div class="ic">🚨</div><div class="val">6</div><div class="lab">Active Alerts</div><div class="trend" style="color:var(--med)">2 investigating</div></div>
      <div class="metric"><div class="ic">🔥</div><div class="val">2</div><div class="lab">Open Incidents</div><div class="trend" style="color:var(--high)">1 high</div></div>
    </div>

    <div class="ai-hero">
      <h2 style="margin:0 0 4px">✨ Ask CyberSentinel AI</h2>
      <p class="muted" style="margin:0">Alert, log, network traffic, лаб эсвэл аюулгүй байдлын ойлголтын талаар асуу.
      <span style="color:var(--faint)">(демо — дүрэмд суурилсан туслах, жинхэнэ LLM биш)</span></p>
      <form class="ai-box" method="post" action="/assistant">
        <input name="q" placeholder="Ask about alerts, logs, labs, or security concepts...">
        <button class="ai-send" type="submit">Send</button>
      </form>
      <div class="chips">
        <a class="chip" href="/log-analyzer">📄 Analyze Logs</a>
        <a class="chip" href="/scanner">📶 Network Scan</a>
        <a class="chip" href="/crypto">🔐 Crypto Lab</a>
        <a class="chip" href="/integrity">🧾 File Integrity</a>
        <a class="chip" href="/password">🔑 Password Check</a>
      </div>
      {% if answer %}<hr><div class="muted" style="white-space:pre-line">{{ answer }}</div>{% endif %}
    </div>

    <div class="card">
      <h2>Recent Alerts <span class="demo-tag">DEMO</span></h2>
      <table>
        <tr><th>Severity</th><th>Alert</th><th>Asset</th><th>Time</th><th>Status</th></tr>
        {% for sev,sevc,title,asset,time,status,statc in alerts %}
        <tr>
          <td><span class="badge {{sevc}}">{{sev}}</span></td>
          <td>{{title}}</td>
          <td class="mono" style="font-size:12px">{{asset}}</td>
          <td class="muted">{{time}}</td>
          <td><span class="badge {{statc}}">{{status}}</span></td>
        </tr>
        {% endfor %}
      </table>
    </div>
    """
    return shell(main, "home", "Dashboard", alerts=alerts, answer=request.args.get("answer"))


@app.route("/assistant", methods=["POST"])
def assistant():
    q = request.form.get("q", "").lower()
    if "hash" in q or "md5" in q or "sha" in q:
        a = "🔐 Hash-ийн талаар бол Crypto Lab → Hash Generator ашиглаарай. SHA-256 найдвартай, MD5/SHA-1 эвдэрсэн."
    elif "password" in q or "нууц" in q:
        a = "🔑 Password Analyzer хэсэгт нууц үгийн хүчийг шалгаж, сайжруулах зөвлөмж авна."
    elif "integrity" in q or "file" in q or "файл" in q:
        a = "🧾 File Integrity хэсэгт SHA-256 baseline үүсгээд, файл өөрчлөгдсөн эсэхийг илрүүлнэ."
    elif "log" in q or "ssh" in q or "brute" in q:
        a = "📄 Лог шинжилгээ: LAB-008 Failed Login Analyzer-ийг ашиглаж brute-force илрүүлж болно (Log Analyzer модуль удахгүй)."
    else:
        a = ("Энэ бол дүрэмд суурилсан демо туслах (жинхэнэ LLM биш). "
             "Ажиллах хэрэгслүүд: 🔑 Password, 🧾 File Integrity, 🔐 Crypto Lab. "
             "Асуултдаа 'hash', 'password', 'file', 'log' гэх түлхүүр үг оруулж үзээрэй.")
    return redirect(url_for("home", answer=a) + "#")


# ====================================================================
# Password Analyzer
# ====================================================================
@app.route("/password", methods=["GET", "POST"])
def password():
    result = None
    if request.method == "POST":
        pw = request.form.get("pw", "")
        if pw:
            score, rating, tips = analyze(pw)
            color = "#22c55e" if score >= 80 else ("#f59e0b" if score >= 50 else "#ef4444")
            result = {"score": score, "rating": rating, "tips": tips, "color": color}
    main = """
    <div class="page-h">Analysis</div>
    <div class="page-t">🔑 Password Analyzer</div>
    <p class="page-s">Нууц үгийн хүчийг шалгаж оноо, зөвлөмж гаргана. Нууц үг сервер рүү хадгалагдахгүй.</p>
    <div class="card">
      <form method="post">
        <label>Нууц үг</label>
        <input type="password" name="pw" autofocus placeholder="нууц үгээ бич...">
        <button type="submit">Шалгах</button>
      </form>
      {% if result %}
      <hr>
      <div style="display:flex;justify-content:space-between;align-items:flex-end">
        <span class="big" style="color:{{result.color}}">{{ result.score }}<span style="font-size:15px;color:var(--muted)">/100</span></span>
        <span class="tag" style="background:{{result.color}}22;color:{{result.color}}">{{ result.rating }}</span>
      </div>
      <div class="meter"><div style="width:{{result.score}}%;background:{{result.color}}"></div></div>
      {% if result.tips %}<p class="muted">Сайжруулах зөвлөмж:</p><ul class="muted">{% for t in result.tips %}<li>{{t}}</li>{% endfor %}</ul>
      {% else %}<p class="muted">Гайхалтай! Нэмж сайжруулах зүйлгүй.</p>{% endif %}
      {% endif %}
    </div>
    """
    return shell(main, "password", "Password Analyzer", result=result)


# ====================================================================
# File Integrity
# ====================================================================
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
    main = """
    <div class="page-h">Analysis</div>
    <div class="page-t">🧾 File Integrity Monitor</div>
    <p class="page-s">Фолдерын файлуудын SHA-256-г baseline болгон хадгалж, дараа нь өөрчлөлтийг илрүүлнэ.</p>
    <div class="card">
      <form method="post">
        <label>Фолдерын бүтэн зам</label>
        <input type="text" name="folder" value="{{ folder }}" placeholder="C:\\Users\\...\\testdir">
        <button type="submit" name="action" value="init">1) Baseline үүсгэх</button>
        <button type="submit" name="action" value="check" class="alt">2) Шалгах</button>
      </form>
      {% if report %}
      <hr><p class="muted">Baseline огноо: <code>{{ report.created }}</code></p>
      {% if not report.changed and not report.added and not report.removed %}
        <div class="flash ok">✓ Өөрчлөлт илрээгүй. Бүх файл бүрэн бүтэн.</div>
      {% else %}
      <table><tr><th>Төлөв</th><th>Файл</th></tr>
        {% for k in report.changed %}<tr><td><span class="badge b-med">ӨӨРЧЛӨГДСӨН</span></td><td class="mono" style="font-size:12px">{{k}}</td></tr>{% endfor %}
        {% for k in report.added %}<tr><td><span class="badge b-low">НЭМЭГДСЭН</span></td><td class="mono" style="font-size:12px">{{k}}</td></tr>{% endfor %}
        {% for k in report.removed %}<tr><td><span class="badge b-open">УСТСАН</span></td><td class="mono" style="font-size:12px">{{k}}</td></tr>{% endfor %}
      </table>{% endif %}
      <p class="muted">Өөрчлөгдөөгүй: {{ report.unchanged }} файл</p>
      {% endif %}
    </div>
    """
    return shell(main, "integrity", "File Integrity", folder=folder, report=report)


# ====================================================================
# Crypto Lab
# ====================================================================
@app.route("/crypto", methods=["GET", "POST"])
def crypto():
    r = {}
    if request.method == "POST":
        tool = request.form.get("tool", "")
        try:
            if tool == "hash":
                txt = request.form.get("text", "")
                r["hash"] = {"input": txt, "rows": hashes_of(txt)}
            elif tool == "salt":
                pw = request.form.get("pw", "")
                s1, s2 = os.urandom(8).hex(), os.urandom(8).hex()
                r["salt"] = {"pw": pw, "no_salt": hashlib.sha256(pw.encode()).hexdigest(),
                             "s1": s1, "h1": hashlib.sha256((s1 + pw).encode()).hexdigest(),
                             "s2": s2, "h2": hashlib.sha256((s2 + pw).encode()).hexdigest()}
            elif tool == "encode":
                txt = request.form.get("text", "")
                op = request.form.get("op", "")
                if op == "b64enc": out = base64.b64encode(txt.encode()).decode()
                elif op == "b64dec": out = base64.b64decode(txt).decode("utf-8", "replace")
                elif op == "hexenc": out = txt.encode().hex()
                elif op == "hexdec": out = bytes.fromhex(txt.strip()).decode("utf-8", "replace")
                else: out = ""
                r["encode"] = {"input": txt, "op": op, "output": out}
            elif tool == "caesar":
                txt = request.form.get("text", "")
                mode = request.form.get("mode", "enc")
                shift = int(request.form.get("shift", "3") or "3")
                if mode == "enc": r["caesar"] = {"single": caesar(txt, shift), "shift": shift}
                elif mode == "dec": r["caesar"] = {"single": caesar(txt, -shift), "shift": shift}
                else: r["caesar"] = {"brute": [(i, caesar(txt, -i)) for i in range(1, 26)]}
        except Exception as e:
            flash(f"Алдаа: {e}", "err")
    main = """
    <div class="page-h">Analysis · Cryptography</div>
    <div class="page-t">🔐 Crypto Lab</div>
    <p class="page-s">Hashing, salting, encoding, classic cipher болон жинхэнэ AES шифрлэлтийг туршиж үзэх лаб.
    Hash ≠ Encoding ≠ Encryption — гурвыг ялгаж ойлго.</p>

    <div class="grid2">
      <div class="card">
        <h2>🧮 Hash Generator</h2>
        <p class="desc">Текстээс hash. Нэг чиглэлт — буцааж задрахгүй.</p>
        <form method="post"><input type="hidden" name="tool" value="hash">
          <input type="text" name="text" value="{{ r.hash.input if r.hash else 'password123' }}" required>
          <button type="submit">Hash тооцоолох</button>
        </form>
        {% if r.hash %}<table><tr><th>Алгоритм</th><th>Hash</th></tr>
          {% for name,(h,note) in r.hash.rows.items() %}<tr><td><b>{{name}}</b><div class="muted" style="font-size:10px">{{note}}</div></td><td class="mono" style="font-size:10.5px;word-break:break-all">{{h}}</td></tr>{% endfor %}
        </table>{% endif %}
      </div>

      <div class="card">
        <h2>🧂 Salting Demo</h2>
        <p class="desc">Ижил нууц үг + өөр salt → өөр hash (rainbow table-ийг хаана).</p>
        <form method="post"><input type="hidden" name="tool" value="salt">
          <input type="text" name="pw" value="{{ r.salt.pw if r.salt else 'hello' }}" required>
          <button type="submit">Харьцуулах</button>
        </form>
        {% if r.salt %}<table>
          <tr><td class="muted">salt-гүй</td><td class="mono" style="font-size:10px;word-break:break-all">{{r.salt.no_salt}}</td></tr>
          <tr><td class="muted">salt #1</td><td class="mono" style="font-size:10px;word-break:break-all">{{r.salt.h1}}</td></tr>
          <tr><td class="muted">salt #2</td><td class="mono" style="font-size:10px;word-break:break-all">{{r.salt.h2}}</td></tr>
        </table>{% endif %}
      </div>
    </div>

    <div class="card">
      <h2>🔤 Encoding Toolkit (Base64 / Hex)</h2>
      <p class="desc">⚠️ Encoding бол шифрлэлт БИШ — нууцлал өгөхгүй.</p>
      <form method="post"><input type="hidden" name="tool" value="encode">
        <input type="text" name="text" value="{{ r.encode.input if r.encode else 'Hello Cyber' }}" required>
        <button type="submit" name="op" value="b64enc">Base64 encode</button>
        <button type="submit" name="op" value="b64dec" class="alt">Base64 decode</button>
        <button type="submit" name="op" value="hexenc" class="alt">Hex encode</button>
        <button type="submit" name="op" value="hexdec" class="alt">Hex decode</button>
      </form>
      {% if r.encode %}<hr><p class="muted">Үр дүн (<code>{{r.encode.op}}</code>):</p>
      <p class="mono" style="word-break:break-all;background:rgba(7,10,18,.7);padding:12px;border-radius:10px;border:1px solid var(--border)">{{r.encode.output}}</p>{% endif %}
    </div>

    <div class="card">
      <h2>🏛️ Caesar Cipher</h2>
      <p class="desc">Эртний шифр. Brute force-оор 25 түлхүүрийг бүгдийг турших боломжтой.</p>
      <form method="post"><input type="hidden" name="tool" value="caesar">
        <input type="text" name="text" value="{{ r.caesar.single if r.caesar and r.caesar.single else 'Khoor Fdhvdu' }}" required>
        <label>Shift (1-25)</label><input type="text" name="shift" value="{{ r.caesar.shift if r.caesar and r.caesar.shift else '3' }}">
        <button type="submit" name="mode" value="enc">Encode</button>
        <button type="submit" name="mode" value="dec" class="alt">Decode</button>
        <button type="submit" name="mode" value="brute" class="alt">🔓 Brute force</button>
      </form>
      {% if r.caesar and r.caesar.single %}<hr><p class="mono" style="background:rgba(7,10,18,.7);padding:12px;border-radius:10px;border:1px solid var(--border)">{{r.caesar.single}}</p>
      {% elif r.caesar and r.caesar.brute %}<hr><table><tr><th>Shift</th><th>Үр дүн</th></tr>
        {% for s,t in r.caesar.brute %}<tr><td class="mono">{{s}}</td><td class="mono">{{t}}</td></tr>{% endfor %}</table>{% endif %}
    </div>

    <div class="card">
      <h2>🔒 AES-256-GCM File Encryption</h2>
      <p class="desc">Жинхэнэ шифрлэлт. Буруу нууц үг → амжилтгүй (GCM tamper detection).</p>
      <div class="split">
        <form method="post" action="/crypto/encrypt" enctype="multipart/form-data">
          <strong>🔒 Шифрлэх</strong>
          <label>Файл</label><input type="file" name="file" required>
          <label>Нууц үг</label><input type="password" name="pw" required>
          <button type="submit">Шифрлэх & татах</button>
        </form>
        <form method="post" action="/crypto/decrypt" enctype="multipart/form-data">
          <strong>🔓 Задлах</strong>
          <label>.enc файл</label><input type="file" name="file" required>
          <label>Нууц үг</label><input type="password" name="pw" required>
          <button type="submit" class="alt">Задлах & татах</button>
        </form>
      </div>
    </div>
    """
    return shell(main, "crypto", "Crypto Lab", r=r)


@app.route("/crypto/encrypt", methods=["POST"])
def crypto_encrypt():
    f = request.files.get("file"); pw = request.form.get("pw", "")
    if not f or not pw:
        flash("Файл болон нууц үг хэрэгтэй.", "err"); return redirect(url_for("crypto"))
    blob = encrypt_bytes(f.read(), pw)
    return send_file(io.BytesIO(blob), as_attachment=True, download_name=f.filename + ".enc",
                     mimetype="application/octet-stream")


@app.route("/crypto/decrypt", methods=["POST"])
def crypto_decrypt():
    f = request.files.get("file"); pw = request.form.get("pw", "")
    if not f or not pw:
        flash("Файл болон нууц үг хэрэгтэй.", "err"); return redirect(url_for("crypto"))
    try:
        plain = decrypt_bytes(f.read(), pw)
    except ValueError as e:
        flash(f"Задлах амжилтгүй: {e}", "err"); return redirect(url_for("crypto"))
    name = f.filename[:-4] if f.filename.endswith(".enc") else f.filename + ".dec"
    return send_file(io.BytesIO(plain), as_attachment=True, download_name=name,
                     mimetype="application/octet-stream")


# ====================================================================
# Log Analyzer (бодит — SSH failed login detection)
# ====================================================================
SAMPLE_LOG = """Oct  2 10:15:32 server sshd[2345]: Failed password for root from 192.168.56.10 port 51920 ssh2
Oct  2 10:15:34 server sshd[2346]: Failed password for root from 192.168.56.10 port 51921 ssh2
Oct  2 10:15:36 server sshd[2347]: Failed password for root from 192.168.56.10 port 51922 ssh2
Oct  2 10:15:38 server sshd[2348]: Failed password for root from 192.168.56.10 port 51923 ssh2
Oct  2 10:15:40 server sshd[2349]: Failed password for invalid user admin from 192.168.56.10 port 51924 ssh2
Oct  2 10:16:01 server sshd[2360]: Accepted password for user1 from 10.0.0.22 port 44100 ssh2
Oct  2 10:22:45 server sshd[2410]: Failed password for invalid user oracle from 203.0.113.9 port 60100 ssh2
Oct  2 10:22:47 server sshd[2411]: Failed password for invalid user postgres from 203.0.113.9 port 60101 ssh2
Oct  2 10:22:49 server sshd[2412]: Failed password for invalid user git from 203.0.113.9 port 60102 ssh2
Oct  2 10:22:51 server sshd[2413]: Failed password for invalid user admin from 203.0.113.9 port 60103 ssh2
Oct  2 10:22:53 server sshd[2414]: Failed password for root from 203.0.113.9 port 60104 ssh2"""


@app.route("/log-analyzer", methods=["GET", "POST"])
def log_analyzer():
    res = None
    text = ""
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            text = f.read().decode("utf-8", "replace")
        else:
            text = request.form.get("text", "")
        if text.strip():
            res = analyze_log(text)
            if res["suspects"]:
                res["summary"] = (f"{res['failed']} амжилтгүй нэвтрэлт илэрлээ. "
                                  f"{len(res['suspects'])} IP босго (5) давсан → brute-force сэжигтэй: "
                                  f"{', '.join(res['suspects'])}. Эдгээрийг firewall дээр хаахыг зөвлөж байна.")
            else:
                res["summary"] = f"{res['failed']} амжилтгүй нэвтрэлт. Босго давсан сэжигтэй IP алга."
    main = """
    <div class="page-h">Analysis</div>
    <div class="page-t">📄 Log Analyzer</div>
    <p class="page-s">SSH auth.log оруулж амжилтгүй нэвтрэлт, brute-force хэв маягийг илрүүлнэ.
    Лог файл сонгох эсвэл доош буулгаж тавь. (LAB-008-ийн логик дээр суурилсан — бодит.)</p>
    <div class="card">
      <form method="post" enctype="multipart/form-data">
        <label>Лог файл (.log / .txt) — эсвэл доорх талбарт буулгана</label>
        <input type="file" name="file">
        <label>Эсвэл лог текст</label>
        <textarea name="text" rows="7" style="width:100%;padding:11px 13px;background:rgba(7,10,18,.6);border:1px solid var(--border);border-radius:11px;color:var(--fg);font-family:'JetBrains Mono',monospace;font-size:12px" placeholder="auth.log мөрүүдээ энд буулга...">{{ text }}</textarea>
        <button type="submit">Шинжлэх</button>
        <button type="submit" name="demo" value="1" formmethod="get" formaction="/log-analyzer/demo" class="alt">Жишээ логоор туршъя</button>
      </form>
      {% if res %}
      <hr>
      <div class="metrics" style="grid-template-columns:repeat(4,1fr)">
        <div class="metric"><div class="val">{{res.failed}}</div><div class="lab">Амжилтгүй</div></div>
        <div class="metric"><div class="val">{{res.accepted}}</div><div class="lab">Амжилттай</div></div>
        <div class="metric"><div class="val">{{res.unique_ips}}</div><div class="lab">Unique IP</div></div>
        <div class="metric"><div class="val" style="color:var(--crit)">{{res.suspects|length}}</div><div class="lab">Сэжигтэй IP</div></div>
      </div>
      <div class="ai-hero" style="margin-top:4px"><b>🤖 AI Summary:</b> <span class="muted">{{res.summary}}</span></div>
      <div class="grid2">
        <div><h2 style="font-size:15px">Top эх IP</h2><table><tr><th>IP</th><th>Оролдлого</th></tr>
          {% for ip,c in res.top_ips %}<tr><td class="mono">{{ip}}</td><td>{{c}} {% if c>=res.threshold %}<span class="badge b-crit">BRUTE</span>{% endif %}</td></tr>{% endfor %}
        </table></div>
        <div><h2 style="font-size:15px">Онилогдсон хэрэглэгч</h2><table><tr><th>User</th><th>Оролдлого</th></tr>
          {% for u,c in res.top_users %}<tr><td class="mono">{{u}}</td><td>{{c}}</td></tr>{% endfor %}
        </table></div>
      </div>
      {% endif %}
    </div>
    """
    return shell(main, "log", "Log Analyzer", res=res, text=text)


@app.route("/log-analyzer/demo")
def log_analyzer_demo():
    res = analyze_log(SAMPLE_LOG)
    res["summary"] = (f"{res['failed']} амжилтгүй нэвтрэлт илэрлээ. "
                      f"{len(res['suspects'])} IP brute-force сэжигтэй: {', '.join(res['suspects'])}.")
    main = """
    <div class="page-h">Analysis · Demo</div>
    <div class="page-t">📄 Log Analyzer <span class="demo-tag">SAMPLE</span></div>
    <p class="page-s">Жишээ auth.log дээрх үр дүн. Өөрийн лог оруулахыг хүсвэл буцаж <a href="/log-analyzer" style="color:var(--purple)">Log Analyzer</a> руу ор.</p>
    <div class="card">
      <div class="metrics" style="grid-template-columns:repeat(4,1fr)">
        <div class="metric"><div class="val">{{res.failed}}</div><div class="lab">Амжилтгүй</div></div>
        <div class="metric"><div class="val">{{res.accepted}}</div><div class="lab">Амжилттай</div></div>
        <div class="metric"><div class="val">{{res.unique_ips}}</div><div class="lab">Unique IP</div></div>
        <div class="metric"><div class="val" style="color:var(--crit)">{{res.suspects|length}}</div><div class="lab">Сэжигтэй IP</div></div>
      </div>
      <div class="ai-hero" style="margin-top:4px"><b>🤖 AI Summary:</b> <span class="muted">{{res.summary}}</span></div>
      <table><tr><th>IP</th><th>Оролдлого</th></tr>
        {% for ip,c in res.top_ips %}<tr><td class="mono">{{ip}}</td><td>{{c}} {% if c>=res.threshold %}<span class="badge b-crit">BRUTE</span>{% endif %}</td></tr>{% endfor %}
      </table>
    </div>
    """
    return shell(main, "log", "Log Analyzer", res=res)


# ====================================================================
# Network Scanner (бодит — Nmap output parsing)
# ====================================================================
SAMPLE_NMAP = """Nmap scan report for ubuntu-server-01 (192.168.56.20)
Host is up (0.00032s latency).
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
443/tcp closed https

Nmap scan report for kali-lab-01 (192.168.56.10)
Host is up.
PORT     STATE SERVICE
22/tcp   open  ssh
3389/tcp closed ms-wbt-server"""


@app.route("/scanner", methods=["GET", "POST"])
def scanner():
    hosts = None
    text = ""
    if request.method == "POST":
        text = request.form.get("text", "")
        if text.strip():
            hosts = parse_nmap(text)
    main = """
    <div class="page-h">Analysis</div>
    <div class="page-t">📶 Network Scanner</div>
    <p class="page-s">Зөвшөөрөгдсөн лабд хийсэн <b>Nmap</b>-ийн гаралтыг энд буулгаж задлан харуулна.
    (Энэ хэрэгсэл скан хийдэггүй — зөвхөн таны импортолсон үр дүнг уншина. LAB-002-той холбоотой.)</p>
    <div class="card">
      <form method="post">
        <label>Nmap гаралт (жишээ: <code>nmap 192.168.56.20</code>-ийн текст)</label>
        <textarea name="text" rows="8" style="width:100%;padding:11px 13px;background:rgba(7,10,18,.6);border:1px solid var(--border);border-radius:11px;color:var(--fg);font-family:'JetBrains Mono',monospace;font-size:12px" placeholder="Nmap scan report for ...">{{ text }}</textarea>
        <button type="submit">Задлах</button>
        <button type="submit" formaction="/scanner/demo" formmethod="get" class="alt">Жишээгээр туршъя</button>
      </form>
      {% if hosts is not none %}
      <hr>
      {% if hosts %}
      {% for h in hosts %}
        <h2 style="font-size:15px">🖥️ {{ h.host }}</h2>
        <table><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th></tr>
          {% for p in h.ports %}<tr>
            <td class="mono">{{p.port}}</td><td class="mono">{{p.proto}}</td>
            <td><span class="badge {{ 'b-low' if p.state=='open' else 'b-open' }}">{{p.state}}</span></td>
            <td class="mono">{{p.svc}}</td></tr>{% endfor %}
        </table>
      {% endfor %}
      {% else %}<div class="flash err">⚠ Nmap гаралт таниагдсангүй. "Nmap scan report for ..." мөр байгаа эсэхийг шалга.</div>{% endif %}
      {% endif %}
    </div>
    """
    return shell(main, "scanner", "Network Scanner", hosts=hosts, text=text)


@app.route("/scanner/demo")
def scanner_demo():
    hosts = parse_nmap(SAMPLE_NMAP)
    main = """
    <div class="page-h">Analysis · Demo</div>
    <div class="page-t">📶 Network Scanner <span class="demo-tag">SAMPLE</span></div>
    <p class="page-s">Жишээ Nmap гаралт. Өөрийнхөө оруулахыг хүсвэл <a href="/scanner" style="color:var(--purple)">Network Scanner</a> руу ор.</p>
    <div class="card">
      {% for h in hosts %}
        <h2 style="font-size:15px">🖥️ {{ h.host }}</h2>
        <table><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th></tr>
          {% for p in h.ports %}<tr><td class="mono">{{p.port}}</td><td class="mono">{{p.proto}}</td>
            <td><span class="badge {{ 'b-low' if p.state=='open' else 'b-open' }}">{{p.state}}</span></td>
            <td class="mono">{{p.svc}}</td></tr>{% endfor %}
        </table>
      {% endfor %}
    </div>
    """
    return shell(main, "scanner", "Network Scanner", hosts=hosts)


# ====================================================================
# Help / Хэрхэн ашиглах
# ====================================================================
@app.route("/help")
def help_page():
    main = """
    <div class="page-h">System</div>
    <div class="page-t">❓ Хэрхэн ашиглах вэ</div>
    <p class="page-s">CyberSentinel AI-ийн ажилладаг хэрэгслүүд ба тэдгээрийг ашиглах заавар.</p>

    <div class="card">
      <h2>🔑 Password Analyzer</h2>
      <p class="desc">Нууц үгийн хүчийг шалгана. Нууц үгээ бичээд <b>Шалгах</b> дар → 0-100 оноо, үнэлгээ, сайжруулах зөвлөмж гарна. Нууц үг хадгалагдахгүй.</p>
    </div>
    <div class="card">
      <h2>🧾 File Integrity</h2>
      <p class="desc">1) Шалгах фолдерынхоо бүтэн замыг оруул → <b>Baseline үүсгэх</b>. 2) Дараа нь дахин орж <b>Шалгах</b> → өөрчлөгдсөн/нэмэгдсэн/устсан файлыг илрүүлнэ. Жишээ зам: <code>C:\\Users\\yalguunjargal.j\\cyber-labs\\02-integrity\\testdir</code></p>
    </div>
    <div class="card">
      <h2>🔐 Crypto Lab</h2>
      <p class="desc"><b>Hash Generator</b> — текстээс hash. <b>Salting</b> — salt-ийн нөлөө. <b>Encoding</b> — Base64/Hex (шифрлэлт биш!). <b>Caesar</b> — классик шифр + brute force. <b>AES файл</b> — файл сонгоод нууц үгээр шифрлэ/задал.</p>
    </div>
    <div class="card">
      <h2>📄 Log Analyzer</h2>
      <p class="desc">SSH auth.log оруул (файл эсвэл текст) → амжилтгүй нэвтрэлт, brute-force сэжигтэй IP-г илрүүлнэ. Туршихдаа <b>"Жишээ логоор туршъя"</b> дар. Өөрийн Linux VM-ийн <code>/var/log/auth.log</code>-ийг оруулж болно.</p>
    </div>
    <div class="card">
      <h2>📶 Network Scanner</h2>
      <p class="desc">Терминал дээр <code>nmap 127.0.0.1</code> ажиллуулаад гарсан текстийг хуулж энд буулга → задлан хүснэгтээр харуулна. Энэ хэрэгсэл өөрөө скан хийхгүй, зөвхөн таны импортолсон үр дүнг уншина.</p>
    </div>
    <div class="card" style="border-color:var(--border2)">
      <p class="muted" style="margin:0">🚧 <b>Roadmap, Calendar, Daily Scrum</b> зэрэг Learning/Planning модулиуд нь таны
      <code>Cybersecurity-Workspace</code> фолдерын markdown файлуудад байгаа. Эдгээрийг вэб дээр биш, workspace дотор хөтлөнө.</p>
    </div>
    """
    return shell(main, "help", "Help")


# ====================================================================
# Empty state for not-yet-built modules (no fake content)
# ====================================================================
@app.route("/soon")
def soon():
    m = request.args.get("m", "Энэ модуль")
    main = """
    <div class="page-h">Module</div>
    <div class="page-t">{{ m }}</div>
    <div class="card"><div class="empty">
      <div class="big-ic">🚧</div>
      <h2>{{ m }} — хөгжүүлэлтэд байна</h2>
      <p class="muted" style="max-width:420px;margin:0 auto">Энэ модуль CyberSentinel AI-ийн төлөвлөгөөнд байгаа ч хараахан хэрэгжээгүй.
      Хуурамч өгөгдөл харуулахгүй. Одоогоор ажиллах хэрэгслүүд: Password Analyzer, File Integrity, Crypto Lab.</p>
    </div></div>
    """
    return shell(main, None, m, m=m)


if __name__ == "__main__":
    print("CyberSentinel AI: http://127.0.0.1:5000  (зогсоох: Ctrl+C)")
    app.run(debug=True, port=5000)
