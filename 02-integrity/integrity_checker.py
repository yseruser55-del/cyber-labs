"""
File Integrity Checker
----------------------
Фолдер доторх файл бүрийн SHA-256 hash-ийг тооцоолж "baseline" болгон хадгална.
Дараа нь дахин шалгаж, файл НЭМЭГДСЭН / УСТСАН / ӨӨРЧЛӨГДСӨН эсэхийг илрүүлнэ.

Ашиглалт:
    python integrity_checker.py init  testdir     # baseline үүсгэх
    python integrity_checker.py check testdir     # baseline-тай харьцуулах

Baseline нь baseline.json файлд хадгалагдана.
"""

import sys
import os
import hashlib
import json
from datetime import datetime

# Windows консол дээр кирилл үсэг зөв хэвлэхийн тулд
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASELINE_FILE = "baseline.json"


def sha256_of_file(path, chunk=65536):
    """Файлыг хэсэгчлэн уншиж SHA-256 буцаана (том файлд ч санах ой хэмнэнэ)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk)
            if not data:
                break
            h.update(data)
    return h.hexdigest()


def scan(folder):
    """Фолдерыг рекурсивээр гүйж {харьцангуй_зам: hash} буцаана."""
    result = {}
    for root, _dirs, files in os.walk(folder):
        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, folder)
            try:
                result[rel] = sha256_of_file(full)
            except (OSError, PermissionError) as e:
                print(f"  [алгассан] {rel}: {e}")
    return result


def do_init(folder):
    hashes = scan(folder)
    data = {
        "folder": folder,
        "created": datetime.now().isoformat(timespec="seconds"),
        "files": hashes,
    }
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Baseline үүслээ: {len(hashes)} файл -> {BASELINE_FILE}")


def do_check(folder):
    if not os.path.exists(BASELINE_FILE):
        print("Baseline алга. Эхлээд: python integrity_checker.py init <folder>")
        return

    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        baseline = json.load(f)

    old = baseline["files"]
    new = scan(folder)

    old_keys = set(old)
    new_keys = set(new)

    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)
    changed = sorted(k for k in (old_keys & new_keys) if old[k] != new[k])
    unchanged = (old_keys & new_keys) - set(changed)

    print(f"Baseline огноо: {baseline.get('created', '?')}")
    print(f"Шалгасан: {folder}\n")

    if not (added or removed or changed):
        print("OK — Өөрчлөлт илрээгүй. Бүх файл бүрэн бүтэн.")
    else:
        if changed:
            print(f"[!] ӨӨРЧЛӨГДСӨН ({len(changed)}):")
            for k in changed:
                print(f"    ~ {k}")
        if added:
            print(f"[+] НЭМЭГДСЭН ({len(added)}):")
            for k in added:
                print(f"    + {k}")
        if removed:
            print(f"[-] УСТСАН ({len(removed)}):")
            for k in removed:
                print(f"    - {k}")

    print(f"\nӨөрчлөгдөөгүй: {len(unchanged)} файл")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return
    cmd, folder = sys.argv[1], sys.argv[2]
    if cmd == "init":
        do_init(folder)
    elif cmd == "check":
        do_check(folder)
    else:
        print("Тушаал буруу. 'init' эсвэл 'check' ашигла.")


if __name__ == "__main__":
    main()
