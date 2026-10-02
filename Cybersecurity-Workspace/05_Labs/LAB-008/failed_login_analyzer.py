"""
Failed Login Analyzer
---------------------
Linux auth.log (эсвэл ижил форматтай) файлыг уншиж, амжилтгүй нэвтрэлтийг
(SSH "Failed password") тоолж, IP болон хэрэглэгчээр бүлэглэн, brute-force
сэжигтэй эх сурвалжийг (босго давсан) тэмдэглэнэ.

Ашиглалт:
    python failed_login_analyzer.py sample_auth.log
    python failed_login_analyzer.py sample_auth.log --threshold 5

Зөвхөн өөрийн / сургалтын лог дээр ашиглана.
"""

import sys
import re
import argparse
from collections import Counter

# Windows консол дээр кирилл үсэг зөв хэвлэхийн тулд
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# Жишээ мөр:
# Oct  2 10:15:32 server sshd[2345]: Failed password for root from 192.168.56.10 port 51920 ssh2
# Oct  2 10:15:40 server sshd[2350]: Failed password for invalid user admin from 10.0.0.5 port 4120 ssh2
LINE_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def analyze(path, threshold):
    by_ip = Counter()
    by_user = Counter()
    total = 0

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = LINE_RE.search(line)
            if m:
                total += 1
                by_ip[m.group("ip")] += 1
                by_user[m.group("user")] += 1

    return total, by_ip, by_user


def main():
    ap = argparse.ArgumentParser(description="Failed login analyzer")
    ap.add_argument("logfile", help="auth.log зам")
    ap.add_argument("--threshold", type=int, default=5,
                    help="Brute-force гэж тэмдэглэх босго (default 5)")
    args = ap.parse_args()

    try:
        total, by_ip, by_user = analyze(args.logfile, args.threshold)
    except FileNotFoundError:
        print(f"Файл олдсонгүй: {args.logfile}")
        return

    print("=" * 50)
    print("  FAILED LOGIN ANALYSIS REPORT")
    print("=" * 50)
    print(f"Нийт амжилтгүй нэвтрэлт: {total}\n")

    print("Top эх IP хаягууд:")
    for ip, cnt in by_ip.most_common(10):
        flag = "  <-- BRUTE FORCE сэжигтэй!" if cnt >= args.threshold else ""
        print(f"  {ip:18} {cnt:4} оролдлого{flag}")

    print("\nTop онилогдсон хэрэглэгчид:")
    for user, cnt in by_user.most_common(10):
        print(f"  {user:18} {cnt:4} оролдлого")

    suspects = [ip for ip, c in by_ip.items() if c >= args.threshold]
    print("\n" + "-" * 50)
    if suspects:
        print(f"[!] {len(suspects)} сэжигтэй IP (босго={args.threshold}): {', '.join(suspects)}")
        print("    Зөвлөмж: эдгээр IP-г firewall дээр хаах, лог нарийвчлан шалгах.")
    else:
        print("[OK] Босго давсан сэжигтэй IP алга.")


if __name__ == "__main__":
    main()
