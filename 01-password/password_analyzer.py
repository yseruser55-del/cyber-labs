"""
Password Strength Analyzer
--------------------------
Нууц үгийн урт, нийлмэл байдал, түгээмэл загвар, толь бичгийн давтамжийг
шалгаж оноо (0-100) болон сайжруулах зөвлөмж гаргана.

Ашиглалт:
    python password_analyzer.py
    (хэрэглэгч нууц үгээ оруулна - дэлгэц дээр харагдахгүй)

Нэмэлт (сонголттой):
    pip install zxcvbn   # мэргэжлийн сантай харьцуулахын тулд
"""

import re
import sys
import getpass

# Windows консол дээр кирилл үсэг зөв хэвлэхийн тулд
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# Хамгийн түгээмэл сул нууц үгнүүд (жишээ. Том жагсаалтыг common.txt-аас уншина)
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "1234567", "111111", "123123", "abc123", "password1", "iloveyou",
    "admin", "welcome", "monkey", "dragon", "letmein", "000000",
}

# Гар дээрх дараалсан/давтагдах загварууд
KEYBOARD_PATTERNS = ["qwerty", "asdf", "zxcv", "1234", "abcd", "0000"]


def load_common_file(path="common.txt"):
    """common.txt байвал нэмэлт түгээмэл нууц үг уншина (сонголттой)."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                COMMON_PASSWORDS.add(line.strip().lower())
    except FileNotFoundError:
        pass  # Байхгүй бол дотоод жагсаалтаар л явна


def analyze(pw):
    """Нууц үгийг шалгаад (оноо, зөвлөмжүүд) буцаана."""
    score = 0
    tips = []

    # 1. Урт
    length = len(pw)
    if length >= 16:
        score += 35
    elif length >= 12:
        score += 25
    elif length >= 8:
        score += 15
    else:
        tips.append("Хамгийн багадаа 12 тэмдэгт ашигла (16+ хамгийн сайн).")

    # 2. Тэмдэгтийн төрлүүд
    has_lower = bool(re.search(r"[a-z]", pw))
    has_upper = bool(re.search(r"[A-Z]", pw))
    has_digit = bool(re.search(r"\d", pw))
    has_symbol = bool(re.search(r"[^A-Za-z0-9]", pw))

    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety * 10  # дээд тал нь 40

    if not has_upper:
        tips.append("Том үсэг нэм (A-Z).")
    if not has_digit:
        tips.append("Тоо нэм (0-9).")
    if not has_symbol:
        tips.append("Тусгай тэмдэгт нэм (!@#$...).")

    # 3. Түгээмэл нууц үг эсэх
    if pw.lower() in COMMON_PASSWORDS:
        score = min(score, 10)
        tips.append("Энэ бол маш түгээмэл нууц үг! Заавал солино.")

    # 4. Гарын загвар / давтагдал
    pw_low = pw.lower()
    for pat in KEYBOARD_PATTERNS:
        if pat in pw_low:
            score -= 15
            tips.append(f"'{pat}' гэх дараалсан/загварласан хэсгээс зайлсхий.")
            break

    # Нэг тэмдэгт олон удаа давтагдсан (ааааа, 1111)
    if re.search(r"(.)\1\1", pw):
        score -= 10
        tips.append("Нэг тэмдэгт 3+ удаа давтагдахаас зайлсхий.")

    # Оноог 0-100 хооронд барих
    score = max(0, min(100, score))

    if score >= 80:
        rating = "ХҮЧТЭЙ"
    elif score >= 50:
        rating = "ДУНД"
    else:
        rating = "СУЛ"

    return score, rating, tips


def main():
    load_common_file()
    print("=== Password Strength Analyzer ===")
    print("(нууц үг бичихэд дэлгэц дээр харагдахгүй)\n")
    pw = getpass.getpass("Нууц үгээ оруул: ")

    if not pw:
        print("Хоосон байна.")
        return

    score, rating, tips = analyze(pw)
    print(f"\nОноо : {score}/100")
    print(f"Үнэлгээ: {rating}")

    if tips:
        print("\nСайжруулах зөвлөмж:")
        for t in tips:
            print(f"  - {t}")
    else:
        print("\nГайхалтай! Нэмж сайжруулах зүйлгүй.")

    # zxcvbn байвал харьцуулалт үзүүлнэ
    try:
        from zxcvbn import zxcvbn
        result = zxcvbn(pw)
        print(f"\n[zxcvbn харьцуулалт] түвшин: {result['score']}/4")
        guesses = result["guesses"]
        print(f"[zxcvbn] таамаглах оролдлого: ~{guesses:,.0f}")
    except ImportError:
        print("\n(zxcvbn суулгавал мэргэжлийн харьцуулалт гарна: pip install zxcvbn)")


if __name__ == "__main__":
    main()
