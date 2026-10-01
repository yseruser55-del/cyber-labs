"""
Secure File Tool (AES-256)
--------------------------
Файлыг нууц үгээр AES-256-GCM ашиглан шифрлэх / задлах хэрэгсэл.
- Нууц үгнээс түлхүүрийг PBKDF2-HMAC-SHA256 (200,000 давталт) аргаар гаргана.
- Файл бүрт санамсаргүй salt, nonce үүсгэнэ.
- GCM горим нь бүрэн бүтэн байдлыг (tamper detection) өөрөө шалгадаг:
  буруу нууц үг эсвэл эвдэрсэн файлыг задлах үед алдаа өгнө.

Ашиглалт:
    python secure_file.py enc  secret.txt            -> secret.txt.enc үүснэ
    python secure_file.py dec  secret.txt.enc        -> secret.txt.dec үүснэ

Шаардлага:
    pip install cryptography
"""

import sys
import os
import getpass

# Windows консол дээр кирилл үсэг зөв хэвлэхийн тулд
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"SFT1"          # файлын танин мэдүүлэг (формат хувилбар)
SALT_LEN = 16
NONCE_LEN = 12
ITERATIONS = 200_000
KEY_LEN = 32             # 32 bytes = AES-256


def derive_key(password: str, salt: bytes) -> bytes:
    """Нууц үг + salt -> 256-bit түлхүүр."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """Байтыг шифрлэж, MAGIC|salt|nonce|ciphertext хэлбэрээр буцаана."""
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, plaintext, None)
    return MAGIC + salt + nonce + ciphertext


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    """Шифрлэсэн байтыг задална. Буруу нууц үг/эвдрэл бол ValueError өгнө."""
    if not blob.startswith(MAGIC):
        raise ValueError("Формат таарахгүй (энэ хэрэгслээр шифрлэсэн файл биш).")
    offset = len(MAGIC)
    salt = blob[offset:offset + SALT_LEN]
    offset += SALT_LEN
    nonce = blob[offset:offset + NONCE_LEN]
    offset += NONCE_LEN
    ciphertext = blob[offset:]
    key = derive_key(password, salt)
    aes = AESGCM(key)
    try:
        return aes.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Нууц үг буруу эсвэл файл эвдэрсэн байна.")


def encrypt(in_path: str, password: str):
    with open(in_path, "rb") as f:
        plaintext = f.read()

    blob = encrypt_bytes(plaintext, password)

    out_path = in_path + ".enc"
    with open(out_path, "wb") as f:
        f.write(blob)

    print(f"Шифрлэв: {in_path} -> {out_path}")
    print(f"  Хэмжээ: {len(plaintext)} -> {os.path.getsize(out_path)} bytes")


def decrypt(in_path: str, password: str):
    with open(in_path, "rb") as f:
        blob = f.read()

    try:
        plaintext = decrypt_bytes(blob, password)
    except ValueError as e:
        print(f"Задлах БҮТЭЛГҮЙТЛЭЭ: {e}")
        return

    # .enc төгсгөлийг авч цэвэр нэр үүсгэнэ (жишээ: secret.txt.enc -> secret.txt.dec)
    if in_path.endswith(".enc"):
        out_path = in_path[:-4] + ".dec"
    else:
        out_path = in_path + ".dec"
    with open(out_path, "wb") as f:
        f.write(plaintext)
    print(f"Задлав: {in_path} -> {out_path}")


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return
    cmd, path = sys.argv[1], sys.argv[2]

    if cmd not in ("enc", "dec"):
        print("Тушаал буруу. 'enc' эсвэл 'dec' ашигла.")
        return
    if not os.path.exists(path):
        print(f"Файл олдсонгүй: {path}")
        return

    password = getpass.getpass("Нууц үг: ")
    if cmd == "enc":
        confirm = getpass.getpass("Нууц үг (давтах): ")
        if password != confirm:
            print("Нууц үг таарсангүй.")
            return
        encrypt(path, password)
    else:
        decrypt(path, password)


if __name__ == "__main__":
    main()
