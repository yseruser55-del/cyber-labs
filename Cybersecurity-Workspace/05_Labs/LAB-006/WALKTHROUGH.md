# LAB-006 — WALKTHROUGH (юун дээр, яаж, хэрхэн хийсэн)

## Юун дээр
- Kali Linux VM (эсвэл Ubuntu + `apt install john`), snapshot авсан
- **Зөвхөн өөрөө үүсгэсэн hash** — бусдын/жинхэнэ системийн hash БИШ

## Яагаад
Нууц үгийн бодлого (12+ тэмдэгт, санамсаргүй) яагаад чухал вэ гэдгийг "онолоор" биш "нүдээр" харах. Pentester болон Blue Team аль аль нь нууц үгийн эмзэг байдлыг үнэлэхэд энэ зарчмыг мэднэ.

## Хэрхэн хийсэн

### 1. Орчин бэлдэх
Kali дээр John, rockyou.txt бэлэн. Ubuntu бол:
```
sudo apt install john
# rockyou: /usr/share/wordlists/rockyou.txt (шаардвал gunzip)
```

### 2. Өөрийн тест hash
```
echo -n "password123" | md5sum | awk '{print $1}' > hashes.txt
echo -n "Xk9$mQ2!vR7pLw3z" | md5sum | awk '{print $1}' >> hashes.txt
```
📸 `LAB-006_DATE_hashes.png`

### 3. Crack оролдлого
```
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --format=raw-md5 --show hashes.txt
```
→ `password123` тайлагдана (жагсаалтад бий), хүчтэй нь тайлагдахгүй.
📸 `LAB-006_DATE_cracked.png`

### 4. Дүгнэлт бичих
Хэдэн секундэд тайлагдав? Яагаад хүчтэй нь тайлагдсангүй? → тайлан руу.

## Гарч болох асуудал
| Асуудал | Шийдэл |
|---|---|
| rockyou.txt алга | `sudo gunzip /usr/share/wordlists/rockyou.txt.gz` |
| `No password hashes loaded` | `--format=raw-md5` зөв эсэхийг шалгах |
| Дахиж "already cracked" | `rm ~/.john/john.pot` → дахин эхлэх |

## Юу сурсан
- Dictionary attack хэрхэн ажилладаг
- Сул нууц үг = секундэд эвдэрдэг
- Урт + санамсаргүй + salt = практикт эвдэшгүй
- Яагаад системүүд bcrypt/argon2 (удаан, salt-тай) ашигладаг
- ⚖️ Ёс зүй: зөвхөн өөрийн/зөвшөөрөгдсөн hash
