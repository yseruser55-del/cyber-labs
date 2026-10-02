# LAB-005 — WALKTHROUGH (юун дээр, яаж, хэрхэн хийсэн)

## Юун дээр
- Windows PowerShell + өөрийн cyber-labs (integrity_checker, dashboard Crypto Lab)
- Зөвхөн өөрийн тест файл

## Яагаад
Hashing нь нууц үг хадгалах, файл бүрэн бүтэн эсэхийг батлах, malware таних (hash lookup) зэрэгт ашиглагддаг суурь. Энэ лаб нь өөрийн хийсэн хэрэгслийг бодит crypto ойлголттой холбоно.

## Хэрхэн хийсэн

### 1. Анхны hash
```powershell
"hello world" | Out-File -Encoding ascii test.txt
Get-FileHash test.txt -Algorithm SHA256
```
📸 `LAB-005_DATE_hash-before.png`

### 2. Avalanche effect
Файлыг нэг үсгээр өөрчилж (`hello world` → `Hello world`) дахин:
```powershell
Get-FileHash test.txt -Algorithm SHA256
```
→ hash бараг бүхэлдээ өөр. 1 бит → том өөрчлөлт.
📸 `LAB-005_DATE_hash-after.png`

### 3. Өөрийн хэрэгслээр баталгаажуулах
```
cd C:\Users\yalguunjargal.j\cyber-labs\02-integrity
python integrity_checker.py init testdir
# testdir\file2.txt -ийг засах
python integrity_checker.py check testdir
```
→ "[!] ӨӨРЧЛӨГДСӨН: file2.txt"
📸 `LAB-005_DATE_integrity-detect.png`

### 4. MD5 vs SHA-256
Dashboard → `/crypto` → Hash Generator → ижил текст оруулаад MD5 (эвдэрсэн) ба SHA-256-г харьцуул.

## Гарч болох асуудал
| Асуудал | Шийдэл |
|---|---|
| Hash адилхан гарч байна | Файл үнэхээр хадгалагдсан эсэхийг шалгах (editor дээр save) |
| `Get-FileHash` олдохгүй | PowerShell 5+ хэрэгтэй (Windows 10/11 дээр бэлэн) |

## Юу сурсан
- Hash = файлын өвөрмөц хурууны хээ
- Avalanche effect: бяцхан өөрчлөлт → огт өөр hash
- Integrity шалгалт хэрхэн ажилладаг (baseline ↔ одоогийн hash)
- MD5/SHA-1 яагаад найдваргүй (collision)
