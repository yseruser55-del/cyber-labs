# Cyber Security Labs

Кибер аюулгүй байдлын ангийн дадлагын хүрээнд бие даан хийсэн 3 жижиг төсөл.
Бүх төсөл зөвхөн хувийн компьютер дээр, өөрийн тест өгөгдөл дээр ажилладаг.
Байгууллагын систем, өгөгдөлд огт хандаагүй.

## Төслүүд

| # | Нэр | Юу хийдэг | Технологи |
|---|-----|-----------|-----------|
| 1 | [Password Analyzer](01-password/) | Нууц үгийн хүчийг шалгаж оноо, зөвлөмж гаргана | Python, regex, zxcvbn |
| 2 | [File Integrity Checker](02-integrity/) | SHA-256-аар файл өөрчлөгдсөн эсэхийг илрүүлнэ | Python, hashlib |
| 3 | [Secure File Tool](03-crypto/) | Файлыг AES-256-GCM-ээр шифрлэх/задлах | Python, cryptography |

## Суулгах
```
pip install zxcvbn cryptography
```

## Ашигласан ур чадвар
- Нууц үгийн аюулгүй байдал, regex
- Hashing ба бүрэн бүтэн байдлын шалгалт (integrity)
- Криптографи (AES, GCM, PBKDF2 key derivation)
- Python, CLI хэрэгсэл хөгжүүлэлт
