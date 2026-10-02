# LAB-009 — WALKTHROUGH (юун дээр, яаж, хэрхэн хийсэн)

## Юун дээр
- Өөрийн машин, Docker, target = `localhost:3000` (OWASP Juice Shop)
- Juice Shop нь **зориуд эмзэг** сургалтын апп — хууль ёсны туршилтын талбар

## Яагаад
Веб эмзэг байдлыг ойлгох хамгийн сайн арга бол аюулгүй орчинд өөрөө "эвдэж" үзэх. SQLi, XSS нь OWASP Top 10-ийн сонгодог. Хамгаалагч тал ч эдгээр хэрхэн ажилладгийг мэдэж байж засдаг.

## Хэрхэн хийсэн

### 1. Juice Shop асаах
```
docker run --rm -p 3000:3000 bkimminich/juice-shop
```
(Docker байхгүй бол: `npm install` → `npm start`, Node.js шаардлагатай.)
Browser: http://localhost:3000
📸 `LAB-009_DATE_juiceshop-home.png`

### 2. SQL Injection — login bypass
Login → Email: `' OR 1=1--` , Password: дурын зүйл → Login.
→ Input validation дутуу тул query гажиж, эхний хэрэглэгч (админ)-аар нэвтэрнэ.
📸 `LAB-009_DATE_sqli.png`
> Яагаад: оролтыг шууд SQL-д наасан. **Засвар:** parameterized query / prepared statements.

### 3. XSS
Search талбарт: `<iframe src="javascript:alert('XSS')">` → хайх.
→ JavaScript ажиллаж alert гарна.
📸 `LAB-009_DATE_xss.png`
> Яагаад: оролтыг encode хийлгүй HTML-д буулгасан. **Засвар:** output encoding, CSP.

### 4. Build-Break-Fix тэмдэглэл
Эмзэг байдал бүрт: (1) юу болов, (2) яагаад, (3) хэрхэн засах — гурвыг тайланд бич.

## Гарч болох асуудал
| Асуудал | Шийдэл |
|---|---|
| Docker байхгүй | Docker Desktop суулгах, эсвэл Node.js хувилбар |
| Порт 3000 завгүй | `-p 3001:3000` болгон өөр порт |
| Payload ажиллахгүй | Juice Shop хувилбар шинэ бол өөр payload шаардаж болно — Score Board-оос hint |

## Юу сурсан
- SQLi нь нэвтрэлт/өгөгдлийг хэрхэн тойрдог
- XSS нь browser дээр скрипт хэрхэн ажиллуулдаг
- Үндсэн шалтгаан = input validation / output encoding дутуу
- ⚖️ Ёс зүй: зөвхөн зориуд эмзэг, өөрийн лаб. Жинхэнэ систем = хууль бус
