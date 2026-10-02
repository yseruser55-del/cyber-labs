# LAB-008 — WALKTHROUGH (юун дээр, яаж, хэрхэн хийсэн)

## Юун дээр
- Python 3, аль ч OS
- `failed_login_analyzer.py` + `sample_auth.log` (энэ фолдерт)

## Яагаад
SOC аналист өдөрт мянга мянган лог мөр хардаг — гараар боломжгүй. Автоматжуулах чадвар (Python) нь Blue Team-ийн чухал ур чадвар. Энэ лаб нь LAB-007-ийн гар ажиллагааг кодоор солино.

## Хэрхэн хийсэн

### 1. Кодоо ойлгох
- `LINE_RE` — regex нь `Failed password for [invalid user] USER from IP` хэв маягийг барина
- `Counter` — IP ба user тус бүрийн давтамжийг тоолно
- Босго (`--threshold`) давсан IP = brute-force сэжигтэй

### 2. Ажиллуулах
```
cd .../05_Labs/LAB-008
python failed_login_analyzer.py sample_auth.log
```
Үр дүн:
- Нийт 14 амжилтгүй
- `192.168.56.10` (7) болон `203.0.113.9` (6) → **BRUTE FORCE сэжигтэй**
📸 `LAB-008_DATE_analyzer-output.png`

### 3. Босго туршилт
```
python failed_login_analyzer.py sample_auth.log --threshold 3
```
→ Threshold-ийг бууруулахад илүү олон IP "сэжигтэй" болно. False positive/negative-ийн тэнцвэрийг ойлго.

### 4. Бодит лог
LAB-007-д Linux VM-ээс авсан жинхэнэ `auth.log`-оо оруулж туршиж болно (sshd-тай Ubuntu VM).

## Гарч болох асуудал
| Асуудал | Шийдэл |
|---|---|
| Кирилл гаралт алдаа | Script дотор `sys.stdout.reconfigure(encoding="utf-8")` бий (засвартай) |
| 0 үр дүн | Лог формат өөр → `LINE_RE`-г өөрийн лог руу тохируулах |
| Windows auth.log байхгүй | Windows нь Event Log (LAB-007); энэ нь Linux формат — sample эсвэл VM-ийн лог ашиглах |

## Юу сурсан
- Regex-ээр структургүй логоос өгөгдөл ялгах
- `Counter`-аар давтамж тоолох
- Threshold-based detection = энгийн detection rule
- Автоматжуулалт нь гар ажиллагааг минутаас секунд болгодог
- Энэ бол cyber-labs төсөлд нэмэх боломжтой 4 дэх tool
