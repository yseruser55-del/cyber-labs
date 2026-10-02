# LAB-007 — WALKTHROUGH (юун дээр, яаж, хэрхэн хийсэн)

## Юун дээр
- Өөрийн Windows машин, Event Viewer + PowerShell (Admin)
- Зөвхөн өөрийн лог, өөрөө зориуд үүсгэсэн амжилтгүй нэвтрэлт

## Яагаад
Blue Team-ийн өдөр тутмын ажил бол лог шинжилж халдлагын шинжийг олох. Windows Event Log бол хамгийн түгээмэл эх сурвалж. 4625 (failed logon)-ийн хэв маяг нь brute force-ийг хамгийн түрүүнд илчилдэг.

## Хэрхэн хийсэн

### 1. Өгөгдөл үүсгэх
`Win+L` → буруу нууц үгээр 5-10 удаа нэвтрэхийг оролдох. Энэ нь 4625 events үүсгэнэ.

### 2. Event Viewer-ээр харах
`eventvwr.msc` → Windows Logs → Security → Filter Current Log → ID `4625`.
📸 `LAB-007_DATE_eventviewer-4625.png`

### 3. PowerShell-аар автоматжуулах
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50 |
  Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}} |
  Format-Table -Auto
```
📸 `LAB-007_DATE_powershell-4625.png`

### 4. CSV экспорт (LAB-008-д дамжуулах)
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 100 |
  Export-Csv failed_logons.csv -NoTypeInformation
```
`failed_logons.csv`-г `06_Evidence/Logs/` руу хуулах.

## Гарч болох асуудал
| Асуудал | Шийдэл |
|---|---|
| 4625 огт алга | Security log-д хандах эрх → PowerShell-ийг Administrator-аар ажиллуул |
| `Get-WinEvent` алдаа | Admin эрх шаардлагатай |
| Properties[5] буруу нэр | Event бүрийн Properties index өөр байж болно — XML-ийг `$_.ToXml()`-ээр шалгах |

## Юу сурсан
- Event ID 4624/4625/4740-ийн утга
- Brute force логт яаж харагддаг (олон 4625 богино зайтай)
- Event Viewer (GUI) vs PowerShell (automation) ялгаа
- Лог экспортлох → дараагийн шатны автомат шинжилгээнд (LAB-008)
