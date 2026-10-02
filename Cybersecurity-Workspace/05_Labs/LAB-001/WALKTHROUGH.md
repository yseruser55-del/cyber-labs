# LAB-001 — WALKTHROUGH (юун дээр, яаж, хэрхэн хийсэн)

## Юун дээр хийсэн бэ (Environment)
- **Төхөөрөмж:** Өөрийн Windows 11 компьютер
- **Хэрэгсэл:** Wireshark + Npcap
- **Сүлжээ:** Зөвхөн loopback (127.0.0.1) — компьютер дотроо, гадагш гарахгүй

## Яагаад энэ лаб (Purpose)
Сүлжээний урсгалыг (network traffic) пакет түвшинд харж, онолоор сурсан **TCP 3-way handshake**-ийг нүдээр баталгаажуулах.

## Хэрхэн хийсэн — алхам алхмаар

### 1. Wireshark суулгах
- https://www.wireshark.org/download.html → Windows x64 Installer
- Суулгахдаа **Npcap**-ийн чагтыг заавал үлдээх (loopback capture-д зайлшгүй)
- 📸 **Screenshot:** суулгац дээр "Install Npcap" чагттай хэсэг → `LAB-001_DATE_npcap-install.png`

### 2. Loopback interface сонгох
- Wireshark нээх
- Interface жагсаалтаас **"Adapter for loopback traffic capture"** дээр 2 дарах
- Capture автоматаар эхэлнэ

### 3. Урсгал үүсгэх
Өөр PowerShell цонхонд өмнө хийсэн dashboard-оо асаана:
```powershell
cd C:\Users\yalguunjargal.j\cyber-labs\04-dashboard
python app.py
```
Browser дээр http://127.0.0.1:5000 нээж, хэдэн хуудсаар дарж орох (урсгал үүснэ).

### 4. Capture зогсоож, filter хийх
- Wireshark дээр улаан дөрвөлжин товч → capture зогсоно
- Filter мөрөнд: `tcp.port == 5000` → Enter
- 📸 **Screenshot:** `[SYN]`, `[SYN, ACK]`, `[ACK]` 3 мөр дараалсан → `LAB-001_DATE_handshake.png`

### 5. HTTP хүсэлт олох
- Filter: `http` → Enter
- `GET / HTTP/1.1` мөрийг олох, дээр нь дарж доод цонхонд задаргааг харах
- 📸 **Screenshot:** HTTP GET packet задаргаа → `LAB-001_DATE_http-get.png`

## Гарч болох асуудал ба шийдэл
| Асуудал | Шийдэл |
|---|---|
| Loopback interface харагдахгүй | Npcap суулгаагүй → Wireshark-ийг дахин суулгаж Npcap чагтлах |
| Пакет огт ирэхгүй | Dashboard асаагүй эсвэл буруу port → `python app.py` ажиллаж байгаа эсэхийг шалгах |
| `tcp.port==5000` юу ч харуулахгүй | Capture-ээ зогсоохоосоо өмнө browser дээр хуудас нээсэн эсэхээ шалгах |

## Юу сурсан бэ
- TCP холболт `SYN → SYN-ACK → ACK` гэсэн 3 алхмаар эхэлдэг
- Port гэдэг нь үйлчилгээг ялгах дугаар (5000 = миний Flask app)
- Wireshark filter ашиглан олон мянган пакетаас хэрэгтэйгээ шүүж авдаг
