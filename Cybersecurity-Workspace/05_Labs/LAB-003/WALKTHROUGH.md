# LAB-003 — WALKTHROUGH (юун дээр, яаж, хэрхэн хийсэн)

## Юун дээр
- Хост: Windows 11, Hypervisor: VirtualBox, Guest: Ubuntu LTS
- Сүлжээ: Host-only (тусгаарлагдсан)

## Яагаад
Security туршилтыг бодит системдээ хийх эрсдэлтэй. VM нь **аюулгүй, эргэж болдог (snapshot)** орчин өгдөг. Бүх цаашдын лаб (Linux, cracking, Suricata) энэ дээр хийгдэнэ.

## Хэрхэн хийсэн

### 1. VirtualBox + ISO татах
- VirtualBox суулгах
- Ubuntu Desktop LTS ISO татах (~4-5GB)

### 2. VM үүсгэх
New → `Ubuntu-Lab`, Linux / Ubuntu 64-bit
- RAM 3072MB, CPU 2, Disk 25GB dynamic
📸 `LAB-003_DATE_vm-settings.png` — VM тохиргооны цонх

### 3. ISO холбож суулгах
Settings → Storage → Empty оптик → ISO сонгох → Start → Ubuntu суулгацын заавраар явах (Minimal installation, хэрэглэгч үүсгэх).

### 4. Isolated network
Settings → Network → Adapter 1 → **Host-only Adapter**.
> Тайлбар: Host-only үед VM гадаад интернэтгүй. Хэрэв эхлээд шинэчлэлт татах бол түр NAT болгож, дараа нь Host-only болгоно.

### 5. Guest Additions
Devices → Insert Guest Additions CD → суулгах → reboot (дэлгэц автоматаар тохирно).
📸 `LAB-003_DATE_ubuntu-running.png`

### 6. Snapshot
Machine → Take Snapshot → `clean-install`.
📸 `LAB-003_DATE_snapshot.png`

### 7. Snapshot тест
Терминал дээр `touch ~/test.txt` → snapshot руу "Restore" → `ls ~/test.txt` → файл алга = snapshot ажиллаж байна.

## Гарч болох асуудал
| Асуудал | Шийдэл |
|---|---|
| VT-x/AMD-V алдаа | BIOS/UEFI дээр Virtualization идэвхжүүлэх |
| VM маш удаан | RAM/CPU нэмэх, "Enable 3D" унтраах |
| Интернэт татахгүй | Эхлээд NAT-аар шинэчлээд, дараа нь Host-only |
| 64-bit сонголт алга | BIOS Virtualization + Windows дээр Hyper-V унтраах |

## Юу сурсан
- Hypervisor, Host/Guest OS ялгаа
- Snapshot нь алдаанаас сэргээх "аврах зам"
- Isolated network яагаад security lab-д чухал (malware гадагш гарахгүй)
