# LAB-004 — WALKTHROUGH (юун дээр, яаж, хэрхэн хийсэн)

## Юун дээр
- LAB-003-ын Ubuntu VM, terminal
- Эхлээд snapshot авсан (аюулгүй)

## Яагаад
Linux бол сервер, security хэрэгслийн гол орчин. Permissions, sudo-г буруу тохируулах нь privilege escalation руу хөтөлдөг. Least privilege = defense in depth-ийн суурь.

## Хэрхэн хийсэн

### 1. Хэрэглэгч/бүлэг
```
sudo adduser analyst
sudo groupadd soc
sudo usermod -aG soc analyst
groups analyst          # шалгах
```

### 2. Файл + эрх
```
echo "secret report" | sudo tee /opt/report.txt
sudo chown root:soc /opt/report.txt
sudo chmod 640 /opt/report.txt
ls -l /opt/report.txt
```
→ `-rw-r----- 1 root soc` гэж харагдана.
📸 `LAB-004_DATE_permissions.png`

### 3. Эрхийг бодитоор тест
```
su - analyst
cat /opt/report.txt      # soc бүлэгт тул УНШИНА
exit
```
Бүлэггүй хэрэглэгчээр → `Permission denied` (least privilege ажиллаж байна).

### 4. Hardening
```
sudo apt update && sudo apt upgrade -y
sudo ufw enable
sudo ufw status verbose
```
📸 `LAB-004_DATE_ufw.png`

### 5. Аудит: sudo хэн юу хийсэн
```
sudo grep sudo /var/log/auth.log | tail
```
📸 `LAB-004_DATE_sudo-log.png`
→ Энэ нь Blue Team-ийн лог шинжилгээтэй (LAB-007/008) холбогдоно.

## Гарч болох асуудал
| Асуудал | Шийдэл |
|---|---|
| `tee: Permission denied` | `sudo tee` ашиглах (pipe-тай үед chmod биш) |
| auth.log алга | Зарим систем `journalctl _COMM=sudo` ашиглана |
| ufw байхгүй | `sudo apt install ufw` |

## Юу сурсан
- rwx тоон утга (4/2/1) ба owner/group/other
- `chmod 640`, `chown` хэрхэн ажилладаг
- Least privilege-ийг бодит файл дээр баталгаажуулсан
- auth.log нь sudo/нэвтрэлтийн аудитын гол эх сурвалж → Blue Team-ийн гүүр
