# 📸 Evidence — Screenshots

Лаб бүрийн `📸` цэгт screenshot аваад энд хадгална.

## Нэрлэх стандарт
```
LAB-XXX_YYYY-MM-DD_тайлбар.png
```
Жишээ:
- `LAB-001_2026-10-04_handshake.png`
- `LAB-002_2026-10-05_nmap-open-ports.png`
- `LAB-006_2026-10-08_john-cracked.png`

## Windows дээр screenshot авах
- **Бүтэн дэлгэц:** `PrtScn` (Clipboard руу) → Paint дээр paste → хадгалах
- **Хэсэгчлэн:** `Win + Shift + S` (Snipping Tool) → хэсгээ сонгож → хадгалах
- **Идэвхтэй цонх:** `Alt + PrtScn`

## Checklist (лаб бүрийн шаардлагатай screenshot)
- [ ] LAB-001 — TCP 3-way handshake, HTTP GET
- [ ] LAB-002 — Nmap нээлттэй портын үр дүн
- [ ] LAB-003 — VM ажиллаж байгаа, snapshot цонх
- [ ] LAB-004 — permission өөрчилсөн өмнө/дараа, sudo log
- [ ] LAB-005 — hash таарсан / өөрчлөгдсөн тохиолдол
- [ ] LAB-006 — John/Hashcat cracked password
- [ ] LAB-007 — Event Viewer 4625 (failed logon)
- [ ] LAB-008 — analyzer script-ийн гаралт
- [ ] LAB-009 — Juice Shop SQLi/XSS амжилттай
- [ ] LAB-010 — ufw status, Suricata alert
