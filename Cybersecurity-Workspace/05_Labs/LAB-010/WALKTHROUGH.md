# LAB-010 — WALKTHROUGH (юун дээр, яаж, хэрхэн хийсэн)

## Юун дээр
- LAB-003-ын Ubuntu VM (snapshot авсан), isolated network
- Скан эх: хост эсвэл хоёр дахь VM

## Яагаад
Firewall нь хаана, IDS нь илрүүлнэ — хоёулаа **defense in depth**-ийн давхарга. SOC аналист alert уншиж, худал/бодит эсэхийг ялгах (triage) чадвартай байх ёстой. Энэ лаб нь өмнөх бүх ур чадварыг (сүлжээ, Linux, лог) нэгтгэнэ.

## Хэрхэн хийсэн

### A. ufw firewall
```
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw enable
sudo ufw status numbered
```
📸 `LAB-010_DATE_ufw.png`
> Default deny → зөвхөн зөвшөөрсөн л орно (least privilege сүлжээнд).

### B. Suricata суулгах
```
sudo apt install suricata -y
sudo suricata-update
ip a                        # interface нэр (жишээ enp0s3)
sudo suricata -i enp0s3 -D
```

### C. Alert үүсгэх
Өөр машинаас:
```
nmap -sS <энэ-VM-IP>
```
VM дээр:
```
sudo tail -f /var/log/suricata/fast.log
```
→ скантай холбоотой alert мөрүүд урсаж харагдана.
📸 `LAB-010_DATE_suricata-alert.png`

### D. Custom rule (сонголттой)
`/etc/suricata/rules/local.rules`:
```
alert icmp any any -> any any (msg:"ICMP ping detected"; sid:1000001; rev:1;)
```
`sudo systemctl restart suricata` → ping → alert шалгах → detection engineering-ийн амт.

## Гарч болох асуудал
| Асуудал | Шийдэл |
|---|---|
| Interface нэр буруу | `ip a`-аар зөв нэрийг олох (enp0s3/eth0) |
| Alert ирэхгүй | `suricata-update` хийсэн эсэх, interface зөв эсэх |
| fast.log хоосон | Суриката ажиллаж буй эсэх: `sudo systemctl status suricata` |
| Хоёр дахь VM алга | Хостоос скан хийх (Host-only сүлжээнд хост↔VM боломжтой) |

## Юу сурсан
- Firewall (хаах) vs IDS (илрүүлэх) ялгаа
- Signature-based detection хэрхэн ажилладаг
- Alert triage: fast.log уншиж юу болсныг ойлгох
- Defense in depth: олон давхарга хамгаалалт
- Энэ лаб = Networking + Linux + Log analysis-ийн нэгдэл
