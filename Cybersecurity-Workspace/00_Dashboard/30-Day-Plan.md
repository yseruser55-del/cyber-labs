# 📅 30-DAY PLAN — 2026-10-01 → 2026-10-30

## Initial Assessment
| | |
|---|---|
| **Current Level** | Дунд (Intermediate) — өөрийн үнэлгээ |
| **Available time** | 7 хоногт 5-7 цаг (өдөрт ~1 цаг) |
| **Focus** | Networking + Linux + Blue Team/Log + Python (бүгд, prerequisite дарааллаар) |
| **Strengths (нотолгоотой)** | Python / Programming (cyber-labs), Git/GitHub |
| **To confirm via lab** | Networking, Linux, Log analysis түвшин |

## Recommended approach
30 цагт 4 домэйныг *эзэмших* боломжгүй тул: **Networking-ийг нуруу болгож, Linux-ийг зэрэгцүүлж, лог шинжилгээг эцэст нь (хоёуланг нэгтгэнэ), Python-ийг бүх долоо хоногийн coding thread болгоно.**

## 4 Weekly Sprint
| Долоо хоног | PRIMARY (Networking) | SECONDARY (Linux) | CODING (Python) | LAB → Deliverable |
|---|---|---|---|---|
| **W1** (10/01-10/07) | OSI model, TCP/IP, common ports & protocols | Linux CLI суурь (navigate, CRUD, permissions) | IP/port жагсаалт задлах жижиг script | **LAB-001** Wireshark суурь (loopback capture) |
| **W2** (10/08-10/14) | DNS, DHCP, ARP, NAT; subnetting суурь | Linux users/groups, services | Log мөр задлагч (regex) | **LAB-002** DNS/ARP урсгал шинжлэх |
| **W3** (10/15-10/21) | TLS/SSL суурь, secure vs insecure protocols | Linux logs (syslog, auth.log) | **Failed Login Analyzer** | **LAB-003** auth.log-оос амжилтгүй нэвтрэлт олох |
| **W4** (10/22-10/30) | Review + Blue Team detection concepts, IOC | Windows Event Logs суурь | Analyzer-ийг brute-force илрүүлдэг болгон өргөтгөх | **LAB-004** brute-force detection + 30-day review |

## 30 хоногийн эцэст хүрэх үр дүн
- ✅ Networking суурь бат (OSI→TLS), Wireshark-аар урсгал уншиж чадна
- ✅ Linux CLI бие даан ажиллана, лог олж уншина
- ✅ Blue Team-ийн анхны ойлголт + бодит detection script
- ✅ Python security tool (Failed Login Analyzer) → cyber-labs-д нэмэгдэнэ
- ✅ 4 LAB report + evidence → 1-2 portfolio candidate
