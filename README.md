# Network Intrusion Detection System (NIDS)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

Hệ thống phát hiện ARP Spoofing tự động với khả năng giám sát mạng 24/7.

**Hybrid Detection**: Active Scan + Passive Monitoring
**Real-time Alerts**: Telegram notifications
**Auto Network Discovery**: Tự động phát hiện network
**Periodic Scanning**: Quét mỗi 5 phút
**Database Logging**: SQLite lưu trữ
**24/7 Monitoring**: Systemd service
**Zero Configuration**: Không cần hardcode MAC

###Kiến trúc hệ thống

┌─────────────────────────────────────────┐
│ NIDS Hybrid Detector │
├─────────────────────────────────────────┤
│ Active Scanner (mỗi 5 phút) │
│ ├─ ARP scan toàn bộ subnet │
│ ├─ Build/update baseline │
│ └─ Detect new devices │
├─────────────────────────────────────────┤
│ Passive Monitor (real-time) │
│ ├─ Listen ARP traffic │
│ ├─ Compare với baseline │
│ └─ Alert on conflicts │
├─────────────────────────────────────────┤
│ Alert System │
│ ├─ Telegram notifications │
│ ├─ Terminal output │
│ └─ SQLite database │
└─────────────────────────────────────────┘

###Cài đặt:

### Yêu cầu

- Python 3.8+
- Linux (Kali Linux)
- Root privileges

### Cài đặt nhanh

```bash
# Clone repository
git clone https://github.com/tdat496/nids-arp-spoofing-detector.git
cd nids-arp-spoofing-detector

# Cài đặt dependencies
sudo pip3 install -r requirements.txt

# Cấu hình Telegram (sửa file nids_hybrid.py)
nano nids_hybrid.py
# Sửa dòng:
# self.TELEGRAM_TOKEN = "your_token"
# self.CHAT_ID = "your_chat_id"

###Sử dụng

###Chạy thủ công
sudo python3 nids_hybrid.py

###Chạy như service (24/7)
# Tạo service
sudo nano /etc/systemd/system/nids-detector.service

###Nội dung service:
[Unit]
Description=NIDS ARP Spoofing Detector
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/kali/nids-project
ExecStart=/usr/bin/python3 /home/kali/nids-project/nids_hybrid.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target

###Kích hoạt:
sudo systemctl daemon-reload
sudo systemctl enable nids-detector
sudo systemctl start nids-detector
sudo systemctl status nids-detector

###Cơ chế hoạt động:
### Nguyên lý:
Mỗi IP CHỈ CÓ 1 MAC address hợp lệ
Nếu 1 IP có NHIỀU MAC → ARP SPOOFING

### Quy trình

1.BUILD BASELINE (Lúc khởi động)
   - Active scan toàn bộ subnet
   - Lưu IP → MAC mappings

2.PASSIVE MONITORING (Liên tục)
   - Lắng nghe ARP traffic
   - So sánh với baseline
   - Alert khi có conflict

3.PERIODIC RESCAN (Mỗi 5 phút)
   - Quét lại subnet
   - Update baseline

##  Ví dụ phát hiện

Bình thường:192.168.32.2 → 00:50:56:E0:A7:74 (Gateway)
Khi bị spoofing:192.168.32.2 → 00:50:56:E0:A7:74 (Thật)
                192.168.32.2 → 00:0C:29:DA:B6:80 (Giả mạo)


##Tech Stack

- Python 3.8: Ngôn ngữ chính
- Scapy: Packet manipulation
- SQLite: Database
- Telegram Bot API: Alerts
- Systemd: Service management

##License

MIT License - xem file [LICENSE](LICENSE)

##Disclaimer

Chỉ sử dụng cho mục đích **học tập và nghiên cứu**. 
Không sử dụng cho mục đích xấu.

##Author
Nguyen Trung Dat
Cybersecurity Student  
GitHub: github.com/tdat496
