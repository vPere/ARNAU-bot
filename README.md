# A.R.N.A.U.
### Autonomous Reconnaissance & Network Analysis Unit

An AI-powered personal assistant specialized in OSINT and home infrastructure management, accessible via Telegram and Discord.

---

## Features

### 🔍 OSINT & Reconnaissance
- **Person search** — generates username/email combinations and searches across breach databases, web, and social media
- **Username hunt** — checks 300+ platforms simultaneously via Sherlock
- **Breach search** — queries breach.vip across 10B+ leaked records (email, username, IP, phone, domain, Steam ID, Discord ID, UUID)
- **Web search** — Brave Search with Google-style dork operators (`site:`, `filetype:`, `inurl:`, etc.)
- **Page scraping** — extracts emails, phone numbers, and social links from any URL
- **PDF analysis** — searches text and tables inside PDFs for names, emails, or any term

### 🌐 Domain & Network Intelligence
- **WHOIS lookup** — registrant, registrar, creation/expiry dates, nameservers
- **DNS records** — A, MX, TXT, NS, CNAME queries
- **Subdomain enumeration** — via certificate transparency logs (crt.sh)
- **Shodan** — search internet-exposed devices or look up a specific IP

### 🏠 Home Infrastructure
- **Network scan** — local network discovery via nmap (IP, MAC, hostname, vendor)
- **Wake-on-LAN** — wake up machines remotely
- **Proxmox VM management** — list, start, stop, reboot, and check status of VMs

### 🌍 Utilities
- **Weather** — current conditions and 5-day forecast via OpenWeatherMap
- **Directions** — live transit, driving, walking, and cycling routes via Google Maps

---

## Setup

### Requirements
```bash
pip install -r requirements.txt
```

### Environment variables
Create a `.env` file:
```env
# Messaging
TELEGRAM_TOKEN=
ALLOWED_USER_ID=
DISCORD_TOKEN=
DISCORD_ALLOWED_USER_ID=

# AWS Bedrock (Claude)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=us-east-1
BEDROCK_MODEL=us.anthropic.claude-3-5-sonnet-20241022-v2:0

# Infrastructure
PC_MAC=
PROXMOX_HOST=192.168.1.76
PROXMOX_PORT=8006
PROXMOX_USER=root@pam
PROXMOX_PASSWORD=
PROXMOX_NODE=pve

# OSINT APIs
SHODAN_API_KEY=
BRAVE_API_KEY=
OPENWEATHER_API_KEY=
GOOGLE_MAPS_API_KEY=

# Network
HOME_SUBNET=192.168.1.0/24
```

### Run
```bash
python main.py
```

### Run as a service
```bash
systemctl enable arnau
systemctl start arnau
journalctl -u arnau -f
```
---

## ⚠️ Disclaimer
ARNAU is intended for **legal, ethical, and personal use only** — penetration testing your own infrastructure, academic research, and defensive security. Always ensure you have proper authorization before performing reconnaissance on any target. The author is not responsible for misuse.