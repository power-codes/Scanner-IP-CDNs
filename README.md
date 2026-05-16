# ⚡ Powercodes — IP & Domain Scanner

## 🔎 Advanced CDN IP Scanner & TCP Checker

---

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python)
![Version](https://img.shields.io/badge/Version-1.0-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Windows%20%7C%20Termux-orange?style=for-the-badge)
![CDN](https://img.shields.io/badge/CDN-Supported-red?style=for-the-badge)

<br>

⚡ اسکن حرفه‌ای IP و دامنه با تشخیص CDN  
⚡ Ping + TCP Validation  
⚡ مناسب تست آیپی‌های قابل استفاده  
⚡ خروجی تمیز و حرفه‌ای  

<br>

🌐 Telegram: https://t.me/powercodes  
📺 YouTube: https://youtube.com/@powercodes  
💻 GitHub: https://github.com/power_codes  

</div>

---

# 🇮🇷 معرفی پروژه

⚠️ فقط پینگ گرفتن ملاک نیست!

در شبکه‌های دارای فیلترینگ، ممکن است یک IP پینگ بدهد اما TCP واقعی نداشته باشد.

این ابزار بررسی می‌کند:
- Ping
- TCP Connection
- CDN Detection

---

# ✨ قابلیت‌ها

- اسکن IP / Subnet / Domain / Subdomain
- Multi Thread Scanner
- TCP Validation
- Ping Test
- CDN Detection
- حذف IP های تکراری
- خروجی TXT تمیز
- پشتیبانی از targets.txt

---

# ☁️ CDN های پشتیبانی شده

- Cloudflare
- Fastly
- Netlify
- Vercel
- Gcore
- AWS CloudFront
- BunnyCDN
- ArvanCloud

---

# 📥 نصب و اجرا

## 💻 Windows

### 1) نصب Python
https://python.org

Add Python to PATH را فعال کنید.

### 2) نصب Git
https://git-scm.com

### 3) Clone

git clone https://github.com/power-codes/Scanner-IP-CDNs.git
cd Scanner-IP-CDNs

### 4) نصب وابستگی‌ها

pip install -r requirements.txt

### 5) اجرا

python scanner.py

---

## 📱 Termux

pkg update -y && pkg upgrade -y
pkg install python git -y

git clone https://github.com/power-codes/Scanner-IP-CDNs.git
cd Scanner-IP-CDNs

pip install -r requirements.txt
python scanner.py

---

## 📁 نصب دستی

1. دانلود ZIP
2. Extract
3. اجرا:

pip install -r requirements.txt
python scanner.py

---

# 📦 Requirements

flask
requests

---

# 📂 Targets

targets.txt:

google.com
cloudflare.com
1.1.1.1
104.16.0.0/24
sub.example.com

---

# 📤 خروجی‌ها

- alive_ips.txt
- clean_domains.txt
- tcp_valid_ips.txt
- cdn_detected.txt

---

# 🧠 نحوه کار

1. Resolve
2. Ping
3. TCP Check
4. CDN Detect
5. Clean duplicates
6. Export

---

# ⭐ Support

⭐ Star  
🍴 Fork  
📢 Share  

---

# 👨‍💻 Powercodes
Telegram: https://t.me/powercodes
