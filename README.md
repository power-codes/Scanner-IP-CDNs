# 🚀 `README.md` — Powercodes IP & CDNs Scanner v1.0

````md
<div align="center">

# ⚡ Powercodes — IP & Domain Scanner
## 🔎 Advanced CDN IP Scanner & TCP Checker

<img src="https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python">
<img src="https://img.shields.io/badge/Version-1.0-green?style=for-the-badge">
<img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Termux-orange?style=for-the-badge">
<img src="https://img.shields.io/badge/CDN-Supported-red?style=for-the-badge">

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

> ⚠️ فقط پینگ گرفتن ملاک نیست!

در بسیاری از شرایط مخصوصاً روی اینترنت‌های دارای فیلترینگ،  
ممکن است یک IP پینگ بدهد اما اتصال TCP واقعی برقرار نکند.

بنابراین برای استفاده واقعی از IP ها باید:

✅ هم Ping پاسخ بدهد  
✅ هم TCP Port باز باشد  

این ابزار دقیقاً همین کار را انجام می‌دهد 🔥

---

# ✨ قابلیت‌ها

# 🚀 Features

- ✅ اسکن IP تکی
- ✅ اسکن Subnet
- ✅ اسکن دامنه و ساب‌دامنه
- ✅ تشخیص CDN
- ✅ تست Ping
- ✅ تست TCP واقعی
- ✅ خروجی TXT تمیز
- ✅ حذف خودکار IP های تکراری
- ✅ حذف متن‌های اضافی
- ✅ پشتیبانی از فایل Targets
- ✅ Import فایل Target
- ✅ Multi Thread Scanner
- ✅ سرعت بالا
- ✅ رابط تحت وب Flask
- ✅ تست شده روی:
  - Windows
  - Termux
  - Linux

---

# 🌍 CDN های پشتیبانی شده

# ☁️ Supported CDN Providers

| CDN | Supported |
|------|-----------|
| Cloudflare | ✅ |
| Fastly | ✅ |
| Netlify | ✅ |
| Vercel | ✅ |
| Gcore | ✅ |
| AWS CloudFront | ✅ |
| BunnyCDN | ✅ |
| ArvanCloud | ✅ |

---

# 🧠 نحوه عملکرد

این ابزار ابتدا:

1️⃣ آیپی یا دامنه را Resolve می‌کند  
2️⃣ Ping واقعی می‌گیرد  
3️⃣ اتصال TCP تست می‌کند  
4️⃣ نوع CDN را تشخیص می‌دهد  
5️⃣ آیپی‌های تکراری را حذف می‌کند  
6️⃣ خروجی تمیز TXT می‌سازد  

---

# 📂 ساختار فایل Targets

می‌توانید فایل:

```txt
targets.txt
````

را کنار اسکریپت قرار دهید.

نمونه:

```txt
google.com
cloudflare.com
104.16.0.0/24
1.1.1.1
sub.example.com
```

---

# 📥 نصب و اجرا — Termux

# 📱 Termux Installation

## 1️⃣ نصب پکیج‌ها

```bash
pkg update -y && pkg upgrade -y
pkg install python git -y
```

---

## 2️⃣ کلون پروژه

```bash
git clone https://github.com/power_codes/scanner-ip-cdns.git
```

---

## 3️⃣ ورود به پوشه

```bash
cd scanner-ip-cdns
```

---

## 4️⃣ نصب وابستگی‌ها

```bash
pip install -r requirements.txt
```

---

## 5️⃣ اجرای ابزار

```bash
python scanner.py
```

---

# 🖥 نصب و اجرا — Windows

# 💻 Windows Installation

## 1️⃣ نصب Python

دانلود:

[https://python.org](https://python.org)

⚠️ هنگام نصب گزینه:

```txt
Add Python to PATH
```

را فعال کنید.

---

## 2️⃣ نصب Git

دانلود:

[https://git-scm.com](https://git-scm.com)

---

## 3️⃣ کلون پروژه

```bash
git clone https://github.com/power_codes/scanner-ip-cdns.git
```

---

## 4️⃣ ورود به پوشه

```bash
cd scanner-ip-cdns
```

---

## 5️⃣ نصب وابستگی‌ها

```bash
pip install -r requirements.txt
```

---

## 6️⃣ اجرای ابزار

```bash
python scanner.py
```

---

# 📦 نصب دستی

# 📁 Manual Installation

اگر Git ندارید:

1️⃣ سورس را ZIP دانلود کنید
2️⃣ Extract کنید
3️⃣ CMD یا Termux را باز کنید
4️⃣ وارد پوشه شوید
5️⃣ اجرا کنید:

```bash
pip install -r requirements.txt
python scanner.py
```

---

# 📄 فایل Dependencies

# 📦 requirements.txt

```txt
flask
requests
```

---

# 📤 خروجی‌ها

ابزار خروجی تمیز TXT تولید می‌کند:

```txt
cloudflare_ips.txt
fastly_clean.txt
alive_tcp.txt
domains_clean.txt
```

---

# ⚡ قابلیت حذف خودکار موارد اضافی

# 🧹 Auto Cleaner

ابزار به صورت خودکار:

* IP های تکراری را حذف می‌کند
* خطوط خراب را پاک می‌کند
* متن‌های اضافی را حذف می‌کند
* خروجی مرتب تولید می‌کند

---

# 🔥 چرا این ابزار متفاوت است؟

# ⭐ Why This Tool Is Different?

بیشتر اسکنرها فقط Ping می‌گیرند ❌

اما این ابزار:

✅ Ping واقعی
✅ TCP Validation
✅ CDN Detection
✅ Clean Output
✅ High Speed Multi Thread

را همزمان انجام می‌دهد.

---

# 📸 اسکرین‌شات

> به زودی...

---

# 🛡 نسخه

```txt
Version: 1.0
```

---

# ❤️ حمایت از پروژه

اگر پروژه برات مفید بود:

⭐ Repo رو Star کن
🍴 Fork کن
📢 Share کن

---

# 👨‍💻 توسعه‌دهنده

## Powercodes

🌐 Telegram: [https://t.me/powercodes](https://t.me/powercodes)
📺 YouTube: [https://youtube.com/@powercodes](https://youtube.com/@powercodes)
💻 GitHub: [https://github.com/power_codes](https://github.com/power_codes)

---

<div align="center">

# ⭐ Give This Project A Star ⭐

🔥 Made With Python & Powercodes 🔥

</div>
```
