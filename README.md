
<div align="center">

# ⚡ Powercodes — Advanced IP & Domain Scanner
### 🛡️ High-Performance TCP Port Validator & Smart CDN Classifier

[![Python Version](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux%20%7C%20Termux-orange?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/power-codes)
[![CDN Support](https://img.shields.io/badge/CDNs-Multi--Provider-red?style=for-the-badge&logo=cloudflare&logoColor=white)](https://t.me/powercodes)

<br>

**🚀 اسکنر برای تفکیک آی‌پی‌های سالم و وایت لیست شده ** 

[🌐 کانال تلگرام](https://t.me/powercodes) • [📺 آموزش یوتیوب](https://youtube.com/@powercodes) • [💻 گیت‌هاب توسعه‌دهنده](https://github.com/power_codes)

</div>

---

## 📖 معرفی پروژه (Overview)

در وضعیت کنونی شبکه، بسیاری از آی‌پی‌ها یا دامنه‌ها ممکن است به درخواست‌های معمولی `Ping (ICMP)` پاسخ دهند، اما هنگام برقراری ارتباط واقعی، پورت‌های آن‌ها کاملاً مسدود باشد. 

**اسکنر ایپی CDN ها** یک ابزار حرفه‌ای و مبتنی بر پایتون است که با متدولوژی **لایه انتقال (Transport Layer)**، پورت‌های TCP را به صورت موازی (Multi-threaded) بررسی می‌کند. این ابزار به شما تضمین می‌دهد که خروجی نهایی، شامل آی‌پی‌های ۱۰۰٪ تمیز و قابل استفاده در انواع تونل‌ها و کانکشن‌ها است.

---

## ✨ قابلیت‌های برجسته (Key Features)

* **⚡ الگوهای اسکن همزمان (Multi-Threading):** اسکن هزاران رنج و دامنه در کمترین زمان بدون اتلاف وقت یا افت سرعت.
* **🔍 تشخیص هوشمند CDN:** برای دسته‌بندی و شناسایی خودکار نوع CDN.
* **🧹 سیستم پاک‌سازی خودکار (Data Sanitize):** فیلتر کردن هوشمند ورودی‌ها، حذف فضاها و متن ها ، و حذف آی‌پی‌های تکراری.
* **🌐 پشتیبانی از CIDR Subnet:** قابلیت پردازش مستقیم رنج‌های شبکه مانند `104.16.0.0/12`.
* **💾 ذخیره‌سازی ایزوله:** تفکیک خودکار خروجی‌های سالم در فایل‌های مجزا.

---

## ☁️ شبکه‌های CDN پشتیبانی‌شده

| لوگو / نشان | نام سرویس‌دهنده (CDN) | قابلیت شناسایی | رنج بین‌المللی |
| :---: | :--- | :---: | :---: |
| 🟠 | **Cloudflare**  | ✅ دارد | 
| 🌐 | **Akamai(شیرخورشید)**  | ✅ دارد |
| 🟣 | **Fastly** | ✅ دارد | 
| 🟢 | **Netlify**  | ✅ دارد | 
| ▲ | **Vercel** | ✅ دارد | 
| 🔵 | **Gcore**  | ✅ دارد | 
| ☁️ | **AWS CloudFront** | ✅ دارد | 
| 🐰 | **BunnyCDN** | ✅ دارد | 
| ☁️ | **ArvanCloud ** | 🇮🇷 ایران | 

---

## 🛠 نحوه نصب و راه‌اندازی (Installation)

### 💻 محیط ویندوز (Windows)
ابتدا مطئن شوید پایتون روی سیستم شما نصب است و تیک **Add Python to PATH** را زده‌اید. سپس ترمینال (CMD یا PowerShell) را باز کرده و دستورات زیر را وارد کنید:

```powershell
# دریافت پروژه از گیت‌هاب
git clone https://github.com/power-codes/Scanner-IP-CDNs.git

# ورود به پوشه پروژه
cd Scanner-IP-CDNs

# نصب پکیج‌های پیش‌نیاز
pip install -r requirements.txt

# اجرای اسکریپت اصلی
python scanner.py

```

### 📱 محیط ترموکس (Termux - Android)

کدهای زیر را کپی کرده و به صورت یکجا در ترموکس پیست کنید:

```bash
pkg update && pkg upgrade -y
pkg install python git -y
git clone https://github.com/power-codes/Scanner-IP-CDNs.git
cd Scanner-IP-CDNs
pip install -r requirements.txt
python scanner.py

```

---

## 📂 ساختار استاندارد فایل ورودی (targets.txt)

برنامه به صورت هوشمند ساختارهای زیر را در فایل ` تشخیص داده و پردازش می‌کند:
برای مواقعی است که میخواهید یکسری ایپی ها را هر روز اسکن کنید پس در کنار فایل پایتون یک فایل با نام targets.txt بسازید و ایپی های خود را وارد کنید.
در ترمینال ترموکس یا لینوکس باید با دستور nano targets.txt این کار را انجام دهید.
```text
# --- نمونه دامنه‌ها و ساب‌دامنه‌ها ---
example.com
my-example.com

# --- نمونه آی‌پی‌های تکی ---
1.1.1.1
104.18.2.5

# --- نمونه رنج‌های شبکه (CIDR) ---
172.67.0.0/16
104.16.0.0/12


```

---

## 📦 پیش‌نیازهای فنی (Dependencies)

کتابخانه‌های زیر به صورت خودکار از طریق فایل `requirements.txt` پیکربندی می‌شوند:

* `requests`: برای ارسال ریکوئست‌های لایه لایه اپلیکیشن و وب.
* `flask`: جهت مدیریت و مانیتورینگ وضعیت اسکن (نسخه پنل).
---

## ⚠️ عیب‌یابی و رفع خطا (Troubleshooting)

* **خطای `pip: command not found`:** مطمئن شوید در زمان نصب پایتون در ویندوز، گزینه **Add to PATH** را فعال کرده‌اید.
* **سرعت پایین اسکن:** مقدار `threads` را در تنظیمات داخلی اسکریپت بر اساس کشش پردازنده و سرعت اینترنت خود افزایش دهید (مثلاً روی 50 یا 100 تنظیم کنید).
* **خطای اتصال در ترموکس:** حتماً قبل از اجرای دستورات، فیلترشکن خود را برای دانلود دپندنسی‌ها روشن کنید.

---

## ⭐ حمایت و توسعه (Support)

اگر این ابزار به شما در پیدا کردن آی‌پی‌های تمیز کمک کرد، می‌توانید با دادن یک **Star** (⭐) به این ریپازیتوری از توسعه آن حمایت کنید. همچنین می‌توانید پروژه را **Fork** کرده و پچ‌های خود را ارسال کنید.

---

## 👨‍💻 کانال‌های ارتباطی توسعه‌دهنده (Contacts)

* **توسعه‌دهنده اصلی:** Powercodes
* **کانال تلگرام:** [Powercodes Telegram](https://t.me/powercodes)
* **یوتیوب:** [Powercodes YouTube](https://youtube.com/@powercodes)
* **گیت‌هاب:** [Powercodes GitHub](https://github.com/power_codes)

---

