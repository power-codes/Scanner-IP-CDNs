# ⚡ پاورکدز — اسکنر IP و دامنه

ابزار حرفه‌ای اسکن IP و CDN با بررسی Ping + TCP

---

## 🚀 درباره پروژه

این ابزار برای شناسایی IP های قابل استفاده پشت CDN طراحی شده است.

⚠️ نکته مهم:
فقط پینگ معیار خوبی نیست، چون بسیاری از IP ها پینگ می‌دهند اما اتصال TCP واقعی ندارند یا پشت فیلترینگ هستند.

این ابزار بررسی می‌کند:
- Ping
- TCP Connection
- تشخیص CDN

---

## ✨ قابلیت‌ها

- اسکن سریع چند نخی (Multi Thread)
- پشتیبانی IP / ساب‌نت / دامنه / ساب‌دامنه
- تست TCP واقعی
- تست Ping
- تشخیص CDN
- حذف IP های تکراری
- خروجی تمیز TXT
- پشتیبانی از فایل targets.txt

---

## ☁️ CDN های پشتیبانی شده

- Cloudflare
- Fastly
- Netlify
- Vercel
- Gcore
- AWS CloudFront
- BunnyCDN
- ArvanCloud

---

## 📦 نصب و راه‌اندازی

## 💻 دانلود پروژه

دو روش دارید:

### 1) با Git

git clone https://github.com/power-codes/Scanner-IP-CDNs.git
cd Scanner-IP-CDNs

---

### 2) دانلود دستی

- وارد GitHub شوید
- روی Code بزنید
- گزینه Download ZIP را انتخاب کنید
- فایل را استخراج کنید

---

## ⚙️ نصب وابستگی‌ها

pip install -r requirements.txt

---

## 🚀 اجرای ابزار

python scanner.py

---

## 📂 فایل targets (اختیاری)

targets.txt را بسازید:

google.com
cloudflare.com
1.1.1.1
104.16.0.0/24
sub.example.com

---

## 📤 خروجی‌ها

- alive_ips.txt
- clean_domains.txt
- tcp_valid_ips.txt
- cdn_detected.txt

---

## 🧠 نحوه کار

1. تبدیل دامنه به IP
2. بررسی Ping
3. تست TCP
4. تشخیص CDN
5. حذف موارد تکراری
6. ذخیره خروجی تمیز

---

## ⚠️ نکته مهم

Ping به تنهایی کافی نیست.  
این ابزار برای بررسی اتصال واقعی طراحی شده است.

---

## ⭐ حمایت

اگر مفید بود:

⭐ ستاره بده  
🍴 فورک کن  
📢 به دیگران معرفی کن  

---

## 👨‍💻 توسعه‌دهنده

Powercodes
