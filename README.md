
```md
<div align="center">

# ⚡ Powercodes — IP & CDN Scanner
## 🔎 Advanced CDN IP Scanner & TCP Checker

<img src="https://img.shields.io/badge/Python-3.9+-blue?style=for-the-badge&logo=python">
<img src="https://img.shields.io/badge/Version-1.0-green?style=for-the-badge">
<img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Termux%20%7C%20Linux-orange?style=for-the-badge">
<img src="https://img.shields.io/badge/CDN-Detection-red?style=for-the-badge">

<br>

**اسکنر حرفه‌ای آی‌پی و دامنه با تشخیص CDN و اعتبارسنجی TCP**

⚡ مناسب تست آیپی‌های Clean و قابل استفاده در پروژه‌های مختلف

<br>

🌐 **Telegram:** [@powercodes](https://t.me/powercodes)  
📺 **YouTube:** [@powercodes](https://youtube.com/@powercodes)  
💻 **GitHub:** [power_codes](https://github.com/power_codes)

</div>

---

## 📌 معرفی پروژه

> ⚠️ فقط پینگ گرفتن کافی نیست!

در بسیاری از شبکه‌ها (به‌خصوص اینترنت با فیلترینگ)، آیپی ممکن است **پینگ** بدهد اما اتصال **TCP** برقرار نشود.

**Powercodes Scanner** دقیقاً همین مشکل را حل کرده:

✅ **Ping Test**  
✅ **TCP Port Validation** (اتصال واقعی)  
✅ **CDN Detection**  
✅ **خروجی تمیز و مرتب**

---

## ✨ قابلیت‌ها

### 🚀 Features

- اسکن تک آی‌پی، سابنت و دامنه
- تشخیص خودکار CDN
- تست Ping + TCP همزمان
- پشتیبانی از فایل `targets.txt`
- حذف خودکار تکراری‌ها و خطوط خراب
- Multi-Thread (سرعت بالا)
- رابط تحت وب (Flask)
- خروجی TXT مرتب و حرفه‌ای
- تست شده روی **Windows**, **Termux** و **Linux**

---

## ☁️ CDNهای پشتیبانی شده

| CDN            | وضعیت     |
|---------------|----------|
| Cloudflare    | ✅       |
| Fastly        | ✅       |
| Netlify       | ✅       |
| Vercel        | ✅       |
| Gcore         | ✅       |
| AWS CloudFront| ✅       |
| BunnyCDN      | ✅       |
| ArvanCloud    | ✅       |

---

## 📥 نصب و اجرا

### Termux

```bash
pkg update -y && pkg upgrade -y
pkg install python git -y

git clone https://github.com/power_codes/scanner-ip-cdns.git
cd scanner-ip-cdns

pip install -r requirements.txt
python scanner.py
```

### Windows

1. Python را از [python.org](https://python.org) نصب کنید (**Add to PATH** را بزنید)
2. Git را از [git-scm.com](https://git-scm.com) نصب کنید
3. دستورات زیر را اجرا کنید:

```bash
git clone https://github.com/power_codes/scanner-ip-cdns.git
cd scanner-ip-cdns
pip install -r requirements.txt
python scanner.py
```

---

## 📂 فایل Targets

فایل `targets.txt` را کنار اسکریپت بسازید:

```txt
google.com
cloudflare.com
104.16.0.0/24
1.1.1.1
sub.example.com
```

---

## 📤 خروجی‌ها

ابزار به‌صورت خودکار فایل‌های زیر را تولید می‌کند:

- `cloudflare_ips.txt`
- `fastly_clean.txt`
- `alive_tcp.txt`
- `domains_clean.txt`

---

## 🧹 قابلیت‌های هوشمند

- حذف خودکار IPهای تکراری
- پاک‌سازی خطوط خراب و متن‌های اضافی
- مرتب‌سازی و تمیز کردن خروجی

---

## 📸 اسکرین‌شات‌ها

> به‌زودی اضافه خواهد شد

---

## ⭐ حمایت از پروژه

اگر این ابزار برای شما مفید بود:

- **Star** این ریپازیتوری را بزنید
- پروژه را برای دوستانتان **Share** کنید
- در صورت داشتن ایده یا باگ، Issue باز کنید

---

<div align="center">

**Made with ❤️ by Powercodes**

**Version 1.0**

</div>
```
