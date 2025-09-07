# Mr-Scan


# ─── 🎯 Mr-Scan ──

🔍 **ابزاری برای شناسایی لینک‌های سالم، مشکوک و مخرب**  
قابل اجرا در: **Termux, Linux, macOS, Windows Terminal**

---

## 📌 مشخصات پروژه
- ✔️ پشتیبانی از چند زبان:
  ![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
  ![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?logo=javascript&logoColor=black)
  ![HTML](https://img.shields.io/badge/HTML5-E34F26?logo=html5&logoColor=white)
  ![CSS](https://img.shields.io/badge/CSS3-1572B6?logo=css3&logoColor=white)

- ⚡ شناسایی لینک‌ها به‌صورت رنگی:
  - ✔️ سبز = سالم  
  - ⚠️ زرد = مشکوک  
  - ❌ قرمز = مخرب  

- 🌐 امکان اجرا روی چند محیط (ترموکس، لینوکس، ویندوز ترمینال)

---

## ⚡ نصب و اجرا

```bash
# 1. کلون کردن پروژه
git clone https://github.com/MRAvarvokiranshare/Mr-Scan.git
cd Mr-Scan

# 2. نصب پیش‌نیازها
pkg install python -y        # برای Termux
sudo apt install python3 -y  # برای Linux
pip install requests colorama

# 3. اجرای ابزار
python scanner.py https://example.com
