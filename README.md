# Phishing Email Analyzer

Phishing Email Analyzer adalah aplikasi web sederhana berbasis Python dan Streamlit yang digunakan untuk menganalisis raw email header. Aplikasi ini dapat mengekstrak informasi penting dari header email, membaca status SPF, DKIM, dan DMARC, mendeteksi anomali domain/IP pengirim, serta menghasilkan risk score untuk membantu mengidentifikasi potensi phishing email.

## Fitur Utama

- Input raw email header melalui textarea.
- Ekstraksi informasi penting dari header email:
  - From
  - Return-Path
  - Reply-To
  - Subject
  - Date
  - Message-ID
  - Sender IP
- Deteksi status autentikasi email:
  - SPF
  - DKIM
  - DMARC
- Deteksi anomali domain:
  - Perbedaan domain From dan Return-Path
  - Perbedaan domain From dan Reply-To
  - Reply-To menggunakan domain email gratis
- Analisis IP pengirim:
  - IP ditemukan atau tidak
  - IP public atau private
- Risk scoring berbasis rule sederhana.
- Verdict akhir:
  - Aman
  - Mencurigakan
  - Berpotensi Phishing

## Teknologi yang Digunakan

- Python 3.x
- Streamlit
- Regular Expression
- ipaddress module
- email parser module

## Struktur Folder

```text
Phishing_Email_Analyzer/
│
├── app.py
├── parser_module.py
├── analyzer_module.py
├── scoring_module.py
├── requirements.txt
├── README.md
│
└── sample_headers/
    ├── safe_email.txt
    ├── suspicious_email.txt
    └── phishing_email.txt
```

## Cara Instalasi

Clone repository atau download project ini, kemudian buka folder project menggunakan VS Code.

Buat virtual environment:

```bash
python -m venv venv
```

Aktifkan virtual environment:

```bash
venv\Scripts\activate
```

Install dependency:

```bash
pip install -r requirements.txt
```

## Cara Menjalankan Aplikasi

Jalankan perintah berikut di terminal:

```bash
streamlit run app.py
```

Jika berhasil, aplikasi akan terbuka di browser dengan alamat:

```text
http://localhost:8501
```

## Cara Menggunakan

1. Buka aplikasi Phishing Email Analyzer.
2. Paste raw email header ke textarea.
3. Klik tombol **Analyze Header**.
4. Lihat hasil analisis yang terdiri dari:
   - Header Information
   - Sender IP Analysis
   - Authentication Results
   - Risk Analysis
   - Findings

## Contoh Input Header

```text
From: Bank Support <support@bankabc.com>
Return-Path: <verify@random-mail.ru>
Reply-To: attacker@gmail.com
Received: from random-mail.ru (185.44.22.10)
Authentication-Results: mx.google.com; spf=fail dkim=fail dmarc=fail
Subject: Urgent Account Verification
Date: Mon, 10 Jun 2026 09:00:00 +0700
Message-ID: <fake123@random-mail.ru>
```

## Contoh Output

```text
SPF Status   : FAIL
DKIM Status  : FAIL
DMARC Status : FAIL

Risk Score   : 100/100
Verdict      : Berpotensi Phishing

Findings:
- SPF gagal
- DKIM gagal
- DMARC gagal
- Domain Return-Path berbeda dengan domain From
- Domain Reply-To berbeda dengan domain From
- Reply-To menggunakan domain email gratis
```

## Metode Scoring

Aplikasi menggunakan rule-based scoring sederhana.

```text
SPF fail                  +25
SPF softfail/neutral      +10
SPF none                  +10
DKIM fail                 +25
DKIM none                 +10
DMARC fail                +30
DMARC none                +15
From vs Return-Path beda  +10
From vs Reply-To beda     +10
Reply-To free domain      +10
IP tidak ditemukan        +5
IP private                +5
```

Skor akhir dibatasi maksimal 100.

## Kategori Risiko

```text
0 - 30    : Aman
31 - 60   : Mencurigakan
61 - 100  : Berpotensi Phishing
```

## Batasan Project

- Aplikasi hanya menganalisis header email, bukan isi/body email.
- Aplikasi tidak melakukan scan attachment.
- Aplikasi tidak melakukan analisis URL di dalam body email.
- Status SPF, DKIM, dan DMARC dibaca dari header, bukan divalidasi ulang melalui DNS lookup.
- Aplikasi belum menggunakan database reputasi IP eksternal.
- Hasil analisis bersifat indikatif dan bukan keputusan final absolut.

## Catatan Privasi

Jangan memasukkan atau mengunggah header email yang mengandung data sensitif tanpa disensor. Informasi seperti alamat email pribadi, Message-ID, token, link verifikasi, IP internal, atau data organisasi sebaiknya disamarkan sebelum digunakan untuk demo atau laporan.

## Future Work

Pengembangan selanjutnya dapat mencakup:

- DNS lookup untuk verifikasi SPF record secara langsung.
- Validasi DKIM lebih mendalam.
- Integrasi IP reputation API.
- Analisis URL pada body email.
- Export hasil analisis ke PDF.
- Upload file `.txt` berisi header email.
- Dashboard statistik hasil analisis.

## Author

Nama: Frengki Hotsabar Parmonangan Simatupang  
Project: Phishing Email Analyzer  
Mata Kuliah: Jaringan Enterprise