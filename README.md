# SQLi-Inject  
**Comprehensive SQL Injection Dork Scanner**  

---

## 🔍 Fitur Utama
- **Google Dorking Otomatis** - Temukan target menggunakan Google Custom Search API
- **Payload Terenkripsi** - Enkripsi payload dengan Fernet untuk menghindari deteksi
- **Multithreaded Scanning** - Eksekusi paralel dengan ThreadPoolExecutor
- **Mekanisme Evasi**:
  - Rotasi User-Agent acak
  - Delay dinamis dengan jitter
  - Spoofing header X-Forwarded-For
  - Referer palsu
- **Multi-Format Reporting** (JSON/CSV/Console)
- **Deteksi Cerdas**:
  - Analisis response time
  - Pola error database
  - Validasi kode status HTTP

---

## 🛠️ Instalasi
1. Clone repositori  
```bash
git clone https://github.com/Lilith-VnK/SQLi-Inject.git
```
2. Install dependensi  
```bash
pip install -r requirements.txt
```

---

## ⚙️ Konfigurasi
Buat file `config.yaml` dengan template berikut:

```yaml
security:
  encryption_key: "kunci_fernet_base64_32_byte"

payloads:
  mysql:
    - "gAAAAAB..."  # Payload terenkripsi MySQL
    - "gAAAAAB..."  # Contoh: ' OR 1=1 -- 
  postgresql:
    - "gAAAAAB..."  # Payload terenkripsi PostgreSQL

network:
  proxies:
    http: "http://proxy:port"
    https: "https://proxy:port"
  timeout: 10

endpoints:
  google: "https://www.googleapis.com/customsearch/v1"

credentials:
  api_key: "your_google_api_key"
  cse_id: "your_cse_id"

stealth:
  referers:
    - "https://www.google.com"
    - "https://www.bing.com"
  time_based_threshold: 3.5

performance:
  threads: 15

detection_patterns:
  - "error in your SQL syntax"
  - "Warning: mysql"
  - "PostgreSQL.*ERROR"
```

### 🔑 Generate Encryption Key
```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
```

### 🔒 Contoh Enkripsi Payload
```python
key = Fernet.generate_key()
cipher = Fernet(key)
encrypted_payload = cipher.encrypt(b"' OR 1=1 -- ").decode()
print(encrypted_payload)
```

---

## 🚀 Penggunaan
Command dasar:
```bash
python scanner.py \
  --dork "inurl:index.php?id=" \
  --max-results 50 \
  --stealth \
  --jitter 0.5 \
  --random-agent \
  --output console
```

Opsi parameter:
```
--dork          Query pencarian Google (wajib)
--site          Filter berdasarkan domain
--file-type     Filter berdasarkan tipe file
--max-results   Jumlah maksimal hasil (1-100)
--stealth       Aktifkan mode stealth
--jitter        Variasi random delay (default: 0.5)
--delay         Base delay antar request (default: 1.0)
--random-agent  Rotasi User-Agent acak
--output        Format laporan (console/json/csv)
```

---

## ⚠️ Disclaimer
Alat ini hanya untuk tujuan edukasi dan pengujian legal. Pengguna bertanggung jawab penuh atas penggunaan alat ini.

---

## 🙌 Special Thanks
Terima kasih kepada kontributor open source:

- [synnaulaid](https://github.com/synnaulaid) - Inspirasi pengembangan alat keamanan serta debugging

---
