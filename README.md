# SQLi-Inject
"Comprehensive SQL Injection Dork"

---

# Security Scanner Toolkit 🔍🛡️

*Python-based Reconnaissance & Vulnerability Scanner dengan Fitur Stealth*

### Fitur Utama
- 🕵️ **Google Dorking Otomatis** - Temukan target potensial menggunakan Google Custom Search API
- 🔒 **Payload Terenkripsi** - Gunakan payload SQLi terenkripsi Fernet untuk menghindari deteksi
- 🚀 **Multithreaded Scanning** - Eksekusi paralel dengan ThreadPoolExecutor
- 🥷 **Mekanisme Evasi**:
  - Rotasi User-Agent acak
  - Delay dinamis dengan jitter
  - Spoofing header X-Forwarded-For
  - Referer palsu
- 📊 **Multi-Format Reporting** (JSON/CSV/Console)
- 🛡️ **Deteksi Cerdas**:
  - Analisis response time
  - Pola error database
  - Kode status HTTP

### Workflow Inti
1. **Target Discovery**  
   `Google CSE API → Query Builder → Result Parser`
   
2. **Stealth Mechanism**  
   `Random Delay + Jitter → Header Spoofing → Agent Rotation`

3. **Vulnerability Testing**  
   `Encrypted Payloads → Concurrent Probes → Response Analysis`

4. **Reporting**  
   `Vulnerability Aggregation → Format Conversion → Output`

# example yaml configuration

```yaml
# config.yaml
security:
  encryption_key: "kunci_fernet_base64_32_byte"  # Hasil dari Fernet.generate_key()

payloads:
  mysql:
    - "gAAAAAB..."  # Payload SQLi terenkripsi untuk MySQL
    - "gAAAAAB..."  # Contoh: ' OR 1=1 -- 
  postgresql:
    - "gAAAAAB..."  # Payload SQLi terenkripsi untuk PostgreSQL
  # DBMS lainnya...

network:
  proxies:
    http: "http://proxy:port"      # Proksi HTTP opsional
    https: "https://proxy:port"    # Proksi HTTPS opsional
  timeout: 10                      # Timeout koneksi dalam detik

endpoints:
  google: "https://www.googleapis.com/customsearch/v1"  # Endpoint Google CSE

credentials:
  api_key: "your_google_api_key"   # API Key Google Custom Search
  cse_id: "your_cse_id"           # ID Mesin Pencari Kustom

stealth:
  referers:
    - "https://www.google.com"
    - "https://www.bing.com"
    - "https://duckduckgo.com"
  time_based_threshold: 3.5        # Ambang deteksi berbasis waktu (detik)

performance:
  threads: 15                      # Jumlah thread maksimum

detection_patterns:
  - "error in your SQL syntax"     # Pola error database umum
  - "Warning: mysql"
  - "PostgreSQL.*ERROR"
  - "ORA-[0-9]{5}"
  - "Microsoft OLE DB Provider"
```

1. **Security**:
   - `encryption_key`: Kunci Fernet untuk enkripsi/dekripsi payload (generate dengan `Fernet.generate_key()`).

2. **Payloads**:
   - Payload SQL Injection terenkripsi untuk berbagai DBMS (enkripsi dengan kunci Fernet).

3. **Network**:
   - Konfigurasi proxy dan timeout jaringan.

4. **Endpoints**:
   - URL endpoint untuk Google Custom Search API.

5. **Credentials**:
   - Kredensial API Google Custom Search.

6. **Stealth**:
   - Referer palsu dan threshold deteksi serangan berbasis waktu.

7. **Performance**:
   - Jumlah thread untuk eksekusi paralel.

8. **Detection Patterns**:
   - Pola regex untuk mendeteksi kerentanan dalam respons server.

### Cara Generate Encryption Key:
Gunakan skrip Python berikut untuk membuat kunci Fernet:
```python
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())  # Salin output ke config.yaml
```

### Contoh Enkripsi Payload:
```python
key = Fernet.generate_key()
cipher = Fernet(key)
encrypted_payload = cipher.encrypt(b"' OR 1=1 -- ").decode()
print(encrypted_payload)  # Salin string ini ke payloads di config.yaml
```

Pastikan file `config.yaml` berada di direktori yang sama dengan skrip utama.

### Konfigurasi Kunci
```yaml
# config.yaml
security:
  encryption_key: "kunci_fernet_32_byte"

payloads:
  mysql: ["gAAAAAB..."]
  postgresql: ["gAAAAAB..."]

network:
  proxies: {http: ...}
  timeout: 10

credentials:
  api_key: "google_api_key"
  cse_id: "search_engine_id"
```

### Prasyarat
```bash
pip install -r requirements.txt
# requests cryptography fake-useragent pyyaml
```

### Contoh Penggunaan
```bash
python scanner.py --dork "inurl:index.php?id=" --site *.gov --file-type php 
                 --max-results 50 --stealth --random-agent --output json
```

### ⚠️ Disclaimer
**Gunakan hanya pada sistem yang memiliki izin resmi.** Proyek ini bertujuan edukasi keamanan siber dan tidak bertanggung jawab atas penyalahgunaan.

---

Lengkap dengan:  
✅ Auto-configuration system  
✅ Error handling terenkapsulasi  
✅ Parameterized scanning  
✅ Modular architecture
