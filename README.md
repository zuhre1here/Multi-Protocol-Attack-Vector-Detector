# Multi-Protocol IDS (Intrusion Detection System)

> **Çoklu Protokol Saldırı Tespit Sistemi**  
> Gerçek zamanlı ağ trafiği analizi ve saldırı tespiti

---

## 👤 Proje Bilgileri

| Bilgi | Değer |
|-------|-------|
| **Öğrenci Adı** | Zührenaz Mısır |
| **Öğrenci No** | 2420191009 |
| **Proje** | Multi-Protocol IDS |
| **Versiyon** | 2.0.0 |

### 📂 Repo Linki

```
https://github.com/zuhre1here/Multi-Protocol-Attack-Vector-Detector
```
> ⚠️ Yukarıdaki linki kendi repo linkinizle güncelleyin.

---

## 🚀 Özellikler

### Desteklenen Protokoller
- ✅ **HTTP/1.1 - HTTP/2** - Web trafiği analizi
- ✅ **GraphQL** - API sorgu analizi
- ✅ **WebSocket** - Gerçek zamanlı bağlantı analizi

### Tespit Edilen Saldırılar
- 🔴 **SQL Injection** - Veritabanı saldırıları
- 🟠 **XSS (Cross-Site Scripting)** - Script enjeksiyonu
- 🟡 **Complexity Attack** - GraphQL aşırı yüklemesi
- 🟢 **Protocol Abuse** - Anormal HTTP metodları

### Yakalama Modları
| Mod | Açıklama | Root Gerekli |
|-----|----------|--------------|
| 📡 PCAP | Raw ağ paketi yakalama | ✅ Evet |
| 🌐 HTTP Proxy | Man-in-the-middle proxy | ❌ Hayır |
| 📄 Log Parser | Nginx/Apache log analizi | ❌ Hayır |
| 🎭 Demo | Simüle saldırı trafiği | ❌ Hayır |

---

## 📦 Kurulum

# test

[![test](https://img.youtube.com/vi/aAzxkVCCzoY/0.jpg)](https://www.youtube.com/watch?v=aAzxkVCCzoY)


### 1. Projeyi İndir
```bash
git clone https://github.com/kullanici-adi/multi-protocol-ids.git
cd multi-protocol-ids
```

### 2. Bağımlılıkları Yükle
```bash
# Temel kurulum
pip install -r requirements.txt

# veya tek tek:
pip install scapy      # PCAP yakalama için
pip install pyyaml     # YAML config için (opsiyonel)
```

### 3. Kurulumu Doğrula
```bash
python3 -m ids.main --help
```

---

## 🎯 Hızlı Başlangıç

```bash
# Demo modu - simüle saldırı trafiği ile test
python3 -m ids.main --demo

# Mevcut ağ arayüzlerini listele
python3 -m ids.main --list-interfaces

# Yardım menüsü
python3 -m ids.main --help
```

---

## 📋 Kullanım Örnekleri

### 1. Demo Modu (Test için)
```bash
# Basit demo
python3 -m ids.main --demo

# JSON çıktı
python3 -m ids.main --demo --output json

# Detaylı çıktı
python3 -m ids.main --demo -vv
```

### 2. HTTP Proxy Modu (Root Gerektirmez ✓)
```bash
# Tek port
python3 -m ids.main --capture-proxy --port 8888

# Birden fazla port
python3 -m ids.main --capture-proxy --ports 8080,8443,9999

# Tüm interface'lerde dinle
python3 -m ids.main --capture-proxy --port 8888 --host 0.0.0.0



# Test (başka terminal):
curl -x http://localhost:8888 "http://example.com/api?id=1 OR 1=1--"
```

### 3. Log Parser Modu (Root Gerektirmez ✓)
```bash
# Nginx log analizi
python3 -m ids.main --parse-log /var/log/nginx/access.log

# Apache log analizi
python3 -m ids.main --parse-log /var/log/apache2/access.log --log-format apache

# Birden fazla dosya
python3 -m ids.main --parse-log access.log error.log

# Canlı izleme (tail -f gibi)
python3 -m ids.main --parse-log /var/log/nginx/access.log --watch
```

### 4. PCAP Yakalama Modu (Root Gerekli ⚠️)
```bash
# Önce interface'leri listele
python3 -m ids.main --list-interfaces

# Otomatik interface tespiti
sudo python3 -m ids.main --capture-pcap

# Belirli interface
sudo python3 -m ids.main --capture-pcap --interface wlan0

# Port filtresi ile
sudo python3 -m ids.main --capture-pcap --interface wlan0 --filter-port 80
```

### 5. Config Dosyası ile Çalıştırma
```bash
# Örnek config oluştur
python3 -m ids.main --generate-config

# Config ile çalıştır
python3 -m ids.main --config config.yaml
```

---

## ⚙️ Config Dosyası Örneği

`config.yaml`:
```yaml
capture:
  mode: proxy
  interface: any
  ports: [8080, 8443, 8888]
  host: 127.0.0.1
  log_files: []
  log_format: auto
  watch: false

output:
  format: text        # text, json, csv
  log_dir: ./logs
  log_file: security_events.log
  verbose: 1          # 0-3

detection:
  enabled_detectors: [sqli, xss, complexity, protocol]
  sqli_sensitivity: high
  xss_sensitivity: high
  max_query_depth: 10
  max_aliases: 50
```

---

## 📊 Desteklenen Log Formatları

| Format | Örnek |
|--------|-------|
| **Nginx Combined** | `127.0.0.1 - - [time] "GET /path HTTP/1.1" 200 1234 "ref" "ua"` |
| **Apache Combined** | Nginx ile aynı format |
| **Apache Common** | `127.0.0.1 - - [time] "GET /path HTTP/1.1" 200 1234` |
| **Auto** | Otomatik tespit |

---

## 🔍 Tespit Edilen Saldırı Türleri

| Saldırı | Protokol | Şiddet | Açıklama |
|---------|----------|--------|----------|
| SQL Injection | HTTP, GraphQL, WebSocket | 🔴 CRITICAL | Veritabanı manipülasyonu |
| XSS | HTTP, WebSocket | 🟠 HIGH | Script enjeksiyonu |
| Complexity Attack | GraphQL | 🟡 MEDIUM | Aşırı derin sorgular |
| Alias Abuse | GraphQL | 🟡 MEDIUM | 50+ alias kullanımı |
| Introspection | GraphQL | 🟢 LOW | Schema keşfi |
| Abnormal Methods | HTTP | 🟢 LOW | TRACE, DEBUG metodları |
| Header Overflow | HTTP | 🟡 MEDIUM | Aşırı büyük header |

---

## 🛠️ Gereksinimler

### Sistem Gereksinimleri
- Python 3.8 veya üzeri
- Linux (Ubuntu/Debian önerilir)
- Root yetkisi (PCAP modu için)

### Python Kütüphaneleri
| Kütüphane | Kullanım | Zorunlu |
|-----------|----------|---------|
| `scapy` | PCAP yakalama | ✅ Evet |
| `pyyaml` | YAML config | ❌ Opsiyonel |
| `netifaces` | Interface listesi | ❌ Opsiyonel |

```bash
pip install scapy pyyaml netifaces
```

---

## 📁 Proje Yapısı

```
multi-protocol-ids/
├── README.md                 # Bu dosya
├── requirements.txt          # Python bağımlılıkları
├── config.example.yaml       # Örnek config dosyası
├── .gitignore               # Git ignore dosyası
├── .env.example             # Örnek environment dosyası
│
└── ids/                     # Ana modül
    ├── __init__.py
    ├── main.py              # CLI entry point
    │
    ├── core/                # Çekirdek modüller
    │   ├── dispatcher.py    # Paket yönlendirici
    │   ├── packet.py        # Packet veri yapısı
    │   ├── logger.py        # Güvenlik logger
    │   └── config.py        # Config yönetimi
    │
    ├── capture/             # Trafik yakalama
    │   ├── base_capture.py  # Base class
    │   ├── pcap_capture.py  # Scapy ile yakalama
    │   ├── http_proxy.py    # HTTP Proxy
    │   └── log_parser.py    # Log parser
    │
    ├── analyzers/           # Protokol analizörleri
    │   ├── base_analyzer.py
    │   ├── http_analyzer.py
    │   ├── graphql_analyzer.py
    │   └── websocket_analyzer.py
    │
    ├── detectors/           # Saldırı detektörleri
    │   ├── sqli_detector.py
    │   └── xss_detector.py
    │
    └── simulation/          # Test simülasyonu
        └── traffic_simulator.py
```

---

## 🧪 Test Etme

### Demo ile Test
```bash
python3 -m ids.main --demo
```

Beklenen çıktı:
```
⚠ ALERT [HTTP] [SQLi] [192.168.1.100] [id=OR 1=1]
⚠ ALERT [HTTP] [XSS] [10.0.0.50] [q=<script>alert('XSS')</script>]
⚠ ALERT [GraphQL] [Deep Query] [192.168.1.100] [depth=12]

Toplam Paket: 24 | Saldırı: 18
```

### Log Dosyası ile Test
```bash
# Test log dosyası oluştur
echo '192.168.1.1 - - [20/Jan/2026:15:00:00 +0300] "GET /api?id=1 OR 1=1-- HTTP/1.1" 200 1234' > /tmp/test.log

# Analiz et
python3 -m ids.main --parse-log /tmp/test.log
```

---

## 📄 Lisans

MIT License

```
Copyright (c) 2026 Zührenaz Mısır

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

## 👤 İletişim

- **Öğrenci**: Zührenaz Mısır
- **Öğrenci No**: 2420191009

---

## 📝 Notlar

- PCAP modu için `sudo` gereklidir
- Port 80, 443 gibi düşük portlar için root yetkisi gerekir
- Log parser modu en kolay test yöntemidir
- Demo modu simülasyon verileri kullanır, gerçek ağ trafiği değildir
