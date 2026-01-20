# QLineSec

# Kime ait?
**Zührenaz Mısır**
**2420191009** 

# Multi-Protocol IDS (Intrusion Detection System)

Gerçek zamanlı çoklu protokol saldırı tespit sistemi.

## 🚀 Özellikler

- **Çoklu Protokol Desteği**: HTTP/1.1-2, GraphQL, WebSocket
- **Saldırı Tespiti**: SQL Injection, XSS, Complexity Attack, Protocol Abuse
- **Yakalama Modları**:
  - 📡 PCAP - Raw ağ paketi yakalama (root gerekli)
  - 🌐 HTTP Proxy - Araya girme (root gerekmez)
  - 📄 Log Parser - Nginx/Apache log analizi
- **Çıktı Formatları**: Text, JSON, CSV
- **Config Dosyası**: YAML/JSON desteği

## 📦 Kurulum

```bash
# Temel kurulum
cd /home/zuhre/Desktop/projectz
pip install -r requirements.txt

# Opsiyonel (YAML config için)
pip install pyyaml

# Opsiyonel (Interface listesi için)
pip install netifaces
```

## 🎯 Hızlı Başlangıç

```bash
# Demo modu - simüle saldırı trafiği
python3 -m ids.main --demo

# Yardım
python3 -m ids.main --help
```

## 📋 Kullanım Örnekleri

### 1. Demo Modu

```bash
# Basit demo
python3 -m ids.main --demo

# JSON çıktı
python3 -m ids.main --demo --output json

# Detaylı çıktı
python3 -m ids.main --demo -vv
```

### 2. HTTP Proxy (Root Gerektirmez ✓)

```bash
# Tek port
python3 -m ids.main --capture-proxy --port 8888

# Birden fazla port
python3 -m ids.main --capture-proxy --ports 80,443,8080

# Tüm interface'lerde dinle
python3 -m ids.main --capture-proxy --ports 8888 --host 0.0.0.0

# Test
curl -x http://localhost:8888 "http://example.com/api?id=1 OR 1=1--"
```

### 3. Log Parser (Root Gerektirmez ✓)

```bash
# Nginx log
python3 -m ids.main --parse-log /var/log/nginx/access.log

# Apache log
python3 -m ids.main --parse-log /var/log/apache2/access.log --log-format apache

# Birden fazla dosya
python3 -m ids.main --parse-log access.log error.log other.log

# Canlı izleme (tail -f)
python3 -m ids.main --parse-log /var/log/nginx/access.log --watch
```

### 4. PCAP Yakalama (Root Gerekli ⚠️)

```bash
# Belirli interface
sudo python3 -m ids.main --capture-pcap --interface eth0

# Tüm interface'ler
sudo python3 -m ids.main --capture-pcap --interface any

# Port filtresi
sudo python3 -m ids.main --capture-pcap --interface eth0 --filter-port 80
```

### 5. Config Dosyası

```bash
# Örnek config oluştur
python3 -m ids.main --generate-config

# Config ile çalıştır
python3 -m ids.main --config config.yaml
```

## ⚙️ Config Dosyası Örneği (config.yaml)

```yaml
capture:
  mode: proxy
  interface: any
  ports: [80, 443, 8080, 8888]
  host: 0.0.0.0
  log_files: []
  log_format: auto
  watch: false

output:
  format: text
  log_dir: ./logs
  log_file: security_events.log
  verbose: 1

detection:
  enabled_detectors: [sqli, xss, complexity, protocol]
  sqli_sensitivity: high
  xss_sensitivity: high
  max_query_depth: 10
  max_aliases: 50
```

## 📊 Desteklenen Log Formatları

| Format | Örnek |
|--------|-------|
| Nginx Combined | `127.0.0.1 - - [time] "GET /path HTTP/1.1" 200 1234 "ref" "ua"` |
| Apache Combined | Nginx ile aynı format |
| Apache Common | `127.0.0.1 - - [time] "GET /path HTTP/1.1" 200 1234` |
| Auto | Otomatik tespit |

## 🔍 Tespit Edilen Saldırılar

| Saldırı | Protokol | Şiddet |
|---------|----------|--------|
| SQL Injection | HTTP, GraphQL, WebSocket | HIGH-CRITICAL |
| XSS | HTTP, WebSocket | MEDIUM-HIGH |
| Complexity Attack | GraphQL | MEDIUM |
| Introspection | GraphQL | LOW |
| Abnormal Methods | HTTP | LOW |
| Header Overflow | HTTP | MEDIUM |

## 🛠️ Gereksinimler

| Kütüphane | Kullanım | Komut |
|-----------|----------|-------|
| scapy | PCAP yakalama | `pip install scapy` |
| pyyaml | YAML config | `pip install pyyaml` |
| netifaces | Interface listesi | `pip install netifaces` |

## 📁 Proje Yapısı

```
ids/
├── main.py              # CLI entry point
├── core/
│   ├── dispatcher.py    # Paket yönlendirici
│   ├── packet.py        # Packet veri yapısı
│   ├── logger.py        # Güvenlik logger
│   └── config.py        # Config yönetimi
├── capture/
│   ├── base_capture.py  # Base class
│   ├── pcap_capture.py  # Scapy ile yakalama
│   ├── http_proxy.py    # HTTP Proxy
│   └── log_parser.py    # Log parser
├── analyzers/
│   ├── http_analyzer.py
│   ├── graphql_analyzer.py
│   └── websocket_analyzer.py
├── detectors/
│   ├── sqli_detector.py
│   └── xss_detector.py
└── simulation/
    └── traffic_simulator.py
```

## 📄 Lisans

MIT License

## 👥 Katkıda Bulunma

Pull request'ler kabul edilir. Büyük değişiklikler için önce issue açın.
