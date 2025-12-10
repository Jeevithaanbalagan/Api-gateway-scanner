# 🚀 API Gateway Security Scanner  
A lightweight, CLI-based security scanner designed to identify vulnerabilities in API Gateways using both **Black-Box** and **OpenAPI-assisted** scanning techniques.

This tool performs automated security checks such as **Missing Authentication**, **CORS misconfiguration**, **Security Header validation**, and **Server Information Leakage**.  
It exports results as **JSON**, **HTML**, **PDF**, and **Word (.docx)** reports.

---

## 🔥 Key Highlights

- **✔ Auto-detects OpenAPI specs** from a folder (e.g., `specs/`)
- **✔ Black-box mode** (no API documentation needed)
- **✔ Passive vulnerability scanning**
- **✔ Generates professional reports:**
  - JSON  
  - HTML  
  - PDF  
  - DOCX  
- **✔ CLI-based — No GUI required**
- **✔ Safe for production (no destructive tests)**
- **✔ Extensible design**

---

## 📂 Project Structure

```
api-gateway-scanner/
│
├── cli.py                # Main scanner CLI
├── config.yaml           # Configuration file
├── specs/                # OpenAPI files auto-detected here
├── reports/              # Output reports generated here
└── venv/                 # Optional virtual environment
```

---

## 🧠 How It Works

The scanner performs the following:

### **1️⃣ Endpoint Discovery**
- If OpenAPI is enabled → reads endpoints from `.yaml`/`.json` files.
- If no OpenAPI exists → scanner runs in **Black-Box Mode**, testing only base URLs.

### **2️⃣ Passive Security Checks**
Each endpoint is tested for:

| Check Type | Description |
|------------|-------------|
| **Missing Authentication** | Returns 2xx without authentication |
| **CORS Misconfiguration** | Detects wildcard or reflected origins |
| **Security Header Validation** | Checks for missing HSTS, CSP, XFO, etc. |
| **Server Information Leak** | Detects `Server` or `X-Powered-By` exposure |

### **3️⃣ Reporting Engine**
After scanning, the tool produces four reports:

| Format | Description |
|--------|-------------|
| **JSON** | Machine-readable output |
| **HTML** | Human-friendly UI table |
| **PDF** | Clean, sharable security report |
| **DOCX** | Word report for documentation |

---

## ⚙️ Installation

### 1. Clone Repository
```bash
git clone https://github.com/yourname/api-gateway-scanner
cd api-gateway-scanner
```

### 2. Create Virtual Environment (Optional but recommended)
```bash
python -m venv venv
venv/Scripts/activate   # Windows
# OR
source venv/bin/activate   # Linux/Mac
```

### 3. Install Dependencies
```bash
pip install click httpx pyyaml jinja2 reportlab python-docx
```

---

## 📝 Configuration (`config.yaml`)

Example:

```yaml
targets:
  - "https://api.staging.example.com"

openapi:
  enabled: true
  folder: "specs"

scan:
  mode: passive
  max_concurrent: 8
  allow_destructive: false

report:
  output: "reports/scan.json"
  html: true
```

### **OpenAPI Auto-detection**
Any `.yaml`, `.yml`, or `.json` file inside the folder:

```
specs/
├── api.yaml
├── users.yaml
└── orders.json
```

will be automatically used as documentation for endpoint discovery.

---

## 🚀 Running the Scanner

### **1️⃣ Black-Box Scan (no OpenAPI required)**
```bash
python cli.py scan -c config.yaml --html
```

### **2️⃣ Scan Using OpenAPI**
```bash
python cli.py scan --openapi specs/api.yaml --html
```

### **3️⃣ Auto OpenAPI Detection (recommended)**
If enabled in config:
```bash
python cli.py scan -c config.yaml
```

### **4️⃣ View Reports**
```
reports/
 ├── scan.json
 ├── scan.html
 ├── scan.pdf
 └── scan.docx
```

Open them directly:

```bash
start reports/scan.html
start reports/scan.pdf
start reports/scan.docx
```

---

## 📊 Report Formats

### **HTML Report**
- Color-coded pass/fail table  
- Easy to read and share  

### **PDF Report**
- Clean security audit layout  
- Ideal for management & compliance teams  

### **DOCX Report**
- Easy to edit and customize  

---

## 🛠 Supported Checks

| Category | Description |
|---------|-------------|
| **Auth Checks** | Detects missing or weak authentication |
| **CORS Checks** | Detects insecure `Access-Control-Allow-Origin` |
| **Header Checks** | Ensures presence of security headers |
| **Server Disclosure** | Detects server information leaks |
| **Passive Only** | No destructive payloads or fuzzing |

---

## 🧪 Example Output Snippet

```json
{
  "method": "GET",
  "url": "https://api.example.com/status",
  "checks": [
    {
      "name": "missing_auth",
      "ok": false,
      "description": "Unauthenticated request returned 200"
    },
    {
      "name": "cors",
      "ok": false,
      "description": "Weak CORS policy: *"
    }
  ]
}
```

---

## 🔮 Future Enhancements (Roadmap)

- Active scanning mode  
- Rate-limit bypass detection  
- API-key brute force simulation  
- JWT validation testing  
- SSRF & Redirect testing  
- Webhook-based outbound detection  
- Severity scoring (CVSS-like)  
- Dashboard UI (optional)

---

## 🤝 Contributing

Pull requests are welcome!

Before contributing:
1. Fork the repo  
2. Create feature branch  
3. Open PR with description  

---

