
# 🚀 API Gateway Attack Surface Scanner

A **CLI-based API security scanner** designed to identify **OWASP API Top 10 risks** at the **API Gateway and backend API layer** using both **Black-Box** and **OpenAPI-assisted** scanning techniques.

The tool performs **safe, passive security checks** and generates **professional, audit-ready reports**, with **Markdown as the primary reporting format**.

---

## 🎯 Purpose of This Tool

Modern applications heavily rely on APIs exposed through **API Gateways** (AWS API Gateway, Kong, Apigee, NGINX, etc.).
Misconfigurations at this layer can lead to:

* Authentication bypass
* Excessive data exposure
* CORS abuse
* SSRF entry points
* Broken function-level authorization
* Poor API inventory management

This tool helps **security engineers, developers, and students** quickly understand the **API attack surface** and highlight **high-risk misconfigurations** early.

---

## ✨ Key Highlights

* ✔ **OpenAPI-assisted scanning** (Swagger / OpenAPI 3.x)
* ✔ **Black-Box scanning** when documentation is unavailable
* ✔ **OWASP API Top 10 aligned checks**
* ✔ **Passive & non-destructive** (safe for staging/production)
* ✔ **Severity classification** (HIGH / MEDIUM / LOW)
* ✔ **Markdown-first professional reporting**
* ✔ **CLI-only (automation & CI/CD friendly)**
* ✔ **Progress bar + executive summary**
* ✔ **Extensible architecture**

---

## 🧠 How It Works

### 1️⃣ Endpoint Discovery

* **OpenAPI Mode**
  Endpoints are extracted from `.yaml`, `.yml`, or `.json` OpenAPI files.

* **Black-Box Mode**
  If OpenAPI is unavailable, the scanner tests base URLs directly.

---

### 2️⃣ Passive Security Checks

Each discovered endpoint is tested using **safe HTTP requests only**.

| Category                     | Description                           |
| ---------------------------- | ------------------------------------- |
| Broken Authentication        | Detects unauthenticated 2xx responses |
| Function-Level Authorization | Detects method override issues        |
| Excessive Data Exposure      | Identifies sensitive fields in JSON   |
| CORS Misconfiguration        | Wildcard or reflected origins         |
| Security Headers             | Missing HSTS, CSP, XFO, etc.          |
| Business Logic Indicators    | OTP, reset, verify endpoints          |
| SSRF Indicators              | URL-like parameters                   |
| Inventory / Versioning       | Version overlap & hygiene             |

---

### 3️⃣ Severity Engine

Each finding is automatically classified:

| Severity   | Meaning                                 |
| ---------- | --------------------------------------- |
| **HIGH**   | Auth bypass, SSRF, function-level auth  |
| **MEDIUM** | CORS issues, data exposure, logic risks |
| **LOW**    | Missing headers, versioning hygiene     |

---

## 📂 Project Structure

```
api-gateway-scanner/
│
├── cli.py              # Main CLI scanner
├── config.yaml         # Configuration file
├── specs/              # OpenAPI specs (optional)
│   └── api.yaml
├── reports/            # Generated reports
│   ├── scan.json
│   ├── scan.md
│   └── scan.html
└── README.md
```

---

## ⚙️ Installation

### 1️⃣ Prerequisites

* Python **3.9+**
* Internet access to target APIs

### 2️⃣ Install Dependencies

```bash
pip install click httpx pyyaml jinja2
```

---

## 📝 Configuration (`config.yaml`)

```yaml
targets:
  - "https://api.staging.example.com"

openapi:
  enabled: true
  folder: "specs"
```

### 🔍 OpenAPI Auto-Detection

Any file inside `specs/` with extensions:

```
.yaml
.yml
.json
```

will be automatically used for endpoint discovery.

---

## 🚀 Running the Scanner

### 🔹 Show Help

```bash
python cli.py --help
```

### 🔹 Show Version

```bash
python cli.py version
```

---

### 🔹 Black-Box Scan

```bash
python cli.py scan --targets https://api.example.com
```

---

### 🔹 Scan Using OpenAPI

```bash
python cli.py scan --openapi specs/api.yaml --targets https://api.example.com
```

---

### 🔹 Scan Using Config File (Recommended)

```bash
python cli.py scan -c config.yaml

---

## 📊 Output Reports

After scanning:

```
reports/
├── scan.json   # Automation / CI
├── scan.md     # PRIMARY security report
└── scan.html   # Rendered view
```

---

## 📄 Report Formats

### 🟢 Markdown Report (Primary)

* Clean, audit-ready format
* Ideal for:

  * Security reports
  * GitHub
  * Documentation
  * Pandoc → PDF if needed

### 🟢 HTML Report

* Color-coded severity
* Easy sharing with stakeholders

### 🟢 JSON Report

* Machine-readable
* CI/CD & automation friendly

---

## 🧪 Example Finding (JSON)

```json
{
  "method": "GET",
  "url": "https://api.example.com/status",
  "checks": [
    {
      "name": "missing_auth",
      "ok": false,
      "severity": "HIGH",
      "description": "Unauthenticated status code: 200"
    }
  ]
}
```

---

## 🛡️ What This Tool IS

✔ API attack surface visibility tool
✔ Pre-assessment security scanner
✔ OWASP API Top 10 learning project
✔ CI/CD security integration candidate

---

## 🚫 What This Tool Is NOT

❌ Not an exploitation framework
❌ Not a fuzzer
❌ Not a replacement for manual pentesting

---

## 🔮 Future Enhancements (Roadmap)

* SARIF export (GitHub Security tab)
* Auth profile testing (JWT / API Keys)
* Risk scoring per endpoint
* CI/CD pipeline integration
* Markdown → PDF via Pandoc
* Active scanning (opt-in mode)
* Rate-limit & abuse detection

---

## ⚠️ Legal Disclaimer

This tool is intended **only for authorized security testing**.

Always obtain **written permission** before scanning any API.
The author is **not responsible for misuse**.

---

## ⭐ Final Note

If you understand this tool end-to-end, you already understand:

* API Gateway security
* OWASP API Top 10
* Real-world API attack surfaces
* Professional security reporting

That’s **industry-level skill** 💪

