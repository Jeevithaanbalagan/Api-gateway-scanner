# 🚀 API Gateway Attack Surface Scanner

A **CLI-based API security scanner** designed to identify **OWASP API Top 10 risks** across **API Gateways and backend APIs** using **Black-Box** and **OpenAPI-assisted** scanning techniques.

The scanner performs **safe, passive security checks** and generates **professional, audit-ready reports**, with **Markdown as the primary reporting format**.

---

## 🎯 Why This Tool Exists

Modern applications expose APIs through **API Gateways** (AWS API Gateway, Kong, Apigee, NGINX, etc.).  
Misconfigurations at this layer often lead to:

- Authentication bypass
- Excessive data exposure
- CORS abuse
- SSRF entry points
- Broken function-level authorization
- Poor API inventory management

This tool helps **security engineers, developers, students, and DevSecOps teams** quickly understand the **API attack surface** and highlight **high-risk misconfigurations** early — before exploitation.

---

## ✨ Key Features

- ✔ **CLI-first design** (no GUI, automation friendly)
- ✔ **Black-Box scanning** (no API documentation required)
- ✔ **OpenAPI-assisted scanning** (Swagger / OpenAPI 3.x)
- ✔ **OWASP API Top 10 aligned checks**
- ✔ **Passive & non-destructive** (safe for staging / prod)
- ✔ **Severity classification** (HIGH / MEDIUM / LOW)
- ✔ **Markdown-first professional reporting**
- ✔ **HTML rendered report**
- ✔ **JSON output for CI/CD**
- ✔ **Progress bar + executive summary**
- ✔ **Extensible architecture**

---

## 🧠 How the Scanner Works

### 1️⃣ Endpoint Discovery

**Two supported modes:**

#### 🔹 OpenAPI Mode
- Reads `.yaml`, `.yml`, `.json` OpenAPI files
- Extracts real API paths & methods
- Best accuracy

#### 🔹 Black-Box Mode
- No OpenAPI required
- Scans base URLs directly
- Useful for unknown or undocumented APIs

> ⚠️ The scanner **does NOT invent endpoints**  
> It only tests **explicitly provided or discovered endpoints**

---

### 2️⃣ Passive Security Checks

Each endpoint is tested using **safe HTTP requests only**.

| Category | Description |
|--------|------------|
| Broken Authentication | Unauthenticated 2xx responses |
| Function-Level Authorization | Method override misuse |
| Excessive Data Exposure | Sensitive fields in JSON |
| CORS Misconfiguration | Wildcard / reflected origins |
| Security Headers | Missing HSTS, CSP, XFO |
| Business Logic Indicators | OTP / reset / verify endpoints |
| SSRF Indicators | URL-like parameters |
| Inventory / Versioning | Version overlap & hygiene |

---

### 3️⃣ Severity Engine

Each finding is automatically classified:

| Severity | Meaning |
|--------|--------|
| **HIGH** | Auth bypass, SSRF, function-level auth |
| **MEDIUM** | CORS issues, data exposure, logic risks |
| **LOW** | Missing headers, versioning hygiene |

---

## 📂 Project Structure (Installed Package)

```text
api-gateway-scanner/
│
├── scanner/
│   ├── __init__.py
│   └── cli.py        # CLI entry point
│
├── pyproject.toml
├── README.md
```

---

## ⚙️ Installation (For End Users)

### ✅ Recommended (Linux / macOS / Windows)

Use **pipx** — this is how modern CLI tools are installed.

```bash
pip install pipx
pipx ensurepath
pipx install api-gateway-scanner
```

Restart your terminal once.

---

### ✅ Alternative (pip)

```bash
pip install api-gateway-scanner
```

---

## 🚀 Using the Scanner (CLI Usage)

Once installed, the tool works like **nmap / trivy / sqlmap**.

### 🔹 Show Help
```bash
api-gateway-scanner --help
```

---

### 🔹 Show Version
```bash
api-gateway-scanner version
```

---

### 🔹 Black-Box Scan
```bash
api-gateway-scanner scan --targets https://api.example.com
```

---

### 🔹 OpenAPI-Assisted Scan
```bash
api-gateway-scanner scan \
  --openapi specs/api.yaml \
  --targets https://api.example.com
```

---

### 🔹 Scan Using Config File (Recommended)

```bash
api-gateway-scanner scan -c config.yaml
```

---

## 📝 Configuration File (`config.yaml`)

```yaml
targets:
  - "https://api.staging.example.com"

openapi:
  enabled: true
  folder: "specs"
```

Any `.yaml`, `.yml`, or `.json` file inside `specs/` will be auto-detected.

---

## 📊 Output Reports

After scanning:

```text
reports/
├── scan.json   # Automation / CI
├── scan.md     # PRIMARY report
└── scan.html   # Rendered view
```

---

## 📄 Report Formats

### 🟢 Markdown (Primary)
- Audit-ready
- GitHub-friendly
- Can be converted to PDF via Pandoc

### 🟢 HTML
- Color-coded severity
- Easy sharing with stakeholders

### 🟢 JSON
- Machine-readable
- CI/CD & automation ready

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

## 🧑‍💻 Developer / Contributor Usage

If running **from source**:

```bash
git clone https://github.com/yourname/api-gateway-scanner
cd api-gateway-scanner
python -m venv venv
source venv/bin/activate
pip install -e .
```

Run using:

```bash
python -m scanner.cli scan --targets http://localhost:8000
```

> ℹ️ `python -m scanner.cli` is **developer mode only**  
> End users should always use `api-gateway-scanner`

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

## 🔮 Roadmap

- SARIF export (GitHub Security)
- Auth profile testing (JWT / API Keys)
- Risk scoring per endpoint
- CI/CD pipeline integration
- Markdown → PDF (Pandoc)
- Optional active scanning
- Rate-limit & abuse detection

---

## ⚠️ Legal Disclaimer

This tool is intended **only for authorized security testing**.  
Always obtain **written permission** before scanning any API.  
The author is **not responsible for misuse**.

---

## ⭐ Final Note

If you fully understand this tool, you already understand:

- API Gateway security
- OWASP API Top 10
- Real-world API attack surfaces
- Professional security reporting

That’s **industry-level skill** 💪

---
