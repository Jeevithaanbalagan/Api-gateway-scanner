#!/usr/bin/env python3
"""
API Gateway Scanner (Final Updated CLI)

Features:
- Auto-detect OpenAPI files from a folder (specs/)
- Supports manual --openapi override
- Black-box scanning when no OpenAPI found
- Passive security checks (CORS, Missing auth, Headers)
- JSON + HTML + PDF + DOCX reporting

Run:
python cli.py scan -c config.yaml --html
"""

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Any

import click
import httpx
import yaml
from jinja2 import Template

# ---------------------------------------------------------
# Load OpenAPI
# ---------------------------------------------------------

def load_openapi(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise click.ClickException(f"OpenAPI file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        try:
            data = yaml.safe_load(f)
        except Exception as e:
            raise click.ClickException(f"Failed to parse OpenAPI file {path}: {e}")
    if not isinstance(data, dict):
        raise click.ClickException("Invalid OpenAPI structure.")
    return data


def enumerate_paths(openapi: Dict[str, Any]) -> List[Tuple[str, str]]:
    routes = []
    for path, methods in openapi.get("paths", {}).items():
        for method in methods.keys():
            if method.lower() in ("get", "post", "put", "delete", "patch", "options", "head"):
                routes.append((method.upper(), path))
    return routes


def build_url(base: str, path: str) -> str:
    if path.startswith("/"):
        path = path[1:]
    if base.endswith("/"):
        base = base[:-1]
    return f"{base}/{path}"


# ---------------------------------------------------------
# Passive Security Checks
# ---------------------------------------------------------

SECURITY_HEADER_CHECKS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}

def check_endpoint(client: httpx.Client, method: str, url: str, timeout=10):
    findings = {"url": url, "method": method, "checks": []}

    # ---------- Missing Auth ----------
    try:
        r = client.request(method, url, timeout=timeout)
    except Exception as e:
        findings["checks"].append({
            "name": "request_error",
            "ok": False,
            "description": str(e)
        })
        return findings

    if 200 <= r.status_code < 300:
        findings["checks"].append({
            "name": "missing_auth",
            "ok": False,
            "description": f"Endpoint returns {r.status_code} without authentication."
        })
    else:
        findings["checks"].append({
            "name": "missing_auth",
            "ok": True,
            "description": f"Protected (HTTP {r.status_code})"
        })

    # ---------- CORS ----------
    try:
        r_cors = client.request(method, url, headers={"Origin": "https://evil.example"})
        ao = r_cors.headers.get("access-control-allow-origin")
        if ao in ("*", "https://evil.example"):
            findings["checks"].append({
                "name": "cors",
                "ok": False,
                "description": f"Weak CORS policy: {ao}"
            })
        else:
            findings["checks"].append({
                "name": "cors",
                "ok": True,
                "description": f"CORS OK ({ao})"
            })
    except:
        findings["checks"].append({
            "name": "cors",
            "ok": False,
            "description": "CORS check failed."
        })

    # ---------- Security Headers ----------
    headers = {k.lower(): v for k, v in r.headers.items()}
    missing = [SECURITY_HEADER_CHECKS[h] for h in SECURITY_HEADER_CHECKS if h not in headers]

    if missing:
        findings["checks"].append({
            "name": "security_headers",
            "ok": False,
            "description": "Missing: " + ", ".join(missing)
        })
    else:
        findings["checks"].append({
            "name": "security_headers",
            "ok": True,
            "description": "All good."
        })

    # ---------- Server Leak ----------
    server_hdr = headers.get("server") or headers.get("x-powered-by")
    if server_hdr:
        findings["checks"].append({
            "name": "server_leak",
            "ok": False,
            "description": f"Server Info Exposed: {server_hdr}"
        })
    else:
        findings["checks"].append({
            "name": "server_leak",
            "ok": True,
            "description": "No server leak"
        })

    return findings


# ---------------------------------------------------------
# Reporting
# ---------------------------------------------------------

def write_json_report(path, report):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(report, f, indent=2)

HTML_TEMPLATE = """
<html><head><style>
body{font-family:Arial;padding:20px;}
.fail{background:#ffcccc;padding:3px;}
.ok{background:#ccffcc;padding:3px;}
table{width:100%;border-collapse:collapse;}
td,th{border-bottom:1px solid #ddd;padding:8px;}
</style></head><body>
<h1>API Scan Report</h1>
<p>Scan Time: {{ scan_time }}</p>
<table>
<tr><th>Method</th><th>URL</th><th>Check</th><th>Status</th><th>Description</th></tr>
{% for ep in endpoints %}
{% for c in ep.checks %}
<tr>
<td>{{ ep.method }}</td>
<td>{{ ep.url }}</td>
<td>{{ c.name }}</td>
<td class="{{ 'fail' if not c.ok else 'ok' }}">
{{ 'FAIL' if not c.ok else 'OK' }}</td>
<td>{{ c.description }}</td>
</tr>
{% endfor %}
{% endfor %}
</table>
</body></html>
"""

def write_html_report(path, report):
    html = Template(HTML_TEMPLATE).render(
        scan_time=report["scan_time"],
        endpoints=report["endpoints"]
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


# ---------------------------------------------------------
# PDF Reporting
# ---------------------------------------------------------

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from textwrap import wrap

def write_pdf_report(path, report):
    c = canvas.Canvas(path, pagesize=letter)
    width, height = letter
    y = height - 50

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "API Gateway Security Scan Report")
    y -= 30

    c.setFont("Helvetica", 12)
    c.drawString(50, y, f"Scan Time: {report['scan_time']}")
    y -= 40

    for ep in report["endpoints"]:
        if y < 100:
            c.showPage()
            y = height - 50

        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, f"{ep['method']} {ep['url']}")
        y -= 20

        for check in ep["checks"]:
            status = "OK" if check["ok"] else "FAIL"
            text = f"[{status}] {check['name']} - {check['description']}"
            for line in wrap(text, 90):
                c.setFont("Helvetica", 10)
                c.drawString(60, y, line)
                y -= 14

        y -= 10

    c.save()


# ---------------------------------------------------------
# DOCX Reporting
# ---------------------------------------------------------

from docx import Document

def write_docx_report(path, report):
    doc = Document()

    doc.add_heading("API Gateway Security Scan Report", 0)
    doc.add_paragraph(f"Scan Time: {report['scan_time']}")

    for ep in report["endpoints"]:
        doc.add_heading(f"{ep['method']} {ep['url']}", level=2)

        for c in ep["checks"]:
            status = "OK" if c["ok"] else "FAIL"
            doc.add_paragraph(f"[{status}] {c['name']} - {c['description']}")

    doc.save(path)


# ---------------------------------------------------------
# CLI
# ---------------------------------------------------------

@click.group()
def cli():
    pass


@cli.command(name="scan")
@click.option("--config", "-c", default="config.yaml")
@click.option("--openapi", "-o", default=None)
@click.option("--targets", "-t", default=None)
@click.option("--output", "-O", default="reports/scan.json")
@click.option("--html", is_flag=True)
def scan_cmd(config, openapi, targets, output, html):

    # ---------------- Load Config ----------------
    cfg = yaml.safe_load(open(config)) or {}

    targets_list = targets.split(",") if targets else cfg.get("targets", [])
    if not targets_list:
        raise click.ClickException("No targets provided.")

    # ---------------- OpenAPI Detection ----------------
    openapi_files = []

    if openapi:
        openapi_files.append(openapi)
    else:
        api_cfg = cfg.get("openapi", {})
        if api_cfg.get("enabled", False):
            folder = api_cfg.get("folder", "specs")
            if os.path.exists(folder):
                for f in os.listdir(folder):
                    if f.endswith((".yaml", ".yml", ".json")):
                        openapi_files.append(os.path.join(folder, f))

    endpoints = []

    # --------- If OpenAPI found ----------
    if openapi_files:
        click.echo(f"Using OpenAPI specs: {openapi_files}")
        for file in openapi_files:
            spec = load_openapi(file)
            routes = enumerate_paths(spec)
            for method, path in routes:
                for base in targets_list:
                    endpoints.append({"method": method, "url": build_url(base, path)})
    else:
        click.echo("No OpenAPI found → Running in BLACK-BOX mode.")
        for base in targets_list:
            endpoints.append({"method": "GET", "url": base})

    # ---------------- Run Scan ----------------
    results = []
    client = httpx.Client(timeout=15)

    with ThreadPoolExecutor(max_workers=8) as pool:
        for fut in as_completed([
            pool.submit(check_endpoint, client, ep["method"], ep["url"])
            for ep in endpoints
        ]):
            results.append(fut.result())

    # ---------------- Build Report ----------------
    report = {
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "targets": targets_list,
        "endpoints": results
    }

    # Save JSON
    write_json_report(output, report)
    click.echo(f"Saved JSON → {output}")

    # Save HTML
    if html:
        html_path = output.replace(".json", ".html")
        write_html_report(html_path, report)
        click.echo(f"Saved HTML → {html_path}")

    # Save PDF
    pdf_path = output.replace(".json", ".pdf")
    write_pdf_report(pdf_path, report)
    click.echo(f"Saved PDF → {pdf_path}")

    # Save DOCX
    docx_path = output.replace(".json", ".docx")
    write_docx_report(docx_path, report)
    click.echo(f"Saved DOCX → {docx_path}")


if __name__ == "__main__":
    cli()
