#!/usr/bin/env python3
"""
API Gateway Attack Surface Scanner (v3.1)

- TRUE Black-Box scanning by default
- OpenAPI ONLY when explicitly provided
- OWASP API Top 10 (Passive)
- Markdown-first professional reporting
"""

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

import click
import httpx
import yaml
from jinja2 import Template

# =========================================================
# META
# =========================================================

BANNER = r"""
███████╗██████╗  ██████╗ ███████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
██╔════╝██╔══██╗██╔════╝ ██╔════╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
█████╗  ██║  ██║██║  ███╗█████╗  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██╔══╝  ██║  ██║██║   ██║██╔══╝  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
███████╗██████╔╝╚██████╔╝███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚══════╝╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝

        API Gateway Attack Surface Scanner
"""


VERSION = "3.1.0"

# =========================================================
# SEVERITY ENGINE
# =========================================================

HIGH = {"missing_auth", "function_level_auth", "ssrf_indicator", "request_error"}
MEDIUM = {"cors", "object_property_exposure", "business_logic"}
LOW = {"security_headers", "inventory_versioning"}

def get_severity(name: str) -> str:
    if name in HIGH:
        return "HIGH"
    if name in MEDIUM:
        return "MEDIUM"
    return "LOW"

# =========================================================
# OPENAPI HELPERS (EXPLICIT ONLY)
# =========================================================

def load_openapi(path: str) -> Dict:
    if not os.path.exists(path):
        raise click.ClickException(f"OpenAPI file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise click.ClickException("Invalid OpenAPI structure")
    return data

def enumerate_paths(spec: Dict) -> List[Tuple[str, str]]:
    routes = []
    for path, methods in spec.get("paths", {}).items():
        if not isinstance(methods, dict):
            continue
        for m in methods:
            if m.lower() in ("get", "post", "put", "delete", "patch"):
                routes.append((m.upper(), path))
    return routes

def build_url(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + path.lstrip("/")

# =========================================================
# SECURITY CHECKS (PASSIVE ONLY)
# =========================================================

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]

SSRF_HINTS = ["url", "redirect", "callback", "target", "image", "fetch"]

def check_endpoint(client: httpx.Client, method: str, url: str) -> Dict:
    result = {"method": method, "url": url, "checks": []}

    try:
        r = client.request(method, url, timeout=10)
    except Exception as e:
        result["checks"].append({
            "name": "request_error",
            "ok": False,
            "severity": "HIGH",
            "description": str(e)
        })
        return result

    headers = {k.lower(): v for k, v in r.headers.items()}

    # Broken Authentication
    unauth = 200 <= r.status_code < 300
    result["checks"].append({
        "name": "missing_auth",
        "ok": not unauth,
        "severity": get_severity("missing_auth"),
        "description": f"HTTP {r.status_code} without authentication"
    })

    # CORS
    try:
        cors = client.request(method, url, headers={"Origin": "https://evil.example"})
        ao = cors.headers.get("access-control-allow-origin")
        bad = ao in ("*", "https://evil.example")
        result["checks"].append({
            "name": "cors",
            "ok": not bad,
            "severity": get_severity("cors"),
            "description": f"Access-Control-Allow-Origin: {ao}"
        })
    except:
        pass

    # Security Headers
    missing = [h for h in SECURITY_HEADERS if h not in headers]
    result["checks"].append({
        "name": "security_headers",
        "ok": not bool(missing),
        "severity": get_severity("security_headers"),
        "description": "Missing: " + ", ".join(missing) if missing else "All present"
    })

    # Inventory / Versioning
    overlap = "/v1" in url and "/v2" in url
    result["checks"].append({
        "name": "inventory_versioning",
        "ok": not overlap,
        "severity": get_severity("inventory_versioning"),
        "description": "Version overlap detected" if overlap else "Clean versioning"
    })

    # Excessive Data Exposure
    if "application/json" in headers.get("content-type", ""):
        try:
            data = r.json()
            if isinstance(data, dict):
                sensitive = [k for k in data if any(s in k.lower() for s in ["password","token","secret","key"])]
                result["checks"].append({
                    "name": "object_property_exposure",
                    "ok": not bool(sensitive),
                    "severity": get_severity("object_property_exposure"),
                    "description": "Exposed fields: " + ", ".join(sensitive) if sensitive else "None"
                })
        except:
            pass

    # Business Logic Indicators
    if any(x in url.lower() for x in ["otp", "reset", "verify", "auth"]):
        result["checks"].append({
            "name": "business_logic",
            "ok": False,
            "severity": get_severity("business_logic"),
            "description": "Sensitive business endpoint detected"
        })

    # SSRF Indicator
    ssrf = any(p in url.lower() for p in SSRF_HINTS)
    result["checks"].append({
        "name": "ssrf_indicator",
        "ok": not ssrf,
        "severity": get_severity("ssrf_indicator"),
        "description": "SSRF-like parameter found" if ssrf else "No SSRF indicators"
    })

    # Function-Level Authorization
    try:
        override = client.request(method, url, headers={"X-HTTP-Method-Override": "DELETE"})
        broken = override.status_code in (200, 204)
    except:
        broken = False

    result["checks"].append({
        "name": "function_level_auth",
        "ok": not broken,
        "severity": get_severity("function_level_auth"),
        "description": "DELETE override accepted" if broken else "Protected"
    })

    return result

# =========================================================
# REPORTING
# =========================================================

def write_json(path: str, report: Dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

def write_markdown(path: str, report: Dict):
    lines = [
        "# API Gateway Security Scan Report",
        f"**Scan Time:** {report['scan_time']}",
        f"**Targets:** {', '.join(report['targets'])}",
        "",
        "## Executive Summary",
        f"- **HIGH:** {report['summary']['HIGH']}",
        f"- **MEDIUM:** {report['summary']['MEDIUM']}",
        f"- **LOW:** {report['summary']['LOW']}",
        "",
        "## Findings",
        "| Method | Endpoint | Issue | Severity | Description |",
        "|--------|----------|-------|----------|-------------|"
    ]

    for ep in report["endpoints"]:
        for c in ep["checks"]:
            if not c["ok"]:
                lines.append(
                    f"| {ep['method']} | {ep['url']} | {c['name']} | {c['severity']} | {c['description']} |"
                )

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

def write_html(path: str, report: Dict):
    html = Template("""
    <html><body>
    <h1>API Gateway Security Scan Report</h1>
    <p><b>Scan Time:</b> {{ scan_time }}</p>
    <p><b>Targets:</b> {{ targets | join(", ") }}</p>
    <table border="1" cellpadding="6">
    <tr><th>Method</th><th>Endpoint</th><th>Issue</th><th>Severity</th><th>Description</th></tr>
    {% for ep in endpoints %}
    {% for c in ep.checks %}
    {% if not c.ok %}
    <tr>
      <td>{{ ep.method }}</td>
      <td>{{ ep.url }}</td>
      <td>{{ c.name }}</td>
      <td>{{ c.severity }}</td>
      <td>{{ c.description }}</td>
    </tr>
    {% endif %}
    {% endfor %}
    {% endfor %}
    </table>
    </body></html>
    """).render(**report)

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

# =========================================================
# CLI
# =========================================================

@click.group(help="API Gateway Attack Surface Scanner (OWASP API Top 10)")
def cli():
    click.secho(BANNER, fg="cyan")

@cli.command(help="Show scanner version")
def version():
    click.echo(f"Version: {VERSION}")

@cli.command(help="Run a passive API security scan")
@click.option("--targets", "-t", required=True, help="Comma-separated target base URLs")
@click.option("--openapi", "-o", default=None, help="Optional OpenAPI file")
@click.option("--output", "-O", default="reports/scan.json", help="Output JSON path")
def scan(targets, openapi, output):

    targets_list = [t.strip() for t in targets.split(",")]

    endpoints = []

    if openapi:
        spec = load_openapi(openapi)
        for m, p in enumerate_paths(spec):
            for base in targets_list:
                endpoints.append((m, build_url(base, p)))
    else:
        # TRUE BLACK-BOX MODE
        for base in targets_list:
            endpoints.append(("GET", base))

    click.echo(f"[+] Scanning {len(endpoints)} endpoint(s)")

    client = httpx.Client()
    results = []

    with click.progressbar(length=len(endpoints), label="Scanning") as bar:
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(check_endpoint, client, m, u) for m, u in endpoints]
            for f in as_completed(futures):
                results.append(f.result())
                bar.update(1)

    summary = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for ep in results:
        for c in ep["checks"]:
            if not c["ok"]:
                summary[c["severity"]] += 1

    report = {
        "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "targets": targets_list,
        "summary": summary,
        "endpoints": results
    }

    write_json(output, report)
    write_markdown(output.replace(".json", ".md"), report)
    write_html(output.replace(".json", ".html"), report)

    click.echo("\n✔ Scan complete")
    click.echo(f"HIGH: {summary['HIGH']} | MEDIUM: {summary['MEDIUM']} | LOW: {summary['LOW']}")
    click.echo(f"Reports saved in: {os.path.dirname(output) or 'reports/'}")

if __name__ == "__main__":
    cli()
