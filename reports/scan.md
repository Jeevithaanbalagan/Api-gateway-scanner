# API Gateway Security Scan Report
**Scan Time:** 2025-12-14 20:16:37
**Targets:** http://preview.owasp-juice.shop/api/Challenges

## Executive Summary
- **HIGH:** 2
- **MEDIUM:** 1
- **LOW:** 1

## Findings
| Method | Endpoint | Issue | Severity | Description |
|--------|----------|-------|----------|-------------|
| GET | http://preview.owasp-juice.shop/api/Challenges | missing_auth | HIGH | HTTP 200 without authentication |
| GET | http://preview.owasp-juice.shop/api/Challenges | cors | MEDIUM | Access-Control-Allow-Origin: * |
| GET | http://preview.owasp-juice.shop/api/Challenges | security_headers | LOW | Missing: strict-transport-security, content-security-policy, referrer-policy |
| GET | http://preview.owasp-juice.shop/api/Challenges | function_level_auth | HIGH | DELETE override accepted |