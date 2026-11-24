# XSSSpect

XSSSpect is a reflected Cross-Site Scripting (XSS) detection utility that checks whether injected probes actually execute inside a real browser environment.

## 1. What XSSSpect Does

XSSSpect automates the detection and verification of reflected XSS vulnerabilities by:
- Parsing query parameters from a target URL.
- Injecting benign probe payloads into individual parameters while preserving overall URI structure.
- Checking for payload reflection within the DOM.
- Utilizing headless Chromium (via Playwright) to detect whether JavaScript dialogs (`alert`, `confirm`, `prompt`) execute, eliminating reflection-only false positives.
- Providing structured JSON assessment results with per-parameter findings and exit codes for CI/CD integration.

---

## 2. Installation

Install dependencies and download the Chromium headless browser:

```bash
pip install -r xssspect/requirements.txt
playwright install chromium
```

---

## 3. Authorized-Use Note

> [!IMPORTANT]
> **Authorized Testing Only**
> Only run XSSSpect against targets you own or have explicit written permission to test. Unauthorized scanning of third-party applications without prior consent is illegal and strictly prohibited.

---

## 4. Local Lab Validation

You can safely validate XSSSpect against a local Damn Vulnerable Web Application (DVWA) container:

1. **Start DVWA**:
   ```bash
   docker run -d -p 8080:80 vulnerables/web-dvwa
   ```
2. **Setup Lab**:
   - Navigate to `http://127.0.0.1:8080/` in your browser.
   - Click **Create / Reset Database** to initialize.
   - Log in with credentials `admin` / `password`.
   - In the left sidebar, navigate to **DVWA Security** and set the security level to **Low**.
   - Navigate to **XSS (Reflected)**.
3. **Execute Scan**:
   ```bash
   python -m xssspect.main scan --url "http://127.0.0.1:8080/vulnerabilities/xss_r/?name=test"
   ```

---

## 5. Expected Output

When testing against DVWA at **Low** security, the scanner outputs JSON with `vulnerable: true` and at least one finding reporting `executed: true`:

```json
{
  "url": "http://127.0.0.1:8080/vulnerabilities/xss_r/?name=test",
  "parameters_tested": [
    "name"
  ],
  "findings": [
    {
      "parameter": "name",
      "payload": "<script>alert(1)</script>",
      "executed": true,
      "reflected": true,
      "dialog_message": "1"
    }
  ],
  "vulnerable": true
}
```

The CLI process will exit with return code `1` when vulnerabilities are detected and `0` when no parameters trigger execution.
