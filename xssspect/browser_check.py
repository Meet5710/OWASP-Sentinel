"""OWASP Sentinel - XSSSpect Browser Execution Verification Module.

Uses Playwright's synchronous API to check whether an injected reflected XSS payload
actually executes (e.g., triggers JavaScript alert/confirm/prompt dialogs) and
appears unencoded within the DOM.
"""

from typing import Any

try:
    from playwright.sync_api import Dialog, sync_playwright
except ImportError:  # pragma: no cover
    sync_playwright = None  # type: ignore[assignment]
    Dialog = Any  # type: ignore[assignment, misc]


def check_payload_execution(
    test_url: str,
    payload: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Checks whether an injected payload reflects and executes in a headless browser.

    Launches headless Chromium via Playwright sync API, registers a dialog listener
    to detect JavaScript dialog execution (alert, prompt, confirm), navigates to the
    target URL, inspects DOM content for reflection, and returns structured results.

    Args:
        test_url: The full target URL with the payload injected into the test parameter.
        payload: The probe payload string to check for unencoded reflection in the DOM.
        timeout: Navigation and load timeout in seconds (default: 10).

    Returns:
        dict[str, Any]: A dictionary containing:
            - "payload" (str): The injected probe payload.
            - "executed" (bool): True if a JavaScript dialog was triggered, False otherwise.
            - "dialog_message" (str | None): Message text from the dialog if triggered.
            - "reflected" (bool): True if payload appears unencoded in page content.
            - "error" (str, optional): Error description if navigation or runtime failed.
    """
    try:
        if sync_playwright is None:
            raise RuntimeError(
                "Playwright is not installed. Please install 'playwright' to run browser checks."
            )

        dialog_state: dict[str, Any] = {
            "executed": False,
            "dialog_message": None,
            "dialog_type": None,
        }

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page()

                def handler(dialog: Dialog) -> None:
                    dialog_state["executed"] = True
                    dialog_state["dialog_message"] = dialog.message
                    dialog_state["dialog_type"] = dialog.type
                    dialog.dismiss()

                page.on("dialog", handler)

                # Playwright timeout is specified in milliseconds
                page.goto(test_url, timeout=timeout * 1000)

                content = page.content()
                reflected = payload in content
            finally:
                browser.close()

        return {
            "payload": payload,
            "executed": dialog_state["executed"],
            "dialog_message": dialog_state["dialog_message"],
            "reflected": reflected,
        }

    except Exception as e:
        return {
            "payload": payload,
            "executed": False,
            "dialog_message": None,
            "reflected": False,
            "error": str(e),
        }

