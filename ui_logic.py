"""OWASP Scanner Side Panel UI State Logic.

Provides stateless UI helpers for rendering category selection checkboxes,
action button state, and generating shell commands for authorized security assessment.
Does not execute scans or network traffic.
"""

from typing import Any
from owasp_registry import OWASP_CATEGORIES, build_scan_command


def get_scan_ui_state(selected_ids: list[str]) -> dict[str, Any]:
    """Generate UI state structure for category checkboxes and action button.

    Args:
        selected_ids: List of OWASP category IDs currently selected by the user.

    Returns:
        Dictionary containing:
        - "categories": List of dicts with keys "id", "name", and "selected"
        - "button_label": Action button display text ("Generate Scan Command")
        - "can_run": Boolean indicating if at least one category is selected
    """
    selected_set = {cid.strip().upper() for cid in selected_ids if cid and isinstance(cid, str)}

    categories: list[dict[str, Any]] = []
    for cat_id, cat_name in OWASP_CATEGORIES.items():
        categories.append(
            {
                "id": cat_id,
                "name": cat_name,
                "selected": cat_id.upper() in selected_set,
            }
        )

    can_run = len(selected_set.intersection(OWASP_CATEGORIES.keys())) > 0

    return {
        "categories": categories,
        "button_label": "Generate Scan Command",
        "can_run": can_run,
    }


def on_run_clicked(target_url: str, selected_ids: list[str]) -> str:
    """Validate user input and generate shell command string for copying.

    Args:
        target_url: Target URL provided by the user.
        selected_ids: List of chosen OWASP category IDs.

    Returns:
        Shell command string formatted for user copying and execution.

    Raises:
        ValueError: If target_url is empty/whitespace or no valid categories are selected.
    """
    cleaned_url = (target_url or "").strip()
    if not cleaned_url:
        raise ValueError("Target URL cannot be empty.")

    valid_selected = [cid.strip().upper() for cid in selected_ids if cid and cid.strip().upper() in OWASP_CATEGORIES]
    if not valid_selected:
        raise ValueError("At least one valid OWASP category ID must be selected.")

    return build_scan_command(target_url=cleaned_url, selected_ids=valid_selected)

