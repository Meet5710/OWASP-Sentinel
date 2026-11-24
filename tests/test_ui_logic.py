"""Unit tests for ui_logic.py module."""

import pytest
from owasp_registry import OWASP_CATEGORIES
import ui_logic


def test_get_scan_ui_state_all_selected() -> None:
    """Verify state when all 10 categories are selected."""
    all_ids = list(OWASP_CATEGORIES.keys())
    state = ui_logic.get_scan_ui_state(all_ids)

    assert state["button_label"] == "Generate Scan Command"
    assert state["can_run"] is True
    assert len(state["categories"]) == 10

    for cat in state["categories"]:
        assert cat["selected"] is True
        assert cat["name"] == OWASP_CATEGORIES[cat["id"]]


def test_get_scan_ui_state_subset_selected() -> None:
    """Verify state when a subset (A01, A05) is selected."""
    state = ui_logic.get_scan_ui_state(["A01", "a05"])

    assert state["button_label"] == "Generate Scan Command"
    assert state["can_run"] is True

    selected_dict = {c["id"]: c["selected"] for c in state["categories"]}
    assert selected_dict["A01"] is True
    assert selected_dict["A05"] is True
    assert selected_dict["A02"] is False
    assert selected_dict["A03"] is False


def test_get_scan_ui_state_empty_selection() -> None:
    """When no categories are selected, can_run must be False."""
    state = ui_logic.get_scan_ui_state([])

    assert state["button_label"] == "Generate Scan Command"
    assert state["can_run"] is False
    assert all(not c["selected"] for c in state["categories"])


def test_on_run_clicked_valid_input() -> None:
    """Valid target URL and category IDs return scan shell command."""
    cmd = ui_logic.on_run_clicked("https://target.local", ["A01", "A02", "A05"])
    assert cmd == "python -m scanner.main scan --target https://target.local --checks A01,A02,A05"


def test_on_run_clicked_empty_url_raises_value_error() -> None:
    """Empty or whitespace URL raises ValueError."""
    with pytest.raises(ValueError, match="Target URL cannot be empty"):
        ui_logic.on_run_clicked("", ["A01"])

    with pytest.raises(ValueError, match="Target URL cannot be empty"):
        ui_logic.on_run_clicked("   ", ["A01"])


def test_on_run_clicked_empty_selection_raises_value_error() -> None:
    """Empty category selection raises ValueError."""
    with pytest.raises(ValueError, match="At least one valid OWASP category ID must be selected"):
        ui_logic.on_run_clicked("https://target.local", [])

