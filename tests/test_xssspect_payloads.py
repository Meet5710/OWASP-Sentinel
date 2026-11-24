"""Unit tests for xssspect.payloads module."""

import pytest
from pathlib import Path
from xssspect.payloads import DEFAULT_PAYLOADS, load_payloads


def test_default_payloads_content():
    expected = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "'><img src=x onerror=alert(1)>",
    ]
    assert DEFAULT_PAYLOADS == expected


def test_load_payloads_default():
    assert load_payloads(None) is DEFAULT_PAYLOADS
    assert load_payloads() is DEFAULT_PAYLOADS


def test_load_payloads_from_file(tmp_path: Path):
    custom_file = tmp_path / "custom_probes.txt"
    content = """# Header comment
<script>alert(99)</script>

  <svg onload=confirm(1)>   
# Another comment line
" autofocus onfocus=alert(1)

"""
    custom_file.write_text(content, encoding="utf-8")

    result = load_payloads(str(custom_file))
    assert result == [
        "<script>alert(99)</script>",
        "<svg onload=confirm(1)>",
        '" autofocus onfocus=alert(1)',
    ]


def test_load_payloads_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_payloads("non_existent_payloads_12345.txt")


def test_load_payloads_modes():
    from xssspect.payloads import DEEP_PAYLOADS, DOM_PAYLOADS, STANDARD_PAYLOADS

    assert load_payloads(mode="STANDARD") is STANDARD_PAYLOADS
    assert len(load_payloads(mode="STANDARD")) == 15

    assert load_payloads(mode="DEEP") is DEEP_PAYLOADS
    assert len(load_payloads(mode="DEEP")) >= 36

    assert load_payloads(mode="DOM") is DOM_PAYLOADS
    assert len(load_payloads(mode="DOM")) == 18


