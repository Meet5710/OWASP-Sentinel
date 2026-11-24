"""Unit tests for xssspect.param_parser module."""

from xssspect.param_parser import build_test_url, parse_url_params


def test_parse_url_params_standard():
    url = "https://example.com/search?q=security&page=2&filter=active"
    params = parse_url_params(url)
    assert params == {
        "q": "security",
        "page": "2",
        "filter": "active",
    }


def test_parse_url_params_empty_query():
    assert parse_url_params("https://example.com/login") == {}
    assert parse_url_params("https://example.com/") == {}
    assert parse_url_params("") == {}
    assert parse_url_params("https://example.com/profile?") == {}


def test_parse_url_params_with_fragment():
    url = "https://example.com/items?cat=books#reviews"
    params = parse_url_params(url)
    assert params == {"cat": "books"}


def test_build_test_url_replace_existing():
    base_url = "https://example.com/search?q=test&lang=en"
    payload = '<script>alert("xss")</script>'
    result = build_test_url(base_url, "q", payload)

    assert "lang=en" in result
    assert "https://example.com/search?" in result
    assert "%3Cscript%3Ealert%28%22xss%22%29%3C%2Fscript%3E" in result

    # Check parsed values
    parsed = parse_url_params(result)
    assert parsed["q"] == payload
    assert parsed["lang"] == "en"


def test_build_test_url_append_new_param():
    base_url = "https://example.com/view?id=42"
    payload = "';alert(1)//"
    result = build_test_url(base_url, "query", payload)

    parsed = parse_url_params(result)
    assert parsed["id"] == "42"
    assert parsed["query"] == payload


def test_build_test_url_preserves_fragment():
    base_url = "https://example.com/details?item=1#specs"
    payload = "xss_test"
    result = build_test_url(base_url, "item", payload)

    assert result.endswith("#specs")
    parsed = parse_url_params(result)
    assert parsed["item"] == payload


def test_build_test_url_no_query_string():
    base_url = "https://example.com/contact"
    payload = "alert(1)"
    result = build_test_url(base_url, "msg", payload)

    assert result == "https://example.com/contact?msg=alert%281%29"
    parsed = parse_url_params(result)
    assert parsed["msg"] == payload

