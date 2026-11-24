"""OWASP Sentinel - XSSSpect URL Parameter Parser.

Provides utility functions to extract query parameters and build test URLs
with injected assessment payloads while strictly preserving original URL
structure, schemes, paths, unaffected parameters, and fragments.
"""

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def parse_url_params(url: str) -> dict[str, str]:
    """Extracts query parameters from a URL into a key-value dictionary.

    Args:
        url: The full or relative target URL string to parse.

    Returns:
        dict[str, str]: A dictionary mapping parameter names to their string values.
        Returns an empty dictionary if the URL has no query string or is empty.
    """
    if not url:
        return {}

    parsed = urlsplit(url)
    if not parsed.query:
        return {}

    return dict(parse_qsl(parsed.query, keep_blank_values=True))


def build_test_url(base_url: str, param: str, payload: str) -> str:
    """Builds a test URL by replacing the specified parameter's value with the payload.

    Preserves all existing parameters, ordering, URI scheme, host, path,
    and URL fragment while properly URL-encoding the injected payload.

    Args:
        base_url: The original URL containing target query parameters.
        param: The specific query parameter name whose value will be replaced.
        payload: The assessment test string/payload to inject.

    Returns:
        str: The reconstructed URL with the payload substituted and encoded.
    """
    if not base_url:
        return ""

    parsed = urlsplit(base_url)
    existing_pairs = parse_qsl(parsed.query, keep_blank_values=True)

    found = False
    updated_pairs: list[tuple[str, str]] = []
    for key, value in existing_pairs:
        if key == param:
            updated_pairs.append((key, payload))
            found = True
        else:
            updated_pairs.append((key, value))

    # If parameter was not present in the query string, append it
    if not found:
        updated_pairs.append((param, payload))

    new_query = urlencode(updated_pairs, doseq=True)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))

