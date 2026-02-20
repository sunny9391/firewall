import math
import re


# ─────────────────────────── helpers ─────────────────────────────────────────

def compute_length(text: str) -> int:
    return len(text)


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def numeric_text_ratio(text: str) -> float:
    """Ratio of digit characters to alphabetic characters."""
    if not text:
        return 0.0
    digits = sum(c.isdigit() for c in text)
    alpha = sum(c.isalpha() for c in text)
    if alpha == 0:
        return float(digits)
    return digits / alpha


_SPECIAL = re.compile(r"""['"{}[\]\\;/=<>|`$]|--""")


def special_char_count(text: str) -> int:
    """Count security-relevant special characters."""
    return len(_SPECIAL.findall(text))


def url_encoded_count(text: str) -> int:
    """Count the number of percent-encoded sequences."""
    return len(re.findall(r"%[0-9A-Fa-f]{2}", text))


def keyword_count(text: str) -> int:
    """Count occurrences of common SQL/XSS keywords."""
    keywords = re.compile(
        r"(?i)\b(select|union|insert|update|delete|drop|exec|script|"
        r"alert|eval|onerror|onload|onclick|javascript|from|where|"
        r"having|order|group|limit|sleep|benchmark|waitfor)\b"
    )
    return len(keywords.findall(text))


# ─────────────────────────── public API ──────────────────────────────────────

FEATURE_NAMES = [
    "URI_Length",
    "GET_Length",
    "POST_Length",
    "URI_Entropy",
    "GET_Entropy",
    "POST_Entropy",
    "Numeric_Text_Ratio",
    "Special_Char_Count",
    "URL_Encoded_Count",
    "Keyword_Count",
]


def extract_features(uri: str, get_data: str, post_data: str) -> list[float]:
    """
    Extract ten numeric features from a WAF request.

    Parameters
    ----------
    uri       : The request URI / path (e.g. "/search?q=foo").
    get_data  : Query-string parameters as a raw string.
    post_data : POST body as a raw string.

    Returns
    -------
    A fixed-length list of floats in FEATURE_NAMES order.
    """
    combined = uri + get_data + post_data
    return [
        compute_length(uri),
        compute_length(get_data),
        compute_length(post_data),
        shannon_entropy(uri),
        shannon_entropy(get_data),
        shannon_entropy(post_data),
        numeric_text_ratio(combined),
        special_char_count(combined),
        url_encoded_count(combined),
        keyword_count(combined),
    ]