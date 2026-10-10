"""Features lexicales d'une URL. Pur Python, aucun accès réseau."""
import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = (
    "login", "verify", "secure", "account", "update", "bank",
    "paypal", "confirm", "signin", "password", "wallet",
)
RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "zip", "work"}

_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

FEATURE_NAMES = [
    "url_length", "host_length", "host_dots", "host_hyphens", "digit_count",
    "has_at_symbol", "is_https", "host_is_ip", "subdomain_count",
    "suspicious_word_count", "path_length", "special_char_count", "risky_tld",
]


def extract_features(url: str) -> list:
    raw = url.strip()
    try:
        parsed = urlparse(raw if "://" in raw else "http://" + raw)
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""
        scheme = parsed.scheme
    except ValueError:  # URL malformée, ex: "http://[bad"
        host, path, scheme = "", "", ""

    low = raw.lower()
    labels = [p for p in host.split(".") if p]
    tld = labels[-1] if labels else ""

    return [
        float(len(raw)),
        float(len(host)),
        float(host.count(".")),
        float(host.count("-")),
        float(sum(c.isdigit() for c in raw)),
        float("@" in raw),
        float(scheme == "https"),
        float(bool(_IP_RE.match(host))),
        float(max(len(labels) - 2, 0)),
        float(sum(w in low for w in SUSPICIOUS_WORDS)),
        float(len(path)),
        float(sum(raw.count(c) for c in "?&=%")),
        float(tld in RISKY_TLDS),
    ]
