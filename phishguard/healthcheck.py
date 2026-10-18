"""Used by the Docker HEALTHCHECK: exit 0 if the API answers, 1 otherwise."""
import sys
import urllib.request

try:
    urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=2)
except Exception:
    sys.exit(1)
