import re
from collections import Counter
from urllib.parse import unquote

from database import add_alert


SQLI_PATTERNS = [
    r"union\s+select",
    r"or\s+1\s*=\s*1",
    r"'\s*or\s+'",
]

XSS_PATTERNS = [
    r"<script",
    r"javascript:",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"%2e%2e",
]


def detect_ssh_bruteforce(events, threshold=5):
    counts = Counter(
        event.get("ip")
        for event in events
        if event.get("type") == "ssh_auth_failure"
        and event.get("ip")
    )

    for ip, count in counts.items():
        if count >= threshold:
            add_alert(
                "SSH Brute Force",
                "HIGH",
                ip,
                f"{count} failed SSH authentication attempts detected",
            )


def contains_pattern(value, patterns):
    return any(
        re.search(pattern, value, re.IGNORECASE)
        for pattern in patterns
    )


def detect_web_attacks(events):
    for event in events:
        if event.get("type") != "http_request":
            continue

        ip = event.get("ip")
        path = unquote(event.get("path", ""))

        if contains_pattern(path, SQLI_PATTERNS):
            add_alert(
                "SQL Injection Pattern",
                "CRITICAL",
                ip,
                f"Possible SQL injection pattern: {path}",
            )

        elif contains_pattern(path, XSS_PATTERNS):
            add_alert(
                "XSS Pattern",
                "HIGH",
                ip,
                f"Possible XSS pattern: {path}",
            )

        elif contains_pattern(path, PATH_TRAVERSAL_PATTERNS):
            add_alert(
                "Path Traversal",
                "HIGH",
                ip,
                f"Possible path traversal pattern: {path}",
            )


def analyze(events):
    detect_ssh_bruteforce(events)
    detect_web_attacks(events)
