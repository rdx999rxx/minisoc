import re


SSH_PATTERN = re.compile(
    r"Failed password .* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

HTTP_PATTERN = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?"(?P<method>GET|POST|PUT|DELETE|HEAD) '
    r'(?P<path>\S+)'
)


def parse_line(line: str) -> dict:
    line = line.strip()

    ssh = SSH_PATTERN.search(line)

    if ssh:
        return {
            "type": "ssh_auth_failure",
            "ip": ssh.group("ip"),
            "raw": line,
        }

    http = HTTP_PATTERN.search(line)

    if http:
        return {
            "type": "http_request",
            "ip": http.group("ip"),
            "method": http.group("method"),
            "path": http.group("path"),
            "raw": line,
        }

    return {
        "type": "unknown",
        "ip": None,
        "raw": line,
    }


def parse_file(filename: str) -> list[dict]:
    events = []

    with open(filename, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            if line.strip():
                events.append(parse_line(line))

    return events
