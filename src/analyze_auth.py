
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import csv
import re

ROOT = Path(__file__).resolve().parents[1]
LOG_FILE = ROOT / "data" / "raw" / "auth.log"
OUTPUT = ROOT / "reports" / "alerts.csv"

THRESHOLD = 5
WINDOW_SECONDS = 300

pattern = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
    r".*sshd\[\d+\]: Failed password for "
    r"(?:invalid user )?(?P<user>\S+)"
    r" from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

failures = defaultdict(list)

with LOG_FILE.open(encoding="utf-8") as file:
    for line in file:
        match = pattern.search(line)
        if not match:
            continue

        time_text = match.group("timestamp")
        timestamp = datetime.strptime(
            f"2026 {time_text}", "%Y %b %d %H:%M:%S"
        )

        ip = match.group("ip")
        failures[ip].append(timestamp)

alerts = []

for ip, timestamps in failures.items():
    timestamps.sort()

    left = 0
    for right, current_time in enumerate(timestamps):
        while (
            current_time - timestamps[left]
        ).total_seconds() > WINDOW_SECONDS:
            left += 1

        count = right - left + 1

        if count >= THRESHOLD:
            alerts.append({
                "ip": ip,
                "failed_attempts": count,
                "window_seconds": WINDOW_SECONDS,
                "last_event": current_time.isoformat(),
                "severity": "HIGH",
            })
            break

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

with OUTPUT.open("w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "ip", "failed_attempts", "window_seconds",
            "last_event", "severity"
        ]
    )
    writer.writeheader()
    writer.writerows(alerts)

print("Total IPs with failed logins:", len(failures))
print("Alerts detected:", len(alerts))

for alert in alerts:
    print(alert)

print("Report saved to:", OUTPUT)
