import json
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone

POLL_INTERVAL = 2
LOG_NAME = "Microsoft-Windows-Sysmon/Operational"

RULES_DIR = Path("rules")
ALERTS_FILE = Path("alerts/alerts.json")


def load_rules():
    """Load all detection rules."""
    rules = []

    for rule_file in RULES_DIR.glob("*.json"):
        try:
            with open(rule_file, "r", encoding="utf-8") as file:
                data = json.load(file)
                rules.extend(data.get("rules", []))
        except Exception as error:
            print(f"[!] Could not load {rule_file}: {error}")

    return rules


def get_events():
    """Get recent Sysmon Event ID 1 events."""

    result = subprocess.run(
        [
            "wevtutil.exe",
            "qe",
            LOG_NAME,
            "/q:*[System[(EventID=1)]]",
            "/f:xml",
            "/c:20",
            "/rd:true"
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace"
    )

    if result.returncode != 0:
        print("[!] Error reading Sysmon events:")
        print(result.stderr)
        return []

    events = []
    xml_text = result.stdout
    start = 0

    while True:

        start = xml_text.find("<Event", start)

        if start == -1:
            break

        end = xml_text.find("</Event>", start)

        if end == -1:
            break

        end += len("</Event>")

        xml_block = xml_text[start:end]
        start = end

        try:

            root = ET.fromstring(xml_block)
            event = {}

            for element in root.iter():

                tag = element.tag.split("}")[-1]

                if tag == "EventRecordID":
                    event["RecordId"] = element.text

                elif tag == "Data":
                    name = element.attrib.get("Name")

                    if name:
                        event[name] = element.text or ""

            events.append(event)

        except ET.ParseError:
            continue

    return events


def detect_event(event, rules):
    """Apply detection rules to an event."""

    alerts = []

    image = event.get("Image", "").lower()
    command_line = event.get("CommandLine", "").lower()

    for rule in rules:

        process_match = rule["process"].lower() in image
        indicator_match = rule["indicator"].lower() in command_line

        if process_match and indicator_match:

            alert = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "mitre_attack": rule["mitre_attack"],
                "reason": rule["description"],
                "process": event.get("Image", ""),
                "command_line": event.get("CommandLine", ""),
                "user": event.get("User", ""),
                "parent_process": event.get("ParentImage", ""),
                "process_id": event.get("ProcessId", ""),
                "utc_time": event.get("UtcTime", ""),
                "record_id": event.get("RecordId", "")
            }

            alerts.append(alert)

    return alerts


def load_existing_alerts():
    """Load previously saved alerts."""

    if not ALERTS_FILE.exists():
        return []

    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except (json.JSONDecodeError, FileNotFoundError):
        return []


def save_alerts(alerts):
    """Save new alerts while preventing duplicates."""

    existing_alerts = load_existing_alerts()

    existing_keys = {
        (
            alert.get("record_id"),
            alert.get("rule_id")
        )
        for alert in existing_alerts
    }

    new_alerts = []

    for alert in alerts:

        key = (
            alert.get("record_id"),
            alert.get("rule_id")
        )

        if key not in existing_keys:

            existing_alerts.append(alert)
            existing_keys.add(key)
            new_alerts.append(alert)

    ALERTS_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(ALERTS_FILE, "w", encoding="utf-8") as file:
        json.dump(existing_alerts, file, indent=4)

    return new_alerts


def display_alert(alert):

    print("\n" + "=" * 60)
    print("🚨 SECURITY ALERT")
    print("=" * 60)

    print(f"Rule ID:       {alert['rule_id']}")
    print(f"Rule:          {alert['rule_name']}")
    print(f"Severity:      {alert['severity']}")
    print(f"MITRE ATT&CK:  {alert['mitre_attack']}")
    print(f"Reason:        {alert['reason']}")
    print(f"Process:       {alert['process']}")
    print(f"Command:       {alert['command_line']}")
    print(f"User:          {alert['user']}")
    print(f"Parent:        {alert['parent_process']}")
    print(f"Record ID:     {alert['record_id']}")

    print("=" * 60)


def monitor():

    print("[*] Loading detection rules...")

    rules = load_rules()

    print(f"[*] Loaded {len(rules)} detection rule(s).")

    for rule in rules:
        print(
            f"    - {rule['id']}: "
            f"{rule['name']} "
            f"[{rule['severity']}]"
        )

    print()
    print("[*] Starting LOLBin Detection Engine...")
    print("[*] Collector: wevtutil.exe")
    print("[*] Monitoring Sysmon Event ID 1")
    print("[*] Alert deduplication: enabled")
    print("[*] Press Ctrl+C to stop.\n")

    seen_ids = set()

    try:

        while True:

            events = get_events()

            events.reverse()

            for event in events:

                record_id = int(event.get("RecordId", 0))

                if record_id == 0:
                    continue

                if record_id in seen_ids:
                    continue

                seen_ids.add(record_id)

                image = event.get("Image", "Unknown")

                print(
                    f"[+] Event {record_id}: {image}"
                )

                alerts = detect_event(event, rules)

                if alerts:

                    new_alerts = save_alerts(alerts)

                    if new_alerts:

                        for alert in new_alerts:
                            display_alert(alert)

                    else:

                        print(
                            "    └─ Alert already recorded."
                        )

                else:

                    print(
                        "    └─ No detection rule matched."
                    )

            if len(seen_ids) > 1000:
                seen_ids = set(list(seen_ids)[-500:])

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:

        print("\n[*] Detection engine stopped.")


if __name__ == "__main__":
    monitor()