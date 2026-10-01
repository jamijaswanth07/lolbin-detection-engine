import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone

RULES_DIR = Path("rules")
ALERTS_FILE = Path("alerts/alerts.json")
LOG_NAME = "Microsoft-Windows-Sysmon/Operational"


def load_rules():
    """Load all JSON detection rules."""
    rules = []

    for rule_file in RULES_DIR.glob("*.json"):
        try:
            with open(rule_file, "r", encoding="utf-8") as file:
                data = json.load(file)
                rules.extend(data.get("rules", []))
        except Exception as error:
            print(f"[!] Could not load {rule_file}: {error}")

    return rules


def get_latest_event():
    """Collect the latest Sysmon Event ID 1 using wevtutil."""

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
        print("[!] Error collecting Sysmon event:")
        print(result.stderr)
        return None

    xml_text = result.stdout

    start = xml_text.find("<Event")
    end = xml_text.find("</Event>", start)

    if start == -1 or end == -1:
        print("[!] No Sysmon Event ID 1 found.")
        return None

    end += len("</Event>")

    try:
        root = ET.fromstring(xml_text[start:end])
        event = {}

        for element in root.iter():

            tag = element.tag.split("}")[-1]

            if tag == "EventRecordID":
                event["RecordId"] = element.text

            elif tag == "Data":

                name = element.attrib.get("Name")

                if name:
                    event[name] = element.text or ""

        return event

    except ET.ParseError:
        print("[!] Could not parse Sysmon event XML.")
        return None


def detect_event(event, rules):
    """Apply detection rules to a Sysmon event."""

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


def main():

    print("[*] Loading detection rules...")

    rules = load_rules()

    print(f"[*] Loaded {len(rules)} detection rule(s).")

    print("[*] Collecting latest Sysmon Event ID 1...")

    event = get_latest_event()

    if event is None:
        return

    print(
        f"[*] Process: "
        f"{event.get('Image', 'Unknown')}"
    )

    print(
        f"[*] Command: "
        f"{event.get('CommandLine', 'Unknown')}"
    )

    alerts = detect_event(event, rules)

    print("\n" + "=" * 60)

    if alerts:

        existing_alerts = []

        if ALERTS_FILE.exists():

            try:
                with open(
                    ALERTS_FILE,
                    "r",
                    encoding="utf-8"
                ) as file:
                    existing_alerts = json.load(file)

            except json.JSONDecodeError:
                existing_alerts = []

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

        ALERTS_FILE.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with open(
            ALERTS_FILE,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                existing_alerts,
                file,
                indent=4
            )

        if new_alerts:

            for alert in new_alerts:

                print("🚨 SECURITY ALERT")
                print("=" * 60)
                print(f"Rule ID:       {alert['rule_id']}")
                print(f"Rule:          {alert['rule_name']}")
                print(f"Severity:      {alert['severity']}")
                print(f"MITRE ATT&CK:  {alert['mitre_attack']}")
                print(f"Reason:        {alert['reason']}")
                print(f"User:          {alert['user']}")
                print(f"Parent:        {alert['parent_process']}")
                print(f"Record ID:     {alert['record_id']}")
                print("=" * 60)

            print(
                f"[*] {len(new_alerts)} alert(s) saved."
            )

        else:

            print("[*] Matching alert already exists.")

    else:

        print("✅ No suspicious activity detected.")

    print("=" * 60)


if __name__ == "__main__":
    main()