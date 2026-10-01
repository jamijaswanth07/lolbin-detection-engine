import json
from pathlib import Path
from collections import Counter
from html import escape
from datetime import datetime

ALERTS_FILE = Path("alerts/alerts.json")
REPORT_DIR = Path("reports")
REPORT_FILE = REPORT_DIR / "dashboard.html"


def load_alerts():
    if not ALERTS_FILE.exists():
        return []

    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, FileNotFoundError):
        return []


def badge_class(value):
    value = str(value).upper()

    if value == "HIGH":
        return "high"

    if value == "MEDIUM":
        return "medium"

    if value == "LOW":
        return "low"

    return "info"


def generate_dashboard():

    alerts = load_alerts()

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------
    # Statistics
    # ---------------------------------------------------------

    severity_counts = Counter(
        alert.get("severity", "UNKNOWN").upper()
        for alert in alerts
    )

    rule_counts = Counter(
        alert.get("rule_id", "UNKNOWN")
        for alert in alerts
    )

    mitre_counts = Counter(
        alert.get("mitre_attack", "UNKNOWN")
        for alert in alerts
    )

    total_alerts = len(alerts)

    rules_triggered = len(
        set(alert.get("rule_id", "UNKNOWN") for alert in alerts)
    )

    techniques_covered = len(
        set(alert.get("mitre_attack", "UNKNOWN") for alert in alerts)
    )

    high = severity_counts.get("HIGH", 0)
    medium = severity_counts.get("MEDIUM", 0)
    low = severity_counts.get("LOW", 0)

    # ---------------------------------------------------------
    # Detection Activity
    # ---------------------------------------------------------

    rule_rows = ""

    max_rule_count = max(rule_counts.values(), default=1)

    for rule, count in rule_counts.most_common():

        percentage = (count / max_rule_count) * 100

        rule_rows += f"""
        <div class="rule-row">

            <div class="rule-info">
                <span class="rule-id">
                    {escape(str(rule))}
                </span>

                <span class="rule-count">
                    {count}
                </span>
            </div>

            <div class="progress-track">
                <div
                    class="progress-bar"
                    style="width: {percentage:.1f}%">
                </div>
            </div>

        </div>
        """

    if not rule_rows:
        rule_rows = """
        <div class="empty-small">
            No detection activity recorded.
        </div>
        """

    # ---------------------------------------------------------
    # MITRE ATT&CK
    # ---------------------------------------------------------

    mitre_rows = ""

    for technique, count in mitre_counts.most_common():

        mitre_rows += f"""
        <div class="mitre-item">

            <span class="mitre-code">
                {escape(str(technique))}
            </span>

            <span class="mitre-count">
                {count}
            </span>

        </div>
        """

    if not mitre_rows:
        mitre_rows = """
        <div class="empty-small">
            No ATT&CK techniques recorded.
        </div>
        """

    # ---------------------------------------------------------
    # Severity Distribution
    # ---------------------------------------------------------

    severity_rows = f"""
    <div class="severity-item">
        <span class="severity-label high-text">
            HIGH
        </span>

        <span class="severity-number">
            {high}
        </span>
    </div>

    <div class="severity-item">
        <span class="severity-label medium-text">
            MEDIUM
        </span>

        <span class="severity-number">
            {medium}
        </span>
    </div>

    <div class="severity-item">
        <span class="severity-label low-text">
            LOW
        </span>

        <span class="severity-number">
            {low}
        </span>
    </div>
    """

    # ---------------------------------------------------------
    # Alert Table
    # ---------------------------------------------------------

    alert_rows = ""

    for alert in reversed(alerts):

        severity = str(
            alert.get("severity", "UNKNOWN")
        ).upper()

        timestamp = escape(
            str(alert.get("timestamp", ""))
        )

        rule_id = escape(
            str(alert.get("rule_id", ""))
        )

        rule_name = escape(
            str(alert.get("rule_name", ""))
        )

        mitre = escape(
            str(alert.get("mitre_attack", ""))
        )

        process = escape(
            str(alert.get("process", ""))
        )

        command = escape(
            str(alert.get("command_line", ""))
        )

        user = escape(
            str(alert.get("user", ""))
        )

        alert_rows += f"""
        <tr>

            <td class="time-cell">
                {timestamp}
            </td>

            <td>
                <span class="rule-badge">
                    {rule_id}
                </span>
            </td>

            <td>

                <div class="alert-name">
                    {rule_name}
                </div>

                <div class="command">
                    {command}
                </div>

            </td>

            <td>

                <span class="severity {badge_class(severity)}">
                    ● {severity}
                </span>

            </td>

            <td>

                <span class="mitre-badge">
                    {mitre}
                </span>

            </td>

            <td>

                <div class="process">
                    {process}
                </div>

                <div class="user">
                    {user}
                </div>

            </td>

        </tr>
        """

    if not alert_rows:

        alert_rows = """
        <tr>
            <td colspan="6" class="empty">
                No security alerts recorded.
            </td>
        </tr>
        """

    generated_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    # ---------------------------------------------------------
    # HTML Dashboard
    # ---------------------------------------------------------

    html = f"""<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0">

<meta
    http-equiv="refresh"
    content="30">

<title>
    LOLBin Detection Engine | SOC Console
</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{

    margin: 0;

    background:
        radial-gradient(
            circle at 20% 0%,
            rgba(0, 212, 255, 0.08),
            transparent 30%
        ),
        radial-gradient(
            circle at 90% 20%,
            rgba(120, 70, 255, 0.08),
            transparent 30%
        ),
        #070b12;

    color: #d9e2ec;

    font-family:
        "Segoe UI",
        Arial,
        sans-serif;
}}

body::before {{

    content: "";

    position: fixed;

    inset: 0;

    pointer-events: none;

    background-image:
        linear-gradient(
            rgba(255,255,255,0.015) 1px,
            transparent 1px
        ),
        linear-gradient(
            90deg,
            rgba(255,255,255,0.015) 1px,
            transparent 1px
        );

    background-size: 40px 40px;

    z-index: -1;
}}

.container {{

    max-width: 1500px;

    margin: auto;

    padding: 28px;
}}

/* =========================================================
   HEADER
   ========================================================= */

.header {{

    display: flex;

    justify-content: space-between;

    align-items: center;

    padding: 22px 26px;

    margin-bottom: 24px;

    background:
        linear-gradient(
            135deg,
            rgba(15,25,38,0.96),
            rgba(8,14,23,0.96)
        );

    border: 1px solid #1c3548;

    border-radius: 14px;

    box-shadow:
        0 0 35px rgba(0,212,255,0.06);
}}

.brand {{

    display: flex;

    align-items: center;

    gap: 16px;
}}

.logo {{

    width: 48px;

    height: 48px;

    display: flex;

    align-items: center;

    justify-content: center;

    border-radius: 12px;

    background: rgba(0,212,255,0.08);

    border: 1px solid #1a829b;

    color: #00d9ff;

    font-size: 24px;

    box-shadow:
        0 0 20px rgba(0,212,255,0.15);
}}

.title {{

    margin: 0;

    font-size: 23px;

    letter-spacing: 0.5px;

    color: #f2f7fb;
}}

.subtitle {{

    margin-top: 5px;

    color: #71879a;

    font-size: 13px;
}}

.status {{

    display: flex;

    align-items: center;

    gap: 9px;

    color: #69f0ae;

    font-size: 13px;

    font-weight: 600;

    padding: 9px 14px;

    border-radius: 20px;

    background: rgba(50,220,130,0.06);

    border: 1px solid rgba(50,220,130,0.2);
}}

.status-dot {{

    width: 8px;

    height: 8px;

    border-radius: 50%;

    background: #69f0ae;

    box-shadow:
        0 0 10px #69f0ae;
}}

/* =========================================================
   STATISTICS
   ========================================================= */

.stats {{

    display: grid;

    grid-template-columns:
        repeat(4, 1fr);

    gap: 16px;

    margin-bottom: 20px;
}}

.card {{

    position: relative;

    overflow: hidden;

    background:
        linear-gradient(
            145deg,
            #0d1621,
            #091019
        );

    border: 1px solid #1b2c3b;

    border-radius: 12px;

    padding: 22px;

    transition: 0.2s;
}}

.card:hover {{

    transform: translateY(-2px);

    border-color: #27506a;
}}

.card::after {{

    content: "";

    position: absolute;

    width: 90px;

    height: 90px;

    right: -30px;

    bottom: -35px;

    border-radius: 50%;

    background: rgba(0,212,255,0.05);
}}

.card-label {{

    color: #71879a;

    font-size: 12px;

    text-transform: uppercase;

    letter-spacing: 1.2px;
}}

.card-value {{

    margin-top: 9px;

    font-size: 34px;

    font-weight: 700;

    color: #00d9ff;
}}

.card.medium-card .card-value {{

    color: #ffbd4a;
}}

/* =========================================================
   ANALYTICS
   ========================================================= */

.dashboard-grid {{

    display: grid;

    grid-template-columns:
        1.25fr
        1fr
        0.8fr;

    gap: 18px;

    margin-bottom: 20px;
}}

.panel {{

    background:
        linear-gradient(
            145deg,
            rgba(13,22,33,0.97),
            rgba(8,14,22,0.97)
        );

    border: 1px solid #1b2c3b;

    border-radius: 12px;

    padding: 22px;
}}

.panel-title {{

    display: flex;

    justify-content: space-between;

    align-items: center;

    margin-bottom: 20px;
}}

.panel-title h2 {{

    margin: 0;

    font-size: 15px;

    letter-spacing: 0.8px;

    text-transform: uppercase;

    color: #dce9f3;
}}

.panel-tag {{

    font-size: 10px;

    color: #5e7a8e;

    letter-spacing: 1px;
}}

/* =========================================================
   DETECTION ACTIVITY
   ========================================================= */

.rule-row {{

    margin-bottom: 17px;
}}

.rule-info {{

    display: flex;

    justify-content: space-between;

    margin-bottom: 7px;
}}

.rule-id {{

    color: #8eeaff;

    font-family: Consolas, monospace;

    font-size: 13px;
}}

.rule-count {{

    color: #9aabba;

    font-size: 12px;
}}

.progress-track {{

    height: 5px;

    background: #101c28;

    border-radius: 10px;

    overflow: hidden;
}}

.progress-bar {{

    height: 100%;

    background:
        linear-gradient(
            90deg,
            #00b8d9,
            #6d5dfc
        );

    border-radius: 10px;

    box-shadow:
        0 0 10px rgba(0,212,255,0.25);
}}

/* =========================================================
   MITRE
   ========================================================= */

.mitre-grid {{

    display: grid;

    grid-template-columns:
        repeat(2, 1fr);

    gap: 10px;
}}

.mitre-item {{

    display: flex;

    justify-content: space-between;

    align-items: center;

    padding: 12px;

    border-radius: 8px;

    background: #0b141e;

    border: 1px solid #162735;
}}

.mitre-code {{

    color: #a8e8ff;

    font-family: Consolas, monospace;

    font-size: 12px;
}}

.mitre-count {{

    color: #657e91;

    font-size: 11px;
}}

/* =========================================================
   SEVERITY
   ========================================================= */

.severity-list {{

    display: flex;

    flex-direction: column;

    gap: 10px;
}}

.severity-item {{

    display: flex;

    justify-content: space-between;

    align-items: center;

    padding: 14px;

    background: #0b141e;

    border: 1px solid #162735;

    border-radius: 8px;
}}

.severity-label {{

    font-family: Consolas, monospace;

    font-size: 12px;

    font-weight: 700;
}}

.high-text {{
    color: #ff5572;
}}

.medium-text {{
    color: #ffbd4a;
}}

.low-text {{
    color: #69d5ff;
}}

.severity-number {{

    color: #9aabba;

    font-family: Consolas, monospace;

    font-size: 13px;
}}

/* =========================================================
   ALERT TABLE
   ========================================================= */

.alert-panel {{

    padding: 0;

    overflow: hidden;
}}

.alert-header {{

    padding: 22px;
}}

.table-wrapper {{

    overflow-x: auto;
}}

table {{

    width: 100%;

    border-collapse: collapse;

    min-width: 1050px;
}}

thead {{

    background: #0a121c;
}}

th {{

    text-align: left;

    padding: 13px 16px;

    color: #637b8e;

    font-size: 10px;

    text-transform: uppercase;

    letter-spacing: 1px;

    border-top: 1px solid #172936;

    border-bottom: 1px solid #172936;
}}

td {{

    padding: 15px 16px;

    border-bottom: 1px solid #12212d;

    vertical-align: top;

    font-size: 12px;
}}

tbody tr:hover {{

    background: rgba(0,212,255,0.025);
}}

.time-cell {{

    color: #61788a;

    font-family: Consolas, monospace;

    white-space: nowrap;
}}

.rule-badge {{

    display: inline-block;

    padding: 5px 8px;

    border-radius: 5px;

    background: rgba(0,212,255,0.07);

    border: 1px solid rgba(0,212,255,0.16);

    color: #70dcf4;

    font-family: Consolas, monospace;

    font-size: 11px;
}}

.alert-name {{

    color: #e2edf5;

    font-weight: 600;

    margin-bottom: 6px;
}}

.command {{

    max-width: 390px;

    color: #637d90;

    font-family: Consolas, monospace;

    font-size: 10px;

    overflow: hidden;

    text-overflow: ellipsis;

    white-space: nowrap;
}}

.severity {{

    display: inline-block;

    padding: 5px 9px;

    border-radius: 20px;

    font-size: 10px;

    font-weight: 700;

    letter-spacing: 0.5px;
}}

.severity.high {{

    color: #ff7188;

    background: rgba(255,70,100,0.09);

    border: 1px solid rgba(255,70,100,0.18);
}}

.severity.medium {{

    color: #ffc65a;

    background: rgba(255,180,50,0.08);

    border: 1px solid rgba(255,180,50,0.18);
}}

.severity.low {{

    color: #71d9ff;

    background: rgba(50,190,255,0.08);

    border: 1px solid rgba(50,190,255,0.18);
}}

.severity.info {{

    color: #9eabb5;

    background: rgba(150,160,170,0.08);

    border: 1px solid rgba(150,160,170,0.15);
}}

.mitre-badge {{

    color: #b9a8ff;

    background: rgba(120,90,255,0.08);

    border: 1px solid rgba(120,90,255,0.18);

    padding: 5px 8px;

    border-radius: 5px;

    font-family: Consolas, monospace;

    font-size: 10px;
}}

.process {{

    color: #a8bdca;

    font-family: Consolas, monospace;

    font-size: 10px;

    max-width: 260px;

    overflow: hidden;

    text-overflow: ellipsis;

    white-space: nowrap;
}}

.user {{

    margin-top: 5px;

    color: #536b7c;

    font-size: 10px;
}}

/* =========================================================
   EMPTY STATES
   ========================================================= */

.empty {{

    text-align: center;

    padding: 50px;

    color: #526879;
}}

.empty-small {{

    text-align: center;

    padding: 30px 10px;

    color: #526879;

    font-size: 12px;
}}

/* =========================================================
   FOOTER
   ========================================================= */

.footer {{

    display: flex;

    justify-content: space-between;

    color: #4e6576;

    font-size: 10px;

    padding: 18px 3px;
}}

/* =========================================================
   RESPONSIVE
   ========================================================= */

@media(max-width: 1100px) {{

    .dashboard-grid {{

        grid-template-columns:
            1fr 1fr;
    }}

    .dashboard-grid .panel:last-child {{

        grid-column:
            span 2;
    }}
}}

@media(max-width: 900px) {{

    .stats {{

        grid-template-columns:
            repeat(2, 1fr);
    }}

    .dashboard-grid {{

        grid-template-columns: 1fr;
    }}

    .dashboard-grid .panel:last-child {{

        grid-column: auto;
    }}

    .header {{

        align-items: flex-start;

        gap: 15px;

        flex-direction: column;
    }}
}}

@media(max-width: 550px) {{

    .container {{

        padding: 14px;
    }}

    .stats {{

        grid-template-columns: 1fr;
    }}

    .mitre-grid {{

        grid-template-columns: 1fr;
    }}
}}

</style>

</head>

<body>

<div class="container">

    <!-- =====================================================
         HEADER
         ===================================================== -->

    <header class="header">

        <div class="brand">

            <div class="logo">
                ◈
            </div>

            <div>

                <h1 class="title">
                    LOLBin Detection Engine
                </h1>

                <div class="subtitle">
                    Behavioral Security Monitoring Console
                </div>

            </div>

        </div>

        <div class="status">

            <span class="status-dot"></span>

            SOC DETECTION CONSOLE

        </div>

    </header>


    <!-- =====================================================
         STATISTICS
         ===================================================== -->

    <section class="stats">

        <div class="card">

            <div class="card-label">
                Detection Events
            </div>

            <div class="card-value">
                {total_alerts}
            </div>

        </div>


        <div class="card">

            <div class="card-label">
                Rules Triggered
            </div>

            <div class="card-value">
                {rules_triggered}
            </div>

        </div>


        <div class="card">

            <div class="card-label">
                ATT&CK Techniques
            </div>

            <div class="card-value">
                {techniques_covered}
            </div>

        </div>


        <div class="card medium-card">

            <div class="card-label">
                Medium Alerts
            </div>

            <div class="card-value">
                {medium}
            </div>

        </div>

    </section>


    <!-- =====================================================
         ANALYTICS
         ===================================================== -->

    <section class="dashboard-grid">


        <!-- Detection Activity -->

        <div class="panel">

            <div class="panel-title">

                <h2>
                    Detection Activity
                </h2>

                <span class="panel-tag">
                    RULE DISTRIBUTION
                </span>

            </div>

            {rule_rows}

        </div>


        <!-- MITRE -->

        <div class="panel">

            <div class="panel-title">

                <h2>
                    MITRE ATT&CK Coverage
                </h2>

                <span class="panel-tag">
                    TECHNIQUES
                </span>

            </div>

            <div class="mitre-grid">

                {mitre_rows}

            </div>

        </div>


        <!-- Severity -->

        <div class="panel">

            <div class="panel-title">

                <h2>
                    Severity
                </h2>

                <span class="panel-tag">
                    CLASSIFICATION
                </span>

            </div>

            <div class="severity-list">

                {severity_rows}

            </div>

        </div>

    </section>


    <!-- =====================================================
         SECURITY ALERT FEED
         ===================================================== -->

    <section class="panel alert-panel">

        <div class="alert-header">

            <div class="panel-title">

                <h2>
                    Security Alert Feed
                </h2>

                <span class="panel-tag">
                    {total_alerts} EVENTS
                </span>

            </div>

        </div>


        <div class="table-wrapper">

            <table>

                <thead>

                    <tr>

                        <th>
                            Timestamp
                        </th>

                        <th>
                            Rule
                        </th>

                        <th>
                            Detection
                        </th>

                        <th>
                            Severity
                        </th>

                        <th>
                            ATT&CK
                        </th>

                        <th>
                            Process / User
                        </th>

                    </tr>

                </thead>


                <tbody>

                    {alert_rows}

                </tbody>

            </table>

        </div>

    </section>


    <!-- =====================================================
         FOOTER
         ===================================================== -->

    <footer class="footer">

        <span>
            LOLBin Detection Engine • SOC Monitoring
        </span>

        <span>
            Generated {generated_time}
        </span>

    </footer>

</div>

</body>

</html>
"""

    # ---------------------------------------------------------
    # Write dashboard
    # ---------------------------------------------------------

    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(html)

    print(
        f"[+] Cyber SOC dashboard generated: "
        f"{REPORT_FILE}"
    )

    print(
        f"[+] Detection events: {total_alerts}"
    )

    print(
        f"[+] Rules triggered: {rules_triggered}"
    )

    print(
        f"[+] ATT&CK techniques: {techniques_covered}"
    )


if __name__ == "__main__":
    generate_dashboard()