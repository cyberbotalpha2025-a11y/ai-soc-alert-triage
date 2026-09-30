from src.parser import load_logs
from src.detector import (
    detect_brute_force,
    detect_success_after_failures
)
from src.ioc_extractor import extract_iocs_from_alert
from src.threat_intel import check_ip_reputation
from src.ai_analyzer import analyze_alert


LOG_FILE = "data/sample_logs.csv"


def main():

    print("=" * 60)
    print("        AI SOC ALERT TRIAGE SYSTEM")
    print("=" * 60)

    # --------------------------------------------------
    # 1. Load security logs
    # --------------------------------------------------

    print("\n[1] Loading security logs...")

    df = load_logs(LOG_FILE)

    print(f"Loaded {len(df)} security events.")

    # --------------------------------------------------
    # 2. Detect brute force
    # --------------------------------------------------

    print("\n[2] Running detection rules...")

    brute_force_alerts = detect_brute_force(df)

    compromise_alerts = detect_success_after_failures(df)

    alerts = brute_force_alerts + compromise_alerts

    print(f"Generated {len(alerts)} alerts.")

    # --------------------------------------------------
    # 3. Process each alert
    # --------------------------------------------------

    for index, alert in enumerate(alerts, start=1):

        print("\n" + "=" * 60)
        print(f"ALERT #{index}")
        print("=" * 60)

        print("\nAlert:")
        print(alert)

        # --------------------------------------------------
        # IOC extraction
        # --------------------------------------------------

        iocs = extract_iocs_from_alert(alert)

        print("\nIOC:")
        print(iocs)

        # --------------------------------------------------
        # Threat intelligence
        # --------------------------------------------------

        threat_intel = {}

        ip_addresses = iocs.get("ip_addresses", [])

        if ip_addresses:

            ip = ip_addresses[0]

            print(f"\nChecking threat intelligence for {ip}...")

            threat_intel = check_ip_reputation(ip)

            print("\nThreat Intelligence:")
            print(threat_intel)

        # --------------------------------------------------
        # AI analysis
        # --------------------------------------------------

        print("\nRunning AI investigation...")

        ai_result = analyze_alert(
            alert,
            threat_intel
        )

        print("\nAI INVESTIGATION")
        print("-" * 60)
        print(ai_result)

    print("\n" + "=" * 60)
    print("SOC TRIAGE COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()