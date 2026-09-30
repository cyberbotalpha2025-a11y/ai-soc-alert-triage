from collections import Counter


import pandas as pd
from collections import Counter

def detect_brute_force(df, threshold=5):
    """
    Detect possible brute-force attacks based on
    repeated failed login attempts from the same IP.
    """

    failed = df[
        (df["event_type"] == "login") &
        (df["status"] == "failed")
    ]

    counts = Counter(failed["source_ip"])

    alerts = []

    for ip, count in counts.items():

        if count >= threshold:

            alerts.append({
                "alert_type": "Brute Force",
                "source_ip": ip,
                "failed_attempts": count,
                "severity": "HIGH",
                "mitre": "T1110 - Brute Force"
            })

    return alerts


def detect_success_after_failures(df, threshold=3, window_minutes=10):
    """
    Detect possible account compromise when multiple
    failed logins are followed by a successful login
    within a defined time window.
    """

    alerts = []

    df = df.copy()

    df["timestamp"] = pd.to_datetime(df["timestamp"])

    for user in df["user"].unique():

        user_logs = df[
            df["user"] == user
        ].sort_values("timestamp")

        failed = user_logs[
            user_logs["status"] == "failed"
        ]

        successful = user_logs[
            user_logs["status"] == "success"
        ]

        for _, success_event in successful.iterrows():

            success_time = success_event["timestamp"]

            window_start = (
                success_time -
                pd.Timedelta(minutes=window_minutes)
            )

            recent_failures = failed[
                (failed["timestamp"] >= window_start) &
                (failed["timestamp"] <= success_time)
            ]

            if len(recent_failures) >= threshold:

                source_ips = recent_failures[
                    "source_ip"
                ].unique()

                alerts.append({
                    "alert_type": "Possible Account Compromise",
                    "user": user,
                    "source_ip": source_ips[0],
                    "failed_attempts": len(recent_failures),
                    "severity": "CRITICAL",
                    "mitre": "T1110 - Brute Force"
                })

                break

    return alerts