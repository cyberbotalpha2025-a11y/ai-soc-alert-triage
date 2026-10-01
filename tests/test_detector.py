import pandas as pd

from src.detector import (
    detect_brute_force,
    detect_success_after_failures
)


def test_brute_force_detection():
    data = [
        {
            "timestamp": "2026-09-27 01:10:22",
            "user": "john",
            "source_ip": "185.220.101.12",
            "event_type": "login",
            "status": "failed"
        },
        {
            "timestamp": "2026-09-27 01:10:25",
            "user": "john",
            "source_ip": "185.220.101.12",
            "event_type": "login",
            "status": "failed"
        },
        {
            "timestamp": "2026-09-27 01:10:28",
            "user": "john",
            "source_ip": "185.220.101.12",
            "event_type": "login",
            "status": "failed"
        },
        {
            "timestamp": "2026-09-27 01:10:31",
            "user": "john",
            "source_ip": "185.220.101.12",
            "event_type": "login",
            "status": "failed"
        },
        {
            "timestamp": "2026-09-27 01:10:35",
            "user": "john",
            "source_ip": "185.220.101.12",
            "event_type": "login",
            "status": "failed"
        }
    ]

    df = pd.DataFrame(data)

    alerts = detect_brute_force(df)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "185.220.101.12"
    assert alerts[0]["failed_attempts"] == 5


def test_account_compromise_detection():
    data = [
        {
            "timestamp": "2026-09-27 01:10:22",
            "user": "john",
            "source_ip": "185.220.101.12",
            "event_type": "login",
            "status": "failed"
        },
        {
            "timestamp": "2026-09-27 01:10:25",
            "user": "john",
            "source_ip": "185.220.101.12",
            "event_type": "login",
            "status": "failed"
        },
        {
            "timestamp": "2026-09-27 01:10:28",
            "user": "john",
            "source_ip": "185.220.101.12",
            "event_type": "login",
            "status": "failed"
        },
        {
            "timestamp": "2026-09-27 01:11:02",
            "user": "john",
            "source_ip": "185.220.101.12",
            "event_type": "login",
            "status": "success"
        }
    ]

    df = pd.DataFrame(data)

    alerts = detect_success_after_failures(df)

    assert len(alerts) == 1
    assert alerts[0]["user"] == "john"
    assert alerts[0]["source_ip"] == "185.220.101.12"
    assert alerts[0]["failed_attempts"] == 3
