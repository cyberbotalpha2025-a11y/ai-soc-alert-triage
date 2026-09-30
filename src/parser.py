import pandas as pd


def load_logs(filepath):
    """
    Load security logs from a CSV file.
    """
    return pd.read_csv(filepath)


def get_failed_logins(df):
    """
    Return all failed login events.
    """
    return df[
        (df["event_type"] == "login") &
        (df["status"] == "failed")
    ]