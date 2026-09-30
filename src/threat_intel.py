import os
import requests
from dotenv import load_dotenv


load_dotenv()


def check_ip_reputation(ip):
    """
    Check an IP address using AbuseIPDB.
    """

    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return {
            "error": "ABUSEIPDB_API_KEY is not configured"
        }

    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=10
        )

        response.raise_for_status()

        data = response.json()["data"]

        return {
            "ip": data.get("ipAddress"),
            "is_public": data.get("isPublic"),
            "abuse_confidence_score": data.get(
                "abuseConfidenceScore"
            ),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt")
        }

    except requests.RequestException as error:
        return {
            "error": str(error)
        }