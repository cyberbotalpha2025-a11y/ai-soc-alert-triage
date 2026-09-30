import re
import ipaddress


def extract_ips(text):
    """
    Extract valid IPv4 addresses from text.
    """

    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    candidates = re.findall(pattern, text)

    valid_ips = []

    for ip in candidates:
        try:
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            pass

    return valid_ips


def extract_iocs_from_alert(alert):
    """
    Extract IOCs from a security alert.
    """

    iocs = {
        "ip_addresses": []
    }

    source_ip = alert.get("source_ip")

    if source_ip:
        extracted = extract_ips(source_ip)
        iocs["ip_addresses"].extend(extracted)

    return iocs