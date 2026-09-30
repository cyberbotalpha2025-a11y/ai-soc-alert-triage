import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen3:4b"


def analyze_alert(alert, threat_intel):
    """
    Analyze a security alert using a locally hosted LLM.
    """

    prompt = f"""
You are a Tier-1 SOC analyst assistant.

Analyze ONLY the evidence provided below.

SECURITY ALERT:
{alert}

THREAT INTELLIGENCE:
{threat_intel}

Give a concise response using exactly these sections:

INCIDENT SUMMARY:
2-3 sentences.

SEVERITY:
Explain the severity using the evidence.

KEY EVIDENCE:
Give the 3 most important pieces of evidence.

MITRE ATT&CK:
Give the technique provided in the alert.

INVESTIGATION:
Give 3 practical investigation steps.

CONTAINMENT:
Give 1-2 possible containment actions.
Phrase them as recommendations for SOC analyst validation.
Do not instruct the analyst to immediately block, disable, or lock anything.
Do not invent durations or organizational policies.

Rules:
- Do not invent facts.
- Do not treat threat intelligence as proof that the current event is malicious.
- Distinguish historical reputation from evidence of the current event.
- Do not claim that an account is compromised unless the provided evidence proves it.
- Do not interpret, compare, or judge timestamps as current, past, or future.
- Treat threat-intelligence timestamps as historical metadata only.
- Do not describe an IP as currently malicious based only on historical reputation.
- Use cautious language such as "possible brute-force activity" when describing the detected behavior.
- Do not claim active compromise unless the alert evidence explicitly demonstrates successful unauthorized access.
- Do not make autonomous response decisions.
- Containment actions must be recommendations for analyst validation.
- The SOC analyst makes the final decision.
"""

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(
            OLLAMA_URL,
            json=payload,
            timeout=180
        )

        response.raise_for_status()

        result = response.json()

        return result["response"]

    except requests.RequestException as error:
        return f"Ollama request failed: {error}"
