# backend/mitre_mapping.py

# A rule-based lookup table mapping CIC-IDS-2018 dataset labels to MITRE ATT&CK stages.
# This does not require machine learning. It just matches the predicted string.

MITRE_STAGE_MAP = {
    # Benign / Baseline
    "Benign": "Normal Traffic",

    # Reconnaissance (Scanning for vulnerabilities)
    "PortScan": "Reconnaissance",

    # Initial Access (Trying to break in)
    "FTP-BruteForce": "Initial Access",
    "SSH-Bruteforce": "Initial Access",
    "Brute Force -Web": "Initial Access",
    "Brute Force -XSS": "Initial Access",
    "SQL Injection": "Initial Access",

    # Lateral Movement / Command & Control (Operating inside the network)
    "Bot": "Command & Control",
    "Infiltration": "Lateral Movement",

    # Impact (Disrupting services)
    "DoS attacks-Hulk": "Impact",
    "DoS attacks-SlowHTTPTest": "Impact",
    "DoS attacks-GoldenEye": "Impact",
    "DoS attacks-Slowloris": "Impact",
    "DDOS attack-LOIC-UDP": "Impact",
    "DDOS attack-HOIC": "Impact"
}

def get_mitre_stage(dataset_label: str) -> str:
    """
    Given a dataset attack label (like 'PortScan'), returns the corresponding
    MITRE ATT&CK stage (like 'Reconnaissance').
    If the label is unknown, returns 'Unknown Stage'.
    """
    # Clean the string just in case it has trailing spaces from the CSV
    clean_label = dataset_label.strip()
    return MITRE_STAGE_MAP.get(clean_label, "Unknown Stage")
