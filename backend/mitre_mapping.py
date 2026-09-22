# backend/mitre_mapping.py

# A rule-based lookup table mapping CIC-IDS-2018 dataset labels to MITRE ATT&CK stages.
# This does not require machine learning. It just matches the predicted string.

MITRE_STAGE_MAP = {
    # Benign / Baseline
    "benign": "Normal Traffic",
    "Benign": "Normal Traffic",
    "normal traffic": "Normal Traffic",

    # Reconnaissance (Scanning for vulnerabilities)
    "portscan": "Reconnaissance",
    "port scan": "Reconnaissance",
    "reconnaissance": "Reconnaissance",

    # Initial Access (Trying to break in)
    "ftp-bruteforce": "Initial Access",
    "ssh-bruteforce": "Initial Access",
    "brute force -web": "Initial Access",
    "brute force -xss": "Initial Access",
    "sql injection": "Initial Access",
    "bruteforce": "Initial Access",
    "credential access / initial access": "Initial Access",
    "initial access": "Initial Access",

    # Lateral Movement (Operating inside the network)
    "infiltration": "Lateral Movement",
    "infilteration": "Lateral Movement",
    "lateral movement": "Lateral Movement",

    # Command & Control
    "bot": "Command & Control",
    "botnet": "Command & Control",
    "command & control": "Command & Control",

    # Impact (Disrupting services)
    "dos attacks-hulk": "Impact",
    "dos attacks-slowhttptest": "Impact",
    "dos attacks-goldeneye": "Impact",
    "dos attacks-slowloris": "Impact",
    "ddos attack-loic-udp": "Impact",
    "ddos attack-hoic": "Impact",
    "ddos attacks-loic-http": "Impact",
    "dos": "Impact",
    "ddos": "Impact",
    "impact": "Impact",
}

def get_mitre_stage(dataset_label: str) -> str:
    """
    Given a dataset attack label (like 'PortScan' or 'Bot') or an existing stage tag,
    returns the corresponding MITRE ATT&CK stage (like 'Reconnaissance' or 'Command & Control').
    If the label is unknown, returns 'Unknown Stage'.
    """
    if not dataset_label:
        return "Unknown Stage"
    clean_label = dataset_label.strip().lower()
    
    # Exact / normalized match
    if clean_label in MITRE_STAGE_MAP:
        return MITRE_STAGE_MAP[clean_label]

    # Partial / substring match fallback
    for key, stage in MITRE_STAGE_MAP.items():
        if key in clean_label or clean_label in key:
            return stage

    return "Unknown Stage"
