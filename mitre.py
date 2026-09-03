from typing import Dict, List, Optional

MITRE_TECHNIQUES = {
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1486": {"name": "Data Encrypted for Impact (Ransomware)", "tactic": "Impact"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1078": {"name": "Valid Accounts / Credential Abuse", "tactic": "Defense Evasion"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1530": {"name": "Data from Cloud Storage Object", "tactic": "Collection"},
    "T1055": {"name": "Process Injection", "tactic": "Privilege Escalation"},
    "T1021": {"name": "Remote Services (RDP/SSH/SMB)", "tactic": "Lateral Movement"},
    "T1562": {"name": "Impair Defenses / Security Evasion", "tactic": "Defense Evasion"},
    "T1498": {"name": "Network Denial of Service", "tactic": "Impact"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    "T1071": {"name": "Application Layer Protocol (C2)", "tactic": "Command and Control"},
    "T1090": {"name": "Proxy / Multi-hop Proxy", "tactic": "Command and Control"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "Credential Access"},
    "T1588": {"name": "Obtain Capabilities / Cobalt Strike", "tactic": "Resource Development"},
    "T1053": {"name": "Scheduled Task / Job", "tactic": "Persistence"},
    "T1574": {"name": "Hijack Execution Flow / DLL Side-Loading", "tactic": "Persistence"},
    "T1134": {"name": "Access Token Manipulation", "tactic": "Privilege Escalation"},
    "T1070": {"name": "Indicator Removal on Host", "tactic": "Defense Evasion"},
    "T1499": {"name": "Endpoint Denial of Service", "tactic": "Impact"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": "Defense Evasion"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    "T1485": {"name": "Data Destruction", "tactic": "Impact"},
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
    "T1560": {"name": "Archive Collected Data", "tactic": "Collection"},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence"},
    "T1218": {"name": "System Binary Proxy Execution", "tactic": "Defense Evasion"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1074": {"name": "Data Staged", "tactic": "Collection"}
}

def get_mitre_name(code: Optional[str]) -> Optional[str]:
    if not code:
        return None
    cleaned = code.strip().upper()
    info = MITRE_TECHNIQUES.get(cleaned)
    if info:
        return info["name"]
    return code

def get_mitre_info(code: Optional[str]) -> Optional[Dict]:
    if not code:
        return None
    cleaned = code.strip().upper()
    info = MITRE_TECHNIQUES.get(cleaned)
    if info:
        return {
            "id": cleaned,
            "name": info["name"],
            "tactic": info["tactic"]
        }
    return {"id": code, "name": code, "tactic": "Unknown"}

def get_all_mitre_techniques() -> List[Dict]:
    return [
        {
            "id": k,
            "name": v["name"],
            "tactic": v["tactic"],
            "display": f"{k}: {v['name']} ({v['tactic']})"
        }
        for k, v in MITRE_TECHNIQUES.items()
    ]
