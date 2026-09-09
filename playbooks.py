from typing import List, Dict, Optional
import json

PLAYBOOK_LIBRARY = {
    "RANSOMWARE": {
        "name": "Ransomware & Host Encryption Playbook",
        "description": "Critical containment and forensics workflow for active ransomware outbreaks.",
        "steps": [
            {
                "id": 1,
                "title": "Immediate Network Isolation",
                "description": "Sever affected hosts from internal networks and VLANs to halt lateral spreading."
            },
            {
                "id": 2,
                "title": "Volatile Memory (RAM) Acquisition",
                "description": "Capture live memory image prior to reboot/power down to preserve unencrypted keys."
            },
            {
                "id": 3,
                "title": "Verify Offline Backup Integrity",
                "description": "Validate that Volume Shadow Copies and offline immutable backups remain uncompromised."
            },
            {
                "id": 4,
                "title": "Identify C2 & Egress Endpoints",
                "description": "Inspect perimeter firewall and NetFlow telemetry for exfiltration staging and external IP connections."
            },
            {
                "id": 5,
                "title": "Domain Kerberos & Admin Credential Reset",
                "description": "Revoke active Kerberos TGT tickets and rotate domain administrator credentials twice."
            },
            {
                "id": 6,
                "title": "Executive & Privacy Officer Briefing",
                "description": "Deliver impact assessment report to CISO, legal counsel, and data protection officers."
            }
        ]
    },
    "SQLI": {
        "name": "Web Application SQL Injection Playbook",
        "description": "Containment and code mitigation workflow for database exploitation attempts.",
        "steps": [
            {
                "id": 1,
                "title": "WAF Mitigation & Attacker IP Block",
                "description": "Deploy immediate blocking rule for source IP on perimeter WAF / CDN."
            },
            {
                "id": 2,
                "title": "Database Query Audit Log Extraction",
                "description": "Extract raw database query logs to determine extracted tables, columns, and records."
            },
            {
                "id": 3,
                "title": "Rotate Application DB Credentials",
                "description": "Rotate database service connection passwords and invalidate active user tokens."
            },
            {
                "id": 4,
                "title": "Verify Code Parameterization",
                "description": "Verify SQL queries in the affected endpoint use prepared statements."
            },
            {
                "id": 5,
                "title": "Data Impact Assessment",
                "description": "Assess if customer PII or sensitive secrets were exfiltrated during the exploit."
            }
        ]
    },
    "PHISHING": {
        "name": "Targeted Phishing & Credential Theft Playbook",
        "description": "Rapid containment workflow for credential harvesting and token theft.",
        "steps": [
            {
                "id": 1,
                "title": "Revoke Active User Sessions & OAuth Tokens",
                "description": "Invalidate active web sessions, refresh tokens, and mobile app authorizations."
            },
            {
                "id": 2,
                "title": "Force Password Reset & Enforce MFA",
                "description": "Reset user password and enforce hardware token or authenticator app authentication."
            },
            {
                "id": 3,
                "title": "Tenant-Wide Mailbox Purge",
                "description": "Execute email compliance search to purge phishing lure messages across all mailboxes."
            },
            {
                "id": 4,
                "title": "Audit Mailbox Forwarding Rules",
                "description": "Inspect mailbox rules for hidden external forwarding or auto-deletion actions."
            },
            {
                "id": 5,
                "title": "Perimeter Domain & Sinkhole Block",
                "description": "Add malicious phishing domain and payload IP to corporate DNS firewall sinkhole."
            }
        ]
    },
    "DATA_EXFILTRATION": {
        "name": "Data Exfiltration & Cloud Storage Exposure Playbook",
        "description": "Containment workflow for unauthorized data egress and exposed cloud storage.",
        "steps": [
            {
                "id": 1,
                "title": "Enforce Restrictive Storage Bucket ACLs",
                "description": "Apply restrictive IAM policies blocking public read/write permissions on the bucket."
            },
            {
                "id": 2,
                "title": "Audit CloudTrail & Egress Logs",
                "description": "Extract storage access logs to measure total bytes egressed and identify destination IPs."
            },
            {
                "id": 3,
                "title": "Rotate IAM Access Keys",
                "description": "Immediately invalidate and regenerate IAM key pairs and temporary role sessions."
            },
            {
                "id": 4,
                "title": "Data Sensitivity Classification",
                "description": "Determine data classification level (Restricted, Confidential) of exposed records."
            },
            {
                "id": 5,
                "title": "Regulatory Notification Preparation",
                "description": "Prepare breach disclosure report if regulated consumer data was accessed."
            }
        ]
    },
    "BRUTE_FORCE": {
        "name": "Brute Force & Credential Stuffing Playbook",
        "description": "Perimeter mitigation for authentication floods and unauthorized access attempts.",
        "steps": [
            {
                "id": 1,
                "title": "Perimeter Source IP Drop",
                "description": "Add attacking source IP subnet to firewall drop list and fail2ban rules."
            },
            {
                "id": 2,
                "title": "Audit Authentication Telemetry",
                "description": "Review auth logs to verify whether any attempts successfully logged in."
            },
            {
                "id": 3,
                "title": "Enforce Exponential Rate Limiting",
                "description": "Verify lockout threshold is active and enforce backoff for repeated failed logins."
            },
            {
                "id": 4,
                "title": "Restrict Management Ports to VPN",
                "description": "Ensure SSH / RDP / Admin ports are restricted to internal VPN CIDR blocks only."
            }
        ]
    },
    "DEFAULT": {
        "name": "Standard Security Incident Response Playbook",
        "description": "Standard four-phase triage, containment, eradication, and recovery workflow.",
        "steps": [
            {
                "id": 1,
                "title": "Triage & Telemetry Verification",
                "description": "Confirm threat indicators against active SIEM logs and threat intelligence feeds."
            },
            {
                "id": 2,
                "title": "Endpoint & Network Containment",
                "description": "Apply network isolation and perimeter filtering to prevent spread."
            },
            {
                "id": 3,
                "title": "Artifact Eradication & Patching",
                "description": "Remove malware artifacts, terminate malicious processes, and apply patches."
            },
            {
                "id": 4,
                "title": "Post-Incident Review & Rule Tuning",
                "description": "Update detection rules, document timeline, and archive audit logs."
            }
        ]
    }
}

def get_playbook_for_incident(incident) -> Dict:
    title_lower = incident.title.lower() if incident.title else ""
    mitre = incident.mitre_technique.upper() if incident.mitre_technique else ""

    if "ransomware" in title_lower or mitre == "T1486" or "encrypt" in title_lower:
        category = "RANSOMWARE"
    elif "sql" in title_lower or mitre == "T1190" or "injection" in title_lower:
        category = "SQLI"
    elif "phish" in title_lower or mitre == "T1566" or "credential" in title_lower or "harvest" in title_lower:
        category = "PHISHING"
    elif "exfiltrat" in title_lower or mitre == "T1048" or mitre == "T1530" or "s3" in title_lower or "bucket" in title_lower:
        category = "DATA_EXFILTRATION"
    elif "brute" in title_lower or mitre == "T1110" or "ssh" in title_lower or "login spike" in title_lower:
        category = "BRUTE_FORCE"
    else:
        category = "DEFAULT"

    pb = PLAYBOOK_LIBRARY[category]
    return {
        "category": category,
        "name": pb["name"],
        "description": pb["description"],
        "steps": pb["steps"]
    }
