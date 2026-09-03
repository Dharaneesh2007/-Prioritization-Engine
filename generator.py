import random
from datetime import datetime, timedelta
import uuid
from typing import List
from models import Incident, Level, Importance, Sensitivity, IncidentStatus, AuditLog
import scoring

ALERT_TEMPLATES = [
    {
        "type": "Data Exfiltration",
        "title": "Active Data Exfiltration on Oracle Financial Ledger Database",
        "severity": Level.HIGH,
        "asset_importance": Importance.CRITICAL,
        "asset_category": "database",
        "target_asset": "Finance Database Cluster (Oracle-RAC-01)",
        "source_ip": "185.73.22.91",
        "data_sensitivity": Sensitivity.RESTRICTED,
        "affected_users_range": (80, 250),
        "confidence_range": (0.92, 0.98),
        "business_impact_range": (9.0, 9.8),
        "mitre_technique": "T1041"
    },
    {
        "type": "Brute Force",
        "title": "High Frequency SSH Password Guessing on Dev Sandbox",
        "severity": Level.CRITICAL,
        "asset_importance": Importance.STANDARD,
        "asset_category": "cloud",
        "target_asset": "Dev Sandbox VM-09 (Ephemeral Lab)",
        "source_ip": "194.26.29.112",
        "data_sensitivity": Sensitivity.PUBLIC,
        "affected_users_range": (1, 1),
        "confidence_range": (0.55, 0.65),
        "business_impact_range": (1.5, 2.5),
        "mitre_technique": "T1110"
    },
    {
        "type": "Ransomware",
        "title": "Rapid File Encryption and Shadow Copy Deletion on Payment Core",
        "severity": Level.CRITICAL,
        "asset_importance": Importance.CRITICAL,
        "asset_category": "cloud",
        "target_asset": "Payment Gateway Core API",
        "source_ip": "45.154.255.87",
        "data_sensitivity": Sensitivity.RESTRICTED,
        "affected_users_range": (400, 1200),
        "confidence_range": (0.92, 0.99),
        "business_impact_range": (9.5, 10.0),
        "mitre_technique": "T1486"
    },
    {
        "type": "Privilege Escalation",
        "title": "Uncorrelated Global Administrator Role Assigned via Stolen Token",
        "severity": Level.HIGH,
        "asset_importance": Importance.CRITICAL,
        "asset_category": "cloud",
        "target_asset": "Identity Provider (Okta / Entra AD)",
        "source_ip": "91.240.118.15",
        "data_sensitivity": Sensitivity.RESTRICTED,
        "affected_users_range": (300, 950),
        "confidence_range": (0.88, 0.96),
        "business_impact_range": (8.5, 9.5),
        "mitre_technique": "T1078"
    },
    {
        "type": "Command & Control",
        "title": "Cobalt Strike HTTPS Beaconing on Production Kubernetes Node",
        "severity": Level.HIGH,
        "asset_importance": Importance.SENSITIVE,
        "asset_category": "cloud",
        "target_asset": "Customer Portal Kubernetes Node (k8s-worker-12)",
        "source_ip": "185.220.101.5",
        "data_sensitivity": Sensitivity.CONFIDENTIAL,
        "affected_users_range": (150, 450),
        "confidence_range": (0.85, 0.93),
        "business_impact_range": (7.0, 8.5),
        "mitre_technique": "T1071"
    },
    {
        "type": "SQL Injection",
        "title": "Boolean-Based Blind SQL Injection Exploiting Billing Invoice Parameter",
        "severity": Level.MEDIUM,
        "asset_importance": Importance.SENSITIVE,
        "asset_category": "database",
        "target_asset": "Legacy Customer Billing Portal",
        "source_ip": "103.145.13.88",
        "data_sensitivity": Sensitivity.CONFIDENTIAL,
        "affected_users_range": (40, 180),
        "confidence_range": (0.89, 0.97),
        "business_impact_range": (6.5, 8.0),
        "mitre_technique": "T1190"
    },
    {
        "type": "Insider Threat",
        "title": "Bulk Repository Download During Employee Resignation Period",
        "severity": Level.HIGH,
        "asset_importance": Importance.CRITICAL,
        "asset_category": "workstation",
        "target_asset": "R&D Intellectual Property Repo (git-core-01)",
        "source_ip": "10.240.12.84",
        "data_sensitivity": Sensitivity.RESTRICTED,
        "affected_users_range": (15, 60),
        "confidence_range": (0.82, 0.91),
        "business_impact_range": (8.0, 9.2),
        "mitre_technique": "T1567"
    },
    {
        "type": "Credential Theft",
        "title": "LSASS Memory Dumping Mimikatz Process Access on Primary Domain Controller",
        "severity": Level.HIGH,
        "asset_importance": Importance.CRITICAL,
        "asset_category": "endpoint",
        "target_asset": "Primary Domain Controller (AD-DC-01)",
        "source_ip": "172.16.89.14",
        "data_sensitivity": Sensitivity.RESTRICTED,
        "affected_users_range": (200, 800),
        "confidence_range": (0.87, 0.95),
        "business_impact_range": (8.8, 9.6),
        "mitre_technique": "T1003"
    },
    {
        "type": "Cloud Exposure",
        "title": "Anonymous Public Read Policy Applied to Analytics Data Lake Bucket",
        "severity": Level.MEDIUM,
        "asset_importance": Importance.SENSITIVE,
        "asset_category": "cloud",
        "target_asset": "Customer Analytics S3 Lake (s3-analytics-prod)",
        "source_ip": "195.123.245.9",
        "data_sensitivity": Sensitivity.CONFIDENTIAL,
        "affected_users_range": (50, 200),
        "confidence_range": (0.90, 0.98),
        "business_impact_range": (5.0, 6.5),
        "mitre_technique": "T1530"
    },
    {
        "type": "Zero-Day Exploit",
        "title": "Unauthenticated Pre-Auth Remote Code Execution on Edge VPN Concentrator",
        "severity": Level.CRITICAL,
        "asset_importance": Importance.CRITICAL,
        "asset_category": "network",
        "target_asset": "Edge VPN Gateway Concentrator (vpn-gw-01)",
        "source_ip": "185.196.8.44",
        "data_sensitivity": Sensitivity.RESTRICTED,
        "affected_users_range": (500, 1500),
        "confidence_range": (0.91, 0.98),
        "business_impact_range": (9.2, 10.0),
        "mitre_technique": "T1190"
    },
    {
        "type": "Phishing",
        "title": "Dynamic QR Code Spearphishing Ingress targeting Executive Mailbox",
        "severity": Level.MEDIUM,
        "asset_importance": Importance.STANDARD,
        "asset_category": "endpoint",
        "target_asset": "Executive Email Gateway (mail-edge-03)",
        "source_ip": "203.0.113.195",
        "data_sensitivity": Sensitivity.CONFIDENTIAL,
        "affected_users_range": (5, 20),
        "confidence_range": (0.78, 0.88),
        "business_impact_range": (4.5, 6.0),
        "mitre_technique": "T1566"
    },
    {
        "type": "Kerberoasting",
        "title": "Spike in Weak RC4 Ticket Granting Service Requests for Service SPNs",
        "severity": Level.MEDIUM,
        "asset_importance": Importance.SENSITIVE,
        "asset_category": "database",
        "target_asset": "SQL Cluster Service SPNs (sql-cluster-a)",
        "source_ip": "10.100.4.19",
        "data_sensitivity": Sensitivity.CONFIDENTIAL,
        "affected_users_range": (30, 90),
        "confidence_range": (0.84, 0.92),
        "business_impact_range": (5.5, 7.0),
        "mitre_technique": "T1558"
    },
    {
        "type": "Port Scan",
        "title": "High Frequency SYN Sweep across Guest Subnet",
        "severity": Level.LOW,
        "asset_importance": Importance.STANDARD,
        "asset_category": "network",
        "target_asset": "Guest Wi-Fi Subnet Gateway",
        "source_ip": "192.168.40.120",
        "data_sensitivity": Sensitivity.PUBLIC,
        "affected_users_range": (1, 2),
        "confidence_range": (0.70, 0.85),
        "business_impact_range": (1.0, 2.0),
        "mitre_technique": "T1046"
    },
    {
        "type": "Suspicious Login",
        "title": "Anomalous Geo-Location Authentication on Staging WordPress CMS",
        "severity": Level.LOW,
        "asset_importance": Importance.STANDARD,
        "asset_category": "cloud",
        "target_asset": "Marketing Blog CMS Server",
        "source_ip": "198.51.100.42",
        "data_sensitivity": Sensitivity.PUBLIC,
        "affected_users_range": (1, 3),
        "confidence_range": (0.40, 0.55),
        "business_impact_range": (1.0, 2.0),
        "mitre_technique": "T1078"
    },
    {
        "type": "Lateral Movement",
        "title": "Remote Service Spawn via SMB Admin Share on Enterprise SAP ERP",
        "severity": Level.HIGH,
        "asset_importance": Importance.CRITICAL,
        "asset_category": "database",
        "target_asset": "Enterprise SAP ERP Production Core",
        "source_ip": "144.76.136.153",
        "data_sensitivity": Sensitivity.RESTRICTED,
        "affected_users_range": (120, 380),
        "confidence_range": (0.89, 0.96),
        "business_impact_range": (8.5, 9.5),
        "mitre_technique": "T1021"
    },
    {
        "type": "API Token Abuse",
        "title": "Mass GraphQL Customer Introspection using Leaked Bearer Token",
        "severity": Level.HIGH,
        "asset_importance": Importance.SENSITIVE,
        "asset_category": "cloud",
        "target_asset": "Microservices Mesh API Gateway",
        "source_ip": "185.73.22.91",
        "data_sensitivity": Sensitivity.CONFIDENTIAL,
        "affected_users_range": (75, 220),
        "confidence_range": (0.86, 0.94),
        "business_impact_range": (7.0, 8.5),
        "mitre_technique": "T1528"
    }
]

SOURCE_IPS_POOL = [
    "185.73.22.91", "194.26.29.112", "45.154.255.87", "91.240.118.15",
    "103.145.13.88", "193.106.191.24", "185.220.101.5", "195.123.245.9",
    "10.240.12.84", "172.16.89.14", "10.100.4.19", "192.168.40.120",
    "185.196.8.44", "203.0.113.195", "198.51.100.42", "144.76.136.153"
]

ANALYSTS_POOL = [
    "Sarah Vance (Senior Analyst)",
    "Marcus Cole (Tier 2 SOC)",
    "Elena Rostova (Lead Handler)",
    "David Kim (Threat Hunter)"
]

def generate_100_shift_incidents(db) -> int:
    """
    Purges existing incidents and populates exactly 100 realistic alerts
    featuring the two showcase anchors and realistic threat distributions.
    """
    db.query(AuditLog).delete()
    db.query(Incident).delete()
    db.commit()

    now = datetime.now()
    created_incidents = []

    # 1. Showcase Anchor #1: Crown Jewel High-Severity Exfiltration (Rank #1)
    inc_1 = Incident(
        id="INC-1042",
        title="Active Data Exfiltration on Oracle Financial Ledger Database",
        severity=Level.HIGH,
        asset_importance=Importance.CRITICAL,
        affected_users=142,
        data_sensitivity=Sensitivity.RESTRICTED,
        attack_confidence=0.96,
        business_impact=9.8,
        status=IncidentStatus.INVESTIGATING,
        assigned_to="Sarah Vance (Senior Analyst)",
        timestamp=now - timedelta(minutes=12),
        mitre_technique="T1041",
        source_ip="185.73.22.91",
        target_asset="Finance Database Cluster (Oracle-RAC-01)",
        asset_category="database"
    )
    db.add(inc_1)
    created_incidents.append(inc_1)

    # 2. Showcase Anchor #2: Loud Sandbox Critical Alert (Loud Alert, Low Actual Risk)
    inc_2 = Incident(
        id="INC-1018",
        title="High Frequency SSH Password Guessing on Dev Sandbox",
        severity=Level.CRITICAL,
        asset_importance=Importance.STANDARD,
        affected_users=1,
        data_sensitivity=Sensitivity.PUBLIC,
        attack_confidence=0.60,
        business_impact=2.0,
        status=IncidentStatus.NEW,
        assigned_to=None,
        timestamp=now - timedelta(minutes=8),
        mitre_technique="T1110",
        source_ip="194.26.29.112",
        target_asset="Dev Sandbox VM-09 (Ephemeral Lab)",
        asset_category="cloud"
    )
    db.add(inc_2)
    created_incidents.append(inc_2)

    # 3. Generate remaining 98 alerts
    id_counter = 1001
    while len(created_incidents) < 100:
        if id_counter == 1042 or id_counter == 1018:
            id_counter += 1
            continue

        tpl = random.choice(ALERT_TEMPLATES)
        minutes_ago = random.randint(5, 720)
        users = random.randint(tpl["affected_users_range"][0], tpl["affected_users_range"][1])
        conf = round(random.uniform(tpl["confidence_range"][0], tpl["confidence_range"][1]), 2)
        impact = round(random.uniform(tpl["business_impact_range"][0], tpl["business_impact_range"][1]), 1)
        
        status_choice = random.choices(
            [IncidentStatus.NEW, IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED],
            weights=[0.65, 0.25, 0.10],
            k=1
        )[0]
        assignee = random.choice(ANALYSTS_POOL) if status_choice != IncidentStatus.NEW else None

        inc = Incident(
            id=f"INC-{id_counter}",
            title=tpl["title"],
            severity=tpl["severity"],
            asset_importance=tpl["asset_importance"],
            affected_users=users,
            data_sensitivity=tpl["data_sensitivity"],
            attack_confidence=conf,
            business_impact=impact,
            status=status_choice,
            assigned_to=assignee,
            timestamp=now - timedelta(minutes=minutes_ago),
            mitre_technique=tpl["mitre_technique"],
            source_ip=random.choice(SOURCE_IPS_POOL),
            target_asset=tpl["target_asset"],
            asset_category=tpl["asset_category"]
        )
        db.add(inc)
        created_incidents.append(inc)
        id_counter += 1

    db.commit()

    # Add initial audit log for each
    for inc in created_incidents:
        log = AuditLog(
            incident_id=inc.id,
            timestamp=inc.timestamp,
            action=f"Alert ingested into Priority Queue (Severity: {inc.severity.value}, Category: {inc.asset_category})",
            user="Detection Engine"
        )
        db.add(log)
    db.commit()

    return len(created_incidents)
