from typing import List, Dict

SOC_DOCUMENTS: List[Dict[str, any]] = [
    {
        "id": "DOC-PRIORITIZATION-FRAMEWORK",
        "title": "Multi-Factor Incident Prioritization Framework (Severity ≠ Priority)",
        "category": "Framework",
        "summary": "Architectural rationale explaining why raw vendor severity must be superseded by multidimensional business & technical risk.",
        "tags": ["Risk Engine", "Severity", "Scoring", "SOC Architecture", "Normalization"],
        "last_updated": "2026-09-01",
        "content": """### 1. Executive Directive: The Pitfall of "Severity = Priority"
Legacy Security Operations Centers (SOCs) fail because analysts triage alerts primarily based on vendor alert severity (*Critical*, *High*, *Medium*, *Low*). In modern distributed infrastructure:
- An isolated brute-force password guess on an unpatched sandbox development VM is assigned **Critical severity** by an automated EDR rule, even though it carries **zero production data** and **no business impact**.
- A subtle **High-severity** data staging alert on a core Oracle/PostgreSQL financial transaction cluster (*Crown Jewel*) carries immediate solvency, compliance, and regulatory catastrophic risk.

Treating the sandbox VM alert before the financial ledger represents a **critical SOC operational failure**.

### 2. Multi-Dimensional Weighted Risk Formula
Our platform evaluates every inbound alert through a 6-channel weighted mathematical vector:

$$\\text{Score} = (w_{\\text{sev}} \\times N_{\\text{sev}}) + (w_{\\text{asset}} \\times N_{\\text{asset}}) + (w_{\\text{users}} \\times N_{\\text{users}}) + (w_{\\text{data}} \\times N_{\\text{data}}) + (w_{\\text{conf}} \\times N_{\\text{conf}}) + (w_{\\text{impact}} \\times N_{\\text{impact}})$$

Where weights sum to $1.00$ (100%):
- **Severity ($w_1 = 25\\%$)**: Critical (10.0), High (7.5), Medium (5.0), Low (2.5).
- **Asset Importance ($w_2 = 20\\%$)**: Critical Crown Jewels (10.0), Sensitive Production (6.0), Standard (3.0).
- **Affected Users ($w_3 = 15\\%$)**: Logarithmic blast radius function $\\min(10.0, \\log_{10}(\\text{users} + 1) \\times 3.32)$.
- **Data Sensitivity ($w_4 = 15\\%$)**: Restricted (10.0), Confidential (8.0), Internal (5.0), Public (2.0).
- **Attack Confidence ($w_5 = 15\\%$)**: Continuous Bayesian confidence percentage (0.0 to 10.0).
- **Business Impact ($w_6 = 10\\%$)**: Evaluated revenue & operational impact scalar (0.0 to 10.0).

### 3. Deterministic Tie-Breaking Protocol
When two incidents produce identical composite risk scores, priority is deterministically resolved:
1. **Fallback 1**: Highest telemetry **Attack Confidence**.
2. **Fallback 2**: Highest normalized **Asset Importance**.
3. **Fallback 3**: Earliest chronological **Detection Ingestion Timestamp** (FIFO)."""
    },
    {
        "id": "DOC-DIMENSION-DATA-SENSITIVITY",
        "title": "Data Classification & Regulatory Exposure Matrix (PCI-DSS, HIPAA, GDPR)",
        "category": "Data Dictionary",
        "summary": "Standardized definitions for classifying compromised data vaults, regulatory exposure tiers, and risk weight modifiers.",
        "tags": ["Data Sensitivity", "PCI-DSS", "GDPR", "HIPAA", "PII", "Data Vault"],
        "last_updated": "2026-09-01",
        "content": """### 1. Classification Tiers
Data sensitivity directly modulates risk velocity. Exposure of regulated assets triggers mandatory statutory breach notification windows (e.g., 72 hours under GDPR Article 33).

- **Restricted (Score: 10.0 / 10.0)**:
  - *Included Data*: Primary payment card numbers (PANs), cryptographic root keys, HSM seed tokens, patient medical records (PHI), core intellectual property master blueprints.
  - *Mandatory Actions*: Immediate CIRT War Room mobilization; automated firewall egress blackhole; CISO notification.

- **Confidential (Score: 8.0 / 10.0)**:
  - *Included Data*: Personally Identifiable Information (PII) of customers, hashed master passwords, financial balance ledgers, payroll tables.
  - *Regulatory Frameworks*: GDPR, CCPA/CPRA, HIPAA Privacy Rule.

- **Internal (Score: 5.0 / 10.0)**:
  - *Included Data*: Internal roadmaps, unreleased vendor contracts, customer communications, employee directory metadata.

- **Public (Score: 2.0 / 10.0)**:
  - *Included Data*: Marketing collateral, open press releases, public staging websites, documentation portals."""
    },
    {
        "id": "DOC-PLAYBOOK-RANSOMWARE",
        "title": "Incident Response SOP: Fast-Moving Ransomware & Lateral Propagation",
        "category": "Playbook",
        "summary": "Tactical containment, network segmentation isolation, and forensic extraction sequence for ransomware outbreaks.",
        "tags": ["Playbook", "Ransomware", "Lateral Movement", "Containment", "CIRT", "SOP"],
        "last_updated": "2026-09-01",
        "content": """### 1. Trigger Conditions
- Rapid file entropy increases detected on network shares or local drives.
- Canary bait file modification or mass shadow copy deletion (`vssadmin delete shadows /all /quiet`).
- Automated detection rule: `RULE-RANSOM-801` or `RULE-EDR-911`.

### 2. Phase 1: Micro-Segmentation & Immediate Isolation
1. **Network Egress Block**: Push automated zero-trust host isolation through EDR API within **180 seconds** of alert prioritization.
2. **Disable Domain Admin Tokens**: Revoke all active Kerberos TGTs for compromised user credentials.
3. **Quarantine Target Hypervisors**: Isolate related VLANs (VLAN 104 Production Financial, VLAN 202 Kubernetes Node Pool).

### 3. Phase 2: Evidence Preservation & Volatile Memory Capture
- Execute remote memory snapshot via kernel memory driver before powering down nodes.
- Ingest forensic memory dump into SOC centralized sandbox for decryptor signature analysis.
- Verify immutability of cold off-site backup repositories."""
    },
    {
        "id": "DOC-MITRE-ATTACK-ALIGNMENT",
        "title": "MITRE ATT&CK Matrix Tactic & Technique Cross-Reference Guide",
        "category": "MITRE Mapping",
        "summary": "Comprehensive mapping between automated SOC detection rules, MITRE ATT&CK tactics, techniques, and risk confidence scores.",
        "tags": ["MITRE ATT&CK", "Techniques", "Tactics", "Detection Rules", "Threat Intel"],
        "last_updated": "2026-09-01",
        "content": """### 1. Ingested Techniques & Risk Weight Modifiers

| Technique ID | Name | Primary Tactic | Default Confidence | Baseline Impact |
|:---|:---|:---|:---:|:---:|
| **T1041** | Exfiltration Over C2 Channel | Exfiltration | 96% | Critical |
| **T1486** | Data Encrypted for Impact | Impact | 98% | Critical |
| **T1021** | SMB/Windows Admin Shares (PsExec) | Lateral Movement | 92% | High |
| **T1558** | Kerberoasting (TGS Request) | Credential Access | 88% | High |
| **T1110** | Password Guessing / Brute Force | Credential Access | 60% | Low |
| **T1046** | Network Service Discovery | Discovery | 75% | Low |
| **T1190** | Exploit Public-Facing Application | Initial Access | 90% | High |
| **T1566** | Spearphishing Link / QR Code | Initial Access | 82% | Medium |

### 2. Detection Rule Syntheses
- `RULE-EXFIL-901`: Real-time egress volume anomaly trigger correlating outbound TLS sessions against IP reputation and threat intelligence lists.
- `RULE-AUTH-104`: Threshold rate limiter flagging sequential authentication failures against directory infrastructure."""
    },
    {
        "id": "DOC-ASSET-INVENTORY-TIERS",
        "title": "Enterprise Asset Criticality Hierarchy & Crown Jewel Register",
        "category": "Architecture",
        "summary": "Topology classification defining Tier-1 Crown Jewels, High-Availability nodes, Corporate Workstations, and Ephemeral Lab instances.",
        "tags": ["Assets", "Crown Jewels", "Topology", "Criticality", "CMDB", "Infrastructure"],
        "last_updated": "2026-09-01",
        "content": """### 1. Criticality Tier Taxonomy
Assets are inventoried from the Configuration Management Database (CMDB) and synced in real-time with the Prioritization Engine.

- **Tier 1: Crown Jewels (Critical)**:
  - *Examples*: `Finance Database Cluster (Oracle-RAC-01)`, `Enterprise SAP ERP Production Core`, `Active Directory Root Domain Controller (AD-DC-01)`.
  - *Impact Factor*: 10.0 / 10.0
  - *Operational SLA*: 15 minutes response / 1 hour resolution.

- **Tier 2: High-Value Production Systems**:
  - *Examples*: `Customer Portal Kubernetes Node`, `Customer CRM PostgreSQL Cluster`.
  - *Impact Factor*: 7.5 / 10.0
  - *Operational SLA*: 30 minutes response.

- **Tier 3: Medium Corporate Support Systems**:
  - *Examples*: Executive email gateways, internal intranet portals, HR knowledge bases.
  - *Impact Factor*: 5.0 / 10.0
  - *Operational SLA*: 2 hours response.

- **Tier 4: Low Ephemeral / Sandbox Nodes**:
  - *Examples*: `Dev Sandbox VM-09 (Ephemeral Lab)`, `Guest Wi-Fi Subnet Gateway`.
  - *Impact Factor*: 2.0 / 10.0
  - *Operational SLA*: Next business day triage."""
    },
    {
        "id": "DOC-ANALYST-TRIAGE-WORKFLOW",
        "title": "SOC Analyst Daily Shift Protocol: Queue Ingest to Triage Resolution",
        "category": "Playbook",
        "summary": "Step-by-step procedures for SOC Tier 1/2/3 analysts handling incoming prioritized alert streams.",
        "tags": ["Analyst Workflow", "Triage", "Escalation", "SOP", "Shift Handover", "Audit Trail"],
        "last_updated": "2026-09-01",
        "content": """### 1. Shift Ingest & Queue Initialization
1. Verify synchronization with the active shift queue (100 shift security alerts).
2. Execute **100-Alert Shift Batch Generator** to ingest normalized multidimensional vectors.
3. Review alerts in the **Prioritized Queue** in strict descending order of **Prioritized Risk Score**.

### 2. Alert Investigation Workflow
- **Step 1**: Open the alert in the **Incident Detail Drawer**.
- **Step 2**: Inspect the **Score Contribution Breakdown** and the **Compare / Justify** pairwise delta analysis.
- **Step 3**: Analyze the **3D Asset Dependency Topology Map** to trace attacker ingress and target pivot nodes.
- **Step 4**: Transition alert status from `New` to `Investigating`.
- **Step 5**: Execute interactive remediation steps in the containment playbook.

### 3. CIRT Escalation Thresholds
Escalate immediately to the **Cyber Incident Response Team (CIRT)** when:
- Calculated Risk Score $\\ge 8.5$.
- Compromised asset is tagged as a **Crown Jewel**.
- Data sensitivity is evaluated as **Restricted** with active outbound exfiltration signatures."""
    }
]

def get_all_knowledge_docs() -> List[Dict[str, any]]:
    return SOC_DOCUMENTS
