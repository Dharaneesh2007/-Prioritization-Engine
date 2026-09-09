# SOC COMMAND CENTER — Official User & Operator Manual
**Version 3.0 — Advanced Enterprise Cyber Incident Prioritization Platform**

---

## 1. System Overview & Getting Started

### 1.1 Mission
The **SOC COMMAND CENTER** is a security operations platform engineered to solve alert fatigue. It mathematically normalizes, weights, correlates, and ranks incoming cyber security incidents so SecOps analysts always investigate the highest-impact threats first.

### 1.2 Authentication & Role-Based Access Control (RBAC)
The application enforces strict session-based authentication with secure HTTP-only cookies and two operator tiers:

| Role | Permissions & Scope | Accessible Views |
| :--- | :--- | :--- |
| **Analyst** | View queue, enqueue alerts, investigate incidents, execute response playbooks, resolve threats, run comparisons, and view analytics. | Dashboard, Enqueue Alert, Incident Detail, Compare / Justify, Analytics, Incident Log |
| **Admin** | Full system access + scoring weight tuning, creating asset category profiles, registering outbound HMAC webhooks, and provisioning operator accounts. | All 9 Command Views (including Scoring Profiles, Integrations, Manage Users) |

#### Default Bootstrap Credentials:
- **Admin Account**: `admin@soccommand.local` | Password: `AdminSOC#2026!`
- **Analyst Account**: `analyst@soccommand.local` | Password: `AnalystSOC#2026!`

---

## 2. Command Views & Feature Guide

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SOC COMMAND CENTER VIEWS                        │
├───────────────────┬───────────────────────────────┬────────────────────┤
│ 1. Dashboard      │ 4. Compare / Justify          │ 7. Incident Log    │
│ 2. Enqueue Alert  │ 5. Scoring Profiles (Admin)   │ 8. Integrations    │
│ 3. Incident Detail│ 6. Intelligence Analytics     │ 9. Users (Admin)   │
└───────────────────┴───────────────────────────────┴────────────────────┘
```

---

### View 1: Dashboard (`#dashboard`)

The primary situational awareness hub for active threats.

1. **Top KPI Stat Strip**:
   - **Total Active Incidents**: Number of open incidents currently in the live queue.
   - **Critical Threat Count**: High-priority alarms requiring immediate remediation.
   - **Avg Priority Score**: Real-time average score (0.0 to 10.0 scale) across active alerts.
   - **Alerts Ingested (24h)**: Ingestion velocity over the last 24 hours.
2. **SLA Response Watch Banner**:
   - Monitors all `Critical` incidents in `New` status.
   - If an unassigned critical alert remains uninvestigated for **>15 minutes**, a pulsating red warning banner appears (`⚠️ SLA BREACH`).
   - Tracks **Avg Time-to-Investigate (TTI)** and **Avg Time-to-Resolve (TTR)** in real-time.
3. **"Investigate Next" Callout**:
   - Prominently displays the #1 ranked threat in the queue along with an automated rationale (e.g. *"Top priority due to Severity (Critical) and Asset Importance (Critical)"*).
   - Click **"Investigate Now"** to jump straight into the incident detail view.
4. **Live Priority Queue**:
   - Dynamically sorted incident cards with rank badges (`#1`, `#2`, ...), severity chips, MITRE ATT&CK badges, source IPs, and target assets.
   - **Campaign Badge (`🔗 Part of Campaign`)**: Displayed on incidents identified by the correlation engine as part of a multi-stage attack. Clicking the badge opens the Campaign Cluster Inspection Modal.
   - **Quick Filters**: Filter the live queue by `All`, `Critical`, `High`, `Investigating`, or `Resolved`.

---

### View 2: Enqueue Cyber Threat Alert (`#enqueue`)

Ingest manual or automated security telemetry and calculate immediate prioritization scores.

1. **Preset Loaders**:
   - Click one of the quick preset buttons (**Ransomware DC**, **SQLi Gateway**, **Phishing Exec**, **S3 Exposure**) to instantly populate realistic threat telemetry.
2. **Core Attributes**:
   - **Incident Title**: Descriptive alarm name.
   - **MITRE ATT&CK Technique**: Searchable dropdown mapping techniques (e.g. `T1486: Data Encrypted for Impact`, `T1190: Exploit Public-Facing Application`).
   - **Asset Category Profile**: Select the infrastructure profile (**Default**, **Database Servers**, **Endpoints & Workstations**, **Cloud Infrastructure**, **Network Gateways**).
   - **Source IP & Target Asset**: Correlation indicators (e.g. `198.51.100.42`, `dc01.corp.internal`).
3. **Scoring Dimensions**:
   - **Severity Level**: `Low` (2.5), `Medium` (5.0), `High` (7.5), `Critical` (10.0).
   - **Asset Importance**: `Standard` (3.0), `Sensitive` (6.0), `Critical` (10.0).
   - **Data Sensitivity**: `Public` (2.0), `Internal` (5.0), `Confidential` (8.0), `Restricted` (10.0).
   - **Affected Users**: Logarithmically scaled impact count ($1$ to $1,000,000+$).
   - **Attack Confidence**: Confidence slider ($0.00$ to $1.00$).
   - **Business Impact**: Financial/operational impact slider ($0.0$ to $10.0$).
4. **Inline Score Preview**:
   - Real-time score calculator and animated meter bar updating live as you adjust inputs, showing top contributing factor and weighted breakdowns.

---

### View 3: Incident Detail & Playbook Response (`#detail`)

Deep-dive investigation and incident lifecycle management.

1. **Lifecycle Management**:
   - Update status between: `New` $\rightarrow$ `Investigating` $\rightarrow$ `Resolved` $\rightarrow$ `Mitigated` $\rightarrow$ `Closed`.
   - **False Positive vs Confirmed Threat**: When setting status to `Resolved` (or `Mitigated`/`Closed`), select the **Resolution Outcome**:
     - **Confirmed Threat**: Real security incident addressed.
     - **False Positive**: Benign activity or misconfigured rule (feeds into Accuracy Analytics).
   - Assign incident to a specific operator/analyst.
2. **Campaign Correlation Panel**:
   - If the alert is linked to a campaign cluster, this panel highlights all sister alerts sharing the same IP, asset, or MITRE tactic.
3. **Interactive Remediation Runbook Checklist**:
   - Automatically selects the relevant threat response playbook (e.g. *DC Ransomware Containment Playbook*, *Web Application SQLi Runbook*).
   - Check off action items as you execute containment and eradication. Progress is auto-saved to the database in real-time.
4. **Factor Contribution Chart & Audit Timeline**:
   - Grouped bar chart showing the exact mathematical contribution of each dimension.
   - Comprehensive audit trail recording every state change, timestamp, and user.

---

### View 4: Incident Comparison & Justification Engine (`#compare`)

Evaluate and justify ranking differences between any two alerts for transparency and audits.

1. **Selector Bar**:
   - Select **Incident Alpha (A)** and **Incident Beta (B)** from the dropdown menus.
   - Click the **Swap (⇄)** button to instantly reverse comparison order.
2. **Automated Auditable Justification**:
   - Generates an explanation justifying why one incident outranks the other:
     > *"Incident 'Critical DC Ransomware Lockdown' (9.93) outranks 'Active Ransomware Exfiltration' (9.91) primarily due to Business Impact (+0.02 weighted)."*
3. **Factor Matrix Comparison Table**:
   - Row-by-row comparative breakdown displaying Factor label, Profile Weight %, Incident A raw input & contribution, Incident B raw input & contribution, and the net Delta (+/– advantage).
4. **Weighted Contribution (A vs B) Chart**:
   - Side-by-side grouped bar chart comparing the factor vectors between Incident A (blue) and Incident B (purple).

---

### View 5: Asset Category Scoring Profiles (`#weights` — Admin Only)

Calibrate factor weighting models tailored to different operational environments.

1. **Profile Tabs**:
   - Switch between infrastructure categories: **Default**, **Database Servers**, **Endpoints & Workstations**, **Cloud Infrastructure**, and **Network Gateways**.
2. **Weight Tuning Sliders**:
   - Adjust the 6 factor weights ($0\%$ to $50\%$).
   - **Live Sum Monitor**: Displays total weight sum (`100.0% [BALANCED]` in green or `[UNBALANCED]` in red).
   - **Auto-Normalize**: Click to automatically rebalance slider weights proportionally to sum to exactly $1.00$ ($100\%$).
3. **Profile Actions**:
   - **💾 Save Profile Weights**: Saves calibrated weights for the selected category.
   - **↻ Rescore Existing Incidents With This Profile**: Recalculates priority scores and re-ranks all open alerts under that category.
   - **+ Create New Profile**: Provision a new asset profile (e.g. `scada`, `iot`, `payment-gateway`).

---

### View 6: Intelligence & Accuracy Analytics (`#analytics`)

High-level threat intelligence and SOC efficiency metrics.

1. **KPI Scorecard**:
   - **Threat Accuracy Rate**: $\frac{\text{Confirmed Threats}}{\text{Confirmed Threats} + \text{False Positives}} \times 100\%$.
   - **Active Queue**: Open backlog volume.
   - **Avg TTI (Investigation Velocity)**: Mean minutes from ingestion to first analyst investigation.
   - **Avg TTR (Resolution Velocity)**: Mean minutes from ingestion to threat resolution.
2. **Analytical Charts**:
   - **Top MITRE ATT&CK Techniques**: Adversary tactic frequency bar chart.
   - **Accuracy Breakdown by Severity**: Confirmed vs False Positive distribution across Critical, High, Medium, and Low tiers.
   - **Priority Score Histogram**: Distribution bins ($0-2$, $2-4$, $4-6$, $6-8$, $8-10$).
   - **Backlog vs Resolution Velocity**: Ingestion rate vs resolution throughput over time.

---

### View 7: Incident Log & Bulk Operations (`#log`)

Historical audit table, multi-criteria filtering, and batch operations.

1. **Saved Filter Quick-Select Views**:
   - Click pre-saved or custom filter chips (e.g. `📌 Critical SLA Watch`, `📌 Investigating Queue`) to apply multi-criteria filters with one click.
   - Click **"★ Save Current View"** to save your active filter combination for future sessions.
2. **Multi-Criteria Search**:
   - Filter simultaneously by Severity, Asset Importance, Status, or search by Title, IP, Hostname, and MITRE Code.
3. **Batch Operations**:
   - Select multiple incidents using row checkboxes or the "Select All" header box.
   - The **Floating Bulk Action Bar** allows you to:
     - **Mark Investigating** (batch status update)
     - **Resolve (Confirmed Threat)**
     - **Resolve (False Positive)**
     - **Export Selected CSV**
4. **Full CSV Export**:
   - Click **"Export All CSV"** to download complete telemetry and audit logs.

---

### View 8: Outbound Webhook Integrations (`#integrations` — Admin Only)

Stream real-time incident notifications to Slack, Discord, PagerDuty, or SIEM endpoints.

1. **Register Webhook Subscription**:
   - Enter target endpoint URL (e.g. Slack webhook or custom HTTP receiver).
   - Enter description label (e.g. *SecOps On-Call Channel*).
   - Select subscribed event triggers:
     - `incident.created` (New incident ingested)
     - `incident.critical` (Critical severity alert trigger)
     - `incident.status_changed` (Status or resolution outcome updated)
2. **HMAC-SHA256 Signing Secret**:
   - Upon creation, a 32-byte secure key is generated and displayed in a modal.
   - Every outbound HTTP POST request includes the `X-SOC-Signature` header containing the HMAC-SHA256 hex digest of the payload.
3. **Test Ping & Retries**:
   - Click **"⚡ Test Ping"** on any subscription to dispatch an immediate signed test payload.
   - Outbound delivery runs asynchronously in the background with **3 exponential backoff retries**.

---

### View 9: User & Access Management (`#users` — Admin Only)

Provision and manage operator access credentials.

1. **Provision New User**:
   - Enter operator email, initial password (min. 8 characters), and assign role (`Analyst` or `Admin`).
2. **Active User Directory**:
   - Audit registered operators, assigned roles, account status, and last login timestamps.

---

## 3. Keyboard Shortcuts & Global Features

- **Global Search**: Press `/` from anywhere in the app to jump to the search bar and filter incidents by title, IP, asset, or MITRE technique.
- **Theme Toggle**: Click the 🌙 / ☀️ icon in the header to switch between Cyber Dark and Clean Light modes. Preference is saved to your browser.
- **Live UTC Clock**: Top header displays live synchronized UTC time for SecOps shifts.
- **Auto-Refresh Interval**: Choose between `Auto: 5s`, `Auto: 10s`, `Auto: 30s`, or `Auto: Off`.

---

## 4. Operational Best Practices & FAQ

> [!TIP]
> **Triage Workflow**: Always begin your shift on `#dashboard`. Check the **SLA Watch Indicator** first to ensure no Critical alarms have exceeded the 15-minute response window, then investigate the top-ranked card in the **Live Priority Queue**.

> [!IMPORTANT]
> **False Positive Handling**: Always tag benign or false alarm incidents as `False Positive` when resolving. This continuously calibrates your SOC Threat Accuracy KPI on the `#analytics` dashboard.

> [!NOTE]
> **Campaign Clustering**: When an alert displays `🔗 Part of Campaign (N related)`, investigate the primary cluster incident first, as resolving or mitigating the root asset often neutralizes lateral movement across all sister alerts.
