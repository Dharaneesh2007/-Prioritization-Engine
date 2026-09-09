# 🛡️ Cyber SOC Command Center & Multi-Factor Incident Prioritization Engine

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688.svg)](https://fastapi.tiangolo.com)
[![Three.js](https://img.shields.io/badge/Three.js-r128-black.svg)](https://threejs.org/)
[![TailwindCSS](https://img.shields.io/badge/Tailwind-3.0-38bdf8.svg)](https://tailwindcss.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An enterprise-grade **Cyber Incident Prioritization & SOC Command Center** engineered to eliminate alert fatigue. The platform evaluates multi-dimensional risk—combining technical vulnerability severity, asset criticality, identity blast radius, data sensitivity, attack confidence, and operational downtime—to ensure security analysts investigate the most damaging threats first.

---

## 📑 Table of Contents
- [Executive Overview](#-executive-overview)
- [Architectural Philosophy: "Severity ≠ Priority"](#-architectural-philosophy-severity--priority)
- [Mathematical Scoring Model](#-mathematical-scoring-model)
- [Key Features & Intelligence Views](#-key-features--intelligence-views)
- [3D WebGL Threat Visualizations](#-3d-webgl-threat-visualizations)
- [SOC Knowledge Base & SOPs](#-soc-knowledge-base--sops)
- [Tech Stack](#-tech-stack)
- [Quickstart & Local Installation](#-quickstart--local-installation)
- [Default Operator Credentials](#-default-operator-credentials)
- [Vercel Cloud Deployment](#-vercel-cloud-deployment)
- [REST API Reference](#-rest-api-reference)

---

## 🎯 Executive Overview

> **"Severity tells you how bad an alert looks. Priority tells you what the organization should act on first."**

Modern Security Operations Centers ingest upwards of 10,000 alerts daily. Traditional SIEMs sort incidents purely by raw vendor severity (**Critical / High / Medium / Low**), resulting in:
1. **Critical Noise Masking Real Threats**: High-volume brute-force attacks on isolated test sandboxes drown out subtle exfiltration on crown-jewel databases.
2. **SLA Breaches on High-Blast-Radius Incidents**: Broad-identity credential compromises are neglected due to medium initial classification.
3. **Analyst Burnout & Inconsistent Triage**: Manual heuristic guesswork without standardized mathematical justification.

This engine solves these challenges by computing a **deterministic 0–10 Composite Priority Score** for every alert and auto-generating natural language explainability verdicts.


---

## 💡 Architectural Philosophy: "Severity ≠ Priority"

| Scenario | Raw Vendor Severity | Target Asset Tier | Sensitive Data | True Business Risk | Multi-Factor Rank |
|---|---|---|---|---|---|
| **Incident A (`INC-1042`)**<br>*Database Exfiltration* | **HIGH** | **Tier 1 (Crown Jewel)**<br>*Oracle Finance RAC* | **RESTRICTED**<br>*(PII / Financial Records)* | **Catastrophic** (Regulatory fines, irreparable brand loss) | 🥇 **Rank #1** *(Score: 9.85/10)* |
| **Incident B (`INC-1018`)**<br>*SSH Password Guessing* | **CRITICAL** | **Tier 4 (Ephemeral Lab)**<br>*Dev Sandbox VM-09* | **PUBLIC**<br>*(Test Mock Data)* | **Negligible** (Isolated sandbox, no crown-jewel pivot) | 🔻 **Rank #92** *(Score: 4.10/10)* |

---

## 📐 Mathematical Scoring Model

The composite priority score $S \in [0.0, 10.0]$ is calculated as a weighted normalized summation across 6 orthogonal dimensions:

$$S = \sum_{i=1}^{6} w_i \cdot F_i$$

### Factor Normalization Rules ($F_i \in [0, 10]$):

1. **Technical Severity ($F_1$)** — Non-linear exponential scaling ($3^{\text{tier}-1}$):
   - `Low` $\rightarrow 1.0$ | `Medium` $\rightarrow 3.0$ | `High` $\rightarrow 6.0$ | `Critical` $\rightarrow 10.0$
2. **Asset Importance ($F_2$)**:
   - `Standard` $\rightarrow 2.5$ | `Sensitive` $\rightarrow 5.0$ | `Critical (Crown Jewel)` $\rightarrow 10.0$
3. **Affected User Blast Radius ($F_3$)** — Logarithmic population scale:
   - $F_3 = \min\left(10.0, \, \frac{\log_{10}(U + 1)}{\log_{10}(1001)} \times 10\right)$
4. **Data Classification ($F_4$)**:
   - `Public` $\rightarrow 1.0$ | `Internal` $\rightarrow 4.0$ | `Confidential` $\rightarrow 7.0$ | `Restricted (PCI/GDPR)` $\rightarrow 10.0$
5. **Attack Confidence ($F_5$)**:
   - Normalized directly from analyst verification $[0.0, 1.0] \rightarrow [0.0, 10.0]$
6. **Business Impact ($F_6$)**:
   - Direct business operational impact scale $[0.0, 10.0]$

### ⚖️ 1-Click Weighting Strategy Presets:

| Preset Profile | Severity ($w_1$) | Asset ($w_2$) | Users ($w_3$) | Data ($w_4$) | Confidence ($w_5$) | Impact ($w_6$) | Strategic Focus |
|---|---|---|---|---|---|---|---|
| **SOC Balanced Standard** | 25% | 20% | 15% | 15% | 15% | 10% | General enterprise multi-factor baseline |
| **Crown Jewel Defense** | 15% | **35%** | 5% | 20% | 10% | 15% | Critical infrastructure & tier-1 database defense |
| **Data Privacy & Exfil** | 15% | 15% | 10% | **35%** | 10% | 15% | PCI-DSS, HIPAA, GDPR regulatory risk focus |
| **Confirmed Threat Hunting** | 20% | 15% | 5% | 10% | **35%** | 15% | Prioritizes verified IoC & signature detections |
| **Business Continuity** | 15% | 20% | 20% | 10% | 10% | **25%** | Maximizes uptime, customer portals, & SLA safety |

### 🎯 Deterministic Tie-Breaking Protocol:
If two alerts have identical priority scores, ties are resolved deterministically using:
$$\text{Attack Confidence} \longrightarrow \text{Asset Importance} \longrightarrow \text{Ingest Timestamp (FIFO)}$$

---

## 🚀 Key Features & Intelligence Views

- **Interactive Priority Queue**: Real-time sorted incident backlog with dynamic SLA breach countdowns, rank delta indicators, and status filters.
- **Pairwise Incident Comparison & Justifier**: Side-by-side comparative radar and factor breakdown explaining exactly why Alert A outranks Alert B.
- **Incident Detail & Playbook Checklist**: Dynamic MITRE ATT&CK technique tags, affected IP indicators, and step-by-step interactive response runbooks with progress tracking.
- **Campaign Graph Correlation**: Automatically clusters related alerts sharing source IPs, target subnets, or attack techniques into correlated Campaign Clusters.
- **Multi-Factor Scoring Profile Editor**: Fine-tune profile weights with real-time normalization enforcement and 1-click strategy presets.
- **Enterprise SIEM Webhook Dispatcher**: Configurable HTTP webhook alerts for `incident.created`, `incident.critical`, and `incident.status_changed` events.
- **Audit Logging & SOC Compliance**: Granular audit log tracking every lifecycle change, status transition, and operator intervention.

---

## 🌐 3D WebGL Threat Visualizations

Built with **Three.js (WebGL)** for immersive, GPU-accelerated spatial threat analysis:

1. **3D Asset Topology Map (`#assets`)**: Visualizes enterprise network architecture from Tier 1 Core Database Vaults down to perimeter DMZ nodes, with interactive orbit controls and raycasting node inspection.
2. **3D Identity Blast Radius Network (`#user-impact`)**: Visualizes identity contagion across 4 concentric population orbital rings (*Mass >500*, *Broad 100–499*, *Team 10–99*, *Isolated <10*).
3. **3D Vertical Severity Elevation Tiers (`#severity`)**: Multi-tiered hovering disc planes illustrating events elevated by technical severity versus true risk scores.

---

## 📚 SOC Knowledge Base & SOPs

Embedded documentation library rendered in GitHub-flavored Markdown:
- `DOC-PRIORITIZATION-FRAMEWORK`: Mathematical Prioritization Foundation & Non-Linear Gravity Model
- `DOC-DIMENSION-DATA-SENSITIVITY`: Data Classification & Regulatory Exposure Matrix (*PCI-DSS, HIPAA, GDPR*)
- `DOC-PLAYBOOK-RANSOMWARE`: Fast-Moving Ransomware & Lateral Propagation Containment SOP
- `DOC-MITRE-ATTACK-ALIGNMENT`: MITRE ATT&CK Matrix Cross-Reference Guide
- `DOC-ASSET-INVENTORY-TIERS`: Enterprise CMDB Hierarchy & Crown Jewel Register
- `DOC-ANALYST-TRIAGE-WORKFLOW`: SOC Analyst Daily Shift Standard Operating Procedure

---

## 🛠️ Tech Stack

- **Backend**: Python 3.10+, FastAPI, SQLAlchemy, SQLite, Pydantic, Uvicorn
- **Frontend**: HTML5, Vanilla JavaScript (ES6+ Modules), TailwindCSS, Three.js (r128), Marked.js, Chart.js
- **Security & Auth**: PBKDF2 Password Hashing, Session Management, RBAC (Admin / Analyst), Audit Logging
- **Deployment**: Vercel Serverless Python Runtime (`vercel.json`) & Docker / Linux / Windows Native

---

## ⚡ Quickstart & Local Installation

### Prerequisites
- Python 3.10 or higher installed
- Git

### 1. Clone & Setup Workspace
```bash
git clone https://github.com/Dharaneesh2007/-Prioritization-Engine.git
cd -Prioritization-Engine
```

### 2. Create Virtual Environment & Install Dependencies
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux / macOS:
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### 3. Launch the SOC Command Center
```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

### 4. Open in Browser
Open your browser and navigate to:
👉 **`http://127.0.0.1:8000`**

---

## 🔑 Default Operator Credentials

| Role | Username / Email | Password | Access Privileges |
|---|---|---|---|
| **SOC Administrator** | `admin@soccommand.local` | `AdminSOC#2026!` | Full access (Weight configs, User management, Webhooks, Triage) |
| **SOC Tier-2 Analyst** | `analyst@soccommand.local` | `AnalystSOC#2026!` | Triage, Incident lifecycle, Playbook execution, Compare |

---

## ☁️ Vercel Cloud Deployment

The repository includes a production-ready `vercel.json` configured for Vercel's Python Serverless Runtime:

```json
{
  "rewrites": [
    { "source": "/api/:match*", "destination": "/api/index.py" },
    { "source": "/docs", "destination": "/api/index.py" },
    { "source": "/openapi.json", "destination": "/api/index.py" },
    { "source": "/", "destination": "/static/index.html" }
  ]
}
```

### Deploy in 1-Click:
1. Push this repository to GitHub.
2. In [Vercel Dashboard](https://vercel.com/new), select **Import Git Repository**.
3. Select Application Preset: **FastAPI** (or **Other**).
4. Click **Deploy**.

---

## 📡 REST API Reference

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `POST` | `/api/auth/login` | Authenticate operator & create session | No |
| `GET` | `/api/incidents` | List prioritized incidents (supports `status`, `severity`, `q` filters) | Yes |
| `GET` | `/api/incidents/{id}` | Retrieve incident detail, score breakdown, & audit log | Yes |
| `POST` | `/api/incidents` | Ingest new security alert into priority queue | Yes |
| `PATCH` | `/api/incidents/{id}/status` | Update incident lifecycle state & assignee | Yes |
| `POST` | `/api/incidents/generate-shift-batch` | Ingest 100 realistic shift incidents with benchmark anchors | Yes |
| `GET` | `/api/weights/presets` | Retrieve standardized 5 multi-factor weight presets | Yes |
| `GET` | `/api/knowledge-docs` | Retrieve all 6 SOC architecture & SOP Markdown docs | No / Optional |
| `GET` | `/api/analytics/summary` | Retrieve MTTR, TTI, MITRE distribution, & score histograms | Yes |
| `GET` | `/api/incidents/export` | Export prioritized queue to CSV | Yes |
| `GET` | `/docs` | Interactive Swagger / OpenAPI documentation | No |

---

## 📄 License
This project is open-source and licensed under the **MIT License**.
