# Thrive Project Round 2: Cyber Incident Prioritization Engine

A professional Security Operations Center (SOC) tool designed to rank cyber security incidents based on technical severity, business impact, and systemic risk.

## 🚀 Features
- **Non-Linear Scoring**: Uses a "gravity" model (powers of 3) to ensure critical incidents aren't masked by volume.
- **Log-Scaled User Impact**: Prevents skewed results from huge user counts.
- **Deterministic Tie-Breaking**: Explicit chain based on Attack Confidence $\rightarrow$ Asset Importance $\rightarrow$ Timestamp.
- **Comparative Justifications**: Generates natural language explanations for why one alert outranks another.
- **SOC-Themed Dashboard**: Dark-mode UI with high-contrast severity indicators.

## 🛠️ Tech Stack
- **Backend**: FastAPI, Python 3.x
- **Frontend**: Tailwind CSS, Vanilla JavaScript
- **Persistence**: JSON Flat-file
- **Architecture**: REST API

## 📦 Installation & Setup
1. **Clone the project**
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the application**:
   ```bash
   uvicorn main:app --reload
   ```
4. **Open the dashboard**:
   Navigate to `http://127.0.0.1:8000` in your browser.

## 📐 Scoring Logic
Scores are normalized to a 0–10 scale across 6 factors:
- **Severity** (25%)
- **Asset Importance** (20%)
- **Affected Users** (15%)
- **Data Sensitivity** (15%)
- **Attack Confidence** (15%)
- **Business Impact** (10%)
