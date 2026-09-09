import json
import os
import uuid
from datetime import datetime
from typing import List
from models import Incident, Level, Importance, Sensitivity

STORAGE_FILE = "incidents.json"

def save_incidents(incidents: List[Incident]):
    data = []
    for inc in incidents:
        data.append({
            "id": inc.id or str(uuid.uuid4()),
            "title": inc.title,
            "severity": inc.severity.value,
            "asset_importance": inc.asset_importance.value,
            "affected_users": inc.affected_users,
            "data_sensitivity": inc.data_sensitivity.value,
            "attack_confidence": inc.attack_confidence,
            "business_impact": inc.business_impact,
            "timestamp": inc.timestamp.isoformat() if inc.timestamp else datetime.now().isoformat()
        })

    with open(STORAGE_FILE, "w") as f:
        json.dump(data, f, indent=4)

def load_incidents() -> List[Incident]:
    if not os.path.exists(STORAGE_FILE):
        return []

    try:
        with open(STORAGE_FILE, "r") as f:
            data = json.load(f)

        incidents = []
        for item in data:
            incidents.append(Incident(
                id=item["id"],
                title=item["title"],
                severity=Level(item["severity"]),
                asset_importance=Importance(item["asset_importance"]),
                affected_users=item["affected_users"],
                data_sensitivity=Sensitivity(item["data_sensitivity"]),
                attack_confidence=item["attack_confidence"],
                business_impact=item["business_impact"],
                timestamp=datetime.fromisoformat(item["timestamp"]) if "timestamp" in item else datetime.now()
            ))
        return incidents
    except Exception as e:
        print(f"Error loading incidents: {e}")
        return []
