from models import Incident, Level, Importance, Sensitivity
from engine import PrioritizationEngine
from justifier import Justifier
from storage import save_incidents, load_incidents
import os

def test_web_logic():
    # Clear previous data
    if os.path.exists("incidents.json"):
        os.remove("incidents.json")

    engine = PrioritizationEngine()
    justifier = Justifier()

    # Create a few test incidents
    test_data = [
        Incident(
            title="Critical DB Breach",
            severity=Level.CRITICAL,
            asset_importance=Importance.CRITICAL,
            affected_users=10,
            data_sensitivity=Sensitivity.RESTRICTED,
            attack_confidence=0.9,
            business_impact=10.0
        ),
        Incident(
            title="Suspicious Login Attempt",
            severity=Level.LOW,
            asset_importance=Importance.STANDARD,
            affected_users=1,
            data_sensitivity=Sensitivity.PUBLIC,
            attack_confidence=0.4,
            business_impact=1.0
        ),
        Incident(
            title="Medium Threat on Sensitive Asset",
            severity=Level.MEDIUM,
            asset_importance=Importance.SENSITIVE,
            affected_users=100,
            data_sensitivity=Sensitivity.CONFIDENTIAL,
            attack_confidence=0.7,
            business_impact=5.0
        )
    ]

    save_incidents(test_data)
    loaded = load_incidents()
    assert len(loaded) == 3, "Failed to save/load incidents"

    ranked = engine.rank_alerts(loaded)
    assert ranked[0][0].title == "Critical DB Breach", "Ranking failed: Critical should be top"

    # Test Justification
    just = justifier.generate_justification(ranked[0][0], ranked[1][0])
    print(f"Justification Test: {just}")
    assert "outranks" in just, "Justification text missing key phrase"

    print("Backend logic verification successful!")

if __name__ == "__main__":
    test_web_logic()
