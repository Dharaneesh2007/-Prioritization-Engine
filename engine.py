from typing import List, Tuple, Dict
from models import Incident, Level, Importance
import scoring
import tie_breaker
from functools import cmp_to_key

class PrioritizationEngine:
    def rank_alerts(self, alerts: List[Incident], weights: Dict[str, float] = None) -> List[Tuple[Incident, float]]:
        scored_alerts = []
        for alert in alerts:
            score = scoring.calculate_weighted_score(alert, weights)
            scored_alerts.append((alert, score))

        def compare_alerts(item1, item2):
            alert_a, score_a = item1
            alert_b, score_b = item2

            if abs(score_a - score_b) > 0.01:
                return -1 if score_a > score_b else 1

            return tie_breaker.resolve_tie(alert_a, alert_b)

        return sorted(scored_alerts, key=cmp_to_key(compare_alerts))

    def generate_playbook(self, incident: Incident) -> List[str]:
        """
        Suggests remediation steps based on incident characteristics.
        """
        playbook = []

        # Logic based on Severity and Asset Importance
        if incident.severity == Level.CRITICAL:
            if incident.asset_importance == Importance.CRITICAL:
                playbook.append("IMMEDIATE: Isolate affected system from the network.")
                playbook.append("URGENT: Trigger Incident Response Team (Tier 3).")
                playbook.append("ACTION: Snapshot memory and disk for forensic analysis.")
            elif incident.asset_importance == Importance.SENSITIVE:
                playbook.append("HIGH: Revoke all active sessions for affected users.")
                playbook.append("ACTION: Block malicious IP at the perimeter firewall.")
                playbook.append("URGENT: Notify data privacy officer.")
            else:
                playbook.append("ACTION: Reset passwords for compromised accounts.")
                playbook.append("ACTION: Update AV signatures and run full scan.")
                playbook.append("ACTION: Monitor logs for lateral movement.")

        elif incident.severity == Level.HIGH:
            playbook.append("ACTION: Increase logging verbosity on target asset.")
            playbook.append("ACTION: Conduct a vulnerability scan on adjacent systems.")
            playbook.append("ACTION: Verify backup integrity for the affected asset.")

        elif incident.severity == Level.MEDIUM:
            playbook.append("ACTION: Review access logs for the last 24 hours.")
            playbook.append("ACTION: Update security group rules to restrict access.")
            playbook.append("ACTION: Schedule a patch window for known vulnerabilities.")

        else: # LOW
            playbook.append("ACTION: Log incident in the security tracker.")
            playbook.append("ACTION: Perform a routine security audit of the asset.")
            playbook.append("ACTION: Update internal documentation on this threat vector.")

        return playbook if playbook else ["Standard monitoring and periodic review."]
