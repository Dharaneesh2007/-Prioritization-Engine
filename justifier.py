from typing import Dict
from models import Incident
import scoring

class Justifier:
    def generate_justification(self, a: Incident, b: Incident, weights: Dict[str, float]) -> str:
        # Identify weighted contributions for both
        factors = [
            ("Severity", "severity", scoring.normalize_severity),
            ("Asset Importance", "asset_importance", scoring.normalize_importance),
            ("Affected Users", "affected_users", scoring.normalize_users),
            ("Data Sensitivity", "data_sensitivity", scoring.normalize_sensitivity),
            ("Attack Confidence", "attack_confidence", scoring.normalize_confidence),
            ("Business Impact", "business_impact", scoring.normalize_impact),
        ]

        contributions_a = {}
        contributions_b = {}

        # Map factors to weight keys
        weight_map = {
            "Severity": "severity",
            "Asset Importance": "asset_importance",
            "Affected Users": "affected_users",
            "Data Sensitivity": "data_sensitivity",
            "Attack Confidence": "attack_confidence",
            "Business Impact": "business_impact",
        }

        for name, attr, norm_func in factors:
            val_a = norm_func(getattr(a, attr))
            val_b = norm_func(getattr(b, attr))

            w = weights.get(weight_map[name], 0.1)
            contributions_a[name] = val_a * w
            contributions_b[name] = val_b * w

        # Find the largest positive delta for a (the reason it outranks b)
        deltas = []
        for name in weight_map:
            delta = contributions_a[name] - contributions_b[name]
            deltas.append((name, delta, contributions_a[name], contributions_b[name]))

        # Sort by delta descending
        deltas.sort(key=lambda x: x[1], reverse=True)

        primary_factor, primary_delta, val_a, val_b = deltas[0]

        # Find if b had any factor where it actually beat a
        losses = [d for d in deltas if d[1] < 0]

        justification = f"Incident '{a.title}' ({scoring.calculate_weighted_score(a, weights)}) outranks '{b.title}' ({scoring.calculate_weighted_score(b, weights)}) primarily due to {primary_factor} (+{primary_delta:.2f} weighted)."

        if losses:
            top_loss_name, top_loss_delta, l_val_a, l_val_b = losses[0]
            justification += f" This outweighs '{b.title}' lead in {top_loss_name} ({abs(top_loss_delta):.2f} weighted)."

        return justification

    def generate_comparison_data(self, a: Incident, b: Incident, weights: Dict[str, float]) -> dict:
        breakdown_a = scoring.get_factor_breakdown(a, weights)
        breakdown_b = scoring.get_factor_breakdown(b, weights)
        score_a = scoring.calculate_weighted_score(a, weights)
        score_b = scoring.calculate_weighted_score(b, weights)

        higher = a if score_a >= score_b else b
        lower = b if score_a >= score_b else a
        justification_text = self.generate_justification(higher, lower, weights)

        factors_comparison = []
        for key in ["severity", "asset_importance", "affected_users", "data_sensitivity", "attack_confidence", "business_impact"]:
            fa = breakdown_a[key]
            fb = breakdown_b[key]
            delta = round(fa["contribution"] - fb["contribution"], 2)
            factors_comparison.append({
                "key": key,
                "label": fa["label"],
                "weight": fa["weight"],
                "incident_a": {
                    "raw": fa["raw"],
                    "normalized": fa["normalized"],
                    "contribution": fa["contribution"]
                },
                "incident_b": {
                    "raw": fb["raw"],
                    "normalized": fb["normalized"],
                    "contribution": fb["contribution"]
                },
                "delta": delta,
                "advantage": "A" if delta > 0 else ("B" if delta < 0 else "TIED")
            })

        return {
            "incident_a": {
                "id": a.id,
                "title": a.title,
                "score": score_a,
                "severity": a.severity.value,
                "status": a.status.value
            },
            "incident_b": {
                "id": b.id,
                "title": b.title,
                "score": score_b,
                "severity": b.severity.value,
                "status": b.status.value
            },
            "winner": "A" if score_a >= score_b else "B",
            "score_diff": round(abs(score_a - score_b), 2),
            "justification": justification_text,
            "factors": factors_comparison
        }

