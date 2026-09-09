import math
from typing import Dict, Any, Union
from models import Level, Importance, Sensitivity

# Default weights if DB is not yet initialized
DEFAULT_WEIGHTS = {
    "severity": 0.25,
    "asset_importance": 0.20,
    "affected_users": 0.15,
    "data_sensitivity": 0.15,
    "attack_confidence": 0.15,
    "business_impact": 0.10
}

PRESET_WEIGHTS = {
    "standard": {
        "label": "SOC Balanced Standard",
        "description": "Balanced enterprise default accounting for asset value, data sensitivity, and threat confidence.",
        "weights": {"severity": 0.25, "asset_importance": 0.20, "affected_users": 0.15, "data_sensitivity": 0.15, "attack_confidence": 0.15, "business_impact": 0.10}
    },
    "assetCentric": {
        "label": "Crown Jewel Defense",
        "description": "Heavily prioritizes high-value production servers, identity providers, and financial databases.",
        "weights": {"severity": 0.15, "asset_importance": 0.35, "affected_users": 0.05, "data_sensitivity": 0.20, "attack_confidence": 0.10, "business_impact": 0.15}
    },
    "dataPrivacy": {
        "label": "Data Exfiltration & Privacy",
        "description": "Focuses on critical PII, financial ledgers, and confidential IP security exposures.",
        "weights": {"severity": 0.15, "asset_importance": 0.15, "affected_users": 0.10, "data_sensitivity": 0.35, "attack_confidence": 0.10, "business_impact": 0.15}
    },
    "confirmedThreats": {
        "label": "Confirmed High-Confidence Threats",
        "description": "Filters noise by putting maximum weight on detections with definitive threat signatures and high confidence.",
        "weights": {"severity": 0.20, "asset_importance": 0.15, "affected_users": 0.05, "data_sensitivity": 0.10, "attack_confidence": 0.35, "business_impact": 0.15}
    },
    "businessContinuity": {
        "label": "Business & Service Impact",
        "description": "Prioritizes revenue-generating endpoints, transactional pipelines, and user-facing outages.",
        "weights": {"severity": 0.15, "asset_importance": 0.20, "affected_users": 0.20, "data_sensitivity": 0.10, "attack_confidence": 0.10, "business_impact": 0.25}
    }
}

def normalize_severity(level: Union[Level, str]) -> float:
    mapping = {
        Level.LOW: 1.0,
        Level.MEDIUM: 3.0,
        Level.HIGH: 6.0,
        Level.CRITICAL: 10.0
    }
    if isinstance(level, str):
        val = level.lower().strip()
        if val == "low": return 1.0
        if val == "medium": return 3.0
        if val == "high": return 6.0
        if val in ["critical", "crit"]: return 10.0
    return mapping.get(level, 1.0)

def normalize_importance(importance: Union[Importance, str]) -> float:
    mapping = {
        Importance.STANDARD: 2.5,
        Importance.SENSITIVE: 5.0,
        Importance.CRITICAL: 10.0
    }
    if isinstance(importance, str):
        val = importance.lower().strip()
        if val in ["standard", "low"]: return 2.5
        if val in ["sensitive", "medium"]: return 5.0
        if val in ["crown jewel", "critical", "crown_jewel", "high"]: return 10.0
    return mapping.get(importance, 2.5)

def normalize_users(count: int) -> float:
    if count <= 0:
        return 0.0
    # Formula: F3 = min(10, log10(U+1) / log10(1001) * 10)
    # log10(1001) ≈ 3.000434
    normalized = (math.log10(count + 1) / math.log10(1001)) * 10.0
    return round(min(10.0, max(0.0, normalized)), 2)

def normalize_sensitivity(sensitivity: Union[Sensitivity, str]) -> float:
    mapping = {
        Sensitivity.PUBLIC: 1.0,
        Sensitivity.INTERNAL: 4.0,
        Sensitivity.CONFIDENTIAL: 7.0,
        Sensitivity.RESTRICTED: 10.0
    }
    if isinstance(sensitivity, str):
        val = sensitivity.lower().strip()
        if val == "public": return 1.0
        if val == "internal": return 4.0
        if val == "confidential": return 7.0
        if val == "restricted": return 10.0
    return mapping.get(sensitivity, 1.0)

def normalize_confidence(confidence: float) -> float:
    if confidence is None:
        return 5.0
    # If confidence is in 0.0-1.0 range, scale to 0-10
    if 0.0 <= confidence <= 1.0:
        return round(confidence * 10.0, 2)
    return round(max(0.0, min(10.0, float(confidence))), 2)

def normalize_impact(impact: float) -> float:
    if impact is None:
        return 5.0
    return round(max(0.0, min(10.0, float(impact))), 2)

def calculate_risk_gravity(score: float, tier: int = None) -> float:
    """
    Applies non-linear risk gravity 3^(tier-1).
    Tiers:
    - Tier 1: Score < 5.0 (Multiplier = 3^0 = 1.0)
    - Tier 2: Score 5.0 - 7.5 (Multiplier = 3^1 = 3.0 relative gravity index)
    - Tier 3: Score >= 7.5 (Multiplier = 3^2 = 9.0 relative gravity index)
    """
    if tier is None:
        if score >= 7.5:
            tier = 3
        elif score >= 5.0:
            tier = 2
        else:
            tier = 1
    gravity_multiplier = 3 ** (tier - 1)
    return round(score * (1.0 + (gravity_multiplier - 1) * 0.05), 2)


def resolve_incident_weights(incident, weights: Union[Dict[str, float], Dict[str, Dict[str, float]]] = None) -> Dict[str, float]:
    """
    Looks up matching weights for the incident's asset_category against custom scoring profiles,
    falling back to the 'Default' profile or DEFAULT_WEIGHTS.
    """
    if not weights:
        return DEFAULT_WEIGHTS

    # If a direct 6-factor dictionary is provided, use it directly
    if "severity" in weights:
        return weights

    # If a profile mapping {category: weights_dict} is provided, look up by asset_category
    cat = getattr(incident, "asset_category", "default")
    if cat and cat.lower() in weights:
        return weights[cat.lower()]

    if "default" in weights:
        return weights["default"]

    return DEFAULT_WEIGHTS

def calculate_weighted_score(incident, weights: Union[Dict[str, float], Dict[str, Dict[str, float]]] = None) -> float:
    w = resolve_incident_weights(incident, weights)

    score = (
        normalize_severity(incident.severity) * w.get("severity", 0.25) +
        normalize_importance(incident.asset_importance) * w.get("asset_importance", 0.20) +
        normalize_users(incident.affected_users) * w.get("affected_users", 0.15) +
        normalize_sensitivity(incident.data_sensitivity) * w.get("data_sensitivity", 0.15) +
        normalize_confidence(incident.attack_confidence) * w.get("attack_confidence", 0.15) +
        normalize_impact(incident.business_impact) * w.get("business_impact", 0.10)
    )
    return round(score, 2)

def get_factor_breakdown(incident, weights: Union[Dict[str, float], Dict[str, Dict[str, float]]] = None) -> Dict[str, dict]:
    w = resolve_incident_weights(incident, weights)

    sev = incident.severity if isinstance(incident.severity, Level) else Level(incident.severity)
    imp = incident.asset_importance if isinstance(incident.asset_importance, Importance) else Importance(incident.asset_importance)
    sens = incident.data_sensitivity if isinstance(incident.data_sensitivity, Sensitivity) else Sensitivity(incident.data_sensitivity)
    users = incident.affected_users
    conf = incident.attack_confidence
    impact = incident.business_impact

    norm_sev = normalize_severity(sev)
    norm_imp = normalize_importance(imp)
    norm_users = normalize_users(users)
    norm_sens = normalize_sensitivity(sens)
    norm_conf = normalize_confidence(conf)
    norm_impact = normalize_impact(impact)

    return {
        "severity": {
            "key": "severity",
            "label": "Severity",
            "raw": sev.value,
            "normalized": round(norm_sev, 2),
            "weight": w.get("severity", 0.25),
            "contribution": round(norm_sev * w.get("severity", 0.25), 2)
        },
        "asset_importance": {
            "key": "asset_importance",
            "label": "Asset Importance",
            "raw": imp.value,
            "normalized": round(norm_imp, 2),
            "weight": w.get("asset_importance", 0.20),
            "contribution": round(norm_imp * w.get("asset_importance", 0.20), 2)
        },
        "affected_users": {
            "key": "affected_users",
            "label": "Affected Users",
            "raw": users,
            "normalized": round(norm_users, 2),
            "weight": w.get("affected_users", 0.15),
            "contribution": round(norm_users * w.get("affected_users", 0.15), 2)
        },
        "data_sensitivity": {
            "key": "data_sensitivity",
            "label": "Data Sensitivity",
            "raw": sens.value,
            "normalized": round(norm_sens, 2),
            "weight": w.get("data_sensitivity", 0.15),
            "contribution": round(norm_sens * w.get("data_sensitivity", 0.15), 2)
        },
        "attack_confidence": {
            "key": "attack_confidence",
            "label": "Attack Confidence",
            "raw": conf,
            "normalized": round(norm_conf, 2),
            "weight": w.get("attack_confidence", 0.15),
            "contribution": round(norm_conf * w.get("attack_confidence", 0.15), 2)
        },
        "business_impact": {
            "key": "business_impact",
            "label": "Business Impact",
            "raw": impact,
            "normalized": round(norm_impact, 2),
            "weight": w.get("business_impact", 0.10),
            "contribution": round(norm_impact * w.get("business_impact", 0.10), 2)
        }
    }

def get_top_factor(incident, weights: Union[Dict[str, float], Dict[str, Dict[str, float]]] = None) -> str:
    breakdown = get_factor_breakdown(incident, weights)
    top = max(breakdown.items(), key=lambda x: x[1]["contribution"])
    factor_key = top[0]
    data = top[1]
    if factor_key == "asset_importance":
        return f"Asset: {data['raw']}"
    elif factor_key == "severity":
        return f"Severity: {data['raw']}"
    elif factor_key == "data_sensitivity":
        return f"Data: {data['raw']}"
    elif factor_key == "affected_users":
        return f"Users: {data['raw']:,}"
    elif factor_key == "attack_confidence":
        return f"Confidence: {int(data['raw']*100)}%"
    elif factor_key == "business_impact":
        return f"Impact: {data['raw']}/10"
    return f"{data['label']}: {data['raw']}"
