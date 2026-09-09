from models import Incident
import scoring

def resolve_tie(a: Incident, b: Incident) -> int:
    """
    Returns:
    -1 if a should be ranked higher than b
     1 if b should be ranked higher than a
     0 if they are truly identical
    """
    # 1. Higher attack confidence
    conf_a = scoring.normalize_confidence(a.attack_confidence)
    conf_b = scoring.normalize_confidence(b.attack_confidence)
    if conf_a > conf_b: return -1
    if conf_b > conf_a: return 1

    # 2. Higher asset importance
    imp_a = scoring.normalize_importance(a.asset_importance)
    imp_b = scoring.normalize_importance(b.asset_importance)
    if imp_a > imp_b: return -1
    if imp_b > imp_a: return 1

    # 3. Earliest timestamp (first-in wins)
    if a.timestamp < b.timestamp: return -1
    if b.timestamp < a.timestamp: return 1

    return 0
