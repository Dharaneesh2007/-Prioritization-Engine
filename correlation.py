from typing import List, Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from models import Incident, IncidentCluster, IncidentStatus, Level
import scoring
import uuid

SEVERITY_ORDER = {
    Level.LOW: 1,
    Level.MEDIUM: 2,
    Level.HIGH: 3,
    Level.CRITICAL: 4
}

def find_related_incidents(incident: Incident, all_incidents: List[Incident], window_minutes: int = 30) -> List[Incident]:
    """
    Identifies related incidents based on:
    1. Exact match on Source IP (if present)
    2. Exact match on Target Asset (if present)
    3. Same asset category / asset importance + overlapping time window (within window_minutes)
    """
    related = []
    inc_time = incident.timestamp or datetime.now()
    window_delta = timedelta(minutes=window_minutes)

    for cand in all_incidents:
        if cand.id == incident.id:
            continue

        cand_time = cand.timestamp or datetime.now()
        time_diff = abs(inc_time - cand_time)

        # Match 1: Same Source IP
        if incident.source_ip and cand.source_ip:
            if incident.source_ip.strip() and incident.source_ip.strip() == cand.source_ip.strip():
                related.append(cand)
                continue

        # Match 2: Same Target Asset
        if incident.target_asset and cand.target_asset:
            if incident.target_asset.strip().lower() == cand.target_asset.strip().lower():
                related.append(cand)
                continue

        # Match 3: Matching category & timestamp within window
        if time_diff <= window_delta:
            same_category = (incident.asset_category and cand.asset_category and incident.asset_category.lower() == cand.asset_category.lower() and incident.asset_category.lower() != 'default')
            same_mitre = (incident.mitre_technique and cand.mitre_technique and incident.mitre_technique.upper() == cand.mitre_technique.upper())
            same_importance = (incident.asset_importance == cand.asset_importance and incident.asset_importance != 'Standard')

            if same_category or same_mitre or (same_importance and incident.severity == cand.severity):
                related.append(cand)

    return related

def correlate_and_cluster_incident(incident: Incident, db: Session, weights: dict = None) -> Optional[IncidentCluster]:
    """
    Evaluates correlation for an incident, creates or joins an IncidentCluster,
    and designates the primary_incident_id with the highest priority score.
    """
    open_statuses = [IncidentStatus.NEW, IncidentStatus.INVESTIGATING]
    all_open = db.query(Incident).filter(Incident.status.in_(open_statuses)).all()

    related_incidents = find_related_incidents(incident, all_open)
    if not related_incidents:
        return None

    # Check if any matching incident already belongs to a cluster
    existing_cluster_id = None
    for cand in related_incidents:
        if cand.cluster_id:
            existing_cluster_id = cand.cluster_id
            break

    if existing_cluster_id:
        cluster = db.query(IncidentCluster).filter(IncidentCluster.id == existing_cluster_id).first()
        if not cluster:
            cluster = IncidentCluster(id=existing_cluster_id)
            db.add(cluster)
    else:
        cluster = IncidentCluster()
        db.add(cluster)
        db.flush()

    incident.cluster_id = cluster.id

    # Add all related incidents to this cluster
    for cand in related_incidents:
        cand.cluster_id = cluster.id

    db.commit()

    # Re-evaluate member list, primary incident, and combined severity
    cluster_members = db.query(Incident).filter(Incident.cluster_id == cluster.id).all()
    cluster.incident_count = len(cluster_members)

    # Primary incident is the one with the highest calculated score
    highest_score = -1.0
    primary_id = incident.id
    highest_sev = Level.LOW

    for m in cluster_members:
        m_score = scoring.calculate_weighted_score(m, weights)
        if m_score > highest_score:
            highest_score = m_score
            primary_id = m.id

        m_sev = m.severity if isinstance(m.severity, Level) else Level(m.severity)
        if SEVERITY_ORDER.get(m_sev, 1) > SEVERITY_ORDER.get(highest_sev, 1):
            highest_sev = m_sev

    cluster.primary_incident_id = primary_id
    cluster.combined_severity = highest_sev.value
    db.commit()
    db.refresh(cluster)

    return cluster

def correlate_and_cluster_incidents(db: Session, weights: dict = None):
    """
    Performs correlation pass across all active incidents.
    """
    incidents = db.query(Incident).filter(Incident.status.in_([IncidentStatus.NEW, IncidentStatus.INVESTIGATING])).all()
    for inc in incidents:
        correlate_and_cluster_incident(inc, db, weights)
