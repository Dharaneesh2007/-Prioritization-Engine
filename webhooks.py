import hmac
import hashlib
import json
import secrets
import time
import urllib.request
import urllib.error
from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from models import WebhookSubscription

def generate_webhook_secret() -> str:
    """Generates a secure 64-character hexadecimal signing secret."""
    return secrets.token_hex(32)

def sign_payload(payload_bytes: bytes, secret: str) -> str:
    """Computes HMAC-SHA256 signature for payload verification."""
    return hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()

def _send_http_post(url: str, headers: dict, data_bytes: bytes, timeout: int = 1) -> int:
    """Synchronous worker executed in background thread."""
    req = urllib.request.Request(url, data=data_bytes, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.status

def deliver_webhook_sync(sub_id: str, url: str, secret: str, event_type: str, payload_dict: dict):
    """
    Delivers a signed webhook payload with up to 3 exponential backoff retry attempts.
    Runs inside FastAPI background worker thread.
    """
    payload_json = json.dumps(payload_dict, default=str)
    payload_bytes = payload_json.encode("utf-8")
    signature = sign_payload(payload_bytes, secret)

    headers = {
        "Content-Type": "application/json",
        "X-SOC-Signature": f"sha256={signature}",
        "X-SOC-Event": event_type,
        "User-Agent": "SOC-Command-Center-Webhook/2.0"
    }

    max_retries = 3
    backoff_delays = [0.1, 0.3, 0.6]

    for attempt in range(1, max_retries + 1):
        try:
            status_code = _send_http_post(url, headers, payload_bytes, timeout=1)
            print(f"[WEBHOOK SUCCESS] Sub: {sub_id} | Event: {event_type} | URL: {url} | Status: {status_code}")
            return True
        except Exception as e:
            delay = backoff_delays[attempt - 1] if attempt <= len(backoff_delays) else 0.5
            print(f"[WEBHOOK ATTEMPT {attempt}/{max_retries} FAILED] Sub: {sub_id} | URL: {url} | Error: {e}")
            if attempt < max_retries:
                time.sleep(delay)

    print(f"[WEBHOOK PERMANENT FAILURE] Sub: {sub_id} | Event: {event_type} | URL: {url} after {max_retries} retries.")
    return False

def dispatch_webhook(event_type: str, payload: dict, get_db_func):
    """
    Finds all active subscriptions matching event_type and dispatches safely in background thread.
    """
    db: Session = next(get_db_func())
    try:
        subs = db.query(WebhookSubscription).filter(WebhookSubscription.is_active == True).all()
        for s in subs:
            try:
                events = json.loads(s.event_types)
                if event_type in events or "*" in events:
                    deliver_webhook_sync(s.id, s.url, s.secret, event_type, payload)
            except Exception as e:
                print(f"[WEBHOOK SUB ERROR] {s.id}: {e}")
    except Exception as e:
        print(f"[WEBHOOK DISPATCH ERROR] {e}")
    finally:
        db.close()
