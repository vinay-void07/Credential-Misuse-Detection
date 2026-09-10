from typing import Dict, Any, List
from app.core.config import settings

def evaluate_rules(features: Dict[str, Any], latest_log_metadata: Dict[str, Any] = None) -> Dict[str, Any]:
    triggered_rules = []
    rule_points = 0.0
    details = {}

    # Rule 1: Off-hours access
    if features.get("off_hours", 0) == 1:
        triggered_rules.append("OFF_HOURS_ACTIVITY")
        rule_points += 15.0
        details["off_hours"] = "Activity occurred outside standard working hours (09:00 - 18:00)"

    # Rule 2: New device fingerprint
    if features.get("new_device", 0) == 1:
        triggered_rules.append("UNRECOGNIZED_DEVICE")
        rule_points += 15.0
        details["new_device"] = "Session initiated from a newly observed device fingerprint"

    # Rule 3: Permission violation (Forbidden / Denied requests)
    denied = features.get("denied_requests", 0)
    if denied > 0:
        triggered_rules.append("PERMISSION_VIOLATION")
        violation_pts = 25.0 + min((denied - 1) * 10.0, 15.0)
        rule_points += violation_pts
        details["permission_violation"] = f"{denied} unauthorized/denied request(s) recorded in window"

    # Rule 4: Confidential resource access
    confidential_cnt = features.get("confidential_access_count", 0)
    if confidential_cnt > 0:
        triggered_rules.append("CONFIDENTIAL_RESOURCE_ACCESS")
        conf_pts = min(confidential_cnt * 3.0, 15.0)
        rule_points += conf_pts
        details["confidential_access"] = f"{confidential_cnt} confidential resource access event(s)"

    # Rule 5: Bulk download violation
    bulk_cnt = features.get("bulk_download_count", 0)
    if bulk_cnt >= settings.BULK_DOWNLOAD_THRESHOLD:
        triggered_rules.append("BULK_DATA_EXFILTRATION_PATTERN")
        # Scaled point curve: 30 base + extra up to 40
        bulk_pts = min(30.0 + (bulk_cnt - settings.BULK_DOWNLOAD_THRESHOLD) * 1.5, 40.0)
        rule_points += bulk_pts
        details["bulk_downloads"] = f"{bulk_cnt} resource downloads within rolling window"

    # Rule 6: High request velocity
    req_rate = features.get("requests_per_minute", 0.0)
    if req_rate >= settings.REQUEST_RATE_THRESHOLD:
        triggered_rules.append("HIGH_VELOCITY_REQUESTS")
        rate_pts = min(15.0 + (req_rate - settings.REQUEST_RATE_THRESHOLD) * 1.0, 25.0)
        rule_points += rate_pts
        details["high_velocity"] = f"{req_rate} requests/min exceeds normal rate threshold"

    # Rule 7: Compound multi-signal escalation
    if len(triggered_rules) >= 2 and bulk_cnt >= settings.BULK_DOWNLOAD_THRESHOLD:
        compound_escalation = 10.0
        rule_points += compound_escalation
        triggered_rules.append("COMPOUND_SUSPICIOUS_SIGNALS")
        details["compound_escalation"] = "High download volume coupled with confidential data access"
    elif len(triggered_rules) >= 3:
        compound_escalation = 10.0
        rule_points += compound_escalation
        triggered_rules.append("COMPOUND_SUSPICIOUS_SIGNALS")
        details["compound_escalation"] = f"Multiple suspicious signals ({len(triggered_rules)-1}) observed concurrently"

    normalized_rule_score = min(rule_points, settings.RULE_WEIGHT)

    return {
        "rule_score": round(normalized_rule_score, 2),
        "raw_rule_points": round(rule_points, 2),
        "triggered_rules": triggered_rules,
        "rule_details": details
    }