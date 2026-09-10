from typing import Dict, Any, List

def generate_alert_explanation(
    severity: str,
    risk_score: float,
    ml_result: Dict[str, Any],
    rule_result: Dict[str, Any],
    features: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Produce structured evidence and a clear, deterministic explanation
    of why an alert was triggered, satisfying requirements:
    "Do not create meaningless generic alerts such as 'Suspicious behavior detected'."
    """
    triggered_rules = rule_result.get("triggered_rules", [])
    rule_details = rule_result.get("rule_details", {})
    evidence_items: List[str] = []

    # Compile clear evidence items
    if "PERMISSION_VIOLATION" in triggered_rules:
        denied_cnt = features.get("denied_requests", 0)
        evidence_items.append(f"{denied_cnt} unauthorized/forbidden permission violation(s)")

    if "BULK_DATA_EXFILTRATION_PATTERN" in triggered_rules:
        bulk_cnt = features.get("bulk_download_count", 0)
        window = features.get("window_minutes", 5)
        evidence_items.append(f"{bulk_cnt} downloads executed within ~{window} minutes")

    if "HIGH_VELOCITY_REQUESTS" in triggered_rules:
        rate = features.get("requests_per_minute", 0)
        evidence_items.append(f"Request rate surged to {rate} requests/min")

    if "CONFIDENTIAL_RESOURCE_ACCESS" in triggered_rules:
        conf_cnt = features.get("confidential_access_count", 0)
        evidence_items.append(f"{conf_cnt} confidential resource access attempts")

    if "OFF_HOURS_ACTIVITY" in triggered_rules:
        evidence_items.append("Activity observed outside authorized working hours (09:00 - 18:00)")

    if "UNRECOGNIZED_DEVICE" in triggered_rules:
        evidence_items.append("Session originated from an unrecognized client device fingerprint")

    if ml_result.get("is_anomaly"):
        evidence_items.append(
            f"IsolationForest statistical anomaly detected (anomaly score: {ml_result.get('ml_score')}/40)"
        )

    # Deterministic natural language summary
    if severity == "critical":
        title = "CRITICAL: Potential Credential Misuse / Bulk Exfiltration Detected"
        if "BULK_DATA_EXFILTRATION_PATTERN" in triggered_rules:
            summary = (
                f"Critical behavioral anomaly detected. The session executed {features.get('bulk_download_count', 0)} "
                f"downloads within approximately {features.get('window_minutes', 5)} minutes, significantly exceeding "
                f"the normal operational baseline and indicating automated credential misuse."
            )
        else:
            summary = (
                f"Critical security violation. Extreme composite risk score ({risk_score}/100) triggered by "
                + "; ".join(evidence_items)
            )
    elif severity == "high":
        title = "HIGH: Suspicious Credential Activity & Policy Violation"
        summary = (
            f"High risk behavioral anomaly ({risk_score}/100). Observed signals: "
            + "; ".join(evidence_items)
        )
    elif severity == "medium":
        title = "MEDIUM: Behavioral Policy Anomaly Detected"
        summary = (
            f"Elevated session risk ({risk_score}/100) flagged due to: "
            + "; ".join(evidence_items)
        )
    else:
        title = "LOW: Minor Behavioral Variance"
        summary = f"Session risk ({risk_score}/100) remains within manageable operational variance."

    return {
        "title": title,
        "description": summary,
        "evidence": {
            "risk_score": risk_score,
            "severity": severity,
            "ml_anomaly_score": ml_result.get("ml_score"),
            "ml_decision_value": ml_result.get("decision_value"),
            "rule_score": rule_result.get("rule_score"),
            "triggered_rules": triggered_rules,
            "evidence_signals": evidence_items,
            "features_summary": {
                "requests_per_minute": features.get("requests_per_minute"),
                "downloads_per_minute": features.get("downloads_per_minute"),
                "bulk_download_count": features.get("bulk_download_count"),
                "denied_requests": features.get("denied_requests"),
                "confidential_access_count": features.get("confidential_access_count"),
                "off_hours": features.get("off_hours"),
                "new_device": features.get("new_device")
            }
        }
    }
