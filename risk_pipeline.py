"""
risk_pipeline.py
-----------------
Member B deliverable: Orchestrating entry point.

Chains together, in order:
    1. database.py            -- persist the raw activity log (+ model result)
    2. risk_engine.py          -- turn triggered_factors into a 0-100 score + severity
    3. explanation_generator.py -- turn triggered_factors + score/severity into sentences
    4. response_engine.py      -- turn severity into a simulated SOC response

If the resulting score is >= ALERT_THRESHOLD, an alert row is also written via
database.insert_alert(). The response_engine's recommendation is NOT persisted
(alerts table has no column for it) -- it's returned in the result dict for
the dashboard/demo script to display live, keyed off severity_bucket.

Usage:
    from risk_pipeline import process_activity

    result = process_activity(
        user_id=priya_id,
        timestamp="2026-08-25 23:45:00",
        action_type="DOWNLOAD",
        triggered_factors={
            "ml_anomaly": 0.9,
            "off_hours": True,
            "unusual_location": True,
            "high_volume_access": True,
            "sensitive_resource": True,
            "privilege_escalation": False,
            "failed_auth_attempts": False,
            "rare_action_for_user": True,
        },
        resource_accessed="employee_salary_data.xlsx",
        ip_address="10.10.10.99",
        session_info="session_003",
        anomaly_score=-0.72,
        is_anomaly=1,
        model_version="IF_v1",
    )
"""

from typing import Dict, Any, Optional

from database import insert_activity_log, insert_model_result, insert_alert
from risk_engine import calculate_risk_score, get_severity
from explanation_generator import generate_explanation
from response_engine import get_response


# Flagged as an open item: tune this once Member A's synthetic data generator
# gives us a real score distribution to calibrate against. 15 is a starting
# placeholder, not a validated cutoff.
ALERT_THRESHOLD = 15


def process_activity(
    user_id: int,
    timestamp: str,
    action_type: str,
    triggered_factors: Dict[str, Any],
    resource_accessed: Optional[str] = None,
    ip_address: Optional[str] = None,
    session_info: Optional[str] = None,
    anomaly_score: Optional[float] = None,
    is_anomaly: Optional[int] = None,
    model_version: Optional[str] = None,
    scored_at: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Run one activity event through the full backend + risk pipeline.

    Args:
        user_id: existing user_id from the users table.
        timestamp: activity timestamp, e.g. "2026-08-25 23:45:00".
        action_type: e.g. "LOGIN", "DOWNLOAD", "FILE_ACCESS".
        triggered_factors: flat dict matching risk_engine.RISK_WEIGHTS keys,
            values are bool or 0-1 float intensity.
        resource_accessed, ip_address, session_info: passed straight through
            to database.insert_activity_log().
        anomaly_score, is_anomaly, model_version, scored_at: if provided,
            a model_results row is also written (mirrors Member A's IsolationForest
            output). If anomaly_score is None, this step is skipped.
        scored_at: defaults to `timestamp` if not given.

    Returns:
        {
            "log_id": int,
            "score": float,
            "severity": str,
            "explanation": List[str],      # from explanation_generator
            "response": dict,              # from response_engine
            "alert_id": int or None,       # None if score < ALERT_THRESHOLD
        }
    """
    # 1. Persist the raw activity log
    log_id = insert_activity_log(
        user_id=user_id,
        timestamp=timestamp,
        action_type=action_type,
        resource_accessed=resource_accessed,
        ip_address=ip_address,
        session_info=session_info,
    )

    # 1b. Optionally persist the model result (Member A's IF output)
    if anomaly_score is not None:
        insert_model_result(
            log_id=log_id,
            anomaly_score=anomaly_score,
            is_anomaly=is_anomaly if is_anomaly is not None else 0,
            model_version=model_version or "unknown",
            scored_at=scored_at or timestamp,
        )

    # 2. Risk scoring
    score = calculate_risk_score(triggered_factors)
    severity = get_severity(score)

    # 3. Explanation
    explanation = generate_explanation(triggered_factors, score, severity)

    # 4. Simulated response recommendation
    response = get_response(severity, score)

    # 5. Conditionally write an alert
    alert_id = None
    if score >= ALERT_THRESHOLD:
        active_factors = ",".join(
            factor for factor, value in triggered_factors.items()
            if (value is True) or (isinstance(value, (int, float)) and value > 0)
        )
        # Skip the summary sentence (index 0); store the factor explanations only.
        explanation_text = "\n".join(explanation[1:]) if len(explanation) > 1 else explanation[0]

        alert_id = insert_alert(
            user_id=user_id,
            log_id=log_id,
            risk_score=score,
            severity_bucket=severity,
            triggered_features=active_factors,
            explanation_text=explanation_text,
            status="open",
            created_at=timestamp,
        )

    return {
        "log_id": log_id,
        "score": score,
        "severity": severity,
        "explanation": explanation,
        "response": response,
        "alert_id": alert_id,
    }


if __name__ == "__main__":
    from database import create_tables, insert_user

    create_tables()
    test_user_id = insert_user("PipelineTestUser", "Employee", "IT", "09:00-18:00")

    scenarios = {
        "Normal": {
            "ml_anomaly": 0, "off_hours": False, "unusual_location": False,
            "high_volume_access": False, "sensitive_resource": False,
            "privilege_escalation": False, "failed_auth_attempts": False,
            "rare_action_for_user": False,
        },
        "Suspicious": {
            "ml_anomaly": 0.7, "off_hours": True, "unusual_location": True,
            "high_volume_access": False, "sensitive_resource": True,
            "privilege_escalation": False, "failed_auth_attempts": False,
            "rare_action_for_user": True,
        },
        "Misuse": {
            "ml_anomaly": 1.0, "off_hours": True, "unusual_location": True,
            "high_volume_access": True, "sensitive_resource": True,
            "privilege_escalation": True, "failed_auth_attempts": True,
            "rare_action_for_user": True,
        },
    }

    for name, factors in scenarios.items():
        result = process_activity(
            user_id=test_user_id,
            timestamp="2026-08-25 23:45:00",
            action_type="TEST_EVENT",
            triggered_factors=factors,
        )
        print(f"=== {name} ===")
        print("Score:", result["score"], "| Severity:", result["severity"])
        print("Alert written:", result["alert_id"] is not None, "(alert_id =", result["alert_id"], ")")
        print("Response:", result["response"]["summary"])
        print()
