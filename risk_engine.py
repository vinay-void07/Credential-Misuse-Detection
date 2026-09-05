RISK_WEIGHTS = {
    "ml_anomaly": 22,
    "off_hours": 7,
    "unusual_location": 11,
    "high_volume_access": 11,
    "sensitive_resource": 15,
    "privilege_escalation": 19,
    "failed_auth_attempts": 7,
    "rare_action_for_user": 7,
}


def calculate_risk_score(triggered_factors):
    """
    Calculate a 0-100 risk score.

    triggered_factors:
        Dictionary containing True/False values or
        0-1 intensity values.
    """

    score = 0

    for factor, weight in RISK_WEIGHTS.items():
        value = triggered_factors.get(factor, 0)

        if isinstance(value, bool):
            score += weight if value else 0
        else:
            score += weight * value

    return min(100, round(score))


def get_severity(score):
    """
    Convert risk score into a severity bucket.
    """

    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 35:
        return "Medium"
    elif score >= 15:
        return "Low"
    else:
        return "Info"


#temp code

if __name__ == "__main__":

    normal_activity = {
        "ml_anomaly": 0,
        "off_hours": False,
        "unusual_location": False,
        "high_volume_access": False,
        "sensitive_resource": False,
        "privilege_escalation": False,
        "failed_auth_attempts": False,
        "rare_action_for_user": False,
    }

    suspicious_activity = {
        "ml_anomaly": 0.7,
        "off_hours": True,
        "unusual_location": True,
        "high_volume_access": False,
        "sensitive_resource": True,
        "privilege_escalation": False,
        "failed_auth_attempts": False,
        "rare_action_for_user": True,
    }

    misuse_activity = {
        "ml_anomaly": 1.0,
        "off_hours": True,
        "unusual_location": True,
        "high_volume_access": True,
        "sensitive_resource": True,
        "privilege_escalation": True,
        "failed_auth_attempts": True,
        "rare_action_for_user": True,
    }

    for name, factors in [
        ("Normal", normal_activity),
        ("Suspicious", suspicious_activity),
        ("Misuse", misuse_activity),
    ]:
        score = calculate_risk_score(factors)
        severity = get_severity(score)

        print(f"{name}: {score} - {severity}")
        