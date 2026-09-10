from typing import Dict

def get_recommended_response(severity: str, risk_score: float) -> str:
    """
    Map alert severity and risk score to clear, operational response recommendations.
    Severity tiers:
      - LOW: Continue monitoring.
      - MEDIUM: Increase monitoring and review recent activity.
      - HIGH: Require additional authentication / step-up challenge.
      - CRITICAL: Terminate session and require re-authentication.
    """
    severity_lower = (severity or "").lower()
    if severity_lower == "critical" or risk_score >= 80.0:
        return "Terminate session and require re-authentication."
    elif severity_lower == "high" or risk_score >= 65.0:
        return "Require additional authentication (MFA/step-up) and notify security team."
    elif severity_lower == "medium" or risk_score >= 45.0:
        return "Increase monitoring and review recent session activity."
    else:
        return "Continue monitoring."
