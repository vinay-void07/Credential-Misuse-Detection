from typing import Dict, Set

# RBAC Matrix defining permitted actions for each role per resource sensitivity level.
# Sensitivity: public, internal, confidential
# Actions: read, write, download, update, full
ROLE_PERMISSIONS: Dict[str, Dict[str, Set[str]]] = {
    "intern": {
        "public": {"read"},
        "internal": {"read"},
        "confidential": set()  # Explicitly NO access to confidential resources
    },
    "senior_dev": {
        "public": {"read"},
        "internal": {"read", "write", "download", "update"},
        "confidential": {"read", "download"}  # Legitimate confidential access allowed
    },
    "admin": {
        "public": {"read", "write", "download", "update", "full"},
        "internal": {"read", "write", "download", "update", "full"},
        "confidential": {"read", "write", "download", "update", "full"}
    }
}

def is_action_allowed(role: str, sensitivity: str, action: str) -> bool:
    """
    Check if a given role is authorized to perform an action on a resource
    with the given sensitivity level.
    """
    role = (role or "").lower()
    sensitivity = (sensitivity or "").lower()
    action = (action or "").lower()

    if role not in ROLE_PERMISSIONS:
        return False

    allowed_actions = ROLE_PERMISSIONS[role].get(sensitivity, set())
    return ("full" in allowed_actions) or (action in allowed_actions)
