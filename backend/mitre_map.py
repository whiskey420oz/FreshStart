MITRE_RULE_MAP = {
    "5710": ["T1110"],  # SSH authentication failed
    "5712": ["T1110"],  # SSH brute force
    "60122": ["T1110"],  # Windows logon failure
    "60106": ["T1078"],  # Windows logon success
    "60110": ["T1098"],  # Account manipulation
}

MITRE_TACTIC_MAP = {
    "T1110": ["Credential Access"],
    "T1078": ["Initial Access", "Persistence", "Privilege Escalation"],
    "T1098": ["Persistence"],
}
