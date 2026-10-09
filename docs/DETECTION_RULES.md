# Detection Rule Engine Specifications

TraceForensics implements a transparent, explainable rule engine mapped to the MITRE ATT&CK Enterprise Matrix.

## Supported Detection Rules

### RULE-001: Repeated Failed Authentication (Brute Force)
- **MITRE ATT&CK Mapping**: T1110 (Brute Force)
- **Severity**: High | **Confidence**: High
- **Description**: Triggers when 3 or more failed authentication events (`auth_result == 'FAILURE'`) occur for the same username or source IP within a sliding 15-minute window.
- **Remediation**: Lock target account, check IP geolocation, enforce MFA, and check endpoint process tree.

### RULE-002: Successful Authentication Post Repeated Failures
- **MITRE ATT&CK Mapping**: T1078 (Valid Accounts)
- **Severity**: Critical | **Confidence**: High
- **Description**: Triggers when a successful authentication (`auth_result == 'SUCCESS'`) immediately follows >=2 prior authentication failures for the same user.
- **Remediation**: Immediately contact user to verify legitimate login, force password reset, terminate active sessions.

### RULE-003: Suspicious Process Command Execution
- **MITRE ATT&CK Mapping**: T1059 (Command and Scripting Interpreter)
- **Severity**: High | **Confidence**: Medium
- **Description**: Detects process execution containing credential dumper or administrative utility abuse strings (`mimikatz`, `certutil`, `powershell -enc`, `whoami /priv`).
- **Remediation**: Isolate host, dump LSASS memory for analysis, inspect child processes.

### RULE-004: Unusual Privilege Change / Escalation
- **MITRE ATT&CK Mapping**: T1098 (Account Manipulation) / T1548 (Abuse Elevation Control)
- **Severity**: High | **Confidence**: High
- **Description**: Detects group membership modifications (e.g. Domain Admins, sudoers) or administrative privilege grants.
- **Remediation**: Verify ticket authorization, revert group membership, review privilege escalation logs.

### RULE-005: Potential Audit Log Tampering / Clearing
- **MITRE ATT&CK Mapping**: T1070 (Indicator Removal)
- **Severity**: Critical | **Confidence**: High
- **Description**: Detects command execution or Windows Event IDs indicating security log clearing (`wevtutil cl`, Event ID 1102 / 4719, `rm -rf /var/log`).
- **Remediation**: Escalate to Tier 3 incident responder immediately, inspect SIEM remote syslog forwarders.

### RULE-006: Login Activity from Suspicious External IP
- **MITRE ATT&CK Mapping**: T1078.004 (Valid Accounts: Cloud Accounts)
- **Severity**: Medium | **Confidence**: Medium
- **Description**: Identifies authentication requests originating from known malicious scanner IP subnets or untrusted external IPs.
- **Remediation**: Verify user location, check VPN logs, add IP to gateway firewall blocklist.
