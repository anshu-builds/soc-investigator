# Account Compromise — SOC Investigation Playbook

## Overview
Account compromise occurs when an attacker successfully gains unauthorized access to a legitimate user account,
typically following credential theft, brute force, or phishing.
MITRE ATT&CK: T1078 (Valid Accounts), T1110 (Brute Force as precursor)

## Detection Indicators
- Multiple failed logins followed by a successful login from the same source IP
- Authentication success from an unusual geographic location or IP
- Login at unusual hours (outside normal work patterns)
- Multiple sessions from geographically distant locations simultaneously
- First-time login from a new device or IP

## Investigation Steps

### Step 1: Confirm the Compromise
- Verify the AUTH_SUCCESS event following failed attempts.
- Is the source IP consistent with the user's normal activity? (baseline)
- Check if the successful login IP matches the attacking IP from the failures.
- Review MFA bypass or reset activity around the time of compromise.

### Step 2: Determine Account Activity Post-Compromise
- What actions did the attacker take after gaining access?
- Were any files accessed, downloaded, or modified?
- Were any new accounts created or permissions modified?
- Were any emails sent or data exfiltrated?
- Check for PRIV_CHANGE events — did the attacker escalate privileges?

### Step 3: Establish Timeline
- When exactly was the account compromised?
- How long did the attacker have access before detection?
- Map all events from compromise to detection.

### Step 4: Identify Impact
- What data or systems did the compromised account have access to?
- Was any sensitive data accessed or exfiltrated?
- Were any downstream systems affected?

## Containment Actions (Immediate — within 15 minutes)
1. **Force logout and invalidate all active sessions** for the compromised account.
2. **Disable the account** immediately.
3. **Block the attacker's source IP** at the firewall.
4. **Reset credentials** — force password change with MFA enrollment.
5. **Preserve logs** — do not rotate or delete authentication logs.
6. **Notify the affected user** — confirm they did not perform the login.

## Evidence to Collect
- All authentication events (failures + success) for the compromised account
- Full session log after the compromise (what was done)
- Network traffic from the attacker's IP
- Email logs if the account has email access
- File access logs for shared/sensitive resources

## Escalation Criteria
- Immediately escalate if: privileged account (admin, service account) was compromised
- Escalate if: sensitive data was accessed (PII, credentials, financial data)
- Escalate if: lateral movement is detected (attacker accessing other systems)
- Notify legal/compliance if: regulated data may have been exposed

## Recovery Steps
1. Reset account credentials with strong password + MFA
2. Review and revoke any OAuth tokens or API keys the account may have had
3. Audit all actions taken during the compromise window
4. Restore any modified files from backup
5. Conduct a post-incident review within 24 hours
