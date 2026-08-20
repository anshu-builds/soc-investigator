# Privilege Escalation — SOC Investigation Playbook

## Overview
Privilege escalation occurs when an attacker or unauthorized user gains higher-level permissions than originally granted.
This often follows account compromise and allows attackers to access sensitive resources or perform privileged operations.
MITRE ATT&CK: T1078.003 (Valid Accounts: Local Accounts), T1548 (Abuse Elevation Control Mechanism)

## Detection Indicators
- PRIV_CHANGE event following a recent AUTH_SUCCESS from a suspicious source
- User account receiving administrative or root privileges unexpectedly
- Sudo/su commands executed for non-admin users
- Windows Event 4672 (Special privileges assigned to new logon)
- Unexpected role changes in IAM or directory services
- Access to sensitive files (SAM, NTDS.dit, /etc/shadow) after privilege change

## Investigation Steps

### Step 1: Confirm the Escalation
- Which account received elevated privileges?
- What exact privileges were granted?
- Was this expected/authorized? (Check change management system)
- When did the escalation occur relative to the account's authentication?

### Step 2: Link to Preceding Events
- Was there a brute force or account compromise event before this?
- How much time elapsed between the authentication and privilege escalation?
- Is this the same IP that attempted brute force?

### Step 3: Assess Damage — Post-Escalation Activity
- What did the attacker do with elevated privileges?
- Were any sensitive files accessed? (Credential stores, SAM, shadow)
- Were any backdoors or persistence mechanisms installed?
- Were any other accounts created or modified?
- Check for credential dumping tools (mimikatz, procdump, secretsdump)

### Step 4: Lateral Movement Check
- Did the attacker use the elevated credentials to access other systems?
- Check authentication logs on other servers for connections from the compromised host.
- Look for pass-the-hash or pass-the-ticket attacks.

## Containment Actions (Immediate — within 5 minutes for CRITICAL)
1. **Isolate the affected host** from the network immediately.
2. **Revoke all elevated privileges** granted during the incident window.
3. **Disable the compromised account** — do not just reset the password.
4. **Block lateral movement** — firewall rules between affected host and other systems.
5. **Preserve memory dump** — volatile evidence of tools/processes.
6. **Do NOT reboot the host** before forensic imaging if possible.

## Evidence to Collect
- Windows Event Logs: 4624, 4625, 4672, 4688, 4663
- Linux: /var/log/auth.log, /var/log/secure, sudo logs
- Memory dump (if forensically feasible)
- File access logs for sensitive paths (/etc/shadow, SAM, NTDS.dit)
- Process execution logs around the time of escalation
- Network connections from the compromised host

## Escalation Criteria
- ALWAYS Critical: escalation on a domain controller (DC)
- ALWAYS Critical: credential store access (SAM, NTDS.dit, /etc/shadow)
- ALWAYS Critical: suspected credential dumping tool execution
- Escalate if: any evidence of lateral movement
- Notify CISO: domain admin compromise

## Post-Incident Hardening
1. Implement Just-In-Time (JIT) privileged access — no standing admin rights
2. Enable Windows Credential Guard / LSA Protection
3. Deploy Privileged Access Workstations (PAWs) for admin tasks
4. Implement LAPS (Local Administrator Password Solution) for local admin accounts
5. Monitor for privileged account usage with behavioral analytics
