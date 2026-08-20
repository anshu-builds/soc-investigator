# Brute Force Attack — SOC Investigation Playbook

## Overview
A brute force attack involves systematic attempts to guess credentials by trying many password combinations.
MITRE ATT&CK: T1110 (Brute Force), T1110.001 (Password Guessing)

## Detection Indicators
- Multiple failed authentication attempts (5+ in 5 minutes) from a single IP
- Rapid, machine-speed login attempts (< 1 second between attempts)
- Sequential or dictionary-based password attempts
- Single source IP targeting one user or multiple users

## Investigation Steps

### Step 1: Identify the Scope
- How many failed attempts were observed and over what time period?
- Is the attack targeting a single user or multiple accounts (password spraying)?
- What is the source IP? Is it internal or external?
- Is the attack ongoing or historical?

### Step 2: Assess Success
- Did any authentication attempts succeed after the failures?
- If yes, the incident should be escalated to Account Compromise playbook.
- Check for AUTH_SUCCESS events from the same source IP within the attack window.

### Step 3: Identify the Target
- Which user account(s) were targeted?
- Is the targeted account privileged (admin, service account)?
- What systems/applications were attacked?

### Step 4: Threat Attribution
- Geolocate the source IP (if external).
- Check threat intelligence for the source IP.
- Review firewall/proxy logs for other activity from this IP.

## Containment Actions
1. **Block the attacking IP** at the firewall/WAF immediately.
2. **Lock the targeted account** temporarily if attacks are ongoing.
3. **Alert the account owner** if attacks were successful.
4. **Enable MFA** on the targeted account if not already enabled.
5. **Rate-limit authentication endpoints** if applicable.

## Evidence to Collect
- All AUTH_FAILURE events from the attacking IP
- Any AUTH_SUCCESS events from the attacking IP
- Network flow data from the source IP
- Application authentication logs

## Escalation Criteria
- Escalate to CRITICAL if: a successful login follows the brute force
- Escalate to CRITICAL if: the targeted account has administrative privileges
- Notify management if: >100 attempts or attack spans >30 minutes

## False Positive Considerations
- Legitimate users forgetting passwords (typically < 5 failures, then success from known IP)
- Automated deployment/testing scripts with incorrect credentials
- Password manager failures
