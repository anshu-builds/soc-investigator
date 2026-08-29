# Lateral Movement — SOC Investigation Playbook

## Overview
Lateral movement refers to techniques adversaries use to extend their access across systems and hosts in a network after gaining an initial foothold.
MITRE ATT&CK: T1021 (Remote Services), T1021.001 (Remote Desktop Protocol), T1021.002 (SMB/Windows Admin Shares), T1021.004 (SSH), T1078 (Valid Accounts)

## Detection Indicators
- Unusual internal SSH, RDP, or SMB connections originating from an endpoint rather than a management jump host
- WinRM (PowerShell Remoting) sessions established across workstations
- PsExec or WMI process creation across remote network shares (Event ID 4624 Type 3/10, 4688)
- Multiple logon attempts using the same compromised credential across different internal subnets
- Use of remote execution tools (psexec, wmic, winrs, sshpass)

## Investigation Steps

### Step 1: Identify the Pivot Source
- Which internal host initiated the lateral connection?
- Is that source host already flagged for previous brute force, account compromise, or privilege escalation?
- What user account credentials were used to authenticate to the remote target?

### Step 2: Map Destination Targets
- How many distinct hosts were targeted from the compromised pivot point?
- Were the targeted hosts servers, domain controllers, or peer workstations?
- Did authentication succeed or fail across the target systems?

### Step 3: Determine Execution Mechanism
- What protocol was used (SMB/RPC, RDP, SSH, WinRM)?
- Was a remote command or scheduled task spawned on the target system (e.g., service creation Event ID 7045)?
- Were files transferred across network shares (admin$, c$)?

### Step 4: Assess Breadth of Compromise
- Has the attacker established persistent footholds on any of the target machines?
- Have additional credentials been harvested on the secondary systems?

## Containment Actions
1. **Network Segmentation**: Block east-west traffic from the source host at the switch/firewall level.
2. **Revoke Active Sessions**: Terminate all active RDP, SSH, and SMB sessions associated with the compromised account and source IP.
3. **Disable Compromised Accounts**: Disable the user and service accounts utilized during the lateral movement.
4. **Isolate Affected Secondary Hosts**: Place all confirmed target hosts into quarantine VLANs.
5. **Enforce Local Admin Password Solution (LAPS)**: Ensure local administrator passwords are unique per host to prevent pass-the-hash replication.

## Evidence to Collect
- Network flow and firewall logs showing internal east-west connection attempts
- Authentication logs on target systems (Windows Event ID 4624, Linux auth.log / sshd logs)
- Service creation and process execution telemetry on target systems (Event IDs 7045, 4688)
- Kerberos ticket requests (Event ID 4768, 4769) to identify pass-the-ticket behavior

## Escalation Criteria
- Escalate to CRITICAL if: Lateral movement targets Domain Controllers or critical database infrastructure.
- Escalate to CRITICAL if: Pass-the-hash or pass-the-ticket execution is confirmed.
- Escalate to HIGH if: More than 3 internal hosts are accessed by the adversary.

## False Positive Considerations
- System administrator maintenance scripts using PsExec or Ansible.
- IT helpdesk remote assistance tools (verify against active IT tickets).
- Vulnerability scanners performing authenticated network sweeps during scheduled maintenance windows.
