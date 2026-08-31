# Credential Dumping — SOC Investigation Playbook

## Overview
Credential dumping involves extracting account login credentials (plaintext passwords, password hashes, Kerberos tickets, or tokens) from the operating system or software memory.
MITRE ATT&CK: T1003 (OS Credential Dumping), T1003.001 (LSASS Memory), T1003.002 (Security Account Manager), T1003.008 (/etc/passwd and /etc/shadow)

## Detection Indicators
- Access to the Local Security Authority Subsystem Service (LSASS) process memory (Sysmon Event ID 10 with PROCESS_VM_READ / PROCESS_VM_WRITE access masks)
- Execution of dumping utilities: `mimikatz`, `procdump`, `comsvcs.dll` minidump, `pwdump`, `secretsdump.py`
- Reading of sensitive system files: `C:\Windows\System32\config\SAM`, `C:\Windows\NTDS\ntds.dit`, or `/etc/shadow`
- Volume Shadow Copy creation targeting the system drive (e.g., `vssadmin create shadow /for=C:`) to copy locked hives
- Suspicious registry export commands targeting `HKLM\SAM`, `HKLM\SECURITY`, or `HKLM\SYSTEM`

## Investigation Steps

### Step 1: Identify Process and User Context
- Which process accessed LSASS or the SAM registry hive?
- Which user account executed the dumping process? Was it already elevated (e.g., SYSTEM or root)?
- What command-line arguments were passed to the suspicious binary?

### Step 2: Determine Credential Scope
- What credential repositories were targeted (LSASS memory, SAM hive, NTDS.dit, shadow file, browser credential databases)?
- Were domain credentials, local administrator accounts, or service accounts exposed in memory?

### Step 3: Check for Exfiltration or Staging
- Did the process create dump files (e.g., `.dmp`, `.kirbi`, `.reg`, or `.txt` in temporary directories like `C:\Windows\Temp` or `/tmp`)?
- Were dump files compressed or staged for exfiltration?
- Check network connections from the host immediately following the dump execution.

### Step 4: Trace Preceding Initial Access & Escalation
- Correlate backwards to identify how the attacker gained execution privileges on the host.
- Look for earlier brute force, account compromise, or privilege escalation alerts associated with the host.

## Containment Actions
1. **Immediate Host Isolation**: Disconnect the host from the network immediately to prevent dumped credentials from being used elsewhere.
2. **Enterprise-Wide Password Resets**: Reset passwords for all accounts logged into the compromised host during the incident window.
3. **KRBTGT Password Reset**: If NTDS.dit was dumped or Domain Controller memory was accessed, perform the two-stage KRBTGT account password reset.
4. **Invalidate Active Kerberos Tickets**: Purge Kerberos tickets across domain endpoints (`klist purge`).
5. **Terminate Malicious Processes**: Kill the offending tool process and remove any associated dump files.

## Evidence to Collect
- Process creation and injection logs (Sysmon Event IDs 1, 8, 10)
- Security audit logs for SAM/LSA policy changes (Windows Event IDs 4663, 4672, 4703)
- Command-line audit logs (Event ID 4688 with command line auditing enabled)
- Memory forensics artifacts showing injected DLLs or credential parsing routines
- Antivirus / EDR quarantine logs

## Escalation Criteria
- ALWAYS Critical: LSASS dumping on Domain Controllers, Exchange, or Active Directory Federation Services (ADFS).
- ALWAYS Critical: NTDS.dit or SAM registry hive access.
- Escalate to High: Execution of recognized dumping utilities on any domain-joined host.

## Prevention & Hardening
1. Enable Windows Defender Credential Guard to isolate LSASS in a virtualization-based security (VBS) container.
2. Enable RunAsPPL (Protected Process Light) for `lsass.exe`.
3. Restrict Debug Privileges (`SeDebugPrivilege`) from non-essential administrative accounts.
4. Enforce strict permissions on `/etc/shadow` and restrict sudo access to memory inspection tools.
