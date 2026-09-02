'use client'

import React, { useState } from 'react'
import Link from 'next/link'
import {
  AlertTriangle,
  BookOpen,
  Check,
  ChevronRight,
  Clock,
  Copy,
  ExternalLink,
  Flame,
  Lock,
  Search,
  Shield,
  Sparkles,
  Terminal,
  Wifi,
  Zap,
} from 'lucide-react'
import { MitreTechniqueChip } from '@/components/ui/badges'

interface PlaybookData {
  id: string
  title: string
  category: string
  attackType: string
  mitreTechniques: { id: string; name?: string }[]
  overview: string
  indicators: string[]
  investigationSteps: { step: string; details: string[] }[]
  containmentActions: string[]
  evidenceToCollect: string[]
  escalationCriteria: string[]
  falsePositives?: string[]
}

const PLAYBOOKS: PlaybookData[] = [
  {
    id: 'brute-force',
    title: 'Brute Force Attack Investigation',
    category: 'Credential Access',
    attackType: 'BRUTE_FORCE',
    mitreTechniques: [
      { id: 'T1110', name: 'Brute Force' },
      { id: 'T1110.001', name: 'Password Guessing' },
    ],
    overview:
      'A brute force attack involves systematic attempts to guess credentials by trying many password combinations against authentication endpoints.',
    indicators: [
      'Multiple failed authentication attempts (5+ in 5 minutes) from a single IP',
      'Rapid, machine-speed login attempts (< 1 second between attempts)',
      'Sequential or dictionary-based password attempts',
      'Single source IP targeting one user or multiple users simultaneously',
    ],
    investigationSteps: [
      {
        step: 'Identify Scope',
        details: [
          'How many failed attempts were observed and over what time period?',
          'Is the attack targeting a single user or multiple accounts (password spraying)?',
          'What is the source IP? Is it internal or external?',
          'Is the attack ongoing or historical?',
        ],
      },
      {
        step: 'Assess Success',
        details: [
          'Did any authentication attempts succeed after the failures?',
          'If yes, escalate immediately to Account Compromise response.',
          'Check for AUTH_SUCCESS events from the same source IP within the attack window.',
        ],
      },
      {
        step: 'Identify Target Context',
        details: [
          'Which user account(s) were targeted?',
          'Is the targeted account privileged (admin, service account)?',
          'What systems and applications were attacked?',
        ],
      },
      {
        step: 'Threat Attribution & Geolocation',
        details: [
          'Geolocate the source IP (if external).',
          'Check threat intelligence feeds for the attacking IP.',
          'Review firewall/proxy logs for other activity from this IP.',
        ],
      },
    ],
    containmentActions: [
      'Block the attacking IP at the firewall / WAF immediately.',
      'Lock the targeted account temporarily if attacks are ongoing.',
      'Alert the account owner if attacks were successful.',
      'Enable Multi-Factor Authentication (MFA) on the targeted account if not enrolled.',
      'Rate-limit authentication endpoints via reverse proxy or security controls.',
    ],
    evidenceToCollect: [
      'All AUTH_FAILURE events from the attacking IP',
      'Any AUTH_SUCCESS events from the attacking IP',
      'Network flow data and firewall logs for the source IP',
      'Application authentication logs',
    ],
    escalationCriteria: [
      'Escalate to CRITICAL if: a successful login follows the brute force',
      'Escalate to CRITICAL if: the targeted account has administrative privileges',
      'Notify management if: >100 attempts or attack spans >30 minutes',
    ],
    falsePositives: [
      'Legitimate users forgetting passwords (typically < 5 failures, then success from known IP)',
      'Automated deployment/testing scripts with incorrect credentials',
      'Password manager synchronization failures',
    ],
  },
  {
    id: 'account-compromise',
    title: 'Account Compromise Response',
    category: 'Initial Access',
    attackType: 'ACCOUNT_COMPROMISE',
    mitreTechniques: [
      { id: 'T1078', name: 'Valid Accounts' },
      { id: 'T1110', name: 'Brute Force Precursor' },
    ],
    overview:
      'Account compromise occurs when an attacker successfully gains unauthorized access to a legitimate user account, typically following credential theft, brute force, or phishing.',
    indicators: [
      'Multiple failed logins followed by a successful login from the same source IP',
      'Authentication success from an unusual geographic location or ASN',
      'Login at unusual hours outside normal work patterns',
      'Multiple sessions from geographically distant locations simultaneously',
      'First-time login from an unknown device or user-agent',
    ],
    investigationSteps: [
      {
        step: 'Confirm the Compromise',
        details: [
          'Verify the AUTH_SUCCESS event following failed attempts.',
          'Is the source IP consistent with the user’s normal activity baseline?',
          'Check if the successful login IP matches the attacking IP from prior failures.',
          'Review MFA reset or bypass activity around the time of compromise.',
        ],
      },
      {
        step: 'Determine Post-Compromise Activity',
        details: [
          'What actions did the attacker take after gaining access?',
          'Were any sensitive files accessed, downloaded, or modified?',
          'Were any new accounts created or permissions elevated?',
          'Check for PRIV_CHANGE events — did the attacker escalate privileges?',
        ],
      },
      {
        step: 'Establish Incident Timeline',
        details: [
          'When exactly was the account compromised?',
          'How long did the adversary have access before detection?',
          'Map all events chronologically from initial breach to detection.',
        ],
      },
    ],
    containmentActions: [
      'Force logout and invalidate all active sessions for the compromised account.',
      'Disable the account immediately in directory services.',
      'Block the attacker source IP at edge firewalls.',
      'Reset credentials with mandatory MFA re-enrollment.',
      'Preserve logs — do not rotate or delete authentication telemetry.',
      'Notify the affected user and security leadership.',
    ],
    evidenceToCollect: [
      'All authentication telemetry (failures + successes) for the compromised account',
      'Full session activity logs post-compromise',
      'Network traffic from the attacker IP',
      'File access logs for shared/sensitive resources',
    ],
    escalationCriteria: [
      'Immediately escalate if: privileged account (admin, service account) was compromised',
      'Escalate if: sensitive data was accessed (PII, credentials, financial data)',
      'Escalate if: lateral movement is detected',
      'Notify legal/compliance if regulated data was exposed',
    ],
  },
  {
    id: 'privilege-escalation',
    title: 'Privilege Escalation Response',
    category: 'Privilege Escalation',
    attackType: 'PRIVILEGE_ESCALATION',
    mitreTechniques: [
      { id: 'T1548', name: 'Abuse Elevation Control' },
      { id: 'T1548.003', name: 'Sudo and Sudo Caching' },
      { id: 'T1078.003', name: 'Local Accounts' },
    ],
    overview:
      'Privilege escalation occurs when an attacker or unauthorized user gains higher-level permissions than originally granted, enabling system-level administrative or root control.',
    indicators: [
      'PRIV_CHANGE event following recent authentication from a suspicious source',
      'User account receiving administrative or root privileges unexpectedly',
      'Sudo/su commands executed for non-administrative accounts',
      'Windows Event 4672 (Special privileges assigned to new logon)',
      'Unexpected role changes in IAM or directory services',
      'Access to sensitive files (/etc/shadow, SAM, NTDS.dit) after privilege change',
    ],
    investigationSteps: [
      {
        step: 'Confirm the Escalation',
        details: [
          'Which account received elevated privileges?',
          'What exact privileges or group memberships were granted?',
          'Was this authorized through an existing change management ticket?',
          'When did escalation occur relative to authentication?',
        ],
      },
      {
        step: 'Link to Preceding Activity',
        details: [
          'Was there a brute force or account compromise precursor?',
          'How much time elapsed between login and privilege escalation?',
          'Is the IP identical to previous failed attempts?',
        ],
      },
      {
        step: 'Assess Impact & Backdoors',
        details: [
          'What commands were executed with elevated privileges?',
          'Were any sensitive credential stores or shadow files accessed?',
          'Were persistence mechanisms installed (cron jobs, scheduled tasks, SSH keys)?',
        ],
      },
    ],
    containmentActions: [
      'Isolate the affected host from the network immediately.',
      'Revoke all elevated privileges granted during the incident window.',
      'Disable the compromised account (do not merely reset the password).',
      'Block lateral movement via firewall rules between the affected host and internal subnets.',
      'Preserve memory dump — capture volatile evidence before any host reboot.',
    ],
    evidenceToCollect: [
      'Linux: /var/log/auth.log, /var/log/secure, and sudo logs',
      'Windows: Event IDs 4624, 4625, 4672, 4688, 4663',
      'Process execution logs around the time of escalation',
      'Memory dump for forensic analysis',
    ],
    escalationCriteria: [
      'ALWAYS Critical: escalation on a Domain Controller (DC) or core database',
      'ALWAYS Critical: credential store access (SAM, NTDS.dit, /etc/shadow)',
      'ALWAYS Critical: execution of known credential dumping binaries',
    ],
  },
  {
    id: 'lateral-movement',
    title: 'Lateral Movement Response',
    category: 'Lateral Movement',
    attackType: 'LATERAL_MOVEMENT',
    mitreTechniques: [
      { id: 'T1021', name: 'Remote Services' },
      { id: 'T1021.001', name: 'RDP' },
      { id: 'T1021.002', name: 'SMB / Admin Shares' },
      { id: 'T1021.004', name: 'SSH' },
    ],
    overview:
      'Lateral movement refers to techniques adversaries use to extend access across systems and hosts in an internal network after gaining an initial foothold.',
    indicators: [
      'Unusual internal SSH, RDP, or SMB connections originating from an endpoint workstation',
      'WinRM (PowerShell Remoting) sessions established across peer workstations',
      'PsExec or WMI process creation across remote network shares',
      'Multiple logon attempts using the same credential across distinct subnets',
      'Use of remote execution tools (psexec, wmic, winrs, sshpass)',
    ],
    investigationSteps: [
      {
        step: 'Identify Pivot Source',
        details: [
          'Which internal host initiated the lateral connection?',
          'Is that source host already flagged for previous security alerts?',
          'What user credentials were used to authenticate to the remote target?',
        ],
      },
      {
        step: 'Map Destination Targets',
        details: [
          'How many distinct hosts were targeted from the compromised pivot point?',
          'Were the targeted hosts servers, domain controllers, or peer workstations?',
          'Did authentication succeed or fail across the target systems?',
        ],
      },
    ],
    containmentActions: [
      'Block east-west traffic from the source host at the switch / firewall level.',
      'Terminate all active RDP, SSH, and SMB sessions associated with the source host.',
      'Disable user and service accounts utilized during the lateral movement.',
      'Place all confirmed target hosts into quarantine VLANs.',
      'Enforce unique local administrator passwords via LAPS.',
    ],
    evidenceToCollect: [
      'Network flow and firewall logs showing internal east-west connection attempts',
      'Authentication logs on target systems (Event ID 4624, sshd logs)',
      'Service creation telemetry on target systems (Event ID 7045)',
      'Kerberos ticket requests (Event ID 4768, 4769)',
    ],
    escalationCriteria: [
      'Escalate to CRITICAL if: Lateral movement targets Domain Controllers or critical database hosts.',
      'Escalate to CRITICAL if: Pass-the-hash or pass-the-ticket execution is confirmed.',
      'Escalate to HIGH if: More than 3 internal hosts are accessed by the adversary.',
    ],
  },
  {
    id: 'credential-dumping',
    title: 'Credential Dumping Response',
    category: 'Credential Access',
    attackType: 'CREDENTIAL_DUMPING',
    mitreTechniques: [
      { id: 'T1003', name: 'OS Credential Dumping' },
      { id: 'T1003.001', name: 'LSASS Memory' },
      { id: 'T1003.002', name: 'Security Account Manager' },
      { id: 'T1003.008', name: '/etc/shadow' },
    ],
    overview:
      'Credential dumping involves extracting account login credentials (plaintext passwords, password hashes, Kerberos tickets, or tokens) from operating system memory or local database hives.',
    indicators: [
      'Access to LSASS process memory (Sysmon Event ID 10 with PROCESS_VM_READ mask)',
      'Execution of dumping utilities: mimikatz, procdump, comsvcs.dll, secretsdump.py',
      'Reading of sensitive system files: SAM hive, NTDS.dit, or /etc/shadow',
      'Volume Shadow Copy creation targeting the system drive (vssadmin create shadow)',
      'Suspicious registry export targeting HKLM\\SAM or HKLM\\SECURITY',
    ],
    investigationSteps: [
      {
        step: 'Identify Process Context',
        details: [
          'Which process accessed LSASS or the SAM registry hive?',
          'Which user account executed the dumping process? Was it already elevated?',
          'What command-line arguments were passed to the suspicious binary?',
        ],
      },
      {
        step: 'Determine Credential Scope',
        details: [
          'What credential repositories were targeted (LSASS, SAM, NTDS.dit, /etc/shadow)?',
          'Were domain credentials or service accounts exposed in memory?',
        ],
      },
    ],
    containmentActions: [
      'Disconnect the host from the network immediately to prevent dumped credentials from being used.',
      'Reset passwords for all accounts logged into the compromised host during the window.',
      'If NTDS.dit was dumped, perform the two-stage KRBTGT account password reset.',
      'Purge active Kerberos tickets across domain endpoints (klist purge).',
      'Terminate malicious processes and remove associated memory dump files.',
    ],
    evidenceToCollect: [
      'Process creation and injection logs (Sysmon Event IDs 1, 8, 10)',
      'Security audit logs for SAM/LSA policy changes (Windows Event IDs 4663, 4672, 4703)',
      'Command-line audit logs (Event ID 4688)',
      'Memory forensics artifacts showing injected DLLs',
    ],
    escalationCriteria: [
      'ALWAYS Critical: LSASS dumping on Domain Controllers, Exchange, or ADFS.',
      'ALWAYS Critical: NTDS.dit or SAM registry hive access.',
      'Escalate to High: Execution of recognized dumping utilities on any domain-joined host.',
    ],
  },
]

export default function PlaybooksPage() {
  const [selectedId, setSelectedId] = useState<string>(PLAYBOOKS[0].id)
  const [search, setSearch] = useState('')
  const [copied, setCopied] = useState(false)

  const activePlaybook = PLAYBOOKS.find((p) => p.id === selectedId) || PLAYBOOKS[0]

  const filteredPlaybooks = PLAYBOOKS.filter((p) => {
    if (!search.trim()) return true
    const q = search.toLowerCase()
    return (
      p.title.toLowerCase().includes(q) ||
      p.category.toLowerCase().includes(q) ||
      p.attackType.toLowerCase().includes(q) ||
      p.mitreTechniques.some((t) => t.id.toLowerCase().includes(q) || (t.name || '').toLowerCase().includes(q))
    )
  })

  const copyPlaybook = () => {
    const text = `# ${activePlaybook.title}\n\nOverview:\n${activePlaybook.overview}\n\nContainment Actions:\n${activePlaybook.containmentActions.map((a, i) => `${i + 1}. ${a}`).join('\n')}`
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#1f2937] pb-5">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[#f3f4f6]">
            Incident Response Playbook Library
          </h1>
          <p className="mt-1 text-xs text-[#9ca3af]">
            MITRE ATT&CK-aligned investigation, containment, and eradication procedures
          </p>
        </div>

        <Link href="/incidents" className="btn-primary text-xs py-1.5 px-3">
          <Shield className="mr-1.5 h-3.5 w-3.5" />
          Triage Incidents
        </Link>
      </div>

      {/* Main Two-Column Layout */}
      <div className="grid gap-6 lg:grid-cols-[320px_1fr]">
        {/* Left: Playbook Selector */}
        <div className="space-y-3">
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[#6b7280]" />
            <input
              type="text"
              placeholder="Search playbooks or MITRE ID..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input w-full pl-9 font-mono text-xs"
            />
          </div>

          <div className="space-y-2">
            {filteredPlaybooks.map((pb) => {
              const isSelected = pb.id === selectedId
              return (
                <button
                  key={pb.id}
                  type="button"
                  onClick={() => setSelectedId(pb.id)}
                  className={`w-full text-left rounded-xl border p-3.5 transition ${
                    isSelected
                      ? 'border-[#10b981] bg-[#171e28] shadow-sm'
                      : 'border-[#1f2937] bg-[#11161d] hover:border-[#374151] hover:bg-[#141b24]'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-[10px] uppercase text-[#10b981] font-semibold">
                      {pb.category}
                    </span>
                    <ChevronRight className={`h-3.5 w-3.5 ${isSelected ? 'text-[#10b981]' : 'text-[#6b7280]'}`} />
                  </div>
                  <h3 className="mt-1 text-xs font-semibold text-[#f3f4f6] line-clamp-1">
                    {pb.title}
                  </h3>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {pb.mitreTechniques.slice(0, 2).map((t) => (
                      <span
                        key={t.id}
                        className="rounded bg-[#0b0f14] px-1.5 py-0.5 font-mono text-[10px] text-[#9ca3af] border border-[#1f2937]"
                      >
                        {t.id}
                      </span>
                    ))}
                  </div>
                </button>
              )
            })}
          </div>
        </div>

        {/* Right: Active Playbook Reader */}
        <div className="card p-6 border-[#1f2937] bg-[#11161d] space-y-6">
          {/* Header */}
          <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#1f2937] pb-4">
            <div className="space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded border border-[#10b981]/30 bg-[#10b981]/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase text-[#34d399]">
                  {activePlaybook.category}
                </span>
                <span className="rounded border border-[#1f2937] bg-[#171e28] px-2 py-0.5 font-mono text-[10px] text-[#9ca3af]">
                  Type: {activePlaybook.attackType}
                </span>
              </div>
              <h2 className="text-lg font-bold text-[#f3f4f6]">
                {activePlaybook.title}
              </h2>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={copyPlaybook}
                className="btn-ghost text-xs py-1.5 px-3"
              >
                {copied ? <Check className="mr-1.5 h-3.5 w-3.5 text-[#10b981]" /> : <Copy className="mr-1.5 h-3.5 w-3.5" />}
                <span>{copied ? 'Copied' : 'Copy Playbook'}</span>
              </button>
            </div>
          </div>

          {/* MITRE Mapping Bar */}
          <div className="rounded-lg border border-[#1f2937] bg-[#0b0f14] p-3.5">
            <span className="font-mono text-[10px] uppercase text-[#6b7280] font-semibold block mb-2">
              Mapped MITRE ATT&CK Techniques:
            </span>
            <div className="flex flex-wrap gap-2">
              {activePlaybook.mitreTechniques.map((t) => (
                <MitreTechniqueChip
                  key={t.id}
                  techniqueId={t.id}
                  techniqueName={t.name}
                  url={`https://attack.mitre.org/techniques/${t.id.replace('.', '/')}`}
                />
              ))}
            </div>
          </div>

          {/* Overview */}
          <div className="space-y-1.5">
            <h4 className="font-mono text-xs uppercase font-semibold text-[#10b981]">
              Overview & Threat Context
            </h4>
            <p className="text-xs text-[#d1d5db] leading-relaxed">
              {activePlaybook.overview}
            </p>
          </div>

          {/* Detection Indicators */}
          <div className="space-y-2">
            <h4 className="font-mono text-xs uppercase font-semibold text-[#facc15] flex items-center gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5" />
              Detection Indicators
            </h4>
            <ul className="space-y-1.5 pl-4 text-xs text-[#9ca3af] list-disc">
              {activePlaybook.indicators.map((ind, idx) => (
                <li key={idx} className="leading-relaxed">{ind}</li>
              ))}
            </ul>
          </div>

          {/* Triage / Investigation Steps */}
          <div className="space-y-3 border-t border-[#1f2937] pt-4">
            <h4 className="font-mono text-xs uppercase font-semibold text-[#38bdf8] flex items-center gap-1.5">
              <Terminal className="h-3.5 w-3.5" />
              Triage & Forensic Steps
            </h4>
            <div className="grid gap-3 sm:grid-cols-2">
              {activePlaybook.investigationSteps.map((step, idx) => (
                <div key={idx} className="rounded-lg border border-[#1f2937] bg-[#141b24] p-3.5 space-y-1.5">
                  <span className="font-mono text-xs font-semibold text-[#f3f4f6] block">
                    Step {idx + 1}: {step.step}
                  </span>
                  <ul className="space-y-1 pl-3 text-xs text-[#9ca3af] list-disc">
                    {step.details.map((d, dIdx) => (
                      <li key={dIdx} className="leading-relaxed">{d}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>

          {/* Containment Actions */}
          <div className="space-y-2 border-t border-[#1f2937] pt-4">
            <h4 className="font-mono text-xs uppercase font-semibold text-[#f87171] flex items-center gap-1.5">
              <Lock className="h-3.5 w-3.5" />
              Mandatory Containment Actions
            </h4>
            <ol className="space-y-2 pl-4 text-xs text-[#d1d5db] list-decimal font-mono">
              {activePlaybook.containmentActions.map((action, idx) => (
                <li key={idx} className="leading-relaxed pl-1">
                  {action}
                </li>
              ))}
            </ol>
          </div>

          {/* Evidence to Collect & Escalation */}
          <div className="grid gap-4 sm:grid-cols-2 border-t border-[#1f2937] pt-4">
            <div className="space-y-2">
              <span className="font-mono text-xs font-semibold text-[#9ca3af] block">
                Forensic Evidence Checklist
              </span>
              <ul className="space-y-1 pl-3 text-xs text-[#6b7280] list-disc">
                {activePlaybook.evidenceToCollect.map((ev, idx) => (
                  <li key={idx}>{ev}</li>
                ))}
              </ul>
            </div>

            <div className="space-y-2">
              <span className="font-mono text-xs font-semibold text-[#f87171] block">
                Escalation Thresholds
              </span>
              <ul className="space-y-1 pl-3 text-xs text-[#6b7280] list-disc">
                {activePlaybook.escalationCriteria.map((esc, idx) => (
                  <li key={idx}>{esc}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
