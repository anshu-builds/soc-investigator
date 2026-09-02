'use client'

import React, { useState } from 'react'
import Link from 'next/link'
import {
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  BookOpen,
  Check,
  CheckCircle2,
  ChevronRight,
  Clock,
  Copy,
  ExternalLink,
  FileCheck,
  FileText,
  Flame,
  Info,
  Layers,
  ListOrdered,
  Lock,
  Search,
  Shield,
  ShieldAlert,
  Sparkles,
  Terminal,
  UserCheck,
  Wifi,
  X,
  Zap,
} from 'lucide-react'

import { MitreTechniqueChip } from '@/components/ui/badges'
import { useToast } from '@/components/ui/Toast'

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
      'Block the attacking IP at the edge firewall / WAF immediately.',
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

const CATEGORIES = [
  'All Categories',
  'Credential Access',
  'Initial Access',
  'Privilege Escalation',
  'Lateral Movement',
]

export default function PlaybooksPage() {
  const { success } = useToast()

  const [selectedId, setSelectedId] = useState<string>(PLAYBOOKS[0].id)
  const [search, setSearch] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('All Categories')
  const [copied, setCopied] = useState(false)

  const activePlaybook = PLAYBOOKS.find((p) => p.id === selectedId) || PLAYBOOKS[0]

  const filteredPlaybooks = PLAYBOOKS.filter((p) => {
    // Category filter
    if (selectedCategory !== 'All Categories' && p.category !== selectedCategory) {
      return false
    }

    // Search query filter
    if (!search.trim()) return true
    const q = search.toLowerCase()
    return (
      p.title.toLowerCase().includes(q) ||
      p.category.toLowerCase().includes(q) ||
      p.attackType.toLowerCase().includes(q) ||
      p.overview.toLowerCase().includes(q) ||
      p.indicators.some((ind) => ind.toLowerCase().includes(q)) ||
      p.containmentActions.some((act) => act.toLowerCase().includes(q)) ||
      p.mitreTechniques.some(
        (t) => t.id.toLowerCase().includes(q) || (t.name || '').toLowerCase().includes(q)
      )
    )
  })

  const copyPlaybook = () => {
    const text = `# ${activePlaybook.title} (SOP)
Category: ${activePlaybook.category}
Attack Type: ${activePlaybook.attackType}
Mode: Analyst-Guided Procedure

## Threat Overview
${activePlaybook.overview}

## Detection Indicators
${activePlaybook.indicators.map((i) => `- ${i}`).join('\n')}

## Triage & Investigation Steps
${activePlaybook.investigationSteps
  .map(
    (step, idx) =>
      `Step ${idx + 1}: ${step.step}\n${step.details.map((d) => `  * ${d}`).join('\n')}`
  )
  .join('\n\n')}

## Mandatory Containment Actions
${activePlaybook.containmentActions.map((a, i) => `${i + 1}. ${a}`).join('\n')}

## Forensic Evidence Checklist
${activePlaybook.evidenceToCollect.map((e) => `- ${e}`).join('\n')}

## Escalation Thresholds
${activePlaybook.escalationCriteria.map((c) => `- ${c}`).join('\n')}`

    navigator.clipboard.writeText(text)
    setCopied(true)
    success('Copied SOP to Clipboard', `${activePlaybook.title} procedure copied`)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-bold tracking-tight text-ink-primary">
              SOC Incident Response Playbooks
            </h1>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-elevated px-2.5 py-0.5 font-mono text-[11px] text-ink-secondary">
              <BookOpen className="h-3 w-3 text-accent-emerald" />
              <span>{PLAYBOOKS.length} Standard Operating Procedures</span>
            </span>
          </div>
          <p className="mt-1 text-xs text-ink-secondary leading-relaxed">
            MITRE ATT&CK-aligned investigation checklists, containment protocols, and evidence preservation guidelines.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Link href="/incidents" className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5">
            <Shield className="h-3.5 w-3.5" />
            <span>Incident Queue</span>
          </Link>
        </div>
      </div>

      {/* Main Two-Column Library Layout */}
      <div className="grid gap-6 lg:grid-cols-[330px_1fr]">
        {/* Left Column: Playbook Selector & Filters */}
        <div className="space-y-3.5">
          {/* Search Box */}
          <div className="relative">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-muted" />
            <input
              type="text"
              placeholder="Search playbooks, MITRE ID..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input w-full pl-9 pr-7 font-mono text-xs"
            />
            {search && (
              <button
                type="button"
                onClick={() => setSearch('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-ink-muted hover:text-ink-primary"
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </div>

          {/* Category Filter Chips */}
          <div className="flex flex-wrap gap-1.5 pb-1">
            {CATEGORIES.map((cat) => {
              const count =
                cat === 'All Categories'
                  ? PLAYBOOKS.length
                  : PLAYBOOKS.filter((p) => p.category === cat).length
              const isActive = selectedCategory === cat
              return (
                <button
                  key={cat}
                  type="button"
                  onClick={() => setSelectedCategory(cat)}
                  className={`rounded-lg px-2 py-1 text-[11px] font-mono transition ${
                    isActive
                      ? 'bg-elevated text-ink-primary font-bold border border-border-active shadow-sm'
                      : 'text-ink-muted hover:text-ink-primary hover:bg-elevated/40'
                  }`}
                >
                  <span>{cat}</span>
                  <span className="ml-1 text-[10px] text-ink-muted font-normal">({count})</span>
                </button>
              )
            })}
          </div>

          {/* Playbook List Cards */}
          <div className="space-y-2">
            {filteredPlaybooks.length === 0 ? (
              <div className="card p-6 text-center border-border-subtle bg-panel space-y-2">
                <Info className="mx-auto h-5 w-5 text-ink-muted" />
                <p className="text-xs text-ink-secondary">No playbooks match filter criteria</p>
                <button
                  type="button"
                  onClick={() => {
                    setSearch('')
                    setSelectedCategory('All Categories')
                  }}
                  className="text-xs text-accent-emerald hover:underline font-mono"
                >
                  Reset filters
                </button>
              </div>
            ) : (
              filteredPlaybooks.map((pb) => {
                const isSelected = pb.id === selectedId
                return (
                  <button
                    key={pb.id}
                    type="button"
                    tabIndex={0}
                    onClick={() => setSelectedId(pb.id)}
                    className={`w-full text-left rounded border p-3 transition-colors group ${
                      isSelected
                        ? 'border-accent-emerald/80 bg-elevated'
                        : 'border-border/80 bg-panel/60 hover:border-border hover:bg-elevated/40'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-[10px] uppercase text-accent-emerald font-medium">
                        {pb.category}
                      </span>
                      <ChevronRight
                        className={`h-3.5 w-3.5 transition-transform ${
                          isSelected
                            ? 'text-accent-emerald translate-x-0.5'
                            : 'text-ink-muted group-hover:text-ink-secondary'
                        }`}
                      />
                    </div>

                    <h3 className="mt-1 text-xs font-semibold text-ink-primary line-clamp-1 group-hover:text-accent-emerald transition-colors">
                      {pb.title}
                    </h3>

                    <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[10px] font-mono text-ink-muted">
                      <span>{pb.investigationSteps.length} Steps</span>
                      <span>·</span>
                      <span>{pb.containmentActions.length} Actions</span>
                    </div>

                    <div className="mt-2 flex flex-wrap gap-1">
                      {pb.mitreTechniques.slice(0, 2).map((t) => (
                        <span
                          key={t.id}
                          className="rounded bg-canvas px-1.5 py-0.5 font-mono text-[10px] text-ink-secondary border border-border-subtle"
                        >
                          {t.id}
                        </span>
                      ))}
                      {pb.mitreTechniques.length > 2 && (
                        <span className="text-[10px] text-ink-muted self-center">
                          +{pb.mitreTechniques.length - 2}
                        </span>
                      )}
                    </div>
                  </button>
                )
              })
            )}
          </div>
        </div>

        {/* Right Column: Active Playbook Reader Dossier */}
        <div className="rounded-lg border border-border/80 bg-panel p-5 sm:p-6 space-y-5 shadow-sm">
          {/* Header Strip */}
          <div className="flex flex-wrap items-start justify-between gap-4 border-b border-border-subtle pb-5">
            <div className="space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="rounded-md border border-accent-emerald/30 bg-accent-emerald/10 px-2 py-0.5 font-mono text-[10px] font-bold uppercase text-accent-emerald">
                  {activePlaybook.category}
                </span>
                <span className="rounded-md border border-border bg-elevated px-2 py-0.5 font-mono text-[10px] text-ink-secondary">
                  Type: {activePlaybook.attackType}
                </span>
                <span className="rounded-md border border-border-subtle bg-canvas px-2 py-0.5 font-mono text-[10px] text-ink-muted flex items-center gap-1">
                  <UserCheck className="h-3 w-3 text-accent-emerald" />
                  <span>Analyst-Guided Procedure</span>
                </span>
              </div>

              <h2 className="text-xl font-bold tracking-tight text-ink-primary">
                {activePlaybook.title}
              </h2>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={copyPlaybook}
                className="btn-ghost text-xs py-1.5 px-3 flex items-center gap-1.5"
                title="Copy full standard operating procedure to clipboard"
              >
                {copied ? (
                  <>
                    <Check className="h-3.5 w-3.5 text-accent-emerald" />
                    <span className="text-accent-emerald">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" />
                    <span>Copy SOP</span>
                  </>
                )}
              </button>

              <Link
                href="/incidents"
                className="btn-primary text-xs py-1.5 px-3 flex items-center gap-1.5"
                title="Triage incidents matching this attack vector"
              >
                <ShieldAlert className="h-3.5 w-3.5" />
                <span>Triage Incidents</span>
              </Link>
            </div>
          </div>

          {/* MITRE ATT&CK Framework Mapping Strip */}
          <div className="rounded-xl border border-border bg-canvas/70 p-4 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="font-mono text-[10px] uppercase text-ink-muted font-bold tracking-wider">
                Mapped MITRE ATT&CK Framework Techniques
              </span>
              <span className="text-[10px] text-ink-muted font-mono">
                Authoritative Reference
              </span>
            </div>
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

          {/* Overview & Threat Context */}
          <div className="space-y-1.5">
            <h3 className="font-mono text-xs uppercase font-bold text-accent-emerald flex items-center gap-1.5 tracking-wide">
              <Info className="h-3.5 w-3.5" />
              <span>Threat Context & Overview</span>
            </h3>
            <p className="text-xs text-ink-secondary leading-relaxed bg-elevated/40 p-4 rounded-xl border border-border-subtle">
              {activePlaybook.overview}
            </p>
          </div>

          {/* Detection Indicators */}
          <div className="space-y-2">
            <h3 className="font-mono text-xs uppercase font-bold text-[#facc15] flex items-center gap-1.5 tracking-wide">
              <AlertTriangle className="h-3.5 w-3.5" />
              <span>Detection Signatures & Telemetry Triggers</span>
            </h3>
            <div className="rounded-xl border border-[#713f12]/30 bg-[#422006]/20 p-4">
              <ul className="space-y-2 text-xs text-ink-primary">
                {activePlaybook.indicators.map((ind, idx) => (
                  <li key={idx} className="flex items-start gap-2.5">
                    <span className="h-1.5 w-1.5 rounded-full bg-[#facc15] mt-1.5 shrink-0" />
                    <span className="leading-relaxed font-sans">{ind}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Triage & Forensic Investigation Steps */}
          <div className="space-y-3 border-t border-border-subtle pt-5">
            <h3 className="font-mono text-xs uppercase font-bold text-accent-cyan flex items-center gap-1.5 tracking-wide">
              <Terminal className="h-3.5 w-3.5" />
              <span>Triage & Forensic Investigation Protocol</span>
            </h3>
            <div className="grid gap-3 sm:grid-cols-2">
              {activePlaybook.investigationSteps.map((step, idx) => (
                <div
                  key={idx}
                  className="rounded-xl border border-border bg-elevated/40 p-4 space-y-2"
                >
                  <span className="font-mono text-xs font-bold text-ink-primary block border-b border-border-subtle pb-1.5">
                    Step {idx + 1}: {step.step}
                  </span>
                  <ul className="space-y-1.5 text-xs text-ink-secondary">
                    {step.details.map((d, dIdx) => (
                      <li key={dIdx} className="flex items-start gap-2">
                        <span className="text-accent-cyan mt-0.5">•</span>
                        <span className="leading-relaxed">{d}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </div>

          {/* Mandatory Containment Actions */}
          <div className="space-y-3 border-t border-border-subtle pt-5">
            <div className="flex items-center justify-between">
              <h3 className="font-mono text-xs uppercase font-bold text-severity-critical flex items-center gap-1.5 tracking-wide">
                <Lock className="h-3.5 w-3.5" />
                <span>Mandatory Threat Containment Actions</span>
              </h3>
              <span className="text-[10px] font-mono font-bold uppercase text-severity-critical bg-severity-critical/10 px-2 py-0.5 rounded border border-severity-critical/30">
                Action Required
              </span>
            </div>
            <div className="rounded-xl border border-severity-critical/30 bg-severity-critical/10 p-4">
              <ol className="space-y-2.5 font-mono text-xs text-ink-primary">
                {activePlaybook.containmentActions.map((action, idx) => (
                  <li key={idx} className="flex items-start gap-3">
                    <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded bg-severity-critical/20 border border-severity-critical/40 text-[10px] font-bold text-severity-critical">
                      {idx + 1}
                    </span>
                    <span className="leading-relaxed font-sans mt-0.5">{action}</span>
                  </li>
                ))}
              </ol>
            </div>
          </div>

          {/* Forensic Evidence Checklist & Escalation Thresholds */}
          <div className="grid gap-4 sm:grid-cols-2 border-t border-border-subtle pt-5">
            {/* Evidence Checklist */}
            <div className="rounded-xl border border-border bg-elevated/30 p-4 space-y-2.5">
              <span className="font-mono text-xs font-bold text-ink-primary block flex items-center gap-1.5">
                <FileCheck className="h-3.5 w-3.5 text-accent-emerald" />
                <span>Forensic Evidence Preservation</span>
              </span>
              <ul className="space-y-1.5 text-xs text-ink-secondary">
                {activePlaybook.evidenceToCollect.map((ev, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="text-accent-emerald mt-0.5">✓</span>
                    <span className="leading-relaxed">{ev}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Escalation Thresholds */}
            <div className="rounded-xl border border-border bg-elevated/30 p-4 space-y-2.5">
              <span className="font-mono text-xs font-bold text-severity-critical block flex items-center gap-1.5">
                <AlertCircle className="h-3.5 w-3.5 text-severity-critical" />
                <span>Escalation Thresholds</span>
              </span>
              <ul className="space-y-1.5 text-xs text-ink-secondary">
                {activePlaybook.escalationCriteria.map((esc, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="text-severity-critical mt-0.5">▲</span>
                    <span className="leading-relaxed">{esc}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* False Positive Guidance if provided */}
          {activePlaybook.falsePositives && activePlaybook.falsePositives.length > 0 && (
            <div className="border-t border-border-subtle pt-4 space-y-2">
              <span className="font-mono text-xs font-bold text-ink-muted uppercase tracking-wider block">
                Known Benign Patterns / False Positives
              </span>
              <ul className="space-y-1 pl-3 text-xs text-ink-secondary list-disc">
                {activePlaybook.falsePositives.map((fp, idx) => (
                  <li key={idx} className="leading-relaxed">{fp}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
