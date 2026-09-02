/**
 * ============================================================================
 * DESIGN PREVIEW ONLY — NOT FOR PRODUCTION
 * ============================================================================
 * Representative, synthetic data used purely so the authenticated SOC UI can
 * be visually inspected inside the v0 sandbox while the real FastAPI backend
 * is unavailable. None of this data is real. This whole `preview/` directory
 * is inert in production builds and is meant to be deleted before merge.
 * ============================================================================
 */
import type {
  AttackHypothesis,
  ChatMessage,
  DashboardSummary,
  Evidence,
  Incident,
  IncidentSummary,
  ReportOut,
  SecurityEvent,
  WazuhStatusResponse,
} from '@/lib/types'

const now = Date.now()
const iso = (minutesAgo: number) => new Date(now - minutesAgo * 60_000).toISOString()

/* -------------------------------------------------------------------------- */
/* Security events                                                            */
/* -------------------------------------------------------------------------- */

export const events: SecurityEvent[] = [
  {
    id: 'ev-2001',
    source_ip: '185.220.101.44',
    destination_ip: '10.4.12.19',
    username: 'jdoe',
    hostname: 'FIN-WKS-07',
    event_type: 'authentication_failure',
    event_category: 'authentication',
    timestamp: iso(184),
    description: 'Repeated failed SSH authentication from foreign ASN',
    raw_log:
      'Sep 03 04:11:22 FIN-WKS-07 sshd[4412]: Failed password for jdoe from 185.220.101.44 port 51544 ssh2',
    source_file: 'auth.log',
    is_flagged: true,
    incident_id: 'inc-1001',
  },
  {
    id: 'ev-2002',
    source_ip: '185.220.101.44',
    destination_ip: '10.4.12.19',
    username: 'jdoe',
    hostname: 'FIN-WKS-07',
    event_type: 'authentication_success',
    event_category: 'authentication',
    timestamp: iso(171),
    description: 'Successful login after burst of failures (possible credential stuffing)',
    raw_log:
      'Sep 03 04:24:03 FIN-WKS-07 sshd[4460]: Accepted password for jdoe from 185.220.101.44 port 51981 ssh2',
    source_file: 'auth.log',
    is_flagged: true,
    incident_id: 'inc-1001',
  },
  {
    id: 'ev-2003',
    source_ip: '10.4.12.19',
    username: 'jdoe',
    hostname: 'FIN-WKS-07',
    event_type: 'privilege_escalation',
    event_category: 'privilege',
    timestamp: iso(158),
    description: 'User added to local Administrators group',
    raw_log:
      'Sep 03 04:37:41 FIN-WKS-07 sudo: jdoe : TTY=pts/1 ; PWD=/home/jdoe ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo jdoe',
    source_file: 'auth.log',
    is_flagged: true,
    incident_id: 'inc-1001',
  },
  {
    id: 'ev-2004',
    source_ip: '10.4.12.19',
    destination_ip: '10.4.2.5',
    username: 'jdoe',
    hostname: 'FIN-WKS-07',
    event_type: 'lateral_movement',
    event_category: 'network',
    timestamp: iso(142),
    description: 'SMB session opened to domain controller with new admin token',
    raw_log:
      'Sep 03 04:53:10 FIN-WKS-07 smbd[7781]: authenticated session to \\\\DC-01\\ADMIN$ as jdoe (elevated)',
    source_file: 'smb.log',
    is_flagged: true,
    incident_id: 'inc-1001',
  },
  {
    id: 'ev-2010',
    source_ip: '92.63.197.12',
    destination_ip: '10.4.12.40',
    username: 'svc_backup',
    hostname: 'DB-EDGE-02',
    event_type: 'authentication_failure',
    event_category: 'authentication',
    timestamp: iso(96),
    description: 'High-volume password spray against service account',
    raw_log:
      'Sep 03 05:39:55 DB-EDGE-02 sshd[9912]: Failed password for svc_backup from 92.63.197.12 port 40122 ssh2',
    source_file: 'auth.log',
    is_flagged: true,
    incident_id: 'inc-1002',
  },
  {
    id: 'ev-2011',
    source_ip: '92.63.197.12',
    destination_ip: '10.4.12.40',
    username: 'svc_backup',
    hostname: 'DB-EDGE-02',
    event_type: 'authentication_failure',
    event_category: 'authentication',
    timestamp: iso(94),
    description: 'Continued brute force, 240 attempts in 2 minutes',
    raw_log:
      'Sep 03 05:41:19 DB-EDGE-02 sshd[9987]: Failed password for svc_backup from 92.63.197.12 port 40410 ssh2',
    source_file: 'auth.log',
    is_flagged: true,
    incident_id: 'inc-1002',
  },
  {
    id: 'ev-2020',
    source_ip: '10.4.8.31',
    username: 'mrossi',
    hostname: 'ENG-WKS-22',
    event_type: 'privilege_escalation',
    event_category: 'privilege',
    timestamp: iso(58),
    description: 'Unexpected sudo policy modification',
    raw_log:
      'Sep 03 06:17:02 ENG-WKS-22 sudo: mrossi : TTY=pts/0 ; PWD=/etc ; USER=root ; COMMAND=/usr/bin/vi /etc/sudoers',
    source_file: 'auth.log',
    is_flagged: true,
    incident_id: 'inc-1003',
  },
  {
    id: 'ev-2030',
    source_ip: '203.0.113.9',
    username: 'awilson',
    hostname: 'HR-WKS-03',
    event_type: 'authentication_success',
    event_category: 'authentication',
    timestamp: iso(410),
    description: 'Login from previously unseen geolocation',
    raw_log:
      'Sep 03 00:05:12 HR-WKS-03 sshd[2201]: Accepted password for awilson from 203.0.113.9 port 33210 ssh2',
    source_file: 'auth.log',
    is_flagged: true,
    incident_id: 'inc-1004',
  },
  {
    id: 'ev-2040',
    source_ip: '198.51.100.23',
    username: 'guest',
    hostname: 'DMZ-PROXY-01',
    event_type: 'authentication_failure',
    event_category: 'authentication',
    timestamp: iso(720),
    description: 'Low-and-slow guest login attempts (later confirmed benign scanner)',
    raw_log:
      'Sep 02 18:02:41 DMZ-PROXY-01 sshd[1180]: Failed password for guest from 198.51.100.23 port 22001 ssh2',
    source_file: 'auth.log',
    is_flagged: false,
    incident_id: 'inc-1005',
  },
  {
    id: 'ev-3001',
    source_ip: '10.4.12.19',
    username: 'jdoe',
    hostname: 'FIN-WKS-07',
    event_type: 'process_creation',
    event_category: 'process',
    timestamp: iso(150),
    description: 'Encoded PowerShell spawned by office application',
    raw_log:
      'Sep 03 04:45:00 FIN-WKS-07 CreateProcess: powershell.exe -enc SQBFAFgAKA... parent=winword.exe',
    source_file: 'sysmon.log',
    is_flagged: true,
  },
  {
    id: 'ev-3002',
    source_ip: '10.4.2.5',
    username: 'SYSTEM',
    hostname: 'DC-01',
    event_type: 'account_created',
    event_category: 'account',
    timestamp: iso(120),
    description: 'New domain account created outside change window',
    raw_log:
      'Sep 03 05:15:33 DC-01 Security: A user account was created. New Account: svc_helpdesk2',
    source_file: 'windows-security.log',
    is_flagged: true,
  },
]

const eventById = (id: string) => events.find((e) => e.id === id)!

/* -------------------------------------------------------------------------- */
/* Incidents                                                                  */
/* -------------------------------------------------------------------------- */

const hypothesis1: AttackHypothesis = {
  classification: 'Account Compromise with Privilege Escalation',
  confidence: 0.91,
  narrative:
    'An external actor conducted credential stuffing against jdoe from a TOR exit node, gained interactive access, escalated to local administrator, then pivoted to the domain controller over SMB. Behaviour is consistent with hands-on-keyboard intrusion progressing toward domain dominance.',
  phases: [
    {
      phase: 'Initial Access',
      technique: 'T1110.004',
      technique_name: 'Credential Stuffing',
      description: 'Burst of failed SSH auth followed by a successful login from the same foreign IP.',
      event_ids: ['ev-2001', 'ev-2002'],
      timestamp_start: iso(184),
      timestamp_end: iso(171),
      event_count: 2,
    },
    {
      phase: 'Execution',
      technique: 'T1059.001',
      technique_name: 'PowerShell',
      description: 'Encoded PowerShell payload spawned from a document macro.',
      event_ids: ['ev-3001'],
      timestamp_start: iso(150),
      timestamp_end: iso(150),
      event_count: 1,
    },
    {
      phase: 'Privilege Escalation',
      technique: 'T1078.003',
      technique_name: 'Local Accounts',
      description: 'Compromised user added to the local Administrators group.',
      event_ids: ['ev-2003'],
      timestamp_start: iso(158),
      timestamp_end: iso(158),
      event_count: 1,
    },
    {
      phase: 'Lateral Movement',
      technique: 'T1021.002',
      technique_name: 'SMB / Admin Shares',
      description: 'Elevated token used to open an admin session to the domain controller.',
      event_ids: ['ev-2004'],
      timestamp_start: iso(142),
      timestamp_end: iso(142),
      event_count: 1,
    },
  ],
}

export const incidents: Incident[] = [
  {
    id: 'inc-1001',
    title: 'Account compromise and privilege escalation on FIN-WKS-07',
    description:
      'jdoe credentials compromised from external IP, escalated to admin, lateral movement toward DC-01 observed.',
    attack_type: 'ACCOUNT_COMPROMISE_WITH_ESCALATION',
    severity: 'CRITICAL',
    confidence: 0.91,
    status: 'OPEN',
    affected_username: 'jdoe',
    affected_host: 'FIN-WKS-07',
    source_ip: '185.220.101.44',
    first_seen: iso(184),
    last_seen: iso(142),
    event_count: 6,
    attack_hypothesis: hypothesis1,
    created_at: iso(180),
    updated_at: iso(30),
    techniques: [
      {
        id: 't-1',
        incident_id: 'inc-1001',
        technique_id: 'T1110.004',
        technique_name: 'Credential Stuffing',
        tactic: 'Credential Access',
        confidence: 0.88,
        mapping_source: 'correlation-engine',
        url: 'https://attack.mitre.org/techniques/T1110/004/',
      },
      {
        id: 't-2',
        incident_id: 'inc-1001',
        technique_id: 'T1078.003',
        technique_name: 'Valid Accounts: Local Accounts',
        tactic: 'Privilege Escalation',
        confidence: 0.82,
        mapping_source: 'correlation-engine',
        url: 'https://attack.mitre.org/techniques/T1078/003/',
      },
      {
        id: 't-3',
        incident_id: 'inc-1001',
        technique_id: 'T1021.002',
        technique_name: 'Remote Services: SMB/Windows Admin Shares',
        tactic: 'Lateral Movement',
        confidence: 0.79,
        mapping_source: 'analyst-review',
        url: 'https://attack.mitre.org/techniques/T1021/002/',
      },
    ],
    evidence: [
      {
        id: 'evd-1',
        incident_id: 'inc-1001',
        event_id: 'ev-2001',
        role: 'initial_access',
        description: 'First failed authentication burst',
        sequence_order: 1,
        event: eventById('ev-2001'),
      },
      {
        id: 'evd-2',
        incident_id: 'inc-1001',
        event_id: 'ev-2002',
        role: 'initial_access',
        description: 'Successful login from same hostile IP',
        sequence_order: 2,
        event: eventById('ev-2002'),
      },
      {
        id: 'evd-3',
        incident_id: 'inc-1001',
        event_id: 'ev-2003',
        role: 'privilege_escalation',
        description: 'Added to Administrators group',
        sequence_order: 3,
        event: eventById('ev-2003'),
      },
      {
        id: 'evd-4',
        incident_id: 'inc-1001',
        event_id: 'ev-2004',
        role: 'lateral_movement',
        description: 'SMB session to DC-01',
        sequence_order: 4,
        event: eventById('ev-2004'),
      },
    ],
  },
  {
    id: 'inc-1002',
    title: 'Password spray against svc_backup on DB-EDGE-02',
    description: 'Sustained brute-force against a service account from a single hostile IP.',
    attack_type: 'BRUTE_FORCE',
    severity: 'HIGH',
    confidence: 0.76,
    status: 'INVESTIGATING',
    affected_username: 'svc_backup',
    affected_host: 'DB-EDGE-02',
    source_ip: '92.63.197.12',
    first_seen: iso(96),
    last_seen: iso(90),
    event_count: 240,
    created_at: iso(95),
    updated_at: iso(20),
    techniques: [
      {
        id: 't-4',
        incident_id: 'inc-1002',
        technique_id: 'T1110.003',
        technique_name: 'Password Spraying',
        tactic: 'Credential Access',
        confidence: 0.86,
        mapping_source: 'correlation-engine',
        url: 'https://attack.mitre.org/techniques/T1110/003/',
      },
    ],
    evidence: [
      {
        id: 'evd-5',
        incident_id: 'inc-1002',
        event_id: 'ev-2010',
        role: 'initial_access',
        sequence_order: 1,
        event: eventById('ev-2010'),
      },
      {
        id: 'evd-6',
        incident_id: 'inc-1002',
        event_id: 'ev-2011',
        role: 'initial_access',
        sequence_order: 2,
        event: eventById('ev-2011'),
      },
    ],
  },
  {
    id: 'inc-1003',
    title: 'Suspicious sudoers modification on ENG-WKS-22',
    description: 'Engineering workstation user edited /etc/sudoers outside approved change process.',
    attack_type: 'PRIVILEGE_ESCALATION',
    severity: 'MEDIUM',
    confidence: 0.64,
    status: 'OPEN',
    affected_username: 'mrossi',
    affected_host: 'ENG-WKS-22',
    source_ip: '10.4.8.31',
    first_seen: iso(58),
    last_seen: iso(58),
    event_count: 3,
    created_at: iso(57),
    updated_at: iso(40),
    techniques: [
      {
        id: 't-5',
        incident_id: 'inc-1003',
        technique_id: 'T1548.003',
        technique_name: 'Sudo and Sudo Caching',
        tactic: 'Privilege Escalation',
        confidence: 0.71,
        mapping_source: 'correlation-engine',
        url: 'https://attack.mitre.org/techniques/T1548/003/',
      },
    ],
    evidence: [
      {
        id: 'evd-7',
        incident_id: 'inc-1003',
        event_id: 'ev-2020',
        role: 'privilege_escalation',
        sequence_order: 1,
        event: eventById('ev-2020'),
      },
    ],
  },
  {
    id: 'inc-1004',
    title: 'Impossible-travel login for awilson on HR-WKS-03',
    description: 'Successful authentication from a geolocation inconsistent with prior activity.',
    attack_type: 'ACCOUNT_COMPROMISE',
    severity: 'HIGH',
    confidence: 0.7,
    status: 'CLOSED',
    affected_username: 'awilson',
    affected_host: 'HR-WKS-03',
    source_ip: '203.0.113.9',
    first_seen: iso(410),
    last_seen: iso(400),
    event_count: 4,
    created_at: iso(409),
    updated_at: iso(300),
    techniques: [
      {
        id: 't-6',
        incident_id: 'inc-1004',
        technique_id: 'T1078',
        technique_name: 'Valid Accounts',
        tactic: 'Initial Access',
        confidence: 0.68,
        mapping_source: 'correlation-engine',
        url: 'https://attack.mitre.org/techniques/T1078/',
      },
    ],
    evidence: [
      {
        id: 'evd-8',
        incident_id: 'inc-1004',
        event_id: 'ev-2030',
        role: 'initial_access',
        sequence_order: 1,
        event: eventById('ev-2030'),
      },
    ],
  },
  {
    id: 'inc-1005',
    title: 'Guest login attempts on DMZ-PROXY-01',
    description: 'Low-volume failed guest logins, confirmed to originate from an authorized scanner.',
    attack_type: 'BRUTE_FORCE',
    severity: 'LOW',
    confidence: 0.31,
    status: 'FALSE_POSITIVE',
    affected_username: 'guest',
    affected_host: 'DMZ-PROXY-01',
    source_ip: '198.51.100.23',
    first_seen: iso(720),
    last_seen: iso(700),
    event_count: 12,
    created_at: iso(719),
    updated_at: iso(650),
    techniques: [],
    evidence: [
      {
        id: 'evd-9',
        incident_id: 'inc-1005',
        event_id: 'ev-2040',
        role: 'initial_access',
        sequence_order: 1,
        event: eventById('ev-2040'),
      },
    ],
  },
]

export const incidentById = (id: string): Incident =>
  incidents.find((i) => i.id === id) ?? incidents[0]

export const toSummary = (i: Incident): IncidentSummary => ({
  id: i.id,
  title: i.title,
  attack_type: i.attack_type,
  severity: i.severity,
  confidence: i.confidence,
  status: i.status,
  affected_username: i.affected_username,
  source_ip: i.source_ip,
  first_seen: i.first_seen,
  last_seen: i.last_seen,
  event_count: i.event_count,
  created_at: i.created_at,
})

export const incidentSummaries: IncidentSummary[] = incidents.map(toSummary)

export const evidenceFor = (id: string): Evidence[] => incidentById(id).evidence

/* -------------------------------------------------------------------------- */
/* Dashboard summary                                                          */
/* -------------------------------------------------------------------------- */

const countBy = <T extends string>(vals: T[]) =>
  vals.reduce<Record<string, number>>((acc, v) => {
    acc[v] = (acc[v] ?? 0) + 1
    return acc
  }, {})

export const dashboardSummary: DashboardSummary = {
  total_incidents: incidents.length,
  open_incidents: incidents.filter((i) => i.status === 'OPEN' || i.status === 'INVESTIGATING').length,
  critical_count: incidents.filter((i) => i.severity === 'CRITICAL').length,
  high_count: incidents.filter((i) => i.severity === 'HIGH').length,
  medium_count: incidents.filter((i) => i.severity === 'MEDIUM').length,
  low_count: incidents.filter((i) => i.severity === 'LOW').length,
  events_processed_total: 184320,
  events_flagged_total: 268,
  incidents_by_type: countBy(incidents.map((i) => i.attack_type)),
  severity_distribution: countBy(incidents.map((i) => i.severity)),
  recent_incidents: incidentSummaries.slice(0, 5),
}

/* -------------------------------------------------------------------------- */
/* Chat session                                                               */
/* -------------------------------------------------------------------------- */

export const chatMessages = (sessionId: string): ChatMessage[] => [
  {
    id: 'msg-1',
    session_id: sessionId,
    role: 'user',
    content: 'What happened on FIN-WKS-07 and how confident are we that the account is compromised?',
    timestamp: iso(25),
  },
  {
    id: 'msg-2',
    session_id: sessionId,
    role: 'assistant',
    content:
      'The account **jdoe** shows a credential-stuffing burst from 185.220.101.44 (a known TOR exit) followed by a successful login, then escalation to local Administrator and an SMB session to DC-01. Taken together these steps indicate a compromised account progressing toward domain access.',
    evidence_ids: ['evd-1', 'evd-2', 'evd-3', 'evd-4'],
    mitre_references: ['T1110.004', 'T1078.003', 'T1021.002'],
    rag_sources: ['MITRE ATT&CK: Credential Access', 'Internal runbook: Account Compromise'],
    answer_type: 'INFERENCE',
    ai_confidence: 0.89,
    timestamp: iso(24),
    isPersisted: true,
    rag_chunks_used: [
      {
        text: 'Credential stuffing uses breached username/password pairs against a target service...',
        title: 'T1110.004 Credential Stuffing',
        source: 'MITRE ATT&CK',
        distance: 0.12,
      },
    ],
  },
  {
    id: 'msg-3',
    session_id: sessionId,
    role: 'user',
    content: 'What should we do to contain it right now?',
    timestamp: iso(22),
  },
  {
    id: 'msg-4',
    session_id: sessionId,
    role: 'assistant',
    content:
      'Recommended containment: (1) disable the jdoe account and revoke active sessions, (2) isolate FIN-WKS-07 from the network, (3) force credential resets for accounts that logged into DC-01 in the last 3 hours, and (4) hunt for the newly created svc_helpdesk2 account.',
    evidence_ids: ['evd-4'],
    mitre_references: ['T1021.002'],
    rag_sources: ['Internal runbook: Containment'],
    answer_type: 'RECOMMENDATION',
    ai_confidence: 0.82,
    timestamp: iso(21),
    isPersisted: true,
  },
]

/* -------------------------------------------------------------------------- */
/* Report                                                                     */
/* -------------------------------------------------------------------------- */

export const report = (incidentId: string): ReportOut => {
  const inc = incidentById(incidentId)
  return {
    id: 'rep-1001',
    incident_id: inc.id,
    generated_at: iso(5),
    format: 'MARKDOWN',
    ai_summary:
      'A critical account-compromise incident on FIN-WKS-07 escalated from credential stuffing to attempted domain dominance within roughly 40 minutes. Immediate containment and credential rotation are advised.',
    recommended_actions: [
      'Disable the jdoe account and revoke active Kerberos/SSH sessions.',
      'Network-isolate FIN-WKS-07 and capture a forensic image.',
      'Reset credentials for all accounts that authenticated to DC-01 in the incident window.',
      'Remove the unauthorized svc_helpdesk2 domain account and audit its activity.',
    ],
    content: `# Incident Report — ${inc.title}

**Incident ID:** ${inc.id}
**Severity:** ${inc.severity}
**Status:** ${inc.status}
**Confidence:** ${(inc.confidence * 100).toFixed(0)}%

## Executive Summary
An external actor compromised the account \`${inc.affected_username}\` on \`${inc.affected_host}\` and escalated privileges before moving laterally toward the domain controller.

## Timeline
1. Credential stuffing from ${inc.source_ip} (T1110.004)
2. Successful interactive login
3. Privilege escalation to local Administrator (T1078.003)
4. SMB session to DC-01 (T1021.002)

## Recommended Actions
- Disable the affected account and revoke sessions.
- Isolate the affected host.
- Rotate credentials for exposed accounts.
`,
  }
}

/* -------------------------------------------------------------------------- */
/* Wazuh integration                                                          */
/* -------------------------------------------------------------------------- */

export const wazuhStatus: WazuhStatusResponse = {
  status: 'connected',
  authentication: 'ok',
  dedup_cache_size: 5120,
  api_polling: {
    enabled: true,
    configured: true,
    api_url: 'https://wazuh.internal.soc.local:55000',
    verify_ssl: true,
    running: true,
    watermark: iso(2),
    last_attempted_poll: iso(1),
    last_successful_poll: iso(1),
    total_alerts_fetched: 48213,
    total_alerts_processed: 47990,
    total_duplicates: 223,
    consecutive_errors: 0,
    last_error: null,
  },
}
