/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Real Detection & Ingestion Engine
 * Zero Dummy Data • Real Signatures & Evidence Only
 */

import {
  SecurityEvent,
  SecurityAlert,
  DetectionRule,
  EventCategory,
  Severity,
} from '../types/cybersecurity.js';

// Real Detection Rules with authentic OWASP & MITRE ATT&CK enterprise mappings
export const DETECTION_RULES: DetectionRule[] = [
  {
    id: 'RULE-SQLI-001',
    name: 'SQL Injection — Union Based Extraction',
    category: 'web_attack',
    severity: 'critical',
    signature: 'union\\s+(all\\s+)?select\\s+.*(from|information_schema|version\\(\\)|user\\(\\)|database\\(\\)|@@version)',
    mitreId: 'T1190',
    mitreName: 'Exploit Public-Facing Application',
    owaspRef: 'A03:2021-Injection',
    description: 'Adversary uses UNION operator to append database query results to legitimate application output.',
    recommendedMitigation: 'Enforce parameterized queries (PreparedStatements) and strict input validation on all parameters.',
  },
  {
    id: 'RULE-SQLI-002',
    name: 'SQL Injection — Boolean / Tautology Bypass',
    category: 'web_attack',
    severity: 'high',
    signature: "('|\")\\s*(or|and)\\s+('?[0-9a-zA-Z]+'?\\s*=\\s*'?[0-9a-zA-Z]+'|[0-9]+\\s*=\\s*[0-9]+|true|false)",
    mitreId: 'T1190',
    mitreName: 'Exploit Public-Facing Application',
    owaspRef: 'A03:2021-Injection',
    description: 'Adversary injects boolean tautology (e.g. OR 1=1) into WHERE clause to bypass authentication or extract records.',
    recommendedMitigation: 'Refactor SQL queries into ORM parameterized calls and implement WAF SQLi inspection rules.',
  },
  {
    id: 'RULE-SQLI-003',
    name: 'SQL Injection — Comment Delimiter / Blind Probe',
    category: 'web_attack',
    severity: 'high',
    signature: "('|\")\\s*(--|#|/\\*).*|sleep\\(\\s*[0-9]+\\s*\\)|benchmark\\(\\s*[0-9]+",
    mitreId: 'T1190',
    mitreName: 'Exploit Public-Facing Application',
    owaspRef: 'A03:2021-Injection',
    description: 'Adversary injects SQL inline comments or time delay functions to conduct blind timing attacks.',
    recommendedMitigation: 'Block raw SQL comments and enforce strict parameter typing across the web tier.',
  },
  {
    id: 'RULE-XSS-001',
    name: 'Cross-Site Scripting — Script Tag Injection',
    category: 'web_attack',
    severity: 'high',
    signature: '<script[\\s>].*</script>|<script[\\s>]|javascript:\\s*[a-zA-Z0-9_]+\\(',
    mitreId: 'T1189',
    mitreName: 'Drive-by Compromise',
    owaspRef: 'A03:2021-Injection',
    description: 'Direct injection of executable JavaScript tags into HTTP request parameters.',
    recommendedMitigation: 'Contextual HTML entity encoding and Content-Security-Policy (CSP) headers.',
  },
  {
    id: 'RULE-XSS-002',
    name: 'Cross-Site Scripting — DOM Event Handler Attribute',
    category: 'web_attack',
    severity: 'high',
    signature: '<(img|svg|iframe|body|input|a|div)[^>]+(onerror|onload|onmouseover|onclick|onfocus)\\s*=',
    mitreId: 'T1189',
    mitreName: 'Drive-by Compromise',
    owaspRef: 'A03:2021-Injection',
    description: 'Adversary injects HTML elements with weaponized event handlers to execute arbitrary JavaScript.',
    recommendedMitigation: 'Sanitize user HTML inputs via DOMPurify and restrict inline scripts with CSP nonces.',
  },
  {
    id: 'RULE-CMDI-001',
    name: 'OS Command Injection — Shell Metacharacters',
    category: 'web_attack',
    severity: 'critical',
    signature: '(;|\\||&&|`|\\$\\()\\s*(cat\\s+/|ls|id|whoami|uname|ping|nc|sh|bash|curl|wget|chmod)',
    mitreId: 'T1059.004',
    mitreName: 'Command and Scripting Interpreter: Unix Shell',
    owaspRef: 'A03:2021-Injection',
    description: 'Execution of arbitrary system shell commands via unvalidated application input parameters.',
    recommendedMitigation: 'Avoid invoking system shell processes; use native language libraries with hardened argument arrays.',
  },
  {
    id: 'RULE-TRAV-001',
    name: 'Directory Traversal / Local File Inclusion (LFI)',
    category: 'web_attack',
    severity: 'high',
    signature: '(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%2e%2e/).*(etc/passwd|etc/shadow|boot\\.ini|windows/win\\.ini|proc/self)',
    mitreId: 'T1083',
    mitreName: 'File and Directory Discovery',
    owaspRef: 'A01:2021-Broken Access Control',
    description: 'Path manipulation attempting to traverse outside document root to access sensitive operating system files.',
    recommendedMitigation: 'Whitelist allowed filenames, sanitize path characters, and resolve realpath within chroot boundaries.',
  },
  {
    id: 'RULE-UPL-001',
    name: 'Malicious Web Shell File Upload',
    category: 'web_attack',
    severity: 'critical',
    signature: 'filename=.*\\.(php|phtml|php3|php4|php5|phar|jsp|asp|aspx)(\\.[a-zA-Z0-9]+)?|(<\\?php|<%|eval\\(\\$_POST|passthru\\()',
    mitreId: 'T1505.003',
    mitreName: 'Server Software Component: Web Shell',
    owaspRef: 'A04:2021-Insecure Design',
    description: 'Attempt to upload executable server-side scripts (e.g. PHP shells) to gain persistent code execution.',
    recommendedMitigation: 'Enforce strict MIME validation, re-encode image files, and store uploads on noexec storage.',
  },
  {
    id: 'RULE-SCAN-001',
    name: 'Automated Security Scanner Probe',
    category: 'network_anomaly',
    severity: 'medium',
    signature: '(sqlmap|nikto|acunetix|nessus|gobuster|dirb|wpscan|openvas|nmap)',
    mitreId: 'T1595.002',
    mitreName: 'Active Scanning: Vulnerability Scanning',
    owaspRef: 'A05:2021-Security Misconfiguration',
    description: 'Automated tool signatures recognized scanning endpoints for exploitable flaws.',
    recommendedMitigation: 'Rate-limit probing IPs and configure WAF to automatically drop known scanner signatures.',
  },
  {
    id: 'RULE-AUTH-001',
    name: 'Authentication Brute Force Abuse',
    category: 'authentication',
    severity: 'high',
    signature: '(failed_login|authentication_failure|invalid_password)',
    mitreId: 'T1110.001',
    mitreName: 'Brute Force: Password Guessing',
    owaspRef: 'A07:2021-Identification and Authentication Failures',
    description: 'Multiple failed authentication events exceeding threshold in short succession.',
    recommendedMitigation: 'Enforce account lockout policies, CAPTCHA after 3 failures, and IP jailing via Fail2ban.',
  },
];

// Helper to inspect request payload against detection rules
export function evaluateRequestPayload(
  payloadString: string,
  uri: string = '',
  method: string = 'GET',
  headers: Record<string, string> = {}
): {
  matchedRule: DetectionRule | null;
  attackName: string;
  category: EventCategory;
  severity: Severity;
  evidence: string;
} {
  const fullTextToInspect = `${method} ${uri} ${payloadString} ${headers['user-agent'] || ''} ${headers['cookie'] || ''}`;

  for (const rule of DETECTION_RULES) {
    try {
      const regex = new RegExp(rule.signature, 'i');
      const match = fullTextToInspect.match(regex);
      if (match) {
        return {
          matchedRule: rule,
          attackName: rule.name,
          category: rule.category,
          severity: rule.severity,
          evidence: match[0],
        };
      }
    } catch {
      // Ignore regex parsing errors
    }
  }

  // Check for suspicious anomalies that don't match specific attack signatures
  const suspiciousChars = ['../', '..\\', '%00', '<', '>', "'", '"', ';', '|'];
  const hasSuspiciousChars = suspiciousChars.some((char) => fullTextToInspect.includes(char));

  if (hasSuspiciousChars && (uri.includes('vulnerabilities') || uri.includes('admin') || uri.includes('login'))) {
    return {
      matchedRule: null,
      attackName: 'Suspicious HTTP Request — Classification Pending',
      category: 'web_attack',
      severity: 'medium',
      evidence: fullTextToInspect.slice(0, 120),
    };
  }

  return {
    matchedRule: null,
    attackName: 'Clean Traffic',
    category: 'web_attack',
    severity: 'low',
    evidence: '',
  };
}

// Suricata EVE JSON parser
export interface SuricataEveEvent {
  timestamp?: string;
  flow_id?: number;
  event_type: string;
  src_ip?: string;
  src_port?: number;
  dest_ip?: string;
  dest_port?: number;
  proto?: string;
  alert?: {
    action?: string;
    gid?: number;
    signature_id?: number;
    rev?: number;
    signature?: string;
    category?: string;
    severity?: number;
  };
  http?: {
    hostname?: string;
    url?: string;
    http_user_agent?: string;
    http_method?: string;
    protocol?: string;
    status?: number;
    length?: number;
  };
  dns?: {
    type?: string;
    rrname?: string;
    rrtype?: string;
    rcode?: string;
  };
  payload_printable?: string;
}

export function parseSuricataEve(rawJson: string | object): {
  isAlert: boolean;
  event?: Partial<SecurityEvent>;
  raw?: any;
} {
  try {
    const data: SuricataEveEvent = typeof rawJson === 'string' ? JSON.parse(rawJson) : rawJson;

    if (data.event_type !== 'alert' || !data.alert) {
      return { isAlert: false, raw: data };
    }

    const alertSev: Severity =
      data.alert.severity === 1 ? 'critical' : data.alert.severity === 2 ? 'high' : data.alert.severity === 3 ? 'medium' : 'low';

    let category: EventCategory = 'network_anomaly';
    const sig = (data.alert.signature || '').toLowerCase();
    const cat = (data.alert.category || '').toLowerCase();

    if (sig.includes('sql') || cat.includes('sql')) category = 'web_attack';
    else if (sig.includes('xss') || cat.includes('cross-site')) category = 'web_attack';
    else if (sig.includes('command') || sig.includes('injection')) category = 'web_attack';
    else if (sig.includes('dns') || data.dns) category = 'dns_tunneling';
    else if (sig.includes('c2') || sig.includes('beacon') || sig.includes('trojan')) category = 'c2_communication';
    else if (sig.includes('brute') || sig.includes('login') || sig.includes('auth')) category = 'authentication';

    return {
      isAlert: true,
      event: {
        timestamp: data.timestamp ? data.timestamp.replace('T', ' ').slice(0, 19) : new Date().toISOString().replace('T', ' ').slice(0, 19),
        source: 'Suricata IDS',
        category,
        title: data.alert.signature || 'Suricata Security Alert',
        severity: alertSev,
        sourceIp: data.src_ip || '0.0.0.0',
        destIp: data.dest_ip || '192.168.100.75',
        protocol: (data.proto as any) || 'TCP',
        port: data.dest_port || 8081,
        mitreTactic: 'Initial Access',
        mitreTechniqueId: category === 'web_attack' ? 'T1190' : 'T1046',
        mitreTechniqueName: category === 'web_attack' ? 'Exploit Public-Facing Application' : 'Network Service Discovery',
        affectedAsset: 'DVWA Home Server (192.168.100.75:8081)',
        rawPayload: data.payload_printable || (data.http ? `${data.http.http_method} ${data.http.url}` : JSON.stringify(data.alert)),
        status: 'detected',
      },
      raw: data,
    };
  } catch (err) {
    return { isAlert: false, raw: null };
  }
}
