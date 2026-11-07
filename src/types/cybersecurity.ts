/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Types and Interfaces
 * Integrated Cyber Defense & Threat Intelligence Platform
 */

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type EventCategory = 
  | 'authentication'
  | 'web_attack'
  | 'network_anomaly'
  | 'endpoint_malware'
  | 'dns_tunneling'
  | 'privilege_escalation'
  | 'c2_communication'
  | 'file_integrity'
  | 'data_exfiltration';

export type DetectionEngine = 
  | 'Suricata IDS'
  | 'Zeek NSM'
  | 'Wazuh FIM/Agent'
  | 'Nusantara WAF'
  | 'Apache Access Log'
  | 'Syslog Analyzer'
  | 'Internal Simulation'
  | 'Behavioral Correlation Engine';

// 8 Granular Defense & Blocking Action Statuses (Prioritas 3)
export type DefenseActionStatus = 
  | 'DETECTED' 
  | 'BLOCKED_BY_WAF'
  | 'BLOCKED_BY_IPS'
  | 'BLOCKED_BY_APPLICATION'
  | 'ALLOWED' 
  | 'NOT_OBSERVED' 
  | 'SENSOR_OFFLINE'
  | 'MONITORING_DEGRADED'
  // Backward compatibility alias:
  | 'BLOCKED'
  | 'OFFLINE';

export interface BlockingProof {
  isBlocked: boolean;
  httpStatus?: number;
  action: 'drop' | 'reject' | 'block' | 'allowed' | 'not_applicable';
  blockingMechanism: 'WAF' | 'IPS' | 'APPLICATION' | 'NONE';
  ruleId?: string;
  packetAction?: string;
  proofDetail: string;
  evidenceReason?: string;
  confidenceScore?: number;
  evidenceSource?: 'suricata_eve' | 'apache_access' | 'waf_audit' | 'app_response' | 'unit_test';
  verifiedAt: string;
  correlationId?: string;
  rawEvidencePayload?: string;
}

export interface CollectorMetadata {
  collectorIp?: string;
  sourceFeed: 'suricata' | 'waf' | 'apache' | 'simulation';
  batchId?: string;
  isExternalTester: boolean;
  testerIdentifier?: string;
  ingestedAt: string;
  replayNonce?: string;
  requestTimestamp?: number;
}

export interface SecurityEvent {
  id: string;
  requestId?: string;
  correlationId?: string;
  eventHash?: string;
  timestamp: string;
  source: DetectionEngine;
  category: EventCategory;
  title: string;
  severity: Severity;
  sourceIp: string;
  destIp: string;
  protocol: 'TCP' | 'UDP' | 'HTTP' | 'HTTPS' | 'DNS' | 'SSH';
  port: number;
  mitreTactic: string;
  mitreTechniqueId: string;
  mitreTechniqueName: string;
  owaspCategory?: string;
  affectedAsset: string;
  requestUri?: string;
  httpMethod?: string;
  rawPayload: string;
  status: 'detected' | 'correlated' | 'investigating' | 'mitigated' | 'false_positive';
  defenseStatus?: DefenseActionStatus;
  blockingProof?: BlockingProof;
  collectorMetadata?: CollectorMetadata;
  isSimulated?: boolean;
}

export interface IncidentTimelineStep {
  step: string;
  time: string;
  status: 'completed' | 'in_progress' | 'pending';
  note: string;
  actionLabel?: string;
}

export interface IncidentEvidence {
  type: string;
  description: string;
  indicator: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: 'new' | 'investigating' | 'contained' | 'remediated' | 'closed';
  category: EventCategory;
  affectedAssets: string[];
  assignedTo: string;
  createdAt: string;
  updatedAt: string;
  threatActor?: string;
  mitreTactics: string[];
  mitreTechniques: { id: string; name: string; tactic: string }[];
  timeline: IncidentTimelineStep[];
  containmentActions: string[];
  evidence: IncidentEvidence[];
  aiSummary?: string;
  rootCause?: string;
  recommendations?: string[];
  isSimulated?: boolean;
}

export interface NetworkNode {
  id: string;
  name: string;
  type: 'internet' | 'firewall' | 'switch' | 'server' | 'workstation' | 'database' | 'cloud';
  ip: string;
  status: 'normal' | 'compromised' | 'isolated' | 'warning';
  connections: string[];
  x: number;
  y: number;
  os?: string;
  criticalTier?: 'Tier 1' | 'Tier 2' | 'Tier 3';
  vulnCount?: number;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  tacticId: string;
  description: string;
  status: 'detected' | 'covered' | 'needs_validation';
  detectionCount: number;
  defensiveControls: string[];
}

export interface MitreTactic {
  id: string;
  name: string;
  shortName: string;
  techniques: MitreTechnique[];
}

export interface ThreatIntelIoc {
  id: string;
  type: 'ip' | 'domain' | 'hash' | 'cve';
  indicator: string;
  reputation: 'malicious' | 'suspicious' | 'benign' | 'unknown';
  confidenceScore: number;
  threatActor?: string;
  feedSource: string;
  lastUpdated: string;
  associatedMalware?: string;
  tags: string[];
}

export interface VulnerabilityItem {
  id: string;
  cveId: string;
  title: string;
  cvssScore: number;
  severity: Severity;
  epssScore: number;
  affectedPackage: string;
  affectedAssets: string[];
  status: 'open' | 'patch_scheduled' | 'mitigated' | 'resolved';
  remediationAdvice: string;
  publishedDate: string;
}

export interface IntegrationAdapter {
  id: string;
  name: string;
  type: 'ids' | 'nsm' | 'edr' | 'waf' | 'siem' | 'feed';
  status: 'connected' | 'degraded' | 'not_configured' | 'offline';
  version: string;
  eventRate: string;
  endpoint: string;
  docsSnippet: string;
  lastHeartbeat: string;
}

export interface AuditLogItem {
  id: string;
  timestamp: string;
  user: string;
  action: string;
  target: string;
  outcome: 'success' | 'failure' | 'denied';
  ipAddress: string;
  details?: string;
}

export interface SimulationScenario {
  id: string;
  name: string;
  description: string;
  targetAsset: string;
  mitreTechnique: string;
  owaspRef?: string;
  severity: Severity;
  simulatedPayload: string;
  detectionMechanism: string;
  recommendedMitigation: string;
}

export interface SecurityAlert {
  id: string;
  attackName: string;
  attackCategory: EventCategory;
  severity: Severity;
  sourceIp: string;
  destIp: string;
  destPort: number;
  httpMethod?: string;
  requestUri?: string;
  targetAsset?: string;
  detectionSource: string;
  detectionRule: string;
  firstSeen: string;
  lastSeen: string;
  timestamp?: string;
  status?: string;
  description?: string;
  eventCount: number;
  evidenceReference: string;
  evidencePayload?: string;
  mitreTechniqueId?: string;
  mitreTechniqueName?: string;
  mitreTacticName?: string;
  owaspCategory?: string;
  recommendedMitigation: string;
  investigationStatus: 'unreviewed' | 'investigating' | 'confirmed' | 'contained' | 'false_positive';
  defenseStatus?: DefenseActionStatus;
  blockingProof?: BlockingProof;
  isExternalTester?: boolean;
  externalTesterIp?: string;
  isSimulated?: boolean;
  correlationId?: string;
  eventIds: string[];
}

export interface DetectionRule {
  id: string;
  name: string;
  category: EventCategory;
  severity: Severity;
  signature: string;
  mitreId: string;
  mitreName: string;
  owaspRef: string;
  description: string;
  recommendedMitigation: string;
}

export interface SensorStatusRecord {
  id: string;
  name: string;
  target: string;
  connectionStatus: 'connected' | 'disconnected' | 'degraded' | 'not_configured' | 'waiting_telemetry' | 'error';
  lastEventTimestamp: string | null;
  lastSuccessfulCollection: string | null;
  errorStatus: string | null;
  eventIngestionCount: number;
  eventRate: string;
  endpoint: string;
  guidance: string;
}

export interface SystemHealthMetrics {
  backendStatus: 'online' | 'degraded' | 'offline';
  databaseStatus: 'online' | 'degraded' | 'offline';
  streamStatus: 'online' | 'offline';
  aiEngineStatus: 'online' | 'configured' | 'offline';
  overallMonitoringState: 'optimal' | 'no_threats_detected' | 'degraded' | 'offline';
  eventIngestionRate: number;
  avgProcessingLatencyMs: number;
  activeSensors: number;
  totalSensors: number;
  systemUptime: string;
}

export interface CollectorStatus {
  status: 'ACTIVE' | 'DEGRADED' | 'OFFLINE';
  isConnected?: boolean;
  version?: string;
  lastHeartbeat: string | null;
  lastEventReceived: string | null;
  collectorIp: string | null;
  collectorVersion: string;
  verifiedEventCount: number;
  suricataFeedActive: boolean;
  wafFeedActive: boolean;
  apacheFeedActive: boolean;
  externalTesterIp: string | null;
  externalTesterName: string;
  authValid: boolean;
}

export interface ExternalTesterSession {
  detected: boolean;
  sourceIp: string;
  hostname: string;
  firstSeen: string;
  lastSeen: string;
  totalRequests: number;
  attackSignaturesMatched: number;
  blockedRequests: number;
  allowedAttacks: number;
  latestUserAgent?: string;
  activeToolsObserved: string[];
}

export interface BlockedIpRecord {
  ipAddress: string;
  firstBlocked: string;
  lastBlocked: string;
  detectionReason: string;
  relatedSecurityEventId?: string;
  blockingMechanism: 'WAF' | 'IPS' | 'APPLICATION' | 'ADMIN_MANUAL';
  blockStatus: 'ACTIVE' | 'UNBLOCKED';
  requestCount: number;
  unblockedAt?: string;
  unblockedBy?: string;
  unblockReason?: string;
}

