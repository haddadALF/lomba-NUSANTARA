/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Overview & Real Detection Command View
 * Zero Dummy Data Policy • External Kali Linux Testing Architecture
 */

import React, { useState } from 'react';
import {
  RotateCw,
  Download,
  Share2,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Sparkles,
  ExternalLink,
  Shield,
  Bot,
  ArrowUpRight,
  Server,
  Terminal,
  Activity,
  Play,
  Trash2,
  Radio,
  FileCode,
  Layers,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { NetworkTopology } from '../components/NetworkTopology.js';
import { Incident, NetworkNode, SecurityEvent, SecurityAlert, SensorStatusRecord, BlockedIpRecord } from '../types/cybersecurity.js';
import { ModuleExplanationCard, ModuleGuideData } from '../components/ModuleExplanationCard.js';

const OVERVIEW_GUIDE: ModuleGuideData = {
  title: 'Modul 1: Ringkasan Pertahanan & Komando SOC (Overview)',
  badge: 'SOC Command Center • External Tester Ready',
  shortSummary: 'Pusat komando terpadu untuk memantau status operasional perisai pertahanan siber, postur risiko, dan topologi jaringan.',
  fungsiUtama: 'Menyediakan visibilitas terpadu (single-pane-of-glass) terhadap seluruh aktivitas keamanan, kesehatan sensor, dan alur trafik dari tester eksternal ke DVWA.',
  alasanDiperlukan: 'Analis SOC Level 1-3 memerlukan status pertahanan instan dalam hitungan detik tanpa membuka puluhan terminal log terpisah.',
  caraKerja: 'Mengkorelasikan data dari Suricata EVE JSON, log WAF, dan health prober target DVWA melalui event bus real-time SSE.',
  dataDitampilkan: 'Status 5 kondisi pertahanan, hitungan alert terverifikasi, peta topologi aset internal (192.168.100.75:8081), dan log aktivitas terkini.',
  artiStatus: 'THREATS_DETECTED: Serangan nyata teridentifikasi; MONITORING_DEGRADED: Target/sensor belum terhubung penuh; NO_THREATS_DETECTED: Bersih.',
  panduanTindakan: 'Periksa konektivitas DVWA, jalankan pengujian dari mesin Kali Linux eksternal, dan amati pembuktian deteksi pada layar secara real-time.',
};

interface OverviewViewProps {
  alerts: SecurityAlert[];
  events: SecurityEvent[];
  incidents: Incident[];
  nodes: NetworkNode[];
  sensors: SensorStatusRecord[];
  blockedIps?: BlockedIpRecord[];
  onIsolateNode: (nodeId: string) => Promise<void>;
  onRefresh: () => void;
  onSelectIncident: (inc: Incident) => void;
  onNavigateToTab: (tab: any) => void;
  onTriggerAiAnalysis: (incidentId: string) => void;
  onProbeDvwa: () => Promise<void>;
  onTestProbe: (type: string) => Promise<void>;
  onResetPipeline: () => Promise<void>;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  alerts,
  events,
  incidents,
  nodes,
  sensors,
  blockedIps = [],
  onIsolateNode,
  onRefresh,
  onSelectIncident,
  onNavigateToTab,
  onTriggerAiAnalysis,
  onProbeDvwa,
  onTestProbe,
  onResetPipeline,
}) => {
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(incidents[0]?.id || '');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isProbing, setIsProbing] = useState(false);
  const [showCollectorModal, setShowCollectorModal] = useState(false);
  const [collectorModalTab, setCollectorModalTab] = useState<'collector' | 'kali'>('kali');
  const [showUnitSimulator, setShowUnitSimulator] = useState(false);
  const [simTestType, setSimTestType] = useState<string>('sqli');
  const [isExecutingSim, setIsExecutingSim] = useState(false);

  const dvwaSensor = sensors.find((s) => s.id === 'sensor-dvwa');
  const suricataSensor = sensors.find((s) => s.id === 'sensor-suricata');

  // Filter real vs simulated alerts
  const realAlerts = alerts.filter((a) => !a.isSimulated);
  const realEvents = events.filter((e) => !e.isSimulated);

  const criticalAlerts = realAlerts.filter((a) => a.severity === 'critical').length;
  const highAlerts = realAlerts.filter((a) => a.severity === 'high').length;
  const mediumAlerts = realAlerts.filter((a) => a.severity === 'medium').length;
  const lowAlerts = realAlerts.filter((a) => a.severity === 'low').length;

  const isDegraded = sensors.some((s) => s.connectionStatus === 'degraded' || s.connectionStatus === 'disconnected');

  // Distinct system defense statuses strictly adhering to rules:
  const allSensorsOffline = sensors.length > 0 && sensors.every((s) => s.connectionStatus === 'disconnected');

  let monitoringStatus:
    | 'THREATS_DETECTED'
    | 'MONITORING_OFFLINE'
    | 'MONITORING_DEGRADED'
    | 'NO_EVENTS_RECEIVED'
    | 'NO_THREATS_DETECTED';

  if (realAlerts.length > 0) {
    monitoringStatus = 'THREATS_DETECTED';
  } else if (allSensorsOffline) {
    monitoringStatus = 'MONITORING_OFFLINE';
  } else if (isDegraded || dvwaSensor?.connectionStatus !== 'connected') {
    monitoringStatus = 'MONITORING_DEGRADED';
  } else if (realEvents.length === 0) {
    monitoringStatus = 'NO_EVENTS_RECEIVED';
  } else {
    monitoringStatus = 'NO_THREATS_DETECTED';
  }

  const activeIncident = incidents.find((i) => i.id === selectedIncidentId) || incidents[0];

  const handleRefreshClick = () => {
    setIsRefreshing(true);
    onRefresh();
    setTimeout(() => setIsRefreshing(false), 500);
  };

  const handleProbeClick = async () => {
    setIsProbing(true);
    try {
      await onProbeDvwa();
    } finally {
      setIsProbing(false);
    }
  };

  const handleRunUnitSim = async () => {
    setIsExecutingSim(true);
    try {
      await onTestProbe(simTestType);
    } finally {
      setIsExecutingSim(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* 6-Aspect Progressive Disclosure Module Guide */}
      <ModuleExplanationCard guide={OVERVIEW_GUIDE} />

      {/* Top Banner: Real Target Identity & Status Indicator */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#101827] border border-[#16233B] rounded-xl p-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded bg-[#16C79A]"></span>
            <h1 className="text-base font-bold text-[#E8EEF7]">Real-Time Security Defense Center</h1>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#36A3FF]/20 text-[#36A3FF] border border-[#36A3FF]/30 font-semibold">
              TARGET: http://192.168.100.75:8081
            </span>
          </div>
          <p className="text-xs text-[#8E9EB5] mt-0.5">
            Arsitektur Pengujian Eksternal: Mesin Kali Linux menguji DVWA secara eksternal; telemetry dialirkan via Suricata / WAF / Apache collector.
          </p>
        </div>

        {/* Global Monitoring State Badge */}
        <div className="flex items-center gap-2">
          {monitoringStatus === 'THREATS_DETECTED' ? (
            <div className="px-3 py-1.5 rounded-lg bg-[#EF5350]/20 border border-[#EF5350] text-[#EF5350] font-mono text-xs font-bold flex items-center gap-2 shadow-lg shadow-[#EF5350]/10">
              <span className="w-2 h-2 rounded-full bg-[#EF5350] animate-pulse"></span>
              {realAlerts.length} THREATS DETECTED
            </div>
          ) : monitoringStatus === 'MONITORING_OFFLINE' ? (
            <div className="px-3 py-1.5 rounded-lg bg-[#EF5350]/20 border border-[#EF5350]/50 text-[#EF5350] font-mono text-xs font-bold flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#EF5350]"></span>
              MONITORING OFFLINE
            </div>
          ) : monitoringStatus === 'MONITORING_DEGRADED' ? (
            <div className="px-3 py-1.5 rounded-lg bg-[#F5B942]/20 border border-[#F5B942] text-[#F5B942] font-mono text-xs font-bold flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#F5B942]"></span>
              MONITORING DEGRADED
            </div>
          ) : monitoringStatus === 'NO_EVENTS_RECEIVED' ? (
            <div className="px-3 py-1.5 rounded-lg bg-[#36A3FF]/20 border border-[#36A3FF] text-[#36A3FF] font-mono text-xs font-bold flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#36A3FF]"></span>
              NO EVENTS RECEIVED
            </div>
          ) : (
            <div className="px-3 py-1.5 rounded-lg bg-[#16C79A]/20 border border-[#16C79A] text-[#16C79A] font-mono text-xs font-bold flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-[#16C79A]"></span>
              NO THREATS DETECTED
            </div>
          )}

          <button
            onClick={handleRefreshClick}
            className="p-2 bg-[#152338] hover:bg-[#1E2D4A] text-[#16C79A] border border-[#16C79A]/30 rounded-lg text-xs font-semibold transition-colors"
            title="Refresh All Feeds"
          >
            <RotateCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Target & Verification Tool Island */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 bg-[#0B111E] border border-[#152033] rounded-xl p-3.5 text-xs">
        {/* Left: DVWA Target Connection Info */}
        <div className="lg:col-span-6 flex flex-col justify-between space-y-2">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-[#36A3FF]" />
            <span className="font-semibold text-[#E8EEF7]">Target Lab:</span>
            <span className="font-mono text-[#36A3FF] font-bold">192.168.100.75:8081 (DVWA on Ubuntu)</span>
          </div>
          <div className="flex flex-wrap items-center gap-3 text-[11px] text-[#8E9EB5]">
            <span>External Tester:</span>
            <span className="font-mono text-[#16C79A] font-semibold">Kali Linux (External Machine)</span>
            <span>·</span>
            <span>Sensor Suricata:</span>
            <span className="font-mono text-[#16C79A]">Listening (eve.json)</span>
          </div>
        </div>

        {/* Right: Real Verification & Probing Controls */}
        <div className="lg:col-span-6 flex flex-wrap items-center justify-end gap-2">
          <button
            onClick={handleProbeClick}
            disabled={isProbing}
            className="px-3 py-1.5 bg-[#152338] hover:bg-[#1E2D4A] text-[#E8EEF7] border border-[#1E2D4A] rounded-lg text-xs font-medium transition-colors"
          >
            {isProbing ? 'Checking...' : 'Check DVWA Reachability'}
          </button>

          {/* External Kali Linux Attack Guide Button */}
          <button
            onClick={() => {
              setCollectorModalTab('kali');
              setShowCollectorModal(true);
            }}
            className="px-3 py-1.5 bg-[#152338] hover:bg-[#36A3FF] text-[#36A3FF] hover:text-[#080D17] border border-[#36A3FF]/40 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5"
          >
            <Terminal className="w-3.5 h-3.5" />
            Panduan Kali Linux
          </button>

          {/* Ubuntu Forwarder Script Button */}
          <button
            onClick={() => {
              setCollectorModalTab('collector');
              setShowCollectorModal(true);
            }}
            className="px-3 py-1.5 bg-[#152338] hover:bg-[#16C79A] text-[#16C79A] hover:text-[#080D17] border border-[#16C79A]/40 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5"
          >
            <Radio className="w-3.5 h-3.5" />
            Collector Script
          </button>

          {/* Reset Clean State button (Test A verification) */}
          <button
            onClick={onResetPipeline}
            className="p-1.5 bg-[#101827] hover:bg-[#EF5350]/20 text-[#8E9EB5] hover:text-[#EF5350] border border-[#19263E] rounded-lg text-xs transition-colors"
            title="Reset Pipeline (Test A: Zero State)"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* 4 Primary Cards (Section 3: Dashboard Overview) — Zero Dummy Data Only */}
      {(() => {
        const blockedEventsCount = events.filter(
          (e) =>
            e.defenseStatus === 'BLOCKED_BY_WAF' ||
            e.defenseStatus === 'BLOCKED_BY_IPS' ||
            e.defenseStatus === 'BLOCKED_BY_APPLICATION' ||
            e.defenseStatus === 'BLOCKED'
        ).length;
        const activeBlockedIpsCount = blockedIps.filter((b) => b.blockStatus === 'ACTIVE').length;
        const connectedSensorsCount = sensors.filter((s) => s.connectionStatus === 'connected').length;

        return (
          <>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              {/* Card 1: Total Detected Threats */}
              <div
                onClick={() => onNavigateToTab('threat_analysis')}
                className="p-3.5 bg-[#101827] border border-[#16233B] hover:border-[#1E2D4A] rounded-xl flex flex-col justify-between cursor-pointer transition-colors group"
              >
                <div className="flex items-center justify-between text-xs text-[#8E9EB5]">
                  <span className="font-semibold group-hover:text-[#E8EEF7]">Total Detected Threats</span>
                  <Activity className="w-4 h-4 text-[#36A3FF]" />
                </div>
                <div className={`text-2xl font-bold font-mono my-1 ${realAlerts.length > 0 ? 'text-[#EF5350]' : 'text-[#E8EEF7]'}`}>
                  {realAlerts.length}
                </div>
                <div className="text-[10px] text-[#64748B]">
                  {realAlerts.length === 0 ? '0 ancaman terdeteksi (sistem aman)' : 'Ancaman aktif terverifikasi sensor'}
                </div>
              </div>

              {/* Card 2: Successfully Blocked */}
              <div
                onClick={() => onNavigateToTab('monitoring')}
                className="p-3.5 bg-[#101827] border border-[#16233B] hover:border-[#1E2D4A] rounded-xl flex flex-col justify-between cursor-pointer transition-colors group"
              >
                <div className="flex items-center justify-between text-xs text-[#8E9EB5]">
                  <span className="font-semibold group-hover:text-[#E8EEF7]">Successfully Blocked</span>
                  <span className="w-2 h-2 rounded-full bg-[#16C79A]"></span>
                </div>
                <div className={`text-2xl font-bold font-mono my-1 ${blockedEventsCount > 0 ? 'text-[#16C79A]' : 'text-[#E8EEF7]'}`}>
                  {blockedEventsCount}
                </div>
                <div className="text-[10px] text-[#64748B]">
                  {blockedEventsCount === 0 ? '0 serangan diblokir (belum ada serangan)' : 'Penolakan HTTP 403 / Drop aktif'}
                </div>
              </div>

              {/* Card 3: Blocked IPs */}
              <div
                onClick={() => onNavigateToTab('blocked_ips')}
                className="p-3.5 bg-[#101827] border border-[#16233B] hover:border-[#1E2D4A] rounded-xl flex flex-col justify-between cursor-pointer transition-colors group"
              >
                <div className="flex items-center justify-between text-xs text-[#8E9EB5]">
                  <span className="font-semibold group-hover:text-[#E8EEF7]">Blocked IPs</span>
                  <span className="w-2 h-2 rounded-full bg-[#EF5350]"></span>
                </div>
                <div className={`text-2xl font-bold font-mono my-1 ${activeBlockedIpsCount > 0 ? 'text-[#EF5350]' : 'text-[#E8EEF7]'}`}>
                  {activeBlockedIpsCount}
                </div>
                <div className="text-[10px] text-[#64748B]">
                  {activeBlockedIpsCount === 0 ? '0 IP terisolasi (daftar bersih)' : 'IP penyerang dalam karantina'}
                </div>
              </div>

              {/* Card 4: Connected Sensors */}
              <div
                onClick={() => onNavigateToTab('sensors')}
                className="p-3.5 bg-[#101827] border border-[#16233B] hover:border-[#1E2D4A] rounded-xl flex flex-col justify-between cursor-pointer transition-colors group"
              >
                <div className="flex items-center justify-between text-xs text-[#8E9EB5]">
                  <span className="font-semibold group-hover:text-[#E8EEF7]">Connected Sensors</span>
                  <Radio className="w-4 h-4 text-[#16C79A]" />
                </div>
                <div className="text-2xl font-bold font-mono my-1 text-[#16C79A]">
                  {connectedSensorsCount} / {sensors.length || 5}
                </div>
                <div className="text-[10px] text-[#64748B]">
                  Suricata, WAF, Apache, & Database
                </div>
              </div>
            </div>

            {/* Defense Posture & Sensor Connection Status Strip */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {/* Protection Status */}
              <div className="bg-[#101827] border border-[#16233B] rounded-xl p-3 flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-[#16C79A]" />
                  <span className="text-[#8E9EB5] font-semibold">Protection Status:</span>
                </div>
                <div className="flex items-center gap-2 font-mono text-[11px]">
                  <span className="px-2 py-0.5 rounded bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30">
                    IDS/IPS: ACTIVE
                  </span>
                  <span className="px-2 py-0.5 rounded bg-[#36A3FF]/20 text-[#36A3FF] border border-[#36A3FF]/30">
                    WAF: ACTIVE
                  </span>
                  <span className="px-2 py-0.5 rounded bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30">
                    AUTO-BLOCK: READY
                  </span>
                </div>
              </div>

              {/* Sensor Connection Quick Status */}
              <div className="bg-[#101827] border border-[#16233B] rounded-xl p-3 flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <Radio className="w-4 h-4 text-[#36A3FF]" />
                  <span className="text-[#8E9EB5] font-semibold">Sensor Status:</span>
                </div>
                <div className="flex items-center gap-2 font-mono text-[11px]">
                  <span className="text-[#8E9EB5]">
                    Suricata:{' '}
                    <span className="text-[#16C79A]">
                      {sensors.find((s) => s.id === 'sensor-suricata')?.connectionStatus === 'connected' ? 'ONLINE' : 'WAITING'}
                    </span>
                  </span>
                  <span>•</span>
                  <span className="text-[#8E9EB5]">
                    Target DVWA:{' '}
                    <span className={dvwaSensor?.connectionStatus === 'connected' ? 'text-[#16C79A]' : 'text-[#F5B942]'}>
                      {dvwaSensor?.connectionStatus === 'connected' ? 'ONLINE' : 'WAITING'}
                    </span>
                  </span>
                </div>
              </div>
            </div>
          </>
        );
      })()}

      {/* Main Grid: Topology & Incident/Alerts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Network Topology of Ubuntu Home Server Subnet - 8 cols */}
        <div className="lg:col-span-8 bg-[#101827] border border-[#16233B] rounded-xl p-4 flex flex-col justify-between">
          <NetworkTopology nodes={nodes} onIsolateNode={onIsolateNode} />
        </div>

        {/* Incident / Active Dossier Stepper - 4 cols */}
        <div className="lg:col-span-4 bg-[#101827] border border-[#16233B] rounded-xl p-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-2 border-b border-[#16233B]">
              <div className="text-xs font-semibold text-[#E8EEF7]">Incident Lifecycle Dossier</div>
              {incidents.length > 0 ? (
                <span className="text-[10px] font-mono text-[#36A3FF]">{incidents.length} Active</span>
              ) : (
                <span className="text-[10px] text-[#64748B]">Zero Incidents</span>
              )}
            </div>

            {incidents.length > 0 && activeIncident ? (
              <div className="mt-3 space-y-2.5">
                <div className="text-xs font-bold text-[#E8EEF7] truncate">{activeIncident.title}</div>
                {activeIncident.timeline.map((step, idx) => (
                  <div key={idx} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span
                        className={`w-3.5 h-3.5 rounded-full flex items-center justify-center text-[8px] font-bold ${
                          step.status === 'completed'
                            ? 'bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]'
                            : step.status === 'in_progress'
                            ? 'bg-[#EF5350]/20 text-[#EF5350] border border-[#EF5350] animate-pulse'
                            : 'bg-[#1B283F] text-[#64748B]'
                        }`}
                      >
                        {step.status === 'completed' ? '✓' : idx + 1}
                      </span>
                      <div>
                        <div className="font-medium text-[#E8EEF7] text-[11px] leading-tight">{step.step}</div>
                        <div className="text-[9px] text-[#64748B] font-mono">{step.time}</div>
                      </div>
                    </div>
                    <button
                      onClick={() => onSelectIncident(activeIncident)}
                      className="px-2 py-0.5 rounded text-[10px] font-medium bg-[#152338] text-[#16C79A]"
                    >
                      {step.actionLabel || 'Investigate'}
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-12 text-center text-xs space-y-2">
                <Shield className="w-8 h-8 text-[#1E2D4A] mx-auto" />
                <div className="font-semibold text-[#E8EEF7]">NO ACTIVE INCIDENTS</div>
                <p className="text-[11px] text-[#64748B] max-w-xs mx-auto">
                  Belum ada aktivitas ancaman yang terdeteksi. Incident hanya akan dibuat jika alert aktual memenuhi kriteria eskalasi.
                </p>
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-[#16233B]">
            <button
              onClick={() => onNavigateToTab('ai_analyst')}
              className="w-full py-2 bg-[#152338] hover:bg-[#16C79A] text-[#16C79A] hover:text-[#080D17] rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-all"
            >
              <Bot className="w-3.5 h-3.5" />
              Open AI Security Analyst
            </button>
          </div>
        </div>
      </div>

      {/* Recent Security Activity Table — ZERO DUMMY DATA */}
      <div className="bg-[#101827] border border-[#16233B] rounded-xl p-4 space-y-3">
        <div className="flex items-center justify-between pb-2 border-b border-[#16233B]">
          <div>
            <h3 className="text-xs font-semibold text-[#E8EEF7]">Recent Security Activity & Alerts</h3>
            <p className="text-[11px] text-[#8E9EB5]">Verified detections evaluated against actual incoming traffic.</p>
          </div>

          <button
            onClick={() => onNavigateToTab('monitoring')}
            className="text-xs text-[#36A3FF] hover:underline flex items-center gap-1 font-medium"
          >
            <span>View All Logs</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {realAlerts.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono text-[11px]">
              <thead className="text-[#64748B] border-b border-[#152033] bg-[#0A0F1D]">
                <tr>
                  <th className="py-2.5 px-3">Alert ID</th>
                  <th className="py-2.5 px-3">Attack Name</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Defense Action</th>
                  <th className="py-2.5 px-3">Source (Kali IP)</th>
                  <th className="py-2.5 px-3">Target Endpoint</th>
                  <th className="py-2.5 px-3">Detection Source</th>
                  <th className="py-2.5 px-3">Hits</th>
                  <th className="py-2.5 px-3">Raw Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#152033]">
                {realAlerts.map((alt) => (
                  <tr key={alt.id} className="hover:bg-[#152338]/40 transition-colors">
                    <td className="py-2.5 px-3 text-[#36A3FF] font-bold">{alt.id}</td>
                    <td className="py-2.5 px-3 font-sans font-medium text-[#E8EEF7]">{alt.attackName}</td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          alt.severity === 'critical'
                            ? 'bg-[#EF5350]/20 text-[#EF5350] border border-[#EF5350]/30'
                            : alt.severity === 'high'
                            ? 'bg-[#F5B942]/20 text-[#F5B942] border border-[#F5B942]/30'
                            : 'bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30'
                        }`}
                      >
                        {alt.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        alt.defenseStatus === 'BLOCKED'
                          ? 'bg-[#EF5350] text-[#080D17]'
                          : 'bg-[#F5B942]/20 text-[#F5B942] border border-[#F5B942]/40'
                      }`}>
                        {alt.defenseStatus === 'BLOCKED' ? 'BLOCKED' : 'ALLOWED'}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-[#E8EEF7]">{alt.sourceIp}</td>
                    <td className="py-2.5 px-3 text-[#8E9EB5]">{alt.requestUri || '/'}</td>
                    <td className="py-2.5 px-3 text-[#16C79A]">{alt.detectionSource}</td>
                    <td className="py-2.5 px-3 text-[#E8EEF7] font-bold">{alt.eventCount}</td>
                    <td className="py-2.5 px-3 text-[#EF5350] truncate max-w-xs">{alt.evidenceReference}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-12 text-center text-xs space-y-2 bg-[#080D17] border border-[#16233B] rounded-xl">
            <CheckCircle2 className="w-8 h-8 text-[#16C79A] mx-auto" />
            <div className="font-bold text-sm text-[#E8EEF7]">NO SECURITY THREATS DETECTED</div>
            <p className="text-xs text-[#8E9EB5] max-w-md mx-auto">
              Belum ada aktivitas ancaman yang terdeteksi. Sistem monitoring aktif dan mendengarkan event dari tester eksternal Kali Linux via Suricata EVE JSON dan DVWA Target.
            </p>
          </div>
        )}
      </div>

      {/* Isolated Internal Engine Pattern Validator (Unit Test Simulator Only) */}
      <div className="bg-[#101827] border border-[#16233B] rounded-xl overflow-hidden">
        <button
          onClick={() => setShowUnitSimulator(!showUnitSimulator)}
          className="w-full p-3.5 flex items-center justify-between text-left text-xs bg-[#0B111E] hover:bg-[#152033] transition-colors"
        >
          <div className="flex items-center gap-2">
            <FileCode className="w-4 h-4 text-[#F5B942]" />
            <span className="font-bold text-[#E8EEF7]">Pengujian Internal Engine (Simulasi Unit Test Lokal)</span>
            <span className="px-2 py-0.5 rounded text-[9px] font-mono bg-[#F5B942]/20 text-[#F5B942] border border-[#F5B942]/30 uppercase font-semibold">
              Simulasi Murni — Bukan Dari Kali Linux
            </span>
          </div>
          {showUnitSimulator ? <ChevronUp className="w-4 h-4 text-[#8E9EB5]" /> : <ChevronDown className="w-4 h-4 text-[#8E9EB5]" />}
        </button>

        {showUnitSimulator && (
          <div className="p-4 space-y-3 text-xs bg-[#080D17] border-t border-[#16233B]">
            <p className="text-[11px] text-[#8E9EB5] leading-relaxed">
              <strong>Pemberitahuan Arsitektur:</strong> Fitur di bawah ini hanya digunakan untuk menguji keakuratan ekspresi reguler detection engine secara lokal. Hasil pengujian ini diberi label <code>[INTERNAL SIMULATION]</code> dan tidak dicampurkan dengan statistik telemetry aktual dari Kali Linux.
            </p>

            <div className="flex flex-wrap items-center gap-2 pt-1">
              <select
                value={simTestType}
                onChange={(e) => setSimTestType(e.target.value)}
                className="bg-[#101827] border border-[#19263E] text-xs text-[#E8EEF7] px-3 py-1.5 rounded-lg outline-none font-mono"
              >
                <option value="sqli">Simulasi SQLi (' UNION SELECT)</option>
                <option value="xss">Simulasi XSS (&lt;script&gt;)</option>
                <option value="cmdi">Simulasi Command Injection (; cat /etc/passwd)</option>
                <option value="traversal">Simulasi LFI (../../../../etc/passwd)</option>
                <option value="clean">Simulasi Clean Traffic (GET /index.php)</option>
              </select>

              <button
                onClick={handleRunUnitSim}
                disabled={isExecutingSim}
                className="px-3 py-1.5 bg-[#F5B942] hover:bg-[#F5B942]/90 text-[#080D17] font-bold rounded-lg text-xs flex items-center gap-1.5 transition-all"
              >
                <Play className="w-3 h-3" />
                {isExecutingSim ? 'Menjalankan Simulasi...' : 'Jalankan Unit Test Lokal'}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Modal: External Testing & Collector Documentation */}
      {showCollectorModal && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-in fade-in font-sans">
          <div className="bg-[#101827] border border-[#1F2E4A] rounded-2xl w-full max-w-2xl p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#1A263D]">
              <div className="flex items-center gap-2">
                <Terminal className="w-5 h-5 text-[#16C79A]" />
                <h3 className="text-sm font-bold text-[#E8EEF7]">Integrasi Pengujian Eksternal & Collector</h3>
              </div>
              <button
                onClick={() => setShowCollectorModal(false)}
                className="text-[#8E9EB5] hover:text-[#E8EEF7] font-bold"
              >
                ✕
              </button>
            </div>

            {/* Modal Tabs */}
            <div className="flex items-center gap-2 border-b border-[#16233B] pb-2 text-xs">
              <button
                onClick={() => setCollectorModalTab('kali')}
                className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
                  collectorModalTab === 'kali'
                    ? 'bg-[#152338] text-[#36A3FF] border border-[#36A3FF]/40'
                    : 'text-[#8E9EB5] hover:text-[#E8EEF7]'
                }`}
              >
                1. Perintah Uji dari Kali Linux
              </button>
              <button
                onClick={() => setCollectorModalTab('collector')}
                className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
                  collectorModalTab === 'collector'
                    ? 'bg-[#152338] text-[#16C79A] border border-[#16C79A]/40'
                    : 'text-[#8E9EB5] hover:text-[#E8EEF7]'
                }`}
              >
                2. Script Forwarder di Ubuntu Server
              </button>
            </div>

            {collectorModalTab === 'kali' ? (
              <div className="space-y-3 text-xs">
                <p className="text-[#8E9EB5] leading-relaxed">
                  Jalankan perintah-perintah ini langsung dari terminal <strong>Kali Linux</strong> Anda menuju target DVWA di <strong>http://192.168.100.75:8081</strong>. Aktivitas akan ditangkap Suricata dan dialirkan ke dashboard ini:
                </p>

                <pre className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg font-mono text-[11px] text-[#36A3FF] overflow-x-auto whitespace-pre leading-relaxed">
{`# 1. Test SQL Injection (Union Extraction)
curl -s -G "http://192.168.100.75:8081/vulnerabilities/sqli/" \\
  --data-urlencode "id=1' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -" \\
  --data-urlencode "Submit=Submit"

# 2. Automated Scan via sqlmap
sqlmap -u "http://192.168.100.75:8081/vulnerabilities/sqli/?id=1&Submit=Submit" --batch

# 3. Test Cross-Site Scripting (XSS)
curl -s -G "http://192.168.100.75:8081/vulnerabilities/xss_r/" \\
  --data-urlencode 'name=<script>alert("NUSANTARA-DEFENSE-PROVEN")</script>'`}
                </pre>
              </div>
            ) : (
              <div className="space-y-3 text-xs">
                <p className="text-[#8E9EB5] leading-relaxed">
                  Jalankan daemon forwarder ini pada <strong>Ubuntu Home Server (192.168.100.75)</strong> untuk mengalirkan event Suricata dan heartbeat secara real-time dengan token autentikasi aman:
                </p>

                <pre className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg font-mono text-[11px] text-[#16C79A] overflow-x-auto whitespace-pre leading-relaxed">
{`# Jalankan forwarder Suricata eve.json dengan token:
tail -F /var/log/suricata/eve.json | while read -r line; do
  curl -s -X POST "${window.location.origin}/api/ingest/suricata" \\
    -H "Content-Type: application/json" \\
    -H "X-Collector-Token: nusantara-sec-collector-key-2026" \\
    -d "$line" > /dev/null
done`}
                </pre>
              </div>
            )}

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setShowCollectorModal(false)}
                className="px-4 py-2 bg-[#152338] hover:bg-[#1E2D4A] text-[#E8EEF7] font-semibold rounded-lg text-xs"
              >
                Tutup
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
