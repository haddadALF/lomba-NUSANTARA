/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Security Operations Center (SOC) Console View
 * Zero Dummy Data • Real Event Telemetry Only
 */

import React, { useState } from 'react';
import {
  ShieldCheck,
  AlertTriangle,
  Clock,
  Activity,
  CheckCircle,
  TrendingUp,
  BarChart3,
  Layers,
  ArrowRight,
  Shield,
} from 'lucide-react';
import { SecurityEvent, Incident } from '../types/cybersecurity.js';

interface SocConsoleViewProps {
  events: SecurityEvent[];
  incidents: Incident[];
  onNavigateToTab: (tab: any) => void;
}

export const SocConsoleView: React.FC<SocConsoleViewProps> = ({
  events,
  incidents,
  onNavigateToTab,
}) => {
  const criticalCount = events.filter((e) => e.severity === 'critical').length;
  const highCount = events.filter((e) => e.severity === 'high').length;
  const mediumCount = events.filter((e) => e.severity === 'medium').length;
  const lowCount = events.filter((e) => e.severity === 'low').length;

  const webAttackCount = events.filter((e) => e.category === 'web_attack').length;
  const c2Count = events.filter((e) => e.category === 'c2_communication').length;
  const dnsCount = events.filter((e) => e.category === 'dns_tunneling').length;
  const authCount = events.filter((e) => e.category === 'authentication').length;

  return (
    <div className="space-y-4">
      {/* SOC Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-1">
        <div>
          <h1 className="text-xl font-bold text-[#E8EEF7] tracking-tight">Security Operations Center (SOC) Console</h1>
          <p className="text-xs text-[#8E9EB5]">Continuous threat triage, sensor performance telemetry, and SLA governance.</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => onNavigateToTab('monitoring')}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#152338] text-[#16C79A] border border-[#16C79A]/30 rounded-lg text-xs font-semibold hover:bg-[#16C79A] hover:text-[#080D17] transition-all"
          >
            <Activity className="w-3.5 h-3.5" />
            Open Raw Log Ingestor
          </button>
        </div>
      </div>

      {/* 4 KPI Telemetry Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <div className="p-3.5 bg-[#101827] border border-[#16233B] rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[11px] text-[#8E9EB5] block mb-1">Mean Time to Detect (MTTD)</span>
            <div className="text-2xl font-bold font-mono text-[#E8EEF7]">
              {events.length > 0 ? 'Real-time' : 'N/A'}
            </div>
            <span className="text-[10px] text-[#16C79A] font-semibold">
              {events.length > 0 ? 'Active Stream Evaluation' : 'Awaiting incoming events'}
            </span>
          </div>
          <div className="w-10 h-10 rounded-xl bg-[#152338] border border-[#16C79A]/30 flex items-center justify-center text-[#16C79A]">
            <Clock className="w-5 h-5" />
          </div>
        </div>

        <div className="p-3.5 bg-[#101827] border border-[#16233B] rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[11px] text-[#8E9EB5] block mb-1">Active Incidents</span>
            <div className="text-2xl font-bold font-mono text-[#E8EEF7]">
              {incidents.filter((i) => i.status !== 'closed').length}
            </div>
            <span className="text-[10px] text-[#36A3FF] font-semibold">NIST 800-61r2 managed</span>
          </div>
          <div className="w-10 h-10 rounded-xl bg-[#152338] border border-[#36A3FF]/30 flex items-center justify-center text-[#36A3FF]">
            <TrendingUp className="w-5 h-5" />
          </div>
        </div>

        <div className="p-3.5 bg-[#101827] border border-[#16233B] rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[11px] text-[#8E9EB5] block mb-1">Total Ingested Events</span>
            <div className="text-2xl font-bold font-mono text-[#E8EEF7]">{events.length}</div>
            <span className="text-[10px] text-[#64748B]">Actual events in database</span>
          </div>
          <div className="w-10 h-10 rounded-xl bg-[#152338] border border-[#F5B942]/30 flex items-center justify-center text-[#F5B942]">
            <Activity className="w-5 h-5" />
          </div>
        </div>

        <div className="p-3.5 bg-[#101827] border border-[#16233B] rounded-xl flex items-center justify-between">
          <div>
            <span className="text-[11px] text-[#8E9EB5] block mb-1">Target Asset</span>
            <div className="text-base font-bold font-mono text-[#16C79A] truncate max-w-[140px]">
              DVWA (192.168.100.75)
            </div>
            <span className="text-[10px] text-[#8E9EB5]">Port 8081 Ingress</span>
          </div>
          <div className="w-10 h-10 rounded-xl bg-[#152338] border border-[#16C79A]/30 flex items-center justify-center text-[#16C79A]">
            <ShieldCheck className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Main SOC Dashboard Grid */}
      {events.length > 0 ? (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* Severity Distribution */}
          <div className="lg:col-span-6 bg-[#101827] border border-[#16233B] rounded-xl p-4 space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-[#16233B]">
              <h3 className="text-xs font-semibold text-[#E8EEF7]">Threat Severity Distribution</h3>
              <span className="text-[10px] font-mono text-[#8E9EB5]">{events.length} actual events</span>
            </div>

            <div className="space-y-3">
              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-[#EF5350] font-semibold">Critical Threats</span>
                  <span className="font-mono text-[#E8EEF7]">{criticalCount} alerts</span>
                </div>
                <div className="w-full bg-[#080D17] rounded-full h-2 overflow-hidden">
                  <div className="bg-[#EF5350] h-full" style={{ width: `${(criticalCount / (events.length || 1)) * 100}%` }}></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-[#F5B942] font-semibold">High Severity</span>
                  <span className="font-mono text-[#E8EEF7]">{highCount} alerts</span>
                </div>
                <div className="w-full bg-[#080D17] rounded-full h-2 overflow-hidden">
                  <div className="bg-[#F5B942] h-full" style={{ width: `${(highCount / (events.length || 1)) * 100}%` }}></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-[#36A3FF] font-semibold">Medium Severity</span>
                  <span className="font-mono text-[#E8EEF7]">{mediumCount} alerts</span>
                </div>
                <div className="w-full bg-[#080D17] rounded-full h-2 overflow-hidden">
                  <div className="bg-[#36A3FF] h-full" style={{ width: `${(mediumCount / (events.length || 1)) * 100}%` }}></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-[#16C79A] font-semibold">Low / Informational</span>
                  <span className="font-mono text-[#E8EEF7]">{lowCount} alerts</span>
                </div>
                <div className="w-full bg-[#080D17] rounded-full h-2 overflow-hidden">
                  <div className="bg-[#16C79A] h-full" style={{ width: `${(lowCount / (events.length || 1)) * 100}%` }}></div>
                </div>
              </div>
            </div>
          </div>

          {/* Attack Category Breakdown */}
          <div className="lg:col-span-6 bg-[#101827] border border-[#16233B] rounded-xl p-4 space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-[#16233B]">
              <h3 className="text-xs font-semibold text-[#E8EEF7]">Attack Category Breakdown</h3>
              <span className="text-[10px] font-mono text-[#36A3FF]">Evaluated Signatures</span>
            </div>

            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
                <span className="text-[#8E9EB5] text-[11px] block">Web Attacks (OWASP)</span>
                <div className="text-lg font-bold font-mono text-[#E8EEF7] mt-0.5">{webAttackCount} Detections</div>
                <span className="text-[10px] text-[#16C79A]">SQLi, XSS, CmdInj</span>
              </div>

              <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
                <span className="text-[#8E9EB5] text-[11px] block">C2 & Beaconing</span>
                <div className="text-lg font-bold font-mono text-[#EF5350] mt-0.5">{c2Count} Detections</div>
                <span className="text-[10px] text-[#EF5350]">Outbound TLS</span>
              </div>

              <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
                <span className="text-[#8E9EB5] text-[11px] block">DNS Anomalies</span>
                <div className="text-lg font-bold font-mono text-[#F5B942] mt-0.5">{dnsCount} Detections</div>
                <span className="text-[10px] text-[#F5B942]">Tunneling & Entropy</span>
              </div>

              <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
                <span className="text-[#8E9EB5] text-[11px] block">Authentication Abuse</span>
                <div className="text-lg font-bold font-mono text-[#36A3FF] mt-0.5">{authCount} Detections</div>
                <span className="text-[10px] text-[#36A3FF]">Brute Force Probes</span>
              </div>
            </div>

            <div className="pt-2 text-right">
              <button
                onClick={() => onNavigateToTab('mitre')}
                className="text-xs text-[#16C79A] hover:underline inline-flex items-center gap-1 font-medium"
              >
                Inspect Full MITRE ATT&CK Matrix <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-12 text-center text-xs space-y-2 bg-[#101827] border border-[#16233B] rounded-xl">
          <Shield className="w-9 h-9 text-[#16C79A] mx-auto" />
          <div className="font-bold text-sm text-[#E8EEF7]">NO SECURITY THREATS DETECTED</div>
          <p className="text-xs text-[#8E9EB5] max-w-md mx-auto">
            Belum ada aktivitas ancaman yang terdeteksi. Sistem monitoring siap menerima event aktual dari Suricata EVE JSON atau pengujian resmi terhadap target DVWA.
          </p>
        </div>
      )}
    </div>
  );
};
