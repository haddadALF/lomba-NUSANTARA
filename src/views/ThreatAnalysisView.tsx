/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Threat Analysis View
 * Forensic Analysis • Attack Patterns • Technical Evidence • Defense Recommendations
 */

import React, { useState } from 'react';
import {
  Crosshair,
  ShieldAlert,
  Search,
  Filter,
  Code,
  FileText,
  Clock,
  Server,
  Terminal,
  ExternalLink,
  ShieldCheck,
  AlertTriangle,
  Lightbulb,
  CheckCircle2,
  Copy,
  Check,
  ChevronRight,
  Shield,
  Layers,
  Sparkles,
} from 'lucide-react';
import { SecurityAlert, SecurityEvent } from '../types/cybersecurity.js';

interface ThreatAnalysisViewProps {
  alerts: SecurityAlert[];
  events: SecurityEvent[];
  onNavigateToTab?: (tab: string) => void;
}

export const ThreatAnalysisView: React.FC<ThreatAnalysisViewProps> = ({
  alerts,
  events,
  onNavigateToTab,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [selectedAlertId, setSelectedAlertId] = useState<string>(alerts[0]?.id || '');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const filteredAlerts = alerts.filter((a) => {
    if (severityFilter !== 'all' && a.severity !== severityFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        a.attackName.toLowerCase().includes(q) ||
        a.sourceIp.includes(q) ||
        (a.targetAsset || '').toLowerCase().includes(q) ||
        (a.mitreTechniqueId || '').toLowerCase().includes(q) ||
        (a.evidencePayload || a.evidenceReference || '').toLowerCase().includes(q)
      );
    }
    return true;
  });

  const activeAlert = alerts.find((a) => a.id === selectedAlertId) || filteredAlerts[0] || alerts[0];

  // Derive defensive recommendations based on attack type
  const getDefenseRecommendations = (alert?: SecurityAlert) => {
    if (!alert) return [];
    const name = (alert.attackName || '').toLowerCase();
    const payload = (alert.evidencePayload || '').toLowerCase();

    if (name.includes('sql') || payload.includes('select') || payload.includes('union') || payload.includes('1=1')) {
      return [
        {
          layer: 'WAF Rule (ModSecurity CRS)',
          rule: 'SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@detectSQLi" "id:942100,phase:2,block,capture,t:none,t:utf8toUnicode,t:urlDecodeUni,msg:\'SQL Injection Attack Detected\'"',
          action: 'Aktifkan CRS Rule 942100 untuk menolak SQLi pattern dengan HTTP 403 Forbidden otomatis.',
        },
        {
          layer: 'Application Defense (Code Level)',
          rule: 'PDO Prepared Statements / Parameterized Queries (bindValue)',
          action: 'Ganti seluruh query dinamis string concatenation dengan prepared statements pada database DVWA.',
        },
        {
          layer: 'Network Containment (iptables)',
          rule: `iptables -I INPUT -s ${alert.sourceIp} -p tcp --dport 8081 -j DROP`,
          action: `Blokir langsung trafik dari penyerang ${alert.sourceIp} pada firewall host Ubuntu.`,
        },
      ];
    }

    if (name.includes('xss') || payload.includes('<script') || payload.includes('alert(')) {
      return [
        {
          layer: 'WAF Rule (ModSecurity CRS)',
          rule: 'SecRule ARGS|ARGS_NAMES "@detectXSS" "id:941100,phase:2,block,msg:\'XSS Filter - Category 1: Script Tag Vector\'"',
          action: 'Tolak request yang mengandung tag skrip eksekusi dan event handler JavaScript.',
        },
        {
          layer: 'HTTP Header Security',
          rule: 'Content-Security-Policy: default-src \'self\'; script-src \'self\'; object-src \'none\';',
          action: 'Pasang header CSP strict pada reverse proxy untuk mencegah browser mengeksekusi payload.',
        },
      ];
    }

    if (name.includes('command') || payload.includes(';') || payload.includes('|') || payload.includes('cat /etc')) {
      return [
        {
          layer: 'WAF Rule (ModSecurity CRS)',
          rule: 'SecRule ARGS "@pmFromFile unix-shell.data" "id:932100,phase:2,block,msg:\'Remote Command Execution Attempt\'"',
          action: 'Deteksi metacharacter shell (|, ;, &&, `, $) pada parameter input form.',
        },
        {
          layer: 'Host Hardening (AppArmor / Seccomp)',
          rule: 'aa-enforce /usr/sbin/apache2',
          action: 'Batasi kemampuan web server Apache dalam memanggil binary shell (/bin/sh, /bin/bash).',
        },
      ];
    }

    return [
      {
        layer: 'Suricata Signature Matching',
        rule: `alert http ${alert.sourceIp} any -> 192.168.100.75 8081 (msg:"NUSANTARA-SMS Target Exploit Detected"; flow:to_server,established; sid:1000999; rev:1;)`,
        action: 'Tambahkan signature spesifik pada /etc/suricata/rules/local.rules.',
      },
      {
        layer: 'Automatic IP Isolation',
        rule: `POST /api/blocked-ips/manual-block -> IP ${alert.sourceIp}`,
        action: 'Karantina alamat IP penyerang secara otomatis di gateway proteksi.',
      },
    ];
  };

  const recommendations = getDefenseRecommendations(activeAlert);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#101827] border border-[#16233B] rounded-xl p-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#152338] border border-[#16C79A]/30 flex items-center justify-center text-[#16C79A]">
            <Crosshair className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-[#E8EEF7]">Threat Analysis & Forensic Intelligence</h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30 font-semibold">
                Forensic Engine
              </span>
            </div>
            <p className="text-xs text-[#8E9EB5]">
              Analisis mendalam pola serangan, bukti teknis payload aktual, dan rekomendasi pertahanan berlapis.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <div className="px-3 py-1.5 bg-[#080D17] border border-[#16233B] rounded-lg">
            <span className="text-[#8E9EB5] block text-[10px]">Verified Threats</span>
            <span className={`text-sm font-bold ${alerts.length > 0 ? 'text-[#EF5350]' : 'text-[#16C79A]'}`}>
              {alerts.length} Analisis Siap
            </span>
          </div>
        </div>
      </div>

      {alerts.length === 0 ? (
        /* Empty State */
        <div className="bg-[#101827] border border-[#16233B] rounded-xl p-12 text-center">
          <div className="w-16 h-16 rounded-2xl bg-[#152338] border border-[#16C79A]/30 flex items-center justify-center mx-auto text-[#16C79A] mb-4">
            <ShieldCheck className="w-8 h-8" />
          </div>
          <h2 className="text-base font-bold text-[#E8EEF7]">Belum Ada Ancaman yang Memerlukan Analisis Forensik</h2>
          <p className="text-xs text-[#8E9EB5] max-w-md mx-auto mt-1">
            NUSANTARA-SMS sedang memantau telemetry dari sensor lab (Suricata & Apache log). Begitu aktivitas serangan
            terdeteksi dari Kali Linux tester ke DVWA, bukti teknis dan rekomendasi pertahanan akan muncul di sini secara otomatis.
          </p>
          <div className="mt-5 inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#080D17] border border-[#16233B] text-[11px] font-mono text-[#16C79A]">
            <span className="w-2 h-2 rounded-full bg-[#16C79A] animate-pulse"></span>
            SENSOR SIAP • MENUNGGU TELEMETRY SERANGAN
          </div>
        </div>
      ) : (
        /* Split Grid: Threat List & Deep Forensic Detail */
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* Left Column: Threats List (4 cols) */}
          <div className="lg:col-span-4 bg-[#101827] border border-[#16233B] rounded-xl p-3.5 space-y-3 flex flex-col">
            <div className="flex items-center justify-between pb-2 border-b border-[#16233B]">
              <span className="text-xs font-semibold text-[#E8EEF7]">Daftar Ancaman Terdeteksi</span>
              <span className="text-[10px] font-mono text-[#8E9EB5]">{filteredAlerts.length} item</span>
            </div>

            {/* Filters */}
            <div className="space-y-2">
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-[#64748B]" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Cari teknik, IP, payload..."
                  className="w-full bg-[#080D17] border border-[#16233B] rounded-lg pl-8 pr-3 py-1.5 text-xs text-[#E8EEF7] placeholder-[#64748B] focus:outline-none focus:border-[#16C79A]"
                />
              </div>

              <div className="flex items-center gap-1">
                {['all', 'critical', 'high', 'medium'].map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(sev)}
                    className={`flex-1 py-1 rounded text-[10px] font-mono uppercase font-semibold transition-colors ${
                      severityFilter === sev
                        ? sev === 'critical'
                          ? 'bg-[#EF5350] text-white'
                          : sev === 'high'
                          ? 'bg-[#F5B942] text-black'
                          : 'bg-[#16C79A] text-black'
                        : 'bg-[#080D17] text-[#8E9EB5] hover:text-[#E8EEF7] border border-[#16233B]'
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>
            </div>

            {/* Threats Scroll List */}
            <div className="flex-1 space-y-2 overflow-y-auto max-h-[580px] pr-1">
              {filteredAlerts.map((alert) => {
                const isSelected = alert.id === activeAlert?.id;
                return (
                  <div
                    key={alert.id}
                    onClick={() => setSelectedAlertId(alert.id)}
                    className={`p-3 rounded-xl border text-xs cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-[#152338] border-[#16C79A]/50 shadow-md shadow-[#16C79A]/10'
                        : 'bg-[#0B111E] border-[#152033] hover:border-[#1E2D4A] hover:bg-[#101827]'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span className="font-bold text-[#E8EEF7] line-clamp-1">{alert.attackName}</span>
                      <span
                        className={`px-1.5 py-0.2 rounded text-[9px] font-mono font-bold uppercase shrink-0 ${
                          alert.severity === 'critical'
                            ? 'bg-[#EF5350]/20 text-[#EF5350] border border-[#EF5350]/30'
                            : alert.severity === 'high'
                            ? 'bg-[#F5B942]/20 text-[#F5B942] border border-[#F5B942]/30'
                            : 'bg-[#36A3FF]/20 text-[#36A3FF] border border-[#36A3FF]/30'
                        }`}
                      >
                        {alert.severity}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 text-[10px] font-mono text-[#8E9EB5] mt-1.5">
                      <span>IP: {alert.sourceIp}</span>
                      <span>•</span>
                      <span>Target: {alert.targetAsset}</span>
                    </div>

                    {alert.mitreTechniqueId && (
                      <div className="mt-1.5 inline-block px-1.5 py-0.2 rounded bg-[#080D17] border border-[#16233B] text-[9px] font-mono text-[#16C79A]">
                        {alert.mitreTechniqueId} {alert.mitreTacticName ? `— ${alert.mitreTacticName}` : ''}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Column: Deep Forensic Evidence & Recommendations (8 cols) */}
          <div className="lg:col-span-8 space-y-4">
            {activeAlert ? (
              <>
                {/* Threat Banner */}
                <div className="bg-[#101827] border border-[#16233B] rounded-xl p-4 space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-[#16233B]">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono text-[#36A3FF] font-bold">{activeAlert.id}</span>
                        <span
                          className={`px-2 py-0.2 rounded text-[10px] font-mono font-bold uppercase ${
                            activeAlert.severity === 'critical'
                              ? 'bg-[#EF5350]/20 text-[#EF5350] border border-[#EF5350]/30'
                              : 'bg-[#F5B942]/20 text-[#F5B942] border border-[#F5B942]/30'
                          }`}
                        >
                          {activeAlert.severity} SEVERITY
                        </span>
                      </div>
                      <h2 className="text-base font-bold text-[#E8EEF7] mt-1">{activeAlert.attackName}</h2>
                    </div>

                    <div className="flex items-center gap-2">
                      <div className="text-right text-[10px] font-mono text-[#8E9EB5]">
                        <div>Timestamp: {activeAlert.timestamp || activeAlert.lastSeen}</div>
                        <div>Status: {(activeAlert.status || activeAlert.investigationStatus || 'UNREVIEWED').toUpperCase()}</div>
                      </div>
                    </div>
                  </div>

                  {/* Forensic Key Indicators */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                    <div className="p-2.5 rounded-lg bg-[#080D17] border border-[#16233B]">
                      <span className="text-[10px] text-[#64748B] block">Penyerang (Tester IP)</span>
                      <span className="font-mono text-[#EF5350] font-bold">{activeAlert.sourceIp}</span>
                    </div>
                    <div className="p-2.5 rounded-lg bg-[#080D17] border border-[#16233B]">
                      <span className="text-[10px] text-[#64748B] block">Aset Target</span>
                      <span className="font-mono text-[#36A3FF] font-bold truncate block">{activeAlert.targetAsset || '192.168.100.75:8081'}</span>
                    </div>
                    <div className="p-2.5 rounded-lg bg-[#080D17] border border-[#16233B]">
                      <span className="text-[10px] text-[#64748B] block">Teknik MITRE</span>
                      <span className="font-mono text-[#16C79A] font-bold">{activeAlert.mitreTechniqueId || 'T1190'}</span>
                    </div>
                    <div className="p-2.5 rounded-lg bg-[#080D17] border border-[#16233B]">
                      <span className="text-[10px] text-[#64748B] block">Kategori Serangan</span>
                      <span className="font-mono text-[#E8EEF7] font-semibold">{activeAlert.attackCategory}</span>
                    </div>
                  </div>
                </div>

                {/* Technical Evidence (Raw Payload / Signature / Request) */}
                <div className="bg-[#101827] border border-[#16233B] rounded-xl p-4 space-y-3">
                  <div className="flex items-center justify-between pb-2 border-b border-[#16233B]">
                    <div className="flex items-center gap-2">
                      <Code className="w-4 h-4 text-[#36A3FF]" />
                      <h3 className="text-xs font-bold text-[#E8EEF7]">Bukti Teknis Serangan (Technical Evidence)</h3>
                    </div>
                    {(activeAlert.evidencePayload || activeAlert.evidenceReference) && (
                      <button
                        onClick={() => handleCopy(activeAlert.evidencePayload || activeAlert.evidenceReference || '', 'payload')}
                        className="flex items-center gap-1 text-[11px] text-[#8E9EB5] hover:text-[#16C79A] transition-colors"
                      >
                        {copiedKey === 'payload' ? <Check className="w-3.5 h-3.5 text-[#16C79A]" /> : <Copy className="w-3.5 h-3.5" />}
                        {copiedKey === 'payload' ? 'Tersalin' : 'Salin Payload'}
                      </button>
                    )}
                  </div>

                  <div className="space-y-2">
                    <span className="text-[10px] text-[#64748B] block uppercase tracking-wider font-semibold">
                      Raw Attack Payload / Query:
                    </span>
                    <pre className="p-3 rounded-lg bg-[#080D17] border border-[#16233B] text-[11px] font-mono text-[#EF5350] overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                      {activeAlert.evidencePayload || 'Tidak ada raw payload tersimpan untuk alert ini.'}
                    </pre>
                  </div>

                  {activeAlert.description && (
                    <div className="pt-2">
                      <span className="text-[10px] text-[#64748B] block uppercase tracking-wider font-semibold">
                        Analisis Pola & Dampak:
                      </span>
                      <p className="text-xs text-[#E8EEF7] mt-1 leading-relaxed">{activeAlert.description}</p>
                    </div>
                  )}
                </div>

                {/* Layered Defense Recommendations */}
                <div className="bg-[#101827] border border-[#16233B] rounded-xl p-4 space-y-3">
                  <div className="flex items-center gap-2 pb-2 border-b border-[#16233B]">
                    <Lightbulb className="w-4 h-4 text-[#16C79A]" />
                    <h3 className="text-xs font-bold text-[#E8EEF7]">Rekomendasi Pertahanan (Defense Remediations)</h3>
                  </div>

                  <div className="space-y-3">
                    {recommendations.map((rec, idx) => (
                      <div key={idx} className="p-3 rounded-lg bg-[#0B111E] border border-[#152033] space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-[#16C79A]">{rec.layer}</span>
                          <button
                            onClick={() => handleCopy(rec.rule, `rule-${idx}`)}
                            className="text-[10px] text-[#64748B] hover:text-[#E8EEF7] flex items-center gap-1 font-mono"
                          >
                            {copiedKey === `rule-${idx}` ? <Check className="w-3 h-3 text-[#16C79A]" /> : <Copy className="w-3 h-3" />}
                            Salin Rule
                          </button>
                        </div>
                        <pre className="p-2 rounded bg-[#080D17] text-[10px] font-mono text-[#8E9EB5] overflow-x-auto whitespace-pre-wrap">
                          {rec.rule}
                        </pre>
                        <p className="text-[11px] text-[#8E9EB5]">{rec.action}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
};
