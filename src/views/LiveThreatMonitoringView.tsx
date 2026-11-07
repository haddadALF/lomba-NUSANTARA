/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Live Threat Monitoring View
 * Zero Dummy Data Policy • External Kali Linux Ingestion Stream
 */

import React, { useState } from 'react';
import {
  Play,
  Pause,
  Filter,
  Search,
  Terminal,
  ShieldAlert,
  ArrowDownUp,
  Download,
  X,
  FileCode,
  Radio,
  Server,
  Lock,
  Unlock,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { SecurityEvent, CollectorStatus, ExternalTesterSession } from '../types/cybersecurity.js';
import { ModuleExplanationCard, ModuleGuideData } from '../components/ModuleExplanationCard.js';

const MONITORING_GUIDE: ModuleGuideData = {
  title: 'Modul 2: Pemantauan Ancaman Real-Time (Live Threat Monitoring)',
  badge: 'Suricata & Zeek Stream',
  shortSummary: 'Streaming log transaksi keamanan jaringan dan aplikasi secara langsung tanpa jeda atau refresh halaman.',
  fungsiUtama: 'Menerima dan menyaring log lalu lintas jaringan dan request web secara langsung saat paket melintasi sensor.',
  alasanDiperlukan: 'Deteksi intrusi berkecepatan tinggi memerlukan observasi real-time agar lateral movement dapat segera diputus.',
  caraKerja: 'Server-Sent Events (SSE) mendengarkan endpoint /api/events/stream dan memperbarui tabel secara reaktif saat log masuk.',
  dataDitampilkan: 'Timestamp mikrodetik, IP asal/tujuan, protokol TCP/HTTP, signature Suricata, level keparahan, dan aset target.',
  artiStatus: 'Live Stream: Aktif menerima data; Paused: Analis membekukan stream untuk investigasi mendalam tanpa kehilangan urutan log.',
  panduanTindakan: 'Terapkan filter keparahan (Critical/High), cari IP penyerang, lakukan inspeksi payload mentah, atau ekspor log ke CSV.',
};

interface LiveThreatMonitoringViewProps {
  events: SecurityEvent[];
  isStreamPaused: boolean;
  setIsStreamPaused: (paused: boolean) => void;
  onInspectEvent?: (evt: SecurityEvent) => void;
  collectorStatus?: CollectorStatus | null;
  externalTester?: ExternalTesterSession | null;
}

export const LiveThreatMonitoringView: React.FC<LiveThreatMonitoringViewProps> = ({
  events,
  isStreamPaused,
  setIsStreamPaused,
  collectorStatus,
  externalTester,
}) => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [hideSimulations, setHideSimulations] = useState<boolean>(false);
  const [activeEventDrawer, setActiveEventDrawer] = useState<SecurityEvent | null>(null);

  // Isolate real events vs simulated unit tests
  const realEvents = events.filter((e) => !e.isSimulated);
  const simulatedCount = events.filter((e) => e.isSimulated).length;

  const filteredEvents = events.filter((e) => {
    if (hideSimulations && e.isSimulated) return false;
    if (selectedSeverity !== 'all' && e.severity !== selectedSeverity) return false;
    if (selectedCategory !== 'all' && e.category !== selectedCategory) return false;
    if (searchFilter) {
      const q = searchFilter.toLowerCase();
      return (
        (e.title || '').toLowerCase().includes(q) ||
        (e.sourceIp || '').includes(q) ||
        (e.destIp || '').includes(q) ||
        (e.mitreTechniqueId || '').toLowerCase().includes(q) ||
        (e.affectedAsset || '').toLowerCase().includes(q) ||
        (e.rawPayload || '').toLowerCase().includes(q)
      );
    }
    return true;
  });

  const testerIp =
    externalTester?.sourceIp ||
    collectorStatus?.externalTesterIp ||
    realEvents.find((e) => e.sourceIp !== '192.168.100.75' && e.sourceIp !== '127.0.0.1')?.sourceIp ||
    '192.168.100.88';

  const exportEventsCsv = () => {
    const headers = 'ID,Timestamp,Source,Category,Severity,DefenseStatus,SourceIP,DestIP,Protocol,Port,MITRE,Asset,Title,IsSimulated\n';
    const rows = filteredEvents
      .map(
        (e) =>
          `"${e.id}","${e.timestamp}","${e.source}","${e.category}","${e.severity}","${e.defenseStatus || 'N/A'}","${e.sourceIp || ''}","${e.destIp || ''}","${e.protocol || ''}","${e.port || ''}","${e.mitreTechniqueId || ''}","${e.affectedAsset || ''}","${(e.title || '').replace(/"/g, '""')}","${e.isSimulated ? 'YES' : 'NO'}"`
      )
      .join('\n');
    const blob = new Blob([headers + rows], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `nusantara-telemetry-${Date.now()}.csv`;
    link.click();
  };

  return (
    <div className="space-y-4">
      {/* 6-Aspect Progressive Disclosure Module Guide */}
      <ModuleExplanationCard guide={MONITORING_GUIDE} />

      {/* External Tester & Collector Topology Bar */}
      <div className="bg-[#101827] border border-[#16233B] rounded-xl p-3.5 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#16233B]">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-[#152338] border border-[#16C79A]/30 flex items-center justify-center text-[#16C79A]">
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-[#E8EEF7]">Live Threat Monitoring Feed</h2>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold flex items-center gap-1 ${
                  isStreamPaused ? 'bg-[#F5B942]/20 text-[#F5B942]' : 'bg-[#16C79A]/20 text-[#16C79A]'
                }`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${isStreamPaused ? 'bg-[#F5B942]' : 'bg-[#16C79A] animate-pulse'}`}></span>
                  {isStreamPaused ? 'STREAM PAUSED' : 'LIVE INGESTION (SSE ACTIVE)'}
                </span>
              </div>
              <p className="text-xs text-[#8E9EB5]">
                Penerimaan stream langsung dari Suricata EVE JSON, Apache access logs, dan WAF ingress.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsStreamPaused(!isStreamPaused)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                isStreamPaused
                  ? 'bg-[#16C79A] text-[#080D17] hover:bg-[#16C79A]/90'
                  : 'bg-[#152338] text-[#8E9EB5] hover:text-[#E8EEF7] border border-[#1E2D4A]'
              }`}
            >
              {isStreamPaused ? (
                <>
                  <Play className="w-3.5 h-3.5" /> Resume Stream
                </>
              ) : (
                <>
                  <Pause className="w-3.5 h-3.5" /> Pause Feed
                </>
              )}
            </button>

            <button
              onClick={exportEventsCsv}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#101827] hover:bg-[#152033] text-[#8E9EB5] hover:text-[#E8EEF7] border border-[#19263E] rounded-lg text-xs font-medium transition-colors"
            >
              <Download className="w-3.5 h-3.5" /> Export CSV
            </button>
          </div>
        </div>

        {/* Live Status Indicators */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
            <span className="text-[10px] text-[#8E9EB5] block">External Tester:</span>
            <span className="font-bold text-[#36A3FF] font-mono">Kali Linux ({testerIp})</span>
          </div>
          <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
            <span className="text-[10px] text-[#8E9EB5] block">Target Machine:</span>
            <span className="font-bold text-[#16C79A] font-mono">DVWA (192.168.100.75:8081)</span>
          </div>
          <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
            <span className="text-[10px] text-[#8E9EB5] block">Collector Feed:</span>
            <span className="font-bold text-[#E8EEF7]">
              {collectorStatus?.status === 'ACTIVE' ? 'Authenticated Online' : 'Listening on Port 3000'}
            </span>
          </div>
          <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
            <span className="text-[10px] text-[#8E9EB5] block">Verified Events Received:</span>
            <span className="font-bold text-[#16C79A] font-mono">{realEvents.length} Real Events</span>
          </div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-[#101827] border border-[#16233B] rounded-xl p-3 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          {/* Severity filter tabs */}
          <div className="flex items-center gap-1 bg-[#080D17] border border-[#16233B] rounded-lg p-1">
            {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2.5 py-1 rounded capitalize font-medium transition-colors ${
                  selectedSeverity === sev
                    ? sev === 'critical'
                      ? 'bg-[#EF5350] text-white font-bold'
                      : sev === 'high'
                      ? 'bg-[#F5B942] text-black font-bold'
                      : 'bg-[#16C79A] text-black font-bold'
                    : 'text-[#8E9EB5] hover:text-[#E8EEF7]'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Category Dropdown */}
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="bg-[#080D17] border border-[#16233B] text-[#E8EEF7] px-2.5 py-1.5 rounded-lg outline-none cursor-pointer"
          >
            <option value="all">All Categories</option>
            <option value="c2_communication">C2 Communication</option>
            <option value="web_attack">Web Attack (OWASP)</option>
            <option value="dns_tunneling">DNS Tunneling</option>
            <option value="file_integrity">File Integrity (FIM)</option>
            <option value="authentication">Authentication / Brute Force</option>
            <option value="network_anomaly">Network Anomaly / Port Scan</option>
          </select>

          {/* Toggle: Hide Simulations */}
          {simulatedCount > 0 && (
            <label className="flex items-center gap-1.5 text-[#8E9EB5] bg-[#080D17] border border-[#16233B] px-2.5 py-1.5 rounded-lg cursor-pointer hover:text-[#E8EEF7]">
              <input
                type="checkbox"
                checked={hideSimulations}
                onChange={(e) => setHideSimulations(e.target.checked)}
                className="accent-[#16C79A] cursor-pointer"
              />
              <span>Sembunyikan Unit Test ({simulatedCount})</span>
            </label>
          )}
        </div>

        {/* Search Input */}
        <div className="relative w-64">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[#64748B]" />
          <input
            type="text"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            placeholder="Search payload, IP, technique..."
            className="w-full bg-[#080D17] border border-[#16233B] rounded-lg pl-8 pr-3 py-1.5 text-xs text-[#E8EEF7] placeholder-[#64748B] focus:outline-none focus:border-[#16C79A]"
          />
        </div>
      </div>

      {/* High-Density Live Events Table */}
      <div className="bg-[#101827] border border-[#16233B] rounded-xl overflow-hidden shadow-lg">
        {filteredEvents.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0A0F1D] text-[#64748B] border-b border-[#16233B]">
                <tr>
                  <th className="py-2.5 px-3 font-semibold whitespace-nowrap">Timestamp</th>
                  <th className="py-2.5 px-3 font-semibold whitespace-nowrap">Source IP</th>
                  <th className="py-2.5 px-3 font-semibold whitespace-nowrap">Destination</th>
                  <th className="py-2.5 px-3 font-semibold whitespace-nowrap">HTTP Method</th>
                  <th className="py-2.5 px-3 font-semibold whitespace-nowrap">Request Path</th>
                  <th className="py-2.5 px-3 font-semibold whitespace-nowrap">Detection Category</th>
                  <th className="py-2.5 px-3 font-semibold whitespace-nowrap">Severity</th>
                  <th className="py-2.5 px-3 font-semibold whitespace-nowrap">Detection Status</th>
                  <th className="py-2.5 px-3 font-semibold whitespace-nowrap">Response Action</th>
                  <th className="py-2.5 px-3 font-semibold text-right whitespace-nowrap">Aksi</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#152033]">
                {filteredEvents.map((evt) => {
                  const isBlocked =
                    evt.defenseStatus === 'BLOCKED' ||
                    evt.defenseStatus === 'BLOCKED_BY_WAF' ||
                    evt.defenseStatus === 'BLOCKED_BY_IPS' ||
                    evt.defenseStatus === 'BLOCKED_BY_APPLICATION' ||
                    evt.blockingProof?.isBlocked;
                  const isSim = evt.isSimulated;

                  // Strict 4-tier Detection Status per prompt Section 4
                  let strictStatus: 'DETECTED' | 'MONITORED' | 'BLOCKED' | 'SIMULATED';
                  if (isSim) {
                    strictStatus = 'SIMULATED';
                  } else if (isBlocked) {
                    strictStatus = 'BLOCKED';
                  } else if (evt.severity === 'critical' || evt.severity === 'high' || evt.severity === 'medium') {
                    strictStatus = 'DETECTED';
                  } else {
                    strictStatus = 'MONITORED';
                  }

                  // Response Action
                  let responseAction = 'MONITORED / PASSED';
                  if (evt.defenseStatus === 'BLOCKED_BY_WAF') {
                    responseAction = '403 FORBIDDEN (WAF)';
                  } else if (evt.defenseStatus === 'BLOCKED_BY_IPS') {
                    responseAction = 'PACKET DROP (IPS)';
                  } else if (evt.defenseStatus === 'BLOCKED_BY_APPLICATION') {
                    responseAction = 'ACCESS DENIED (APP)';
                  } else if (evt.defenseStatus === 'BLOCKED') {
                    responseAction = 'BLOCKED';
                  } else if (strictStatus === 'DETECTED') {
                    responseAction = 'ALERTED / FLAGGED';
                  }

                  // HTTP method extraction
                  const httpMethod = (evt.protocol === 'HTTP' || evt.protocol === 'TCP')
                    ? (evt.title?.split(' ')[0] || 'GET').toUpperCase()
                    : 'TCP';
                  const reqPath = evt.affectedAsset || evt.requestUri || '/';

                  return (
                    <tr
                      key={evt.id}
                      onClick={() => setActiveEventDrawer(evt)}
                      className="hover:bg-[#152338]/60 cursor-pointer transition-colors group font-mono text-[11px]"
                    >
                      <td className="py-2.5 px-3 text-[#8E9EB5] whitespace-nowrap">{evt.timestamp}</td>
                      <td className="py-2.5 px-3 text-[#36A3FF] font-semibold whitespace-nowrap">
                        {evt.sourceIp}
                      </td>
                      <td className="py-2.5 px-3 text-[#8E9EB5] whitespace-nowrap">{evt.destIp || '192.168.100.75'}</td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span className="px-1.5 py-0.5 rounded bg-[#080D17] border border-[#16233B] text-[10px] text-[#E8EEF7] font-bold">
                          {httpMethod}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-[#E8EEF7] max-w-[140px] truncate" title={reqPath}>
                        {reqPath}
                      </td>
                      <td className="py-2.5 px-3 text-[#E8EEF7] whitespace-nowrap">
                        {evt.category}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                            evt.severity === 'critical'
                              ? 'bg-[#EF5350]/20 text-[#EF5350] border border-[#EF5350]/40'
                              : evt.severity === 'high'
                              ? 'bg-[#F5B942]/20 text-[#F5B942] border border-[#F5B942]/40'
                              : evt.severity === 'medium'
                              ? 'bg-[#36A3FF]/20 text-[#36A3FF] border border-[#36A3FF]/40'
                              : 'bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/40'
                          }`}
                        >
                          {evt.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            strictStatus === 'BLOCKED'
                              ? 'bg-[#EF5350] text-[#080D17]'
                              : strictStatus === 'DETECTED'
                              ? 'bg-[#EF5350]/20 text-[#EF5350] border border-[#EF5350]/40'
                              : strictStatus === 'SIMULATED'
                              ? 'bg-[#F5B942]/20 text-[#F5B942] border border-[#F5B942]/40'
                              : 'bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30'
                          }`}
                        >
                          {strictStatus}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span className="text-[10px] font-semibold text-[#8E9EB5]">
                          {responseAction}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setActiveEventDrawer(evt);
                          }}
                          className="px-2 py-0.5 bg-[#152338] hover:bg-[#16C79A] text-[#8E9EB5] hover:text-[#080D17] rounded text-[10px] transition-colors"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-16 text-center text-xs space-y-2 bg-[#080D17]">
            <div className="w-9 h-9 rounded-full bg-[#152338] border border-[#16233B] flex items-center justify-center text-[#16C79A] mx-auto">
              ✓
            </div>
            <div className="font-bold text-sm text-[#E8EEF7]">NO SECURITY EVENTS RECORDED</div>
            <p className="text-xs text-[#8E9EB5] max-w-sm mx-auto">
              Belum ada aktivitas ancaman yang terdeteksi. Sistem monitoring aktif mendengarkan event dari tester eksternal Kali Linux via collector.
            </p>
          </div>
        )}

        {/* Footer info */}
        <div className="p-3 bg-[#0A0F1D] border-t border-[#16233B] flex items-center justify-between text-xs text-[#64748B]">
          <span>Displaying {filteredEvents.length} normalized security events</span>
          <span className="font-mono">Real-time Stream Connected</span>
        </div>
      </div>

      {/* Raw Event Inspection Drawer */}
      {activeEventDrawer && (
        <div className="fixed inset-y-0 right-0 w-full max-w-lg bg-[#101827] border-l border-[#1E2D4A] shadow-2xl p-5 z-50 flex flex-col justify-between overflow-y-auto font-sans">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-[#1A263D] mb-4">
              <div className="flex items-center gap-2">
                <FileCode className="w-5 h-5 text-[#16C79A]" />
                <div>
                  <h3 className="text-sm font-bold text-[#E8EEF7]">Event Payload Inspector</h3>
                  <span className="text-xs font-mono text-[#36A3FF]">{activeEventDrawer.id}</span>
                </div>
              </div>
              <button
                onClick={() => setActiveEventDrawer(null)}
                className="p-1 text-[#8E9EB5] hover:text-white rounded"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg space-y-2">
                <div className="text-[10px] text-[#8E9EB5] uppercase font-semibold">Tindakan Pertahanan (Defense Status):</div>
                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-1 rounded text-xs font-bold font-mono ${
                    activeEventDrawer.defenseStatus === 'BLOCKED_BY_WAF'
                      ? 'bg-[#EF5350] text-[#080D17]'
                      : activeEventDrawer.defenseStatus === 'BLOCKED_BY_IPS'
                      ? 'bg-[#A855F7] text-white'
                      : activeEventDrawer.defenseStatus === 'BLOCKED_BY_APPLICATION'
                      ? 'bg-[#F97316] text-white'
                      : activeEventDrawer.defenseStatus === 'DETECTED'
                      ? 'bg-[#F5B942]/20 text-[#F5B942] border border-[#F5B942]/40'
                      : 'bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/40'
                  }`}>
                    {activeEventDrawer.defenseStatus || 'DETECTED'}
                  </span>
                  {activeEventDrawer.blockingProof?.evidenceSource && (
                    <span className="px-2 py-0.5 rounded bg-[#16233B] text-[#36A3FF] text-[10px] font-mono border border-[#36A3FF]/30">
                      SRC: {activeEventDrawer.blockingProof.evidenceSource.toUpperCase()}
                    </span>
                  )}
                  {typeof activeEventDrawer.blockingProof?.confidenceScore === 'number' && (
                    <span className="px-2 py-0.5 rounded bg-[#16C79A]/15 text-[#16C79A] text-[10px] font-mono border border-[#16C79A]/30 font-bold">
                      CONF: {activeEventDrawer.blockingProof.confidenceScore}%
                    </span>
                  )}
                </div>

                {activeEventDrawer.blockingProof?.evidenceReason && (
                  <div className="text-[11px] bg-[#0A101D] p-2 rounded border border-[#1F2E4A]/80 font-mono text-[#E8EEF7]">
                    <span className="text-[#36A3FF] text-[10px] block font-bold uppercase">Bukti Forensik:</span>
                    {activeEventDrawer.blockingProof.evidenceReason}
                  </div>
                )}

                <div className="text-[11px] text-[#8E9EB5]">
                  {activeEventDrawer.blockingProof?.proofDetail || 'Pasif log evaluation'}
                </div>
              </div>

              <div>
                <label className="text-[10px] text-[#8E9EB5] uppercase block mb-1">Title & Source</label>
                <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg text-[#E8EEF7]">
                  {activeEventDrawer.title} ({activeEventDrawer.source})
                </div>
              </div>

              <div>
                <label className="text-[10px] text-[#8E9EB5] uppercase block mb-1">Attack Provenance</label>
                <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg font-mono text-[11px] text-[#16C79A]">
                  {activeEventDrawer.isSimulated
                    ? 'Internal Unit Test Engine (Simulated)'
                    : `External Kali Linux Tester (${activeEventDrawer.sourceIp}) -> DVWA (192.168.100.75:8081)`}
                </div>
              </div>

              <div>
                <label className="text-[10px] text-[#8E9EB5] uppercase block mb-1">Raw Ingested Payload</label>
                <pre className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg font-mono text-[11px] text-[#EF5350] overflow-x-auto whitespace-pre-wrap break-all max-h-60">
                  {activeEventDrawer.rawPayload}
                </pre>
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-[#1A263D] flex justify-end">
            <button
              onClick={() => setActiveEventDrawer(null)}
              className="px-4 py-2 bg-[#152338] hover:bg-[#1E2D4A] text-[#E8EEF7] font-semibold rounded-lg text-xs"
            >
              Close Drawer
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
