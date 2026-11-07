/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Security Event Explorer (Phase 1 Foundation)
 * Detailed Inspection, Multi-Criteria Filtering & Raw Payload Auditing
 */

import React, { useState, useMemo } from 'react';
import {
  Search,
  Filter,
  Layers,
  ShieldAlert,
  ShieldCheck,
  FileCode,
  ExternalLink,
  Clock,
  Radio,
  Download,
  Eye,
  X,
  Server,
  ArrowRight,
} from 'lucide-react';
import { SecurityEvent, SecurityAlert } from '../types/cybersecurity.js';
import { ModuleExplanationCard, ModuleGuideData } from '../components/ModuleExplanationCard.js';

const EVENTS_GUIDE: ModuleGuideData = {
  title: 'Modul 3: Penjelajah Catatan Keamanan (Security Event Explorer)',
  badge: 'Forensic Evidence Vault',
  shortSummary: 'Pemeriksaan forensik mendalam terhadap seluruh catatan event dengan audit muatan payload mentah (raw payload).',
  fungsiUtama: 'Menyimpan dan mengindeks seluruh bukti teknis mentah dari setiap request untuk keperluan analisis forensik dan pembuktian dewan juri.',
  alasanDiperlukan: 'Klaim deteksi serangan harus dapat dibuktikan dengan payload asli, bukan sekadar ringkasan abstrak tanpa bukti sah.',
  caraKerja: 'Setiap event yang masuk diurai field per field, dinormalisasi ke skema standar, dan dipetakan ke taksonomi MITRE & OWASP.',
  dataDitampilkan: 'ID unik event, URI request, string payload hex/ASCII, header HTTP, rule pengenal, dan korelasi ke ID alert.',
  artiStatus: 'Detected: Teridentifikasi mencurigakan oleh aturan regex; Clean: Permintaan normal tanpa indikasi eksploitasi.',
  panduanTindakan: 'Gunakan pencarian multi-kriteria, buka modal inspeksi JSON mentah, dan verifikasi apakah payload merupakan false positive.',
};

interface SecurityEventsViewProps {
  events: SecurityEvent[];
  alerts: SecurityAlert[];
  onInspectAlert?: (alertId: string) => void;
}

export const SecurityEventsView: React.FC<SecurityEventsViewProps> = ({
  events,
  alerts,
  onInspectAlert,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedSource, setSelectedSource] = useState<string>('all');
  const [activeEventModal, setActiveEventModal] = useState<SecurityEvent | null>(null);

  // Filtered real events
  const filteredEvents = useMemo(() => {
    return events.filter((evt) => {
      if (selectedCategory !== 'all' && evt.category !== selectedCategory) return false;
      if (selectedSeverity !== 'all' && evt.severity !== selectedSeverity) return false;
      if (selectedSource !== 'all' && evt.source !== selectedSource) return false;

      if (searchTerm.trim()) {
        const q = searchTerm.toLowerCase();
        const matchesTitle = (evt.title || '').toLowerCase().includes(q);
        const matchesIp = (evt.sourceIp || '').includes(q) || (evt.destIp || '').includes(q);
        const matchesPayload = evt.rawPayload?.toLowerCase().includes(q);
        const matchesMitre = (evt.mitreTechniqueId || '').toLowerCase().includes(q);
        const matchesOwasp = evt.owaspCategory?.toLowerCase().includes(q);
        if (!matchesTitle && !matchesIp && !matchesPayload && !matchesMitre && !matchesOwasp) {
          return false;
        }
      }
      return true;
    });
  }, [events, searchTerm, selectedCategory, selectedSeverity, selectedSource]);

  // Find if an event is correlated to an alert
  const getCorrelatedAlert = (evtId: string) => {
    return alerts.find((a) => a.eventIds.includes(evtId));
  };

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(filteredEvents, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `nusantara-security-events-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-4">
      {/* 6-Aspect Progressive Disclosure Module Guide */}
      <ModuleExplanationCard guide={EVENTS_GUIDE} />

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#101827] border border-[#16233B] rounded-xl p-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#152338] border border-[#36A3FF]/40 flex items-center justify-center text-[#36A3FF]">
            <Layers className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-[#E8EEF7]">Security Event Explorer</h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#36A3FF]/20 text-[#36A3FF] border border-[#36A3FF]/30">
                Raw Telemetry Archive
              </span>
            </div>
            <p className="text-xs text-[#8E9EB5]">
              Audit trail of every normalized event ingested from Suricata EVE, WAF, and DVWA access logs.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportJson}
            disabled={filteredEvents.length === 0}
            className="px-3 py-1.5 rounded-lg bg-[#080D17] border border-[#16233B] hover:border-[#1E2D4A] text-xs font-mono text-[#8E9EB5] hover:text-[#E8EEF7] flex items-center gap-1.5 transition-colors disabled:opacity-40"
          >
            <Download className="w-3.5 h-3.5" /> Export JSON
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-[#101827] border border-[#16233B] rounded-xl p-3 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-2 text-xs">
          {/* Search Input */}
          <div className="md:col-span-5 relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#64748B]" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search IP, payload, rule, MITRE, or OWASP..."
              className="w-full bg-[#080D17] border border-[#16233B] rounded-lg pl-9 pr-3 py-2 text-xs text-[#E8EEF7] placeholder-[#64748B] focus:border-[#36A3FF] focus:outline-none font-mono"
            />
          </div>

          {/* Category Filter */}
          <div className="md:col-span-3">
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="w-full bg-[#080D17] border border-[#16233B] rounded-lg px-3 py-2 text-xs text-[#E8EEF7] focus:border-[#36A3FF] focus:outline-none"
            >
              <option value="all">All Categories</option>
              <option value="web_attack">Web Attack (SQLi, XSS, Cmd)</option>
              <option value="network_anomaly">Network Anomaly</option>
              <option value="brute_force">Brute Force / Auth</option>
              <option value="c2_communication">C2 / Outbound</option>
              <option value="dns_tunneling">DNS Tunneling</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div className="md:col-span-2">
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="w-full bg-[#080D17] border border-[#16233B] rounded-lg px-3 py-2 text-xs text-[#E8EEF7] focus:border-[#36A3FF] focus:outline-none"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {/* Source Sensor Filter */}
          <div className="md:col-span-2">
            <select
              value={selectedSource}
              onChange={(e) => setSelectedSource(e.target.value)}
              className="w-full bg-[#080D17] border border-[#16233B] rounded-lg px-3 py-2 text-xs text-[#E8EEF7] focus:border-[#36A3FF] focus:outline-none"
            >
              <option value="all">All Sources</option>
              <option value="Suricata IDS">Suricata EVE IDS</option>
              <option value="Nusantara WAF">Nusantara WAF</option>
              <option value="Zeek NSM">Zeek NSM</option>
              <option value="Wazuh FIM/Agent">Wazuh Host</option>
            </select>
          </div>
        </div>

        {/* Telemetry Count Summary */}
        <div className="flex items-center justify-between text-[11px] text-[#8E9EB5] pt-1 border-t border-[#152033]">
          <div>
            Showing <span className="font-mono font-bold text-[#E8EEF7]">{filteredEvents.length}</span> of{' '}
            <span className="font-mono">{events.length}</span> total verified events
          </div>
          {events.length === 0 && (
            <span className="text-[#F5B942] font-mono">
              Database currently pristine (0 events ingested).
            </span>
          )}
        </div>
      </div>

      {/* Events Table or Zero State */}
      <div className="bg-[#101827] border border-[#16233B] rounded-xl overflow-hidden shadow-lg">
        {events.length === 0 ? (
          <div className="p-16 text-center">
            <ShieldCheck className="w-12 h-12 text-[#16C79A] mx-auto mb-3 opacity-60" />
            <h3 className="text-sm font-semibold text-[#E8EEF7]">NO EVENTS RECEIVED</h3>
            <p className="text-xs text-[#8E9EB5] mt-1 max-w-md mx-auto">
              Belum ada event keamanan yang diterima. Sistem tidak menyatakan jaringan aman secara sepihak sebelum data aktual masuk.
            </p>
          </div>
        ) : filteredEvents.length === 0 ? (
          <div className="p-12 text-center">
            <Filter className="w-10 h-10 text-[#64748B] mx-auto mb-2 opacity-60" />
            <h3 className="text-sm font-semibold text-[#E8EEF7]">No Matching Events</h3>
            <p className="text-xs text-[#8E9EB5] mt-1">
              Tidak ada event yang cocok dengan filter atau kata kunci pencarian Anda.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0A0F1D] text-[#64748B] border-b border-[#16233B] text-[11px]">
                <tr>
                  <th className="py-2.5 px-3">Event ID / Time</th>
                  <th className="py-2.5 px-3">Sensor Source</th>
                  <th className="py-2.5 px-3">Event Title</th>
                  <th className="py-2.5 px-3">Flow (Src → Dest)</th>
                  <th className="py-2.5 px-3">MITRE / OWASP</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#152033] text-[11px]">
                {filteredEvents.map((evt) => {
                  const corrAlert = getCorrelatedAlert(evt.id);
                  return (
                    <tr key={evt.id} className="hover:bg-[#152338]/40 transition-colors">
                      <td className="py-2.5 px-3">
                        <span className="text-[#36A3FF] font-bold block">{evt.id}</span>
                        <span className="text-[#64748B] text-[10px]">{evt.timestamp}</span>
                      </td>
                      <td className="py-2.5 px-3 text-[#8E9EB5]">
                        <span className="px-2 py-0.5 rounded bg-[#080D17] border border-[#16233B] text-[10px]">
                          {evt.source}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-sans">
                        <div className="font-semibold text-[#E8EEF7]">{evt.title}</div>
                        {corrAlert && (
                          <span className="inline-flex items-center gap-1 text-[10px] text-[#EF5350] font-mono mt-0.5">
                            <ShieldAlert className="w-3 h-3" /> Promoted to Alert {corrAlert.id}
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="text-[#E8EEF7]">{evt.sourceIp}</div>
                        <div className="text-[#64748B] text-[10px]">→ {evt.destIp}:{evt.port}</div>
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="text-[#36A3FF]">{evt.mitreTechniqueId}</div>
                        <div className="text-[#64748B] text-[10px] truncate max-w-[120px]">{evt.owaspCategory || '-'}</div>
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            evt.severity === 'critical'
                              ? 'bg-[#EF5350]/20 text-[#EF5350] border border-[#EF5350]/30'
                              : evt.severity === 'high'
                              ? 'bg-[#F5B942]/20 text-[#F5B942] border border-[#F5B942]/30'
                              : 'bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30'
                          }`}
                        >
                          {evt.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => setActiveEventModal(evt)}
                          className="px-2.5 py-1 rounded bg-[#080D17] border border-[#16233B] hover:border-[#36A3FF] text-[#36A3FF] hover:text-white transition-colors"
                        >
                          <Eye className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Raw Event Deep Inspection Modal */}
      {activeEventModal && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-[#101827] border border-[#16233B] rounded-2xl w-full max-w-2xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="p-4 border-b border-[#16233B] flex items-center justify-between bg-[#0A0F1D]">
              <div className="flex items-center gap-2">
                <FileCode className="w-5 h-5 text-[#36A3FF]" />
                <div>
                  <h3 className="text-sm font-bold text-[#E8EEF7]">Raw Event Evidence — {activeEventModal.id}</h3>
                  <div className="text-[10px] text-[#64748B] font-mono">{activeEventModal.timestamp}</div>
                </div>
              </div>
              <button
                onClick={() => setActiveEventModal(null)}
                className="w-8 h-8 rounded-lg bg-[#080D17] border border-[#16233B] hover:border-[#EF5350] text-[#8E9EB5] hover:text-[#EF5350] flex items-center justify-center transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 overflow-y-auto space-y-4 font-mono text-xs">
              {/* Event Attributes Grid */}
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
                  <span className="text-[#64748B] block text-[10px]">DETECTION SENSOR:</span>
                  <span className="text-[#E8EEF7] font-semibold">{activeEventModal.source}</span>
                </div>
                <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
                  <span className="text-[#64748B] block text-[10px]">CATEGORY:</span>
                  <span className="text-[#36A3FF] uppercase">{activeEventModal.category}</span>
                </div>
                <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
                  <span className="text-[#64748B] block text-[10px]">SOURCE IP:</span>
                  <span className="text-[#E8EEF7]">{activeEventModal.sourceIp}</span>
                </div>
                <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
                  <span className="text-[#64748B] block text-[10px]">DESTINATION:</span>
                  <span className="text-[#E8EEF7]">{activeEventModal.destIp}:{activeEventModal.port} ({activeEventModal.protocol})</span>
                </div>
                <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
                  <span className="text-[#64748B] block text-[10px]">MITRE ATT&CK:</span>
                  <span className="text-[#16C79A]">{activeEventModal.mitreTechniqueId} — {activeEventModal.mitreTechniqueName}</span>
                </div>
                <div className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
                  <span className="text-[#64748B] block text-[10px]">OWASP TOP 10:</span>
                  <span className="text-[#F5B942]">{activeEventModal.owaspCategory || 'Not Mapped'}</span>
                </div>
              </div>

              {/* Raw Payload Evidence */}
              <div>
                <span className="text-[#64748B] block text-[10px] mb-1">RAW PAYLOAD / HTTP BODY FRAGMENT:</span>
                <div className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg text-[#EF5350] break-all select-all font-mono text-[11px] max-h-36 overflow-y-auto">
                  {activeEventModal.rawPayload || 'No raw payload attached (Flow / Header level event)'}
                </div>
              </div>

              {/* Full JSON Representation */}
              <div>
                <span className="text-[#64748B] block text-[10px] mb-1">FULL NORMALIZED JSON:</span>
                <pre className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg text-[#8E9EB5] text-[10px] overflow-x-auto max-h-48">
                  {JSON.stringify(activeEventModal, null, 2)}
                </pre>
              </div>
            </div>

            <div className="p-3 border-t border-[#16233B] bg-[#0A0F1D] flex items-center justify-between">
              <span className="text-[10px] text-[#64748B] font-mono">
                Asset: {activeEventModal.affectedAsset || '192.168.100.75:8081'}
              </span>
              <button
                onClick={() => setActiveEventModal(null)}
                className="px-4 py-1.5 rounded-lg bg-[#152338] hover:bg-[#1A2C46] text-xs font-semibold text-[#E8EEF7] transition-colors"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
