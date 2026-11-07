/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Incident Response Center (NIST SP 800-61r2)
 */

import React, { useState } from 'react';
import {
  ShieldAlert,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Unlock,
  FileText,
  User,
  Shield,
  Layers,
  Sparkles,
} from 'lucide-react';
import { Incident, AuditLogItem } from '../types/cybersecurity.js';
import { ModuleExplanationCard, ModuleGuideData } from '../components/ModuleExplanationCard.js';

const INCIDENT_GUIDE: ModuleGuideData = {
  title: 'Modul 6: Pusat Penanganan Insiden (Incident Response Center)',
  badge: 'NIST SP 800-61 Rev 2',
  shortSummary: 'Orkestrasi alur penanganan insiden keamanan berstandar NIST dari deteksi, penahanan (containment), hingga penutupan.',
  fungsiUtama: 'Mengelompokkan alert kritis menjadi berkas kasus insiden terstruktur dengan kronologi investigasi dan loker bukti forensik.',
  alasanDiperlukan: 'Respons terhadap insiden tidak boleh acak; harus memiliki alur approval terverifikasi, catatan waktu akurat, dan audit trail.',
  caraKerja: 'Sistem mengeskalasi alert berulang atau berkeparah tinggi menjadi kasus insiden dengan penugasan analis bertingkat.',
  dataDitampilkan: 'Nomor kasus (INC-xxxx), aset terdampak, level keparahan, kronologi kejadian, catatan analis, dan riwayat audit kekal.',
  artiStatus: 'Open: Kasus baru membutuhkan investigasi; Contained: Aset diisolasi; Remediated: Celah ditambal; Closed: Kasus selesai.',
  panduanTindakan: 'Ubah status siklus hidup insiden, tambahkan catatan temuan forensik, dan picu analisis akar masalah berbasis AI.',
};

interface IncidentResponseViewProps {
  incidents: Incident[];
  auditLogs: AuditLogItem[];
  onUpdateIncidentStatus: (id: string, status: Incident['status'], note: string) => Promise<void>;
  onTriggerAiAnalysis: (id: string) => void;
}

export const IncidentResponseView: React.FC<IncidentResponseViewProps> = ({
  incidents,
  auditLogs,
  onUpdateIncidentStatus,
  onTriggerAiAnalysis,
}) => {
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(incidents[0]?.id || '');
  const [newAnalystNote, setNewAnalystNote] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const activeIncident = incidents.find((i) => i.id === selectedIncidentId) || incidents[0];

  const handleAdvanceStatus = async (newStatus: Incident['status']) => {
    if (!activeIncident) return;
    setIsSubmitting(true);
    try {
      await onUpdateIncidentStatus(
        activeIncident.id,
        newStatus,
        newAnalystNote || `Incident lifecycle advanced to ${newStatus}`
      );
      setNewAnalystNote('');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* 6-Aspect Progressive Disclosure Module Guide */}
      <ModuleExplanationCard guide={INCIDENT_GUIDE} />

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#101827] border border-[#16233B] rounded-xl p-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#152338] border border-[#EF5350]/40 flex items-center justify-center text-[#EF5350]">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-[#E8EEF7]">Incident Response Center</h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30">
                NIST SP 800-61 Rev 2
              </span>
            </div>
            <p className="text-xs text-[#8E9EB5]">Orchestrated containment, evidence preservation, timeline correlation, and audit tracking.</p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <button
            onClick={() => activeIncident && onTriggerAiAnalysis(activeIncident.id)}
            disabled={!activeIncident}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#16C79A] hover:bg-[#16C79A]/90 text-[#080D17] rounded-lg font-bold transition-all shadow-md shadow-[#16C79A]/20 disabled:opacity-40"
          >
            <Sparkles className="w-3.5 h-3.5" />
            Generate AI Root Cause
          </button>
        </div>
      </div>

      {/* Main Grid: Incident Selector / Master Case View */}
      {incidents.length > 0 && activeIncident ? (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* Incident List Sidebar - 4 cols */}
          <div className="lg:col-span-4 bg-[#101827] border border-[#16233B] rounded-xl p-3 space-y-2">
            <div className="text-xs font-semibold text-[#E8EEF7] pb-2 border-b border-[#16233B] flex justify-between items-center">
              <span>Active Incident Dossiers</span>
              <span className="text-[10px] font-mono text-[#36A3FF]">{incidents.length} cases</span>
            </div>

            <div className="space-y-2">
              {incidents.map((inc) => (
                <div
                  key={inc.id}
                  onClick={() => setSelectedIncidentId(inc.id)}
                  className={`p-3 rounded-xl border text-xs cursor-pointer transition-colors ${
                    selectedIncidentId === inc.id
                      ? 'bg-[#152338] border-[#16C79A]/60 shadow-md'
                      : 'bg-[#080D17] border-[#16233B] hover:border-[#1E2D4A]'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono font-bold text-[#36A3FF]">{inc.id}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        inc.severity === 'critical'
                          ? 'bg-[#EF5350]/20 text-[#EF5350]'
                          : inc.severity === 'high'
                          ? 'bg-[#F5B942]/20 text-[#F5B942]'
                          : 'bg-[#36A3FF]/20 text-[#36A3FF]'
                      }`}
                    >
                      {inc.severity}
                    </span>
                  </div>
                  <h4 className="font-semibold text-[#E8EEF7] mb-1 leading-snug">{inc.title}</h4>
                  <div className="flex items-center justify-between text-[11px] text-[#8E9EB5]">
                    <span>{inc.assignedTo.split(' ')[0]} {inc.assignedTo.split(' ')[1]}</span>
                    <span className="capitalize text-[#16C79A] font-medium">{inc.status}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Selected Incident Dossier - 8 cols */}
          <div className="lg:col-span-8 bg-[#101827] border border-[#16233B] rounded-xl p-4 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-[#16233B]">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-bold text-[#36A3FF]">{activeIncident.id}</span>
                  <h2 className="text-base font-bold text-[#E8EEF7]">{activeIncident.title}</h2>
                </div>
                <p className="text-xs text-[#8E9EB5] mt-0.5">
                  Impacted Assets: <span className="text-[#E8EEF7] font-semibold">{activeIncident.affectedAssets.join(', ')}</span> · Lead: {activeIncident.assignedTo}
                </p>
              </div>

              {/* Status Transition Action Buttons */}
              <div className="flex items-center gap-1.5 text-xs">
                {activeIncident.status !== 'contained' && (
                  <button
                    onClick={() => handleAdvanceStatus('contained')}
                    disabled={isSubmitting}
                    className="px-3 py-1.5 bg-[#EF5350] hover:bg-[#EF5350]/90 text-white font-semibold rounded-lg shadow-sm"
                  >
                    Mark Contained
                  </button>
                )}
                {activeIncident.status !== 'remediated' && (
                  <button
                    onClick={() => handleAdvanceStatus('remediated')}
                    disabled={isSubmitting}
                    className="px-3 py-1.5 bg-[#F5B942] hover:bg-[#F5B942]/90 text-black font-semibold rounded-lg shadow-sm"
                  >
                    Mark Remediated
                  </button>
                )}
                {activeIncident.status !== 'closed' && (
                  <button
                    onClick={() => handleAdvanceStatus('closed')}
                    disabled={isSubmitting}
                    className="px-3 py-1.5 bg-[#16C79A] hover:bg-[#16C79A]/90 text-[#080D17] font-semibold rounded-lg shadow-sm"
                  >
                    Close Incident
                  </button>
                )}
              </div>
            </div>

            {/* Incident Timeline Progression */}
            <div>
              <h3 className="text-xs font-semibold text-[#E8EEF7] mb-2.5">NIST Incident Timeline</h3>
              <div className="space-y-2">
                {activeIncident.timeline.map((step, idx) => (
                  <div key={idx} className="flex items-start gap-3 p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg text-xs">
                    <div className="pt-0.5">
                      <span
                        className={`w-4 h-4 rounded-full flex items-center justify-center text-[9px] font-bold ${
                          step.status === 'completed'
                            ? 'bg-[#16C79A] text-[#080D17]'
                            : step.status === 'in_progress'
                            ? 'bg-[#EF5350] text-white animate-pulse'
                            : 'bg-[#1E293B] text-[#64748B]'
                        }`}
                      >
                        {step.status === 'completed' ? '✓' : idx + 1}
                      </span>
                    </div>
                    <div className="flex-1">
                      <div className="flex justify-between items-center mb-0.5">
                        <span className="font-semibold text-[#E8EEF7]">{step.step}</span>
                        <span className="font-mono text-[10px] text-[#64748B]">{step.time}</span>
                      </div>
                      <p className="text-[#8E9EB5] text-[11px] leading-relaxed">{step.note}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Evidence Locker */}
            <div>
              <h3 className="text-xs font-semibold text-[#E8EEF7] mb-2">Preserved Forensic Evidence Locker</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                {activeIncident.evidence.map((ev, i) => (
                  <div key={i} className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
                    <span className="text-[10px] text-[#36A3FF] font-mono block uppercase font-bold">{ev.type}</span>
                    <div className="font-medium text-[#E8EEF7] mt-0.5">{ev.description}</div>
                    <div className="text-[10px] font-mono text-[#16C79A] mt-1 bg-[#05080F] p-1 rounded border border-[#152033] truncate">
                      {ev.indicator}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Add Analyst Note Form */}
            <div className="pt-3 border-t border-[#16233B]">
              <h3 className="text-xs font-semibold text-[#E8EEF7] mb-1.5">Add Incident Investigation Note</h3>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={newAnalystNote}
                  onChange={(e) => setNewAnalystNote(e.target.value)}
                  placeholder="Log containment actions, forensic findings, or external coordinator updates..."
                  className="flex-1 bg-[#080D17] border border-[#16233B] rounded-lg px-3 py-1.5 text-xs text-[#E8EEF7] focus:outline-none focus:border-[#16C79A]"
                />
                <button
                  onClick={() => activeIncident && handleAdvanceStatus(activeIncident.status)}
                  disabled={!newAnalystNote.trim() || isSubmitting || !activeIncident}
                  className="px-3.5 py-1.5 bg-[#152338] hover:bg-[#16C79A] text-[#16C79A] hover:text-[#080D17] border border-[#16C79A]/40 rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
                >
                  Log Entry
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-16 text-center text-xs space-y-3 bg-[#101827] border border-[#16233B] rounded-xl">
          <Shield className="w-10 h-10 text-[#16C79A] mx-auto" />
          <div className="font-bold text-base text-[#E8EEF7]">NO SECURITY INCIDENTS OPEN</div>
          <p className="text-xs text-[#8E9EB5] max-w-md mx-auto leading-relaxed">
            Belum ada insiden keamanan yang terdaftar. Sesuai aturan Zero Dummy Data, insiden hanya akan dibuat ketika alert keamanan aktual memenuhi kriteria eskalasi kritis atau serangan berulang terhadap DVWA (192.168.100.75:8081).
          </p>
        </div>
      )}

      {/* Audit Log Table */}
      <div className="bg-[#101827] border border-[#16233B] rounded-xl overflow-hidden shadow-lg">
        <div className="p-3 bg-[#0A0F1D] border-b border-[#16233B] flex items-center justify-between">
          <h3 className="text-xs font-semibold text-[#E8EEF7]">Immutable Administrator & Containment Audit Trail</h3>
          <span className="text-[10px] font-mono text-[#16C79A]">SOC Compliance Verified</span>
        </div>
        <table className="w-full text-left text-xs font-mono text-[11px]">
          <thead className="text-[#64748B] border-b border-[#152033] bg-[#0A0F1D]">
            <tr>
              <th className="py-2.5 px-3">Audit ID</th>
              <th className="py-2.5 px-3">Timestamp</th>
              <th className="py-2.5 px-3">Operator</th>
              <th className="py-2.5 px-3">Action Executed</th>
              <th className="py-2.5 px-3">Target Entity</th>
              <th className="py-2.5 px-3 text-right">Outcome</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#152033]">
            {auditLogs.slice(0, 5).map((log) => (
              <tr key={log.id} className="hover:bg-[#152338]/40">
                <td className="py-2 px-3 text-[#36A3FF]">{log.id}</td>
                <td className="py-2 px-3 text-[#8E9EB5]">{log.timestamp}</td>
                <td className="py-2 px-3 text-[#E8EEF7] font-sans font-medium">{log.user}</td>
                <td className="py-2 px-3 text-[#F5B942] font-semibold">{log.action}</td>
                <td className="py-2 px-3 text-[#E8EEF7]">{log.target}</td>
                <td className="py-2 px-3 text-right">
                  <span className="px-1.5 py-0.5 rounded bg-[#16C79A]/20 text-[#16C79A] text-[10px] font-bold uppercase">
                    {log.outcome}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
