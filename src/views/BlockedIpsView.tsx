/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Blocked IP Management View
 * Zero Dummy Data Policy • Real Enforcement Evidence Only
 */

import React, { useState } from 'react';
import {
  ShieldX,
  Search,
  Filter,
  CheckCircle2,
  Lock,
  Unlock,
  AlertTriangle,
  Clock,
  Radio,
  FileCode,
  Copy,
  Check,
  ShieldCheck,
  AlertOctagon,
  RefreshCw,
  Info,
  KeyRound,
} from 'lucide-react';
import { BlockedIpRecord, SecurityEvent } from '../types/cybersecurity.js';

interface BlockedIpsViewProps {
  blockedIps: BlockedIpRecord[];
  events?: SecurityEvent[];
  onRefresh?: () => void;
  onNavigateToEvent?: (eventId: string) => void;
}

export const BlockedIpsView: React.FC<BlockedIpsViewProps> = ({
  blockedIps,
  events = [],
  onRefresh,
  onNavigateToEvent,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'ACTIVE' | 'UNBLOCKED'>('all');
  const [mechanismFilter, setMechanismFilter] = useState<string>('all');
  const [copiedIp, setCopiedIp] = useState<string | null>(null);

  // Unblock Dialog State
  const [selectedIpToUnblock, setSelectedIpToUnblock] = useState<BlockedIpRecord | null>(null);
  const [adminTokenInput, setAdminTokenInput] = useState('');
  const [unblockReason, setUnblockReason] = useState('Penyelidikan selesai — Alamat IP diverifikasi aman atau masa karantina berakhir.');
  const [confirmedCheck, setConfirmedCheck] = useState(false);
  const [isSubmittingUnblock, setIsSubmittingUnblock] = useState(false);
  const [unblockError, setUnblockError] = useState<string | null>(null);
  const [unblockSuccessMessage, setUnblockSuccessMessage] = useState<string | null>(null);

  // Filtered dataset
  const filteredList = blockedIps.filter((item) => {
    if (statusFilter !== 'all' && item.blockStatus !== statusFilter) return false;
    if (mechanismFilter !== 'all' && item.blockingMechanism !== mechanismFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        item.ipAddress.toLowerCase().includes(q) ||
        item.detectionReason.toLowerCase().includes(q) ||
        (item.relatedSecurityEventId || '').toLowerCase().includes(q)
      );
    }
    return true;
  });

  const activeBlockedCount = blockedIps.filter((b) => b.blockStatus === 'ACTIVE').length;
  const unblockedCount = blockedIps.filter((b) => b.blockStatus === 'UNBLOCKED').length;

  const handleCopyIp = (ip: string) => {
    navigator.clipboard.writeText(ip);
    setCopiedIp(ip);
    setTimeout(() => setCopiedIp(null), 2000);
  };

  const handleExecuteUnblock = async () => {
    if (!selectedIpToUnblock) return;
    if (!confirmedCheck) {
      setUnblockError('Harap centang konfirmasi sebelum membuka blokir.');
      return;
    }

    setIsSubmittingUnblock(true);
    setUnblockError(null);

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };
      if (adminTokenInput.trim()) {
        headers['X-Admin-Token'] = adminTokenInput.trim();
      }

      const res = await fetch('/api/blocked-ips/unblock', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          ipAddress: selectedIpToUnblock.ipAddress,
          reason: unblockReason,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.message || data.error || 'Gagal membuka blokir.');
      }

      setUnblockSuccessMessage(data.message || `IP ${selectedIpToUnblock.ipAddress} berhasil dibuka blokirnya.`);
      if (onRefresh) onRefresh();

      setTimeout(() => {
        setSelectedIpToUnblock(null);
        setUnblockSuccessMessage(null);
        setAdminTokenInput('');
        setConfirmedCheck(false);
      }, 1500);
    } catch (err: any) {
      setUnblockError(err.message || 'Terjadi kesalahan sistem.');
    } finally {
      setIsSubmittingUnblock(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Module Overview Header */}
      <div className="bg-[#101827] border border-[#16233B] rounded-xl p-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-[#16233B]">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#152338] border border-[#EF5350]/40 flex items-center justify-center text-[#EF5350]">
              <ShieldX className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold text-[#E8EEF7]">Blocked IPs (Manajemen Alamat IP Terblokir)</h1>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#EF5350]/20 text-[#EF5350] border border-[#EF5350]/30 font-semibold">
                  ENFORCEMENT EVIDENCE ONLY
                </span>
              </div>
              <p className="text-xs text-[#8E9EB5]">
                Daftar alamat IP yang terbukti secara teknis berhasil ditolak oleh WAF (HTTP 403), Suricata IPS (Drop), atau Kebijakan Aplikasi.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {onRefresh && (
              <button
                onClick={onRefresh}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#152338] hover:bg-[#1E2D4A] text-xs font-semibold text-[#8E9EB5] hover:text-[#E8EEF7] transition-colors border border-[#1E2D4A]"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Segarkan
              </button>
            )}
          </div>
        </div>

        {/* 4 Summary Stats */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 text-xs">
          <div className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg">
            <span className="text-[10px] text-[#8E9EB5] uppercase block font-semibold">Total IP Terblokir:</span>
            <span className="text-lg font-bold font-mono text-[#EF5350]">{activeBlockedCount}</span>
            <span className="text-[10px] text-[#8E9EB5] block mt-0.5">Penolakan aktif</span>
          </div>

          <div className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg">
            <span className="text-[10px] text-[#8E9EB5] uppercase block font-semibold">Sudah Dibuka (Unblocked):</span>
            <span className="text-lg font-bold font-mono text-[#16C79A]">{unblockedCount}</span>
            <span className="text-[10px] text-[#8E9EB5] block mt-0.5">Diaudit administrator</span>
          </div>

          <div className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg">
            <span className="text-[10px] text-[#8E9EB5] uppercase block font-semibold">Mekanisme Penangkalan:</span>
            <span className="text-xs font-bold text-[#36A3FF]">WAF Layer 7 & Suricata IPS</span>
            <span className="text-[10px] text-[#8E9EB5] block mt-0.5">Dual-tier enforcement</span>
          </div>

          <div className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg">
            <span className="text-[10px] text-[#8E9EB5] uppercase block font-semibold">Integritas Data:</span>
            <span className="text-xs font-bold text-[#16C79A] flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> Zero Fake IP
            </span>
            <span className="text-[10px] text-[#8E9EB5] block mt-0.5">Hanya dari event nyata</span>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-[#101827] border border-[#16233B] rounded-xl p-3 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          {/* Status Tabs */}
          <div className="flex items-center gap-1 bg-[#080D17] border border-[#16233B] rounded-lg p-1">
            <button
              onClick={() => setStatusFilter('all')}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                statusFilter === 'all'
                  ? 'bg-[#152338] text-[#16C79A] font-bold shadow-sm'
                  : 'text-[#8E9EB5] hover:text-[#E8EEF7]'
              }`}
            >
              Semua ({blockedIps.length})
            </button>
            <button
              onClick={() => setStatusFilter('ACTIVE')}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                statusFilter === 'ACTIVE'
                  ? 'bg-[#EF5350]/20 text-[#EF5350] font-bold border border-[#EF5350]/40'
                  : 'text-[#8E9EB5] hover:text-[#E8EEF7]'
              }`}
            >
              Aktif Terblokir ({activeBlockedCount})
            </button>
            <button
              onClick={() => setStatusFilter('UNBLOCKED')}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                statusFilter === 'UNBLOCKED'
                  ? 'bg-[#16C79A]/20 text-[#16C79A] font-bold border border-[#16C79A]/40'
                  : 'text-[#8E9EB5] hover:text-[#E8EEF7]'
              }`}
            >
              Sudah Dibuka ({unblockedCount})
            </button>
          </div>

          {/* Mechanism Dropdown */}
          <select
            value={mechanismFilter}
            onChange={(e) => setMechanismFilter(e.target.value)}
            className="bg-[#080D17] border border-[#16233B] text-[#E8EEF7] px-3 py-1.5 rounded-lg outline-none cursor-pointer text-xs"
          >
            <option value="all">Semua Mekanisme Penangkalan</option>
            <option value="WAF">WAF (HTTP 403 Forbidden)</option>
            <option value="IPS">Suricata IPS (Network Packet Drop)</option>
            <option value="APPLICATION">Application Tier Denial</option>
            <option value="ADMIN_MANUAL">Admin Manual Block</option>
          </select>
        </div>

        {/* Search Input */}
        <div className="relative w-72">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[#64748B]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Cari IP address, alasan penolakan..."
            className="w-full bg-[#080D17] border border-[#16233B] rounded-lg pl-8 pr-3 py-1.5 text-xs text-[#E8EEF7] placeholder-[#64748B] focus:outline-none focus:border-[#16C79A]"
          />
        </div>
      </div>

      {/* Main Table or Clean Empty State */}
      <div className="bg-[#101827] border border-[#16233B] rounded-xl overflow-hidden shadow-xl">
        {filteredList.length === 0 ? (
          <div className="p-12 text-center space-y-3">
            <div className="w-12 h-12 rounded-full bg-[#152338] border border-[#16233B] flex items-center justify-center text-[#16C79A] mx-auto">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <h3 className="text-sm font-semibold text-[#E8EEF7]">BELUM ADA ALAMAT IP YANG DIBLOKIR</h3>
            <p className="text-xs text-[#8E9EB5] max-w-md mx-auto leading-relaxed">
              NUSANTARA-SMS mematuhi kebijakan <strong>Zero Dummy Data</strong>. Daftar ini hanya akan terisi apabila mekanisme penangkalan (WAF/IPS/App) secara aktual berhasil menolak serangan dari mesin penguji eksternal (seperti Kali Linux).
            </p>
            <div className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg max-w-lg mx-auto text-left font-mono text-[11px] text-[#36A3FF] space-y-1">
              <div className="text-[10px] text-[#8E9EB5]">Cara Menguji Penangkalan dari Terminal Kali Linux:</div>
              <code>curl -s "http://localhost:3000/protected/login?id=1'+OR+1=1"</code>
              <p className="text-[10px] text-[#8E9EB5] pt-1">
                Request berbahaya akan diinspeksi, ditolak dengan HTTP 403 Forbidden, dan IP tester akan otomatis masuk ke daftar ini dengan bukti teknis forensik.
              </p>
            </div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono text-[11px]">
              <thead className="bg-[#0A0F1D] text-[#64748B] border-b border-[#16233B]">
                <tr>
                  <th className="py-2.5 px-3">IP Address</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Mekanisme Penangkalan</th>
                  <th className="py-2.5 px-3">Alasan Pemblokiran</th>
                  <th className="py-2.5 px-3">Event Terkait</th>
                  <th className="py-2.5 px-3">Pertama Diblokir</th>
                  <th className="py-2.5 px-3">Terakhir Terdeteksi</th>
                  <th className="py-2.5 px-3 text-center">Permintaan Ditolak</th>
                  <th className="py-2.5 px-3 text-right">Tindakan</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#152033]">
                {filteredList.map((item) => {
                  const isActive = item.blockStatus === 'ACTIVE';

                  return (
                    <tr key={item.ipAddress} className="hover:bg-[#152338]/50 transition-colors">
                      {/* IP Address */}
                      <td className="py-2.5 px-3 font-bold text-[#E8EEF7]">
                        <div className="flex items-center gap-1.5">
                          <span>{item.ipAddress}</span>
                          <button
                            onClick={() => handleCopyIp(item.ipAddress)}
                            className="text-[#64748B] hover:text-[#36A3FF] p-0.5 rounded"
                            title="Salin IP"
                          >
                            {copiedIp === item.ipAddress ? (
                              <Check className="w-3 h-3 text-[#16C79A]" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                      </td>

                      {/* Status */}
                      <td className="py-2.5 px-3">
                        {isActive ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#EF5350]/20 text-[#EF5350] border border-[#EF5350]/30 inline-flex items-center gap-1">
                            <Lock className="w-3 h-3" /> ACTIVE BLOCKED
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30 inline-flex items-center gap-1">
                            <Unlock className="w-3 h-3" /> UNBLOCKED
                          </span>
                        )}
                      </td>

                      {/* Mechanism */}
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                          item.blockingMechanism === 'WAF'
                            ? 'bg-[#EF5350] text-[#080D17] font-bold'
                            : item.blockingMechanism === 'IPS'
                            ? 'bg-[#A855F7] text-white font-bold'
                            : item.blockingMechanism === 'APPLICATION'
                            ? 'bg-[#F97316] text-white font-bold'
                            : 'bg-[#36A3FF]/20 text-[#36A3FF] border border-[#36A3FF]/40'
                        }`}>
                          {item.blockingMechanism === 'WAF'
                            ? 'WAF (HTTP 403)'
                            : item.blockingMechanism === 'IPS'
                            ? 'Suricata IPS (Drop)'
                            : item.blockingMechanism === 'APPLICATION'
                            ? 'Application 401/403'
                            : 'Admin Manual Block'}
                        </span>
                      </td>

                      {/* Detection Reason */}
                      <td className="py-2.5 px-3 text-[#CBD5E1] max-w-xs truncate font-sans text-xs" title={item.detectionReason}>
                        {item.detectionReason}
                        {item.unblockReason && (
                          <span className="block text-[10px] text-[#16C79A] font-mono mt-0.5">
                            Catatan Buka: {item.unblockReason}
                          </span>
                        )}
                      </td>

                      {/* Related Event */}
                      <td className="py-2.5 px-3 text-[#36A3FF]">
                        {item.relatedSecurityEventId ? (
                          <button
                            onClick={() => onNavigateToEvent && onNavigateToEvent(item.relatedSecurityEventId!)}
                            className="hover:underline flex items-center gap-1 font-mono"
                          >
                            <FileCode className="w-3 h-3" />
                            {item.relatedSecurityEventId}
                          </button>
                        ) : (
                          <span className="text-[#64748B]">-</span>
                        )}
                      </td>

                      {/* First & Last Blocked */}
                      <td className="py-2.5 px-3 text-[#8E9EB5] whitespace-nowrap">{item.firstBlocked}</td>
                      <td className="py-2.5 px-3 text-[#8E9EB5] whitespace-nowrap">{item.lastBlocked}</td>

                      {/* Request Count */}
                      <td className="py-2.5 px-3 text-center font-bold text-[#EF5350]">
                        {item.requestCount}x
                      </td>

                      {/* Actions */}
                      <td className="py-2.5 px-3 text-right">
                        {isActive ? (
                          <button
                            onClick={() => setSelectedIpToUnblock(item)}
                            className="px-2.5 py-1 rounded bg-[#152338] hover:bg-[#1E2D4A] text-[#16C79A] font-semibold text-[11px] transition-colors border border-[#16C79A]/40 inline-flex items-center gap-1"
                          >
                            <Unlock className="w-3 h-3" /> Buka Blokir
                          </button>
                        ) : (
                          <span className="text-[10px] text-[#64748B]">
                            Oleh {item.unblockedBy || 'Admin'}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Unblock Confirmation Modal */}
      {selectedIpToUnblock && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-in fade-in">
          <div className="bg-[#101827] border border-[#1E2D4A] rounded-2xl w-full max-w-lg p-5 shadow-2xl space-y-4 font-sans">
            <div className="flex items-center justify-between pb-3 border-b border-[#1A263D]">
              <div className="flex items-center gap-2">
                <Unlock className="w-5 h-5 text-[#16C79A]" />
                <h3 className="text-sm font-bold text-[#E8EEF7]">Buka Blokir Alamat IP (Unblock Enforcement)</h3>
              </div>
              <button
                onClick={() => setSelectedIpToUnblock(null)}
                className="text-[#8E9EB5] hover:text-[#E8EEF7] font-bold"
              >
                ✕
              </button>
            </div>

            <div className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg text-xs space-y-1">
              <div className="text-[10px] text-[#8E9EB5] uppercase font-semibold">Alamat IP Target:</div>
              <div className="text-base font-bold font-mono text-[#EF5350]">{selectedIpToUnblock.ipAddress}</div>
              <div className="text-[11px] text-[#8E9EB5]">
                Alasan diblokir: {selectedIpToUnblock.detectionReason}
              </div>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-[11px] text-[#8E9EB5] font-semibold block mb-1">
                  Catatan Alasan Pembukaan Blokir (Wajib Dicatat di Audit Log):
                </label>
                <textarea
                  value={unblockReason}
                  onChange={(e) => setUnblockReason(e.target.value)}
                  rows={2}
                  className="w-full bg-[#080D17] border border-[#16233B] rounded-lg p-2.5 text-xs text-[#E8EEF7] placeholder-[#64748B] focus:outline-none focus:border-[#16C79A]"
                />
              </div>

              <div>
                <label className="text-[11px] text-[#8E9EB5] font-semibold block mb-1 flex items-center gap-1">
                  <KeyRound className="w-3.5 h-3.5 text-[#36A3FF]" />
                  Admin Authorization Token (Opsional jika session terotentikasi):
                </label>
                <input
                  type="password"
                  value={adminTokenInput}
                  onChange={(e) => setAdminTokenInput(e.target.value)}
                  placeholder="Masukkan X-Admin-Token..."
                  className="w-full bg-[#080D17] border border-[#16233B] rounded-lg px-3 py-2 text-xs text-[#E8EEF7] font-mono focus:outline-none focus:border-[#16C79A]"
                />
              </div>

              <label className="flex items-start gap-2 p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg cursor-pointer">
                <input
                  type="checkbox"
                  checked={confirmedCheck}
                  onChange={(e) => setConfirmedCheck(e.target.checked)}
                  className="mt-0.5 accent-[#16C79A]"
                />
                <span className="text-[11px] text-[#CBD5E1]">
                  Saya menyatakan bahwa alamat IP ini telah diverifikasi aman dan menyetujui pemulihan akses trafik menuju infrastruktur yang dilindungi.
                </span>
              </label>
            </div>

            {unblockError && (
              <div className="p-2.5 bg-[#EF5350]/15 border border-[#EF5350]/40 rounded-lg text-xs text-[#EF5350] flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{unblockError}</span>
              </div>
            )}

            {unblockSuccessMessage && (
              <div className="p-2.5 bg-[#16C79A]/15 border border-[#16C79A]/40 rounded-lg text-xs text-[#16C79A] flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                <span>{unblockSuccessMessage}</span>
              </div>
            )}

            <div className="pt-2 flex items-center justify-end gap-2">
              <button
                onClick={() => setSelectedIpToUnblock(null)}
                className="px-3.5 py-2 rounded-lg bg-[#152338] hover:bg-[#1E2D4A] text-[#8E9EB5] hover:text-[#E8EEF7] text-xs font-semibold"
                disabled={isSubmittingUnblock}
              >
                Batal
              </button>
              <button
                onClick={handleExecuteUnblock}
                disabled={isSubmittingUnblock || !confirmedCheck}
                className="px-4 py-2 rounded-lg bg-[#16C79A] hover:bg-[#16C79A]/90 text-[#080D17] font-bold text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isSubmittingUnblock ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Memproses...
                  </>
                ) : (
                  <>
                    <Unlock className="w-3.5 h-3.5" /> Konfirmasi Buka Blokir
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
