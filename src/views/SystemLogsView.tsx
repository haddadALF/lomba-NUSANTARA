/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - System Logs & Audit Trail View
 * Zero Dummy Data Policy • Authentic Internal System & Operational Audit Logs
 */

import React, { useState } from 'react';
import {
  ScrollText,
  Search,
  Filter,
  Download,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Shield,
  Terminal,
  Server,
  Layers,
} from 'lucide-react';
import { AuditLogItem } from '../types/cybersecurity.js';

interface SystemLogsViewProps {
  auditLogs: AuditLogItem[];
  onRefresh?: () => void;
}

export const SystemLogsView: React.FC<SystemLogsViewProps> = ({
  auditLogs,
  onRefresh,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [levelFilter, setLevelFilter] = useState<'all' | 'INFO' | 'WARN' | 'ERROR'>('all');
  const [sourceFilter, setSourceFilter] = useState<string>('all');

  // Derive enriched system logs combining audit items and internal engine logs
  const enrichedLogs = auditLogs.map((log) => {
    let level: 'INFO' | 'WARN' | 'ERROR' = 'INFO';
    const actionLower = log.action.toLowerCase();
    const detailsLower = (log.details || '').toLowerCase();

    if (actionLower.includes('block') || detailsLower.includes('drop') || detailsLower.includes('attack')) {
      level = 'WARN';
    } else if (actionLower.includes('error') || detailsLower.includes('fail') || actionLower.includes('isolation')) {
      level = 'ERROR';
    }

    return {
      id: log.id,
      timestamp: log.timestamp,
      user: log.user,
      action: log.action,
      details: log.details || '',
      level,
      source: actionLower.includes('collector') ? 'COLLECTOR' : actionLower.includes('system') ? 'ENGINE' : 'AUDIT',
    };
  });

  const filteredLogs = enrichedLogs.filter((log) => {
    if (levelFilter !== 'all' && log.level !== levelFilter) return false;
    if (sourceFilter !== 'all' && log.source !== sourceFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        log.action.toLowerCase().includes(q) ||
        log.details.toLowerCase().includes(q) ||
        log.user.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const exportLogs = () => {
    const headers = 'ID,Timestamp,Level,Source,User,Action,Details\n';
    const rows = filteredLogs
      .map(
        (l) =>
          `"${l.id}","${l.timestamp}","${l.level}","${l.source}","${l.user}","${l.action.replace(/"/g, '""')}","${l.details.replace(/"/g, '""')}"`
      )
      .join('\n');
    const blob = new Blob([headers + rows], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `nusantara-system-logs-${Date.now()}.csv`;
    link.click();
  };

  const infoCount = enrichedLogs.filter((l) => l.level === 'INFO').length;
  const warnCount = enrichedLogs.filter((l) => l.level === 'WARN').length;
  const errorCount = enrichedLogs.filter((l) => l.level === 'ERROR').length;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#101827] border border-[#16233B] rounded-xl p-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#152338] border border-[#16C79A]/30 flex items-center justify-center text-[#16C79A]">
            <ScrollText className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-[#E8EEF7]">System Logs & Audit Trail</h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30 font-semibold">
                Audit Trail
              </span>
            </div>
            <p className="text-xs text-[#8E9EB5]">
              Log internal sistem NUSANTARA-SMS, riwayat audit aksi pengguna, dan catatan aktivitas collector.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={exportLogs}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#152338] hover:bg-[#1E2D4A] text-[#8E9EB5] hover:text-[#E8EEF7] border border-[#1E2D4A] rounded-lg text-xs font-semibold transition-colors"
          >
            <Download className="w-3.5 h-3.5" /> Export Log
          </button>
          {onRefresh && (
            <button
              onClick={onRefresh}
              className="p-2 bg-[#152338] hover:bg-[#1E2D4A] text-[#16C79A] border border-[#16C79A]/30 rounded-lg text-xs transition-colors"
              title="Refresh Logs"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Filter and Metrics Toolbar */}
      <div className="bg-[#101827] border border-[#16233B] rounded-xl p-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          {/* Level Tabs */}
          <div className="flex items-center gap-1 bg-[#080D17] border border-[#16233B] rounded-lg p-1 font-mono text-[11px]">
            <button
              onClick={() => setLevelFilter('all')}
              className={`px-2.5 py-1 rounded transition-colors ${
                levelFilter === 'all' ? 'bg-[#152338] text-[#E8EEF7] font-bold' : 'text-[#8E9EB5] hover:text-[#E8EEF7]'
              }`}
            >
              ALL ({enrichedLogs.length})
            </button>
            <button
              onClick={() => setLevelFilter('INFO')}
              className={`px-2.5 py-1 rounded transition-colors ${
                levelFilter === 'INFO' ? 'bg-[#16C79A]/20 text-[#16C79A] font-bold border border-[#16C79A]/30' : 'text-[#8E9EB5] hover:text-[#16C79A]'
              }`}
            >
              INFO ({infoCount})
            </button>
            <button
              onClick={() => setLevelFilter('WARN')}
              className={`px-2.5 py-1 rounded transition-colors ${
                levelFilter === 'WARN' ? 'bg-[#F5B942]/20 text-[#F5B942] font-bold border border-[#F5B942]/30' : 'text-[#8E9EB5] hover:text-[#F5B942]'
              }`}
            >
              WARN ({warnCount})
            </button>
            <button
              onClick={() => setLevelFilter('ERROR')}
              className={`px-2.5 py-1 rounded transition-colors ${
                levelFilter === 'ERROR' ? 'bg-[#EF5350]/20 text-[#EF5350] font-bold border border-[#EF5350]/30' : 'text-[#8E9EB5] hover:text-[#EF5350]'
              }`}
            >
              ERROR ({errorCount})
            </button>
          </div>

          {/* Source Dropdown */}
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="bg-[#080D17] border border-[#16233B] text-[#E8EEF7] px-2.5 py-1.5 rounded-lg outline-none cursor-pointer text-xs"
          >
            <option value="all">Semua Sumber Log</option>
            <option value="ENGINE">ENGINE</option>
            <option value="COLLECTOR">COLLECTOR</option>
            <option value="AUDIT">AUDIT</option>
          </select>
        </div>

        {/* Search */}
        <div className="relative w-full md:w-72">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[#64748B]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Cari aksi, pengguna, atau detail..."
            className="w-full bg-[#080D17] border border-[#16233B] rounded-lg pl-8 pr-3 py-1.5 text-xs text-[#E8EEF7] placeholder-[#64748B] focus:outline-none focus:border-[#16C79A]"
          />
        </div>
      </div>

      {/* Logs Table / List */}
      <div className="bg-[#101827] border border-[#16233B] rounded-xl overflow-hidden shadow-lg">
        {filteredLogs.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-[#0A0F1D] text-[#64748B] border-b border-[#16233B] text-[11px]">
                <tr>
                  <th className="py-2.5 px-3.5 font-semibold">Timestamp</th>
                  <th className="py-2.5 px-3 font-semibold">Level</th>
                  <th className="py-2.5 px-3 font-semibold">Source</th>
                  <th className="py-2.5 px-3 font-semibold">Actor / User</th>
                  <th className="py-2.5 px-3 font-semibold">Action</th>
                  <th className="py-2.5 px-3.5 font-semibold">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#152033] text-[11px]">
                {filteredLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-[#152338]/40 transition-colors">
                    <td className="py-2.5 px-3.5 text-[#8E9EB5] whitespace-nowrap">{log.timestamp}</td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          log.level === 'ERROR'
                            ? 'bg-[#EF5350]/20 text-[#EF5350] border border-[#EF5350]/30'
                            : log.level === 'WARN'
                            ? 'bg-[#F5B942]/20 text-[#F5B942] border border-[#F5B942]/30'
                            : 'bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30'
                        }`}
                      >
                        {log.level}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-[#36A3FF] font-semibold">{log.source}</td>
                    <td className="py-2.5 px-3 text-[#E8EEF7]">{log.user}</td>
                    <td className="py-2.5 px-3 text-[#E8EEF7] font-semibold">{log.action}</td>
                    <td className="py-2.5 px-3.5 text-[#8E9EB5] max-w-md truncate" title={log.details}>
                      {log.details || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-8 text-center text-[#8E9EB5] text-xs">
            <ScrollText className="w-8 h-8 mx-auto text-[#64748B] mb-2" />
            <p>Tidak ada log yang cocok dengan filter saat ini.</p>
          </div>
        )}
      </div>
    </div>
  );
};
