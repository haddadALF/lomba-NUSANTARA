/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Reusable Module Explanation & Progressive Disclosure Card
 * Standardizes Indonesian operational guidance + technical standards across all 10 modules
 */

import React, { useState } from 'react';
import {
  Info,
  ChevronDown,
  ChevronUp,
  HelpCircle,
  Shield,
  Activity,
  Layers,
  CheckCircle2,
  AlertCircle,
} from 'lucide-react';

export interface ModuleGuideData {
  title: string;
  badge: string;
  shortSummary: string;
  fungsiUtama: string;
  alasanDiperlukan: string;
  caraKerja: string;
  dataDitampilkan: string;
  artiStatus: string;
  panduanTindakan: string;
}

interface ModuleExplanationCardProps {
  guide: ModuleGuideData;
  defaultExpanded?: boolean;
}

export const ModuleExplanationCard: React.FC<ModuleExplanationCardProps> = ({
  guide,
  defaultExpanded = false,
}) => {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);

  return (
    <div className="bg-[#101827] border border-[#16233B] rounded-xl overflow-hidden transition-all duration-200 shadow-md">
      {/* Synopsis Header & Toggle Bar */}
      <div className="p-3 sm:p-4 flex items-start sm:items-center justify-between gap-3">
        <div className="flex items-start sm:items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-[#152338] border border-[#16C79A]/30 flex items-center justify-center text-[#16C79A] shrink-0">
            <Info className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-bold text-[#E8EEF7]">{guide.title}</span>
              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#16C79A]/15 text-[#16C79A] border border-[#16C79A]/25">
                {guide.badge}
              </span>
            </div>
            <p className="text-xs text-[#8E9EB5] mt-0.5 leading-relaxed">
              {guide.shortSummary}
            </p>
          </div>
        </div>

        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-[#152338] hover:bg-[#1E2D4A] border border-[#19263E] text-[#36A3FF] hover:text-[#E8EEF7] text-xs font-medium transition-colors shrink-0"
          title="Buka panduan lengkap modul"
        >
          <HelpCircle className="w-3.5 h-3.5 text-[#36A3FF]" />
          <span className="hidden sm:inline">
            {isExpanded ? 'Tutup Panduan' : 'Panduan Modul (6 Aspek)'}
          </span>
          {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>
      </div>

      {/* Expanded 6-Aspect Technical & Operational Guide (Progressive Disclosure) */}
      {isExpanded && (
        <div className="p-4 pt-1 border-t border-[#16233B] bg-[#0A0F1D]/80 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 animate-in fade-in duration-200 text-xs">
          {/* 1. Fungsi Utama */}
          <div className="p-3 bg-[#101827] border border-[#16233B] rounded-lg space-y-1">
            <div className="flex items-center gap-1.5 font-bold text-[#36A3FF]">
              <Shield className="w-3.5 h-3.5" />
              <span>1. Apa Fungsi Fitur Ini?</span>
            </div>
            <p className="text-[#8E9EB5] text-[11px] leading-relaxed">
              {guide.fungsiUtama}
            </p>
          </div>

          {/* 2. Alasan Diperlukan */}
          <div className="p-3 bg-[#101827] border border-[#16233B] rounded-lg space-y-1">
            <div className="flex items-center gap-1.5 font-bold text-[#16C79A]">
              <Layers className="w-3.5 h-3.5" />
              <span>2. Mengapa Diperlukan?</span>
            </div>
            <p className="text-[#8E9EB5] text-[11px] leading-relaxed">
              {guide.alasanDiperlukan}
            </p>
          </div>

          {/* 3. Cara Kerja Sistem */}
          <div className="p-3 bg-[#101827] border border-[#16233B] rounded-lg space-y-1">
            <div className="flex items-center gap-1.5 font-bold text-[#F5B942]">
              <Activity className="w-3.5 h-3.5" />
              <span>3. Bagaimana Sistem Bekerja?</span>
            </div>
            <p className="text-[#8E9EB5] text-[11px] leading-relaxed">
              {guide.caraKerja}
            </p>
          </div>

          {/* 4. Data yang Ditampilkan */}
          <div className="p-3 bg-[#101827] border border-[#16233B] rounded-lg space-y-1">
            <div className="flex items-center gap-1.5 font-bold text-[#E8EEF7]">
              <CheckCircle2 className="w-3.5 h-3.5 text-[#16C79A]" />
              <span>4. Data Apa yang Ditampilkan?</span>
            </div>
            <p className="text-[#8E9EB5] text-[11px] leading-relaxed">
              {guide.dataDitampilkan}
            </p>
          </div>

          {/* 5. Arti Status & Indikator */}
          <div className="p-3 bg-[#101827] border border-[#16233B] rounded-lg space-y-1">
            <div className="flex items-center gap-1.5 font-bold text-[#EF5350]">
              <AlertCircle className="w-3.5 h-3.5" />
              <span>5. Apa Arti Statusnya?</span>
            </div>
            <p className="text-[#8E9EB5] text-[11px] leading-relaxed">
              {guide.artiStatus}
            </p>
          </div>

          {/* 6. Panduan Tindakan Pengguna */}
          <div className="p-3 bg-[#101827] border border-[#16233B] rounded-lg space-y-1">
            <div className="flex items-center gap-1.5 font-bold text-[#36A3FF]">
              <HelpCircle className="w-3.5 h-3.5" />
              <span>6. Tindakan Analis / Operator</span>
            </div>
            <p className="text-[#8E9EB5] text-[11px] leading-relaxed">
              {guide.panduanTindakan}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
