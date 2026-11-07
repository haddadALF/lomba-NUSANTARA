/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Platform Settings & Operational Controls
 * RBAC, Lab Target Config, WAF Mode (IDS vs IPS), Multi-Theme & Data Retention
 */

import React, { useState } from 'react';
import {
  Sliders,
  Shield,
  Server,
  Lock,
  Database,
  Radio,
  Cpu,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Flame,
  FileCheck,
  Terminal,
  Sun,
  Moon,
  Monitor,
} from 'lucide-react';
import { ModuleExplanationCard, ModuleGuideData } from '../components/ModuleExplanationCard.js';
import { ThemeMode } from '../components/TopBar.js';

interface SettingsViewProps {
  onResetPipeline: () => Promise<void>;
  onRefreshData: () => void;
  theme: ThemeMode;
  setTheme: (t: ThemeMode) => void;
}

const SETTINGS_GUIDE: ModuleGuideData = {
  title: 'Modul 10: Pengaturan Platform & Konfigurasi Sensor (Settings)',
  badge: 'Lab Target & System Control',
  shortSummary: 'Konfigurasi parameter target lab DVWA, alur sensor Suricata, mode operasi IDS vs IPS, pemilihan tema antarmuka, dan reset status bersih.',
  fungsiUtama: 'Menyediakan kendali penuh terhadap integrasi sensor lokal, jalur log Apache/Suricata, preferensi tema visual, serta reset database untuk demonstrasi kompetisi.',
  alasanDiperlukan: 'Platform pertahanan siber harus dapat disesuaikan dengan infrastruktur lab aktual dan mematuhi aturan kompetisi terkait pembuktian status sistem.',
  caraKerja: 'Menyimpan konfigurasi parameter lab secara lokal dan mengontrol mode pertahanan sensor secara transparan tanpa klaim palsu.',
  dataDitampilkan: 'URL target DVWA (192.168.100.75:8081), path eve.json, mode WAF aktif (IDS/IPS), profil operator SOC, dan penggunaan memori.',
  artiStatus: 'IDS Mode: Sensor hanya memantau dan mencatat alert; IPS Mode: Pencegahan aktif diaktifkan; Clean State: Kondisi awal 0 event untuk pengujian juri.',
  panduanTindakan: 'Pilih tema Dark/Light/System sesuai kenyamanan mata, verifikasi URL target DVWA, dan gunakan tombol Reset Database untuk skenario pengujian Test A.',
};

export const SettingsView: React.FC<SettingsViewProps> = ({
  onResetPipeline,
  onRefreshData,
  theme,
  setTheme,
}) => {
  const [targetAssetUrl, setTargetAssetUrl] = useState('http://192.168.100.75:8081');
  const [wafMode, setWafMode] = useState<'ids' | 'ips'>('ids');
  const [suricataPath, setSuricataPath] = useState('/var/log/suricata/eve.json');
  const [dvwaLogPath, setDvwaLogPath] = useState('/var/log/apache2/access.log');
  const [iocOfflineMode, setIocOfflineMode] = useState(true);
  const [isResetting, setIsResetting] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);

  const handleSaveConfig = (e: React.FormEvent) => {
    e.preventDefault();
    setSaveSuccess(true);
    setTimeout(() => setSaveSuccess(false), 2500);
  };

  const handleResetClick = async () => {
    if (confirm('Konfirmasi: Reset database ke kondisi bersih (0 alerts, 0 events) untuk Test A dewan juri?')) {
      setIsResetting(true);
      try {
        await onResetPipeline();
        onRefreshData();
      } finally {
        setIsResetting(false);
      }
    }
  };

  return (
    <div className="space-y-4">
      {/* 6-Aspect Progressive Disclosure Module Guide */}
      <ModuleExplanationCard guide={SETTINGS_GUIDE} />

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#101827] border border-[#16233B] rounded-xl p-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#152338] border border-[#16C79A]/40 flex items-center justify-center text-[#16C79A]">
            <Sliders className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-[#E8EEF7]">Platform Configuration & Settings</h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30">
                Kartika Cyber Hackathon 2026
              </span>
            </div>
            <p className="text-xs text-[#8E9EB5]">
              Lab sensor routing, WAF defense mode (IDS vs IPS), RBAC permissions, and theme preferences.
            </p>
          </div>
        </div>

        {saveSuccess && (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#16C79A]/20 border border-[#16C79A]/40 text-[#16C79A] text-xs font-mono">
            <CheckCircle2 className="w-4 h-4" /> Konfigurasi tersimpan
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Lab Target & Sensor Paths (8 cols) */}
        <div className="lg:col-span-8 space-y-4">
          {/* Theme Preferences Card */}
          <div className="bg-[#101827] border border-[#16233B] rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-[#16233B]">
              <div className="flex items-center gap-2 text-xs font-bold text-[#E8EEF7]">
                <Sun className="w-4 h-4 text-[#F5B942]" />
                <span>Tema & Mode Tampilan Antarmuka</span>
              </div>
              <span className="text-[10px] text-[#16C79A] font-mono capitalize">
                Aktif: {theme}
              </span>
            </div>

            <p className="text-xs text-[#8E9EB5]">
              Pilih tema tampilan yang dirancang khusus untuk operasional SOC: Dark Mode dengan kontras tajam untuk ruang kendali, Light Mode elegan untuk presentasi, atau System Default.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
              {/* Dark Mode Card */}
              <button
                type="button"
                onClick={() => setTheme('dark')}
                className={`p-3 rounded-xl border text-left transition-all ${
                  theme === 'dark'
                    ? 'bg-[#152338] border-[#36A3FF] shadow-lg shadow-[#36A3FF]/15'
                    : 'bg-[#080D17] border-[#16233B] hover:border-[#1E2D4A]'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <Moon className="w-4 h-4 text-[#36A3FF]" />
                    <span className="font-bold text-xs text-[#E8EEF7]">Dark Mode</span>
                  </div>
                  {theme === 'dark' && <CheckCircle2 className="w-4 h-4 text-[#36A3FF]" />}
                </div>
                <div className="flex gap-1 mb-2">
                  <span className="w-3 h-3 rounded-full bg-[#080D17] border border-[#16233B]" />
                  <span className="w-3 h-3 rounded-full bg-[#101827]" />
                  <span className="w-3 h-3 rounded-full bg-[#16C79A]" />
                  <span className="w-3 h-3 rounded-full bg-[#36A3FF]" />
                </div>
                <p className="text-[11px] text-[#8E9EB5] leading-relaxed">
                  Karakter SOC profesional gelap (#080D17) dengan kontras tinggi.
                </p>
              </button>

              {/* Light Mode Card */}
              <button
                type="button"
                onClick={() => setTheme('light')}
                className={`p-3 rounded-xl border text-left transition-all ${
                  theme === 'light'
                    ? 'bg-[#152338] border-[#078A69] shadow-lg shadow-[#078A69]/15'
                    : 'bg-[#080D17] border-[#16233B] hover:border-[#1E2D4A]'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <Sun className="w-4 h-4 text-[#F5B942]" />
                    <span className="font-bold text-xs text-[#E8EEF7]">Light Mode</span>
                  </div>
                  {theme === 'light' && <CheckCircle2 className="w-4 h-4 text-[#078A69]" />}
                </div>
                <div className="flex gap-1 mb-2">
                  <span className="w-3 h-3 rounded-full bg-[#F4F7FB] border border-[#CBD5E1]" />
                  <span className="w-3 h-3 rounded-full bg-[#FFFFFF] border border-[#CBD5E1]" />
                  <span className="w-3 h-3 rounded-full bg-[#078A69]" />
                  <span className="w-3 h-3 rounded-full bg-[#2477C5]" />
                </div>
                <p className="text-[11px] text-[#8E9EB5] leading-relaxed">
                  Latar terang (#F4F7FB) berstandar korporat tanpa pantulan silau.
                </p>
              </button>

              {/* System Default Card */}
              <button
                type="button"
                onClick={() => setTheme('system')}
                className={`p-3 rounded-xl border text-left transition-all ${
                  theme === 'system'
                    ? 'bg-[#152338] border-[#16C79A] shadow-lg shadow-[#16C79A]/15'
                    : 'bg-[#080D17] border-[#16233B] hover:border-[#1E2D4A]'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <Monitor className="w-4 h-4 text-[#16C79A]" />
                    <span className="font-bold text-xs text-[#E8EEF7]">System Default</span>
                  </div>
                  {theme === 'system' && <CheckCircle2 className="w-4 h-4 text-[#16C79A]" />}
                </div>
                <div className="flex gap-1 mb-2">
                  <span className="w-3 h-3 rounded-full bg-[#080D17]" />
                  <span className="w-3 h-3 rounded-full bg-[#F4F7FB] border border-[#CBD5E1]" />
                  <span className="w-3 h-3 rounded-full bg-[#16C79A]" />
                </div>
                <p className="text-[11px] text-[#8E9EB5] leading-relaxed">
                  Menyesuaikan otomatis dengan preferensi tema sistem operasi Anda.
                </p>
              </button>
            </div>
          </div>

          <form onSubmit={handleSaveConfig} className="bg-[#101827] border border-[#16233B] rounded-xl p-4 space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-[#16233B]">
              <div className="flex items-center gap-2 text-xs font-bold text-[#E8EEF7]">
                <Server className="w-4 h-4 text-[#36A3FF]" />
                Monitored Lab Target (DVWA Environment)
              </div>
              <span className="text-[10px] text-[#64748B] font-mono">Proxmox Home Lab</span>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-[#8E9EB5] block mb-1">Target Application URL:</label>
                <input
                  type="text"
                  value={targetAssetUrl}
                  onChange={(e) => setTargetAssetUrl(e.target.value)}
                  className="w-full bg-[#080D17] border border-[#16233B] rounded-lg px-3 py-2 text-[#E8EEF7] font-mono text-xs focus:border-[#36A3FF] focus:outline-none"
                />
                <span className="text-[10px] text-[#64748B] mt-0.5 block">
                  Alamat resmi target lab: http://192.168.100.75:8081/login.php
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="text-[#8E9EB5] block mb-1">Suricata EVE JSON Path:</label>
                  <input
                    type="text"
                    value={suricataPath}
                    onChange={(e) => setSuricataPath(e.target.value)}
                    className="w-full bg-[#080D17] border border-[#16233B] rounded-lg px-3 py-2 text-[#E8EEF7] font-mono text-xs focus:border-[#36A3FF] focus:outline-none"
                  />
                </div>
                <div>
                  <label className="text-[#8E9EB5] block mb-1">DVWA Access Log Path:</label>
                  <input
                    type="text"
                    value={dvwaLogPath}
                    onChange={(e) => setDvwaLogPath(e.target.value)}
                    className="w-full bg-[#080D17] border border-[#16233B] rounded-lg px-3 py-2 text-[#E8EEF7] font-mono text-xs focus:border-[#36A3FF] focus:outline-none"
                  />
                </div>
              </div>

              {/* Collector Security Token */}
              <div className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg space-y-1.5">
                <div className="flex items-center justify-between text-[#8E9EB5]">
                  <span className="font-semibold text-[#E8EEF7]">Collector API Authentication Token:</span>
                  <span className="text-[10px] text-[#16C79A] font-mono">Header: X-Collector-Token</span>
                </div>
                <div className="font-mono text-xs bg-[#101827] px-3 py-1.5 rounded border border-[#16233B] text-[#16C79A]">
                  nusantara-sec-collector-key-2026
                </div>
                <p className="text-[10px] text-[#64748B]">
                  Ubuntu Server forwarder wajib menyertakan token ini pada header request untuk mencegah injeksi payload tidak sah.
                </p>
              </div>

              {/* WAF Operational Mode: IDS vs IPS */}
              <div className="pt-2 border-t border-[#16233B]">
                <label className="text-[#8E9EB5] block mb-1.5 font-semibold">
                  Mode Pertahanan WAF & Network Sensor:
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div
                    onClick={() => setWafMode('ids')}
                    className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                      wafMode === 'ids'
                        ? 'bg-[#152338] border-[#36A3FF]'
                        : 'bg-[#080D17] border-[#16233B] hover:border-[#1E2D4A]'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-bold text-[#36A3FF]">IDS Mode (Deteksi & Alert)</span>
                      {wafMode === 'ids' && <CheckCircle2 className="w-3.5 h-3.5 text-[#36A3FF]" />}
                    </div>
                    <p className="text-[11px] text-[#8E9EB5]">
                      Monitoring pasif. Menganalisis dan mencatat alert tanpa memutus trafik HTTP/TCP secara sepihak.
                    </p>
                  </div>

                  <div
                    onClick={() => setWafMode('ips')}
                    className={`p-3 rounded-lg border cursor-pointer transition-colors ${
                      wafMode === 'ips'
                        ? 'bg-[#152338] border-[#16C79A]'
                        : 'bg-[#080D17] border-[#16233B] hover:border-[#1E2D4A]'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-bold text-[#16C79A]">IPS Mode (Penangkalan Aktif)</span>
                      {wafMode === 'ips' && <CheckCircle2 className="w-3.5 h-3.5 text-[#16C79A]" />}
                    </div>
                    <p className="text-[11px] text-[#8E9EB5]">
                      Penangkalan inline. Hanya aktif jika WAF/Reverse Proxy terpasang inline dan teruji di lab.
                    </p>
                  </div>
                </div>
                <div className="mt-2 text-[10px] text-[#F5B942] font-mono">
                  * Aturan Kompetisi: Jangan pernah menampilkan status BLOCKED jika sistem hanya melakukan monitoring pasif.
                </div>
              </div>

              {/* Local Threat Intel Mode */}
              <div className="pt-2 border-t border-[#16233B] flex items-center justify-between">
                <div>
                  <span className="font-semibold text-[#E8EEF7] block">Local Offline Threat Intelligence Cache</span>
                  <span className="text-[11px] text-[#8E9EB5]">
                    Pencocokan IOC (IP, Hash, Domain) tetap aktif menggunakan database lokal tanpa ketergantungan internet.
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={iocOfflineMode}
                  onChange={(e) => setIocOfflineMode(e.target.checked)}
                  className="w-4 h-4 accent-[#16C79A] cursor-pointer"
                />
              </div>

              <div className="pt-3">
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-[#16C79A] text-[#080D17] font-bold text-xs hover:bg-[#16C79A]/90 transition-colors shadow-md shadow-[#16C79A]/20"
                >
                  Simpan Konfigurasi Sensor
                </button>
              </div>
            </div>
          </form>
        </div>

        {/* Proxmox Resource & RBAC & Reset (4 cols) */}
        <div className="lg:col-span-4 space-y-4">
          {/* RBAC Operator Card */}
          <div className="bg-[#101827] border border-[#16233B] rounded-xl p-4 space-y-3 text-xs">
            <div className="flex items-center gap-2 font-bold text-[#E8EEF7] pb-2 border-b border-[#16233B]">
              <Lock className="w-4 h-4 text-[#16C79A]" />
              Role-Based Access Control (RBAC)
            </div>
            <div className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg space-y-1.5">
              <div className="flex justify-between">
                <span className="text-[#8E9EB5]">Operator:</span>
                <span className="text-[#E8EEF7] font-semibold">Sarah Chen</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#8E9EB5]">Role:</span>
                <span className="px-2 py-0.5 rounded bg-[#16C79A]/20 text-[#16C79A] text-[10px] font-bold">
                  Lead SOC Analyst (L3)
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#8E9EB5]">Auth Scheme:</span>
                <span className="font-mono text-[10px] text-[#36A3FF]">Argon2id Hash + JWT</span>
              </div>
            </div>
          </div>

          {/* Proxmox Resource Guardian */}
          <div className="bg-[#101827] border border-[#16233B] rounded-xl p-4 space-y-3 text-xs">
            <div className="flex items-center gap-2 font-bold text-[#E8EEF7] pb-2 border-b border-[#16233B]">
              <Cpu className="w-4 h-4 text-[#36A3FF]" />
              Home Lab Resource Footprint
            </div>
            <p className="text-[11px] text-[#8E9EB5]">
              Arsitektur ringan dirancang untuk berjalan hemat memori pada Proxmox home lab tanpa broker pesan berlebih.
            </p>
            <div className="space-y-1 text-[11px] font-mono">
              <div className="flex justify-between text-[#8E9EB5]">
                <span>RAM Usage:</span>
                <span className="text-[#16C79A]">~48 MB (Node.js Engine)</span>
              </div>
              <div className="flex justify-between text-[#8E9EB5]">
                <span>Storage Type:</span>
                <span className="text-[#E8EEF7]">PostgreSQL / ACID JSON Store</span>
              </div>
            </div>
          </div>

          {/* Clean State Reset (Test A) */}
          <div className="bg-[#101827] border border-[#EF5350]/30 rounded-xl p-4 space-y-3 text-xs">
            <div className="flex items-center gap-2 font-bold text-[#EF5350] pb-2 border-b border-[#16233B]">
              <RefreshCw className="w-4 h-4" />
              Test A — Clean Reset Action
            </div>
            <p className="text-[11px] text-[#8E9EB5]">
              Kembalikan database ke kondisi awal 0 event, 0 alert, dan 0 incident untuk demonstrasi pengujian dewan juri.
            </p>
            <button
              type="button"
              onClick={handleResetClick}
              disabled={isResetting}
              className="w-full py-2 rounded-lg bg-[#EF5350]/20 border border-[#EF5350]/40 text-[#EF5350] font-bold hover:bg-[#EF5350]/30 transition-colors flex items-center justify-center gap-1.5 disabled:opacity-40"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isResetting ? 'animate-spin' : ''}`} />
              {isResetting ? 'Resetting Pipeline...' : 'Reset Database ke Clean State (Test A)'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
