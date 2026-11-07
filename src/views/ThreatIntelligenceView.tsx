/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Threat Intelligence & IOC Management View
 */

import React, { useState } from 'react';
import {
  Flame,
  Search,
  Download,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  Layers,
  Database,
} from 'lucide-react';
import { ThreatIntelIoc } from '../types/cybersecurity.js';
import { ModuleExplanationCard, ModuleGuideData } from '../components/ModuleExplanationCard.js';

const THREAT_INTEL_GUIDE: ModuleGuideData = {
  title: 'Modul 4: Intelijen Ancaman Siber (Threat Intelligence & IOC)',
  badge: 'STIX 2.1 & Local IOC',
  shortSummary: 'Pencocokan indikator ancaman (IP berbahaya, domain C2, hash malware) dengan lalu lintas aktual.',
  fungsiUtama: 'Mencocokkan indikator kompromi (IOC) lokal maupun eksternal terhadap alamat IP dan request yang masuk.',
  alasanDiperlukan: 'Mempercepat deteksi aktor ancaman yang sudah dikenal (threat actors) sebelum mereka mengeksploitasi sistem target.',
  caraKerja: 'Setiap IP sumber dari request dibandingkan dengan database IOC offline berkecepatan tinggi berbasis hash table.',
  dataDitampilkan: 'Alamat IP jahat, domain C2, hash SHA256, confidence score, nama aktor ancaman (APT), dan tag kampanye serangan.',
  artiStatus: 'Malicious: Indikator terkonfirmasi aktif berbahaya; Suspicious: Reputasi mencurigakan; Clean: Tidak terdaftar dalam IOC.',
  panduanTindakan: 'Lakukan lookup indikator secara manual, tambahkan IOC lokal baru, atau ekspor bundle STIX 2.1 untuk integrasi antar-SOC.',
};

interface ThreatIntelligenceViewProps {
  iocs: ThreatIntelIoc[];
}

export const ThreatIntelligenceView: React.FC<ThreatIntelligenceViewProps> = ({ iocs }) => {
  const [lookupQuery, setLookupQuery] = useState('');
  const [lookupResult, setLookupResult] = useState<any | null>(null);
  const [isSearching, setIsSearching] = useState(false);

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!lookupQuery.trim()) return;

    setIsSearching(true);
    try {
      const res = await fetch('/api/threat-intel/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: lookupQuery }),
      });
      const data = await res.json();
      setLookupResult(data);
    } catch (err) {
      console.error('Threat intel lookup failed', err);
    } finally {
      setIsSearching(false);
    }
  };

  const exportStix = () => {
    const stixPackage = {
      type: 'bundle',
      id: `bundle--${Date.now()}`,
      spec_version: '2.1',
      objects: iocs.map((ioc) => ({
        type: 'indicator',
        id: `indicator--${ioc.id}`,
        created: ioc.lastUpdated,
        modified: ioc.lastUpdated,
        pattern: `[${ioc.type}-addr:value = '${ioc.indicator}']`,
        pattern_type: 'stix',
        confidence: ioc.confidenceScore,
        labels: ioc.tags,
        description: `Threat Actor: ${ioc.threatActor || 'Unknown'} - Source: ${ioc.feedSource}`,
      })),
    };

    const blob = new Blob([JSON.stringify(stixPackage, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nusantara-threat-intel-stix2.1-${Date.now()}.json`;
    a.click();
  };

  return (
    <div className="space-y-4">
      {/* 6-Aspect Progressive Disclosure Module Guide */}
      <ModuleExplanationCard guide={THREAT_INTEL_GUIDE} />

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#101827] border border-[#16233B] rounded-xl p-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#152338] border border-[#F5B942]/40 flex items-center justify-center text-[#F5B942]">
            <Flame className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-[#E8EEF7]">Threat Intelligence & IOC Engine</h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30">
                STIX 2.1 / TAXII Interoperable
              </span>
            </div>
            <p className="text-xs text-[#8E9EB5]">Centralized Indicators of Compromise (IOC), actor attribution, and reputation correlation.</p>
          </div>
        </div>

        <button
          onClick={exportStix}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-[#152338] hover:bg-[#16C79A] text-[#16C79A] hover:text-[#080D17] border border-[#16C79A]/40 rounded-lg text-xs font-semibold transition-all shadow-sm"
        >
          <Download className="w-3.5 h-3.5" /> Export STIX 2.1 Bundle
        </button>
      </div>

      {/* Interactive IOC Lookup Bar */}
      <div className="bg-[#101827] border border-[#16233B] rounded-xl p-4 space-y-3">
        <h3 className="text-xs font-semibold text-[#E8EEF7]">Real-Time Threat Intelligence Query</h3>
        <form onSubmit={handleLookup} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#64748B]" />
            <input
              type="text"
              value={lookupQuery}
              onChange={(e) => setLookupQuery(e.target.value)}
              placeholder="Query any IP address (e.g. 185.220.101.5), domain (e.g. darkdns-tunnel.org), or SHA-256 hash..."
              className="w-full bg-[#080D17] border border-[#16233B] rounded-lg pl-9 pr-3 py-2 text-xs text-[#E8EEF7] placeholder-[#64748B] focus:outline-none focus:border-[#16C79A] font-mono"
            />
          </div>
          <button
            type="submit"
            disabled={isSearching}
            className="px-4 py-2 bg-[#16C79A] hover:bg-[#16C79A]/90 text-[#080D17] text-xs font-bold rounded-lg transition-colors"
          >
            {isSearching ? 'Evaluating Feeds...' : 'Lookup IOC'}
          </button>
        </form>

        {/* Lookup Result Box */}
        {lookupResult && (
          <div className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg text-xs animate-in fade-in">
            {lookupResult.found ? (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-[#EF5350]"></span>
                    <span className="font-mono font-bold text-sm text-[#EF5350]">{lookupResult.ioc.indicator}</span>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-[#EF5350]/20 text-[#EF5350] font-mono text-[10px] font-bold">
                    CONFIDENCE: {lookupResult.ioc.confidenceScore}% (MALICIOUS)
                  </span>
                </div>
                <div className="text-[#E8EEF7]">
                  Threat Actor / Campaign: <span className="font-semibold text-[#F5B942]">{lookupResult.ioc.threatActor}</span>
                </div>
                <div className="text-[#8E9EB5]">
                  Associated Tooling: <span className="text-[#36A3FF] font-mono">{lookupResult.ioc.associatedMalware}</span>
                </div>
                <div className="text-[11px] text-[#64748B]">
                  Reported by: {lookupResult.ioc.feedSource} · Updated: {lookupResult.ioc.lastUpdated}
                </div>
              </div>
            ) : (
              <div className="flex items-center justify-between">
                <div>
                  <span className="font-mono text-[#E8EEF7] font-semibold">{lookupResult.evaluatedQuery}</span>
                  <div className="text-[11px] text-[#8E9EB5]">{lookupResult.note}</div>
                </div>
                <span className="px-2 py-0.5 rounded bg-[#16C79A]/20 text-[#16C79A] font-mono text-[10px]">
                  REPUTATION: {lookupResult.reputation.toUpperCase()}
                </span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* IOC Catalog Table */}
      <div className="bg-[#101827] border border-[#16233B] rounded-xl overflow-hidden shadow-lg">
        <div className="p-3 bg-[#0A0F1D] border-b border-[#16233B] flex items-center justify-between">
          <h3 className="text-xs font-semibold text-[#E8EEF7]">Verified Threat Indicator Feed ({iocs.length})</h3>
          <span className="text-[10px] font-mono text-[#16C79A]">Sync Active: AlienVault OTX + CERT-ID</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="text-[#64748B] border-b border-[#152033] bg-[#0A0F1D] text-[11px]">
              <tr>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Indicator</th>
                <th className="py-2.5 px-3">Reputation</th>
                <th className="py-2.5 px-3">Confidence</th>
                <th className="py-2.5 px-3">Threat Actor / Campaign</th>
                <th className="py-2.5 px-3">Feed Source</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#152033] text-[11px]">
              {iocs.map((ioc) => (
                <tr key={ioc.id} className="hover:bg-[#152338]/40 transition-colors">
                  <td className="py-2.5 px-3 text-[#36A3FF] uppercase font-bold">{ioc.type}</td>
                  <td className="py-2.5 px-3 text-[#E8EEF7] font-semibold truncate max-w-xs">{ioc.indicator}</td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        ioc.reputation === 'malicious'
                          ? 'bg-[#EF5350]/20 text-[#EF5350] border border-[#EF5350]/30'
                          : ioc.reputation === 'suspicious'
                          ? 'bg-[#F5B942]/20 text-[#F5B942] border border-[#F5B942]/30'
                          : 'bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30'
                      }`}
                    >
                      {ioc.reputation}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-[#E8EEF7]">{ioc.confidenceScore}%</td>
                  <td className="py-2.5 px-3 text-[#F5B942] font-sans font-medium">{ioc.threatActor || 'Generic Botnet'}</td>
                  <td className="py-2.5 px-3 text-[#8E9EB5] font-sans text-[10px]">{ioc.feedSource}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
