/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - MITRE ATT&CK Enterprise Matrix Threat Mapping
 */

import React, { useState } from 'react';
import {
  Grid3X3,
  Shield,
  AlertTriangle,
  CheckCircle2,
  Info,
  X,
  Layers,
  Search,
} from 'lucide-react';
import { MitreTactic, MitreTechnique, SecurityEvent } from '../types/cybersecurity.js';

interface MitreMatrixViewProps {
  tactics: MitreTactic[];
  events: SecurityEvent[];
}

export const MitreMatrixView: React.FC<MitreMatrixViewProps> = ({ tactics, events }) => {
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  // Calculate overall metrics
  const totalTechniques = tactics.reduce((sum, t) => sum + t.techniques.length, 0);
  const detectedCount = tactics.reduce(
    (sum, t) => sum + t.techniques.filter((tc) => tc.status === 'detected').length,
    0
  );
  const coveredCount = tactics.reduce(
    (sum, t) => sum + t.techniques.filter((tc) => tc.status === 'covered').length,
    0
  );
  const coverageRate = Math.round(((detectedCount + coveredCount) / totalTechniques) * 100);

  // Correlated events for currently selected technique
  const linkedEvents = selectedTechnique
    ? events.filter((e) => e.mitreTechniqueId.startsWith(selectedTechnique.id))
    : [];

  return (
    <div className="space-y-4">
      {/* Header & Metrics */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#101827] border border-[#16233B] rounded-xl p-4">
        <div>
          <div className="flex items-center gap-2">
            <Grid3X3 className="w-5 h-5 text-[#16C79A]" />
            <h1 className="text-base font-bold text-[#E8EEF7]">MITRE ATT&CK Enterprise Matrix (v14.1)</h1>
          </div>
          <p className="text-xs text-[#8E9EB5]">Defensive coverage mapping and threat technique attribution across the cyber kill chain.</p>
        </div>

        {/* Coverage Metrics Strip */}
        <div className="flex items-center gap-4 text-xs">
          <div className="px-3 py-1.5 bg-[#080D17] border border-[#16233B] rounded-lg">
            <span className="text-[#8E9EB5] block text-[10px]">Matrix Coverage</span>
            <span className="text-sm font-bold font-mono text-[#16C79A]">{coverageRate}%</span>
          </div>

          <div className="px-3 py-1.5 bg-[#080D17] border border-[#16233B] rounded-lg">
            <span className="text-[#8E9EB5] block text-[10px]">Active Detections</span>
            <span className="text-sm font-bold font-mono text-[#EF5350]">{detectedCount}</span>
          </div>

          <div className="px-3 py-1.5 bg-[#080D17] border border-[#16233B] rounded-lg">
            <span className="text-[#8E9EB5] block text-[10px]">Defended Controls</span>
            <span className="text-sm font-bold font-mono text-[#36A3FF]">{coveredCount}</span>
          </div>
        </div>
      </div>

      {/* Legend & Filter */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#101827] border border-[#16233B] rounded-xl p-3 text-xs">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-[#EF5350]"></span>
            <span className="text-[#E8EEF7]">Active Threat Detected</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-[#16C79A]"></span>
            <span className="text-[#E8EEF7]">Covered by Defensive Rules</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded bg-[#1E293B]"></span>
            <span className="text-[#8E9EB5]">Needs Validation</span>
          </div>
        </div>

        <div className="relative w-64">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[#64748B]" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Filter techniques (e.g., T1190, Shell)..."
            className="w-full bg-[#080D17] border border-[#16233B] rounded-lg pl-8 pr-3 py-1 text-xs text-[#E8EEF7] placeholder-[#64748B] focus:outline-none focus:border-[#16C79A]"
          />
        </div>
      </div>

      {/* Interactive Horizontal Scrollable MITRE Tactics Grid */}
      <div className="bg-[#101827] border border-[#16233B] rounded-xl p-3 overflow-x-auto shadow-2xl">
        <div className="flex gap-2.5 min-w-[1200px]">
          {tactics.map((tactic) => (
            <div key={tactic.id} className="w-48 shrink-0 flex flex-col gap-2">
              {/* Column Header */}
              <div className="p-2 bg-[#0A0F1D] border border-[#16233B] rounded-lg text-center">
                <span className="font-mono text-[9px] text-[#36A3FF] block">{tactic.id}</span>
                <span className="text-xs font-bold text-[#E8EEF7] truncate block">{tactic.name}</span>
              </div>

              {/* Technique Cards in Column */}
              <div className="flex flex-col gap-1.5">
                {tactic.techniques
                  .filter(
                    (tech) =>
                      !searchTerm ||
                      tech.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
                      tech.name.toLowerCase().includes(searchTerm.toLowerCase())
                  )
                  .map((tech) => {
                    const isDetected = tech.status === 'detected' || tech.detectionCount > 0;
                    const isCovered = tech.status === 'covered';

                    return (
                      <div
                        key={tech.id}
                        onClick={() => setSelectedTechnique(tech)}
                        className={`p-2 rounded-lg border text-xs cursor-pointer transition-all hover:scale-[1.02] ${
                          isDetected
                            ? 'bg-[#2A0D11] border-[#EF5350]/60 text-[#FFA4A2] shadow-sm shadow-[#EF5350]/20'
                            : isCovered
                            ? 'bg-[#0B1E1C] border-[#16C79A]/40 text-[#A7F3D0]'
                            : 'bg-[#0B111E] border-[#152033] text-[#8E9EB5] hover:border-[#1E2D4A]'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-mono text-[10px] font-bold">{tech.id}</span>
                          {isDetected && (
                            <span className="px-1.5 py-0.2 rounded bg-[#EF5350] text-white font-mono text-[9px] font-bold">
                              {tech.detectionCount} hits
                            </span>
                          )}
                        </div>
                        <div className="font-medium leading-tight text-[11px] truncate" title={tech.name}>
                          {tech.name}
                        </div>
                      </div>
                    );
                  })}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Technique Modal Drilldown */}
      {selectedTechnique && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-in fade-in">
          <div className="bg-[#101827] border border-[#1F2E4A] rounded-2xl w-full max-w-2xl max-h-[85vh] overflow-y-auto p-5 shadow-2xl flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-[#1A263D] mb-4">
                <div className="flex items-center gap-2">
                  <div className={`p-2 rounded-lg ${
                    selectedTechnique.status === 'detected' ? 'bg-[#EF5350]/20 text-[#EF5350]' : 'bg-[#16C79A]/20 text-[#16C79A]'
                  }`}>
                    <Layers className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-[#E8EEF7]">{selectedTechnique.name}</h3>
                    <div className="text-xs font-mono text-[#36A3FF]">
                      ID: {selectedTechnique.id} · Tactic: {selectedTechnique.tactic}
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedTechnique(null)}
                  className="p-1 text-[#8E9EB5] hover:text-[#E8EEF7] rounded"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-4 text-xs text-[#8E9EB5]">
                <div>
                  <span className="font-semibold text-[#E8EEF7] block mb-1">Description</span>
                  <p className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg text-[#CBD5E1] leading-relaxed">
                    {selectedTechnique.description}
                  </p>
                </div>

                <div>
                  <span className="font-semibold text-[#16C79A] block mb-1">Active Defensive Controls & Mitigation</span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {selectedTechnique.defensiveControls.map((ctrl, i) => (
                      <div key={i} className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg flex items-center gap-2 text-[#E8EEF7]">
                        <CheckCircle2 className="w-4 h-4 text-[#16C79A] shrink-0" />
                        <span>{ctrl}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-semibold text-[#EF5350]">Correlated Security Events ({linkedEvents.length})</span>
                    <span className="text-[10px] text-[#64748B]">Real telemetry linked to this technique</span>
                  </div>

                  {linkedEvents.length > 0 ? (
                    <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                      {linkedEvents.map((e) => (
                        <div key={e.id} className="p-2.5 bg-[#080D17] border border-[#16233B] rounded-lg">
                          <div className="flex justify-between text-[#E8EEF7] font-semibold mb-1">
                            <span>{e.title}</span>
                            <span className="font-mono text-[#EF5350]">{e.severity}</span>
                          </div>
                          <div className="flex justify-between text-[11px] text-[#8E9EB5] font-mono">
                            <span>{e.sourceIp} → {e.destIp}:{e.port}</span>
                            <span>{e.timestamp}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg text-center text-[#64748B]">
                      No active incident hits currently correlated with this specific technique.
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-[#1A263D] mt-4 flex justify-end">
              <button
                onClick={() => setSelectedTechnique(null)}
                className="px-4 py-2 bg-[#152338] hover:bg-[#1E2D4A] text-[#E8EEF7] font-semibold rounded-lg text-xs"
              >
                Close Matrix Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
