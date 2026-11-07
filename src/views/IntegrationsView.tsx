/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Sensors & Integrations View
 */

import React, { useState } from 'react';
import {
  SlidersHorizontal,
  CheckCircle2,
  AlertTriangle,
  Code,
  Copy,
  Check,
  ExternalLink,
  Radio,
} from 'lucide-react';
import { IntegrationAdapter } from '../types/cybersecurity.js';

interface IntegrationsViewProps {
  adapters: IntegrationAdapter[];
}

export const IntegrationsView: React.FC<IntegrationsViewProps> = ({ adapters }) => {
  const [selectedAdapter, setSelectedAdapter] = useState<IntegrationAdapter | null>(null);
  const [copied, setCopied] = useState(false);

  const copyConfig = (text: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#101827] border border-[#16233B] rounded-xl p-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#152338] border border-[#36A3FF]/40 flex items-center justify-center text-[#36A3FF]">
            <SlidersHorizontal className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-[#E8EEF7]">Sensor Adapters & Ingestion Connectors</h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30">
                Plug-and-Play Cyber Sensors
              </span>
            </div>
            <p className="text-xs text-[#8E9EB5]">Real-time connection verification for Suricata IDS, Zeek, Wazuh Agent Fleet, ModSecurity, and STIX.</p>
          </div>
        </div>

        <div className="text-xs font-mono text-[#8E9EB5] px-3 py-1.5 bg-[#080D17] border border-[#16233B] rounded-lg">
          Active Ingestors: <span className="text-[#16C79A] font-bold">{adapters.filter((a) => a.status === 'connected').length} / {adapters.length}</span>
        </div>
      </div>

      {/* Adapters Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {adapters.map((adapter) => {
          const isConnected = adapter.status === 'connected';
          return (
            <div
              key={adapter.id}
              className="p-4 bg-[#101827] border border-[#16233B] rounded-xl flex flex-col justify-between hover:border-[#1E2D4A] transition-colors"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-[10px] uppercase font-bold text-[#36A3FF]">{adapter.type} ENGINE</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold flex items-center gap-1 ${
                      isConnected
                        ? 'bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30'
                        : 'bg-[#EF5350]/20 text-[#EF5350] border border-[#EF5350]/30'
                    }`}
                  >
                    <span className={`w-1.5 h-1.5 rounded-full ${isConnected ? 'bg-[#16C79A]' : 'bg-[#EF5350]'}`}></span>
                    {isConnected ? 'Connected' : 'Offline'}
                  </span>
                </div>

                <h3 className="text-sm font-bold text-[#E8EEF7] mb-1">{adapter.name}</h3>
                <div className="text-xs text-[#8E9EB5] font-mono mb-2">v{adapter.version}</div>

                <div className="space-y-1 text-xs text-[#8E9EB5] border-t border-[#16233B] pt-2">
                  <div className="flex justify-between">
                    <span>Throughput:</span>
                    <span className="font-mono text-[#E8EEF7] font-semibold">{adapter.eventRate}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Endpoint:</span>
                    <span className="font-mono text-[#64748B] text-[10px] truncate max-w-[150px]">{adapter.endpoint}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Heartbeat:</span>
                    <span className="font-mono text-[#16C79A]">{adapter.lastHeartbeat}</span>
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-[#16233B]">
                <button
                  onClick={() => setSelectedAdapter(adapter)}
                  className="w-full py-1.5 bg-[#152338] hover:bg-[#1E2D4A] text-[#E8EEF7] text-xs font-semibold rounded-lg flex items-center justify-center gap-1.5 transition-colors"
                >
                  <Code className="w-3.5 h-3.5 text-[#36A3FF]" />
                  View Integration Config
                </button>
              </div>
            </div>
          );
        })}
      </div>

      {/* Adapter Configuration Modal */}
      {selectedAdapter && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-in fade-in">
          <div className="bg-[#101827] border border-[#1F2E4A] rounded-2xl w-full max-w-xl p-5 shadow-2xl flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-[#1A263D] mb-3">
                <div className="flex items-center gap-2">
                  <Code className="w-5 h-5 text-[#16C79A]" />
                  <div>
                    <h3 className="text-sm font-bold text-[#E8EEF7]">{selectedAdapter.name}</h3>
                    <div className="text-xs text-[#8E9EB5] font-mono">{selectedAdapter.endpoint}</div>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedAdapter(null)}
                  className="p-1 text-[#8E9EB5] hover:text-[#E8EEF7] rounded"
                >
                  ✕
                </button>
              </div>

              <div className="space-y-3">
                <p className="text-xs text-[#8E9EB5] leading-relaxed">
                  To connect your physical or virtual <strong>{selectedAdapter.name}</strong> sensor to the Nusantara-SMS event bus, apply the following configuration to your daemon:
                </p>

                <div className="relative">
                  <pre className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg text-xs font-mono text-[#16C79A] overflow-x-auto whitespace-pre leading-relaxed">
                    {selectedAdapter.docsSnippet}
                  </pre>
                  <button
                    onClick={() => copyConfig(selectedAdapter.docsSnippet)}
                    className="absolute top-2 right-2 p-1.5 bg-[#152338] hover:bg-[#1E2D4A] text-[#E8EEF7] rounded text-xs flex items-center gap-1 transition-colors"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-[#16C79A]" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-[#1A263D] mt-4 flex justify-end">
              <button
                onClick={() => setSelectedAdapter(null)}
                className="px-4 py-2 bg-[#152338] hover:bg-[#1E2D4A] text-[#E8EEF7] font-semibold rounded-lg text-xs"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
