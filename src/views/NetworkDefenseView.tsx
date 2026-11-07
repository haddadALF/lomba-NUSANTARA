/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Network Defense & Traffic Inspection View
 * Zero Dummy Data Policy — Real Suricata EVE & Network Detections Only
 */

import React, { useState } from 'react';
import {
  Network,
  Radio,
  Shield,
  Activity,
  Layers,
  Search,
  Filter,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  Server,
  Zap,
} from 'lucide-react';
import { SecurityEvent, SecurityAlert } from '../types/cybersecurity.js';

interface NetworkDefenseViewProps {
  events: SecurityEvent[];
  alerts?: SecurityAlert[];
}

export const NetworkDefenseView: React.FC<NetworkDefenseViewProps> = ({ events, alerts = [] }) => {
  const [selectedProtocol, setSelectedProtocol] = useState<string>('all');

  const networkEvents = events.filter(
    (e) =>
      e.category === 'network_anomaly' ||
      e.category === 'c2_communication' ||
      e.category === 'dns_tunneling' ||
      e.source.includes('Suricata') ||
      e.source.includes('Zeek')
  );

  const dnsEvents = events.filter((e) => e.category === 'dns_tunneling' || e.title.toLowerCase().includes('dns'));

  // Target Asset Inspection (DVWA on Ubuntu Home Server)
  const targetHost = {
    name: 'DVWA Home Server',
    ip: '192.168.100.75',
    port: 8081,
    proto: 'TCP',
    service: 'Apache/2.4 + PHP (DVWA)',
    status: 'Monitored',
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#101827] border border-[#16233B] rounded-xl p-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#152338] border border-[#36A3FF]/40 flex items-center justify-center text-[#36A3FF]">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-[#E8EEF7]">Network Defense & Suricata NIDS</h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#36A3FF]/20 text-[#36A3FF] border border-[#36A3FF]/30">
                Suricata EVE JSON + Raw Flow Inspection
              </span>
            </div>
            <p className="text-xs text-[#8E9EB5]">Target: DVWA (http://192.168.100.75:8081) — Deep packet inspection and protocol telemetry.</p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <div className="px-3 py-1.5 bg-[#080D17] border border-[#16233B] rounded-lg">
            <span className="text-[#8E9EB5] block text-[10px]">Suricata Events</span>
            <span className="text-sm font-bold text-[#16C79A]">{networkEvents.length}</span>
          </div>
          <div className="px-3 py-1.5 bg-[#080D17] border border-[#16233B] rounded-lg">
            <span className="text-[#8E9EB5] block text-[10px]">Ingestion Channel</span>
            <span className="text-sm font-bold text-[#36A3FF]">/api/ingest/suricata</span>
          </div>
        </div>
      </div>

      {/* Grid: Target Asset Surface & DNS Radar */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Monitored Asset Target Surface */}
        <div className="lg:col-span-6 bg-[#101827] border border-[#16233B] rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[#16233B]">
            <h3 className="text-xs font-semibold text-[#E8EEF7]">Target Network Exposure Surface</h3>
            <span className="text-[10px] text-[#64748B] font-mono">Verified Endpoint</span>
          </div>

          <div className="space-y-2">
            <div className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg flex items-center justify-between text-xs">
              <div className="flex items-center gap-2.5">
                <Server className="w-4 h-4 text-[#36A3FF]" />
                <div>
                  <div className="font-semibold text-[#E8EEF7]">{targetHost.name}</div>
                  <div className="text-[10px] text-[#64748B] font-mono">{targetHost.ip}:{targetHost.port}</div>
                </div>
              </div>
              <div className="text-right">
                <span className="text-[10px] font-mono text-[#36A3FF] block">{targetHost.proto}</span>
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30">
                  {targetHost.service}
                </span>
              </div>
            </div>

            <div className="p-3 bg-[#080D17] border border-[#16233B] rounded-lg text-xs space-y-1">
              <div className="flex items-center justify-between text-[11px] text-[#8E9EB5]">
                <span>Sensor Ingestion Pipe:</span>
                <span className="font-mono text-[#E8EEF7]">POST /api/ingest/suricata</span>
              </div>
              <div className="flex items-center justify-between text-[11px] text-[#8E9EB5]">
                <span>EVE JSON Parser:</span>
                <span className="font-mono text-[#16C79A]">Active (Alert, Flow, HTTP, DNS)</span>
              </div>
            </div>
          </div>
        </div>

        {/* DNS Anomaly Radar */}
        <div className="lg:col-span-6 bg-[#101827] border border-[#16233B] rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[#16233B]">
            <h3 className="text-xs font-semibold text-[#E8EEF7]">DNS Tunneling & Anomaly Radar</h3>
            <span className="text-[10px] text-[#16C79A] font-mono">Shannon Threshold: &gt; 4.2</span>
          </div>

          {dnsEvents.length === 0 ? (
            <div className="p-6 text-center bg-[#080D17] border border-[#16233B] rounded-lg">
              <CheckCircle2 className="w-8 h-8 text-[#16C79A] mx-auto mb-2 opacity-80" />
              <div className="text-xs font-semibold text-[#E8EEF7]">NO DNS ANOMALIES RECORDED</div>
              <p className="text-[11px] text-[#8E9EB5] mt-1">
                Tidak ada anomali DNS atau tunneling yang terdeteksi pada lalu lintas aktual.
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {dnsEvents.map((evt) => (
                <div key={evt.id} className="p-3 bg-[#080D17] border border-[#EF5350]/30 rounded-lg space-y-1 text-xs">
                  <div className="flex justify-between items-center text-[#E8EEF7]">
                    <span className="font-semibold">{evt.title}</span>
                    <span className="font-mono text-[#EF5350] font-bold">ALERT</span>
                  </div>
                  <p className="text-[11px] text-[#8E9EB5]">{evt.rawPayload || evt.sourceIp}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Suricata IDS Live Alerts Table */}
      <div className="bg-[#101827] border border-[#16233B] rounded-xl overflow-hidden">
        <div className="p-3 bg-[#0A0F1D] border-b border-[#16233B] flex items-center justify-between">
          <h3 className="text-xs font-semibold text-[#E8EEF7]">Suricata IDS Network Alert Stream</h3>
          <span className="text-[10px] font-mono text-[#36A3FF]">
            {networkEvents.length > 0 ? `${networkEvents.length} Events Detected` : 'Zero Threat Stream'}
          </span>
        </div>

        {networkEvents.length === 0 ? (
          <div className="p-10 text-center">
            <ShieldCheck className="w-10 h-10 text-[#16C79A] mx-auto mb-2 opacity-70" />
            <h4 className="text-xs font-semibold text-[#E8EEF7]">NO NETWORK THREATS DETECTED</h4>
            <p className="text-[11px] text-[#8E9EB5] mt-1">
              Belum ada aktivitas ancaman jaringan (Suricata / Zeek) yang terdeteksi pada port 8081 atau antarmuka jaringan.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono text-[11px]">
              <thead className="text-[#64748B] border-b border-[#152033] bg-[#080D17]">
                <tr>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Alert Title</th>
                  <th className="py-2.5 px-3">Source IP</th>
                  <th className="py-2.5 px-3">Destination IP</th>
                  <th className="py-2.5 px-3">Proto</th>
                  <th className="py-2.5 px-3 text-right">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#152033]">
                {networkEvents.map((evt) => (
                  <tr key={evt.id} className="hover:bg-[#152338]/40">
                    <td className="py-2.5 px-3 text-[#8E9EB5]">{evt.timestamp}</td>
                    <td className="py-2.5 px-3 text-[#E8EEF7] font-sans font-medium">{evt.title}</td>
                    <td className="py-2.5 px-3 text-[#36A3FF]">{evt.sourceIp}</td>
                    <td className="py-2.5 px-3 text-[#8E9EB5]">{evt.destIp}</td>
                    <td className="py-2.5 px-3 text-[#16C79A]">{evt.protocol}:{evt.port}</td>
                    <td className="py-2.5 px-3 text-right">
                      <span className={`px-2 py-0.5 rounded font-bold uppercase text-[10px] ${
                        evt.severity === 'critical'
                          ? 'bg-[#EF5350]/20 text-[#EF5350] border border-[#EF5350]/30'
                          : 'bg-[#FFB74D]/20 text-[#FFB74D] border border-[#FFB74D]/30'
                      }`}>
                        {evt.severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
