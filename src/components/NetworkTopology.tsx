/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Interactive Network Topology Component
 */

import React, { useState } from 'react';
import {
  Globe,
  Shield,
  Server,
  Database,
  Cloud,
  Monitor,
  AlertTriangle,
  Lock,
  Unlock,
  X,
  Info,
  Radio,
} from 'lucide-react';
import { NetworkNode } from '../types/cybersecurity.js';

interface NetworkTopologyProps {
  nodes: NetworkNode[];
  onIsolateNode: (nodeId: string) => Promise<void>;
}

export const NetworkTopology: React.FC<NetworkTopologyProps> = ({ nodes, onIsolateNode }) => {
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);

  // SVG dimensions
  const svgWidth = 720;
  const svgHeight = 290;

  // Find node by id helper
  const getNode = (id: string) => nodes.find((n) => n.id === id);

  // Render node icon
  const getNodeIcon = (type: NetworkNode['type'], className = 'w-4 h-4') => {
    switch (type) {
      case 'internet':
        return <Globe className={className} />;
      case 'firewall':
        return <Shield className={className} />;
      case 'switch':
        return <Server className={className} />;
      case 'database':
        return <Database className={className} />;
      case 'cloud':
        return <Cloud className={className} />;
      default:
        return <Monitor className={className} />;
    }
  };

  const handleToggleIsolation = async () => {
    if (!selectedNode) return;
    setIsProcessing(true);
    try {
      await onIsolateNode(selectedNode.id);
      const updated = getNode(selectedNode.id);
      if (updated) setSelectedNode(updated);
    } finally {
      setIsProcessing(false);
    }
  };

  return (
    <div className="relative w-full h-full flex flex-col justify-between">
      {/* Topology Header & Legend */}
      <div className="flex items-center justify-between pb-2">
        <div>
          <h3 className="text-sm font-semibold text-[#E8EEF7]">Network Topology</h3>
          <p className="text-[11px] text-[#8E9EB5]">Monitor and secure network infrastructure visibility.</p>
        </div>
        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#EF5350] animate-pulse"></span>
            <span className="text-[#8E9EB5]">Attack Path</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#16C79A]"></span>
            <span className="text-[#8E9EB5]">Normal</span>
          </div>
        </div>
      </div>

      {/* SVG Canvas */}
      <div className="relative w-full flex-1 min-h-[220px] bg-[#0A0F1D]/80 rounded-xl border border-[#16233B] overflow-hidden flex items-center justify-center">
        {/* Subtle background cyber coordinate grid */}
        <div 
          className="absolute inset-0 opacity-15 pointer-events-none"
          style={{
            backgroundImage: `radial-gradient(#36A3FF 1px, transparent 1px)`,
            backgroundSize: '24px 24px',
          }}
        />

        <svg
          viewBox={`0 0 ${svgWidth} ${svgHeight}`}
          className="w-full h-full select-none"
          preserveAspectRatio="xMidYMid meet"
        >
          {/* Defs for gradients & glowing drop shadows */}
          <defs>
            <filter id="glow-red" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
            <filter id="glow-teal" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="2" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
            <linearGradient id="normalLineGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#16C79A" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#36A3FF" stopOpacity="0.8" />
            </linearGradient>
            <linearGradient id="attackLineGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#EF5350" stopOpacity="0.9" />
              <stop offset="100%" stopColor="#F5B942" stopOpacity="0.9" />
            </linearGradient>
          </defs>

          {/* Connections / Edges */}
          {nodes.map((node) =>
            node.connections.map((targetId) => {
              const target = getNode(targetId);
              if (!target) return null;

              // Avoid duplicate reverse lines
              if (node.id > target.id) return null;

              const isAttackEdge =
                (node.status === 'compromised' || target.status === 'compromised') ||
                (node.id === 'node-finsrv' || target.id === 'node-finsrv');

              const isIsolated = node.status === 'isolated' || target.status === 'isolated';

              // Curved bezier path
              const dx = target.x - node.x;
              const dy = target.y - node.y;
              const cx1 = node.x + dx * 0.5;
              const cy1 = node.y;
              const cx2 = node.x + dx * 0.5;
              const cy2 = target.y;

              const pathData = `M ${node.x} ${node.y} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${target.x} ${target.y}`;

              return (
                <g key={`${node.id}-${target.id}`}>
                  {/* Outer subtle glow line */}
                  <path
                    d={pathData}
                    fill="none"
                    stroke={isIsolated ? '#475569' : isAttackEdge ? '#EF5350' : '#16C79A'}
                    strokeWidth={isAttackEdge ? 3 : 2}
                    strokeDasharray={isIsolated ? '4,4' : isAttackEdge ? '6,4' : undefined}
                    opacity={isIsolated ? 0.3 : isAttackEdge ? 0.9 : 0.6}
                    filter={isAttackEdge ? 'url(#glow-red)' : 'url(#glow-teal)'}
                  />
                  {/* Subtle data flow pulse along active edges */}
                  {!isIsolated && (
                    <circle r="2.5" fill={isAttackEdge ? '#EF5350' : '#36A3FF'}>
                      <animateMotion
                        path={pathData}
                        dur={isAttackEdge ? '2.5s' : '4s'}
                        repeatCount="indefinite"
                      />
                    </circle>
                  )}
                </g>
              );
            })
          )}

          {/* Nodes */}
          {nodes.map((node) => {
            const isCompromised = node.status === 'compromised';
            const isIsolated = node.status === 'isolated';
            const isWarning = node.status === 'warning';

            const fillColor = isIsolated
              ? '#1E293B'
              : isCompromised
              ? '#3E1015'
              : isWarning
              ? '#3B2912'
              : '#0D242B';

            const strokeColor = isIsolated
              ? '#64748B'
              : isCompromised
              ? '#EF5350'
              : isWarning
              ? '#F5B942'
              : '#16C79A';

            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                onClick={() => setSelectedNode(node)}
                className="cursor-pointer group"
              >
                {/* Ping ring for compromised node */}
                {isCompromised && (
                  <circle
                    r="22"
                    fill="none"
                    stroke="#EF5350"
                    strokeWidth="1.5"
                    className="animate-ping opacity-60"
                  />
                )}

                {/* Outer Circle Container */}
                <circle
                  r="16"
                  fill={fillColor}
                  stroke={strokeColor}
                  strokeWidth="2"
                  className="transition-transform duration-200 group-hover:scale-115"
                />

                {/* Icon wrapper inside foreignObject */}
                <foreignObject x="-9" y="-9" width="18" height="18" className="pointer-events-none">
                  <div className="w-full h-full flex items-center justify-center text-white" style={{ color: strokeColor }}>
                    {getNodeIcon(node.type, 'w-3.5 h-3.5')}
                  </div>
                </foreignObject>

                {/* Node Label Below */}
                <text
                  y="28"
                  textAnchor="middle"
                  className="text-[10px] font-mono font-medium fill-[#E8EEF7] pointer-events-none"
                >
                  {node.name.split(' ')[0]}
                </text>
                <text
                  y="38"
                  textAnchor="middle"
                  className="text-[8px] font-mono fill-[#8E9EB5] pointer-events-none"
                >
                  {node.ip}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Selected Node Details Drawer / Popover */}
        {selectedNode && (
          <div className="absolute right-3 top-3 bottom-3 w-72 bg-[#101827]/95 backdrop-blur-md border border-[#1E2D4A] rounded-xl shadow-2xl p-3 z-30 flex flex-col justify-between text-xs animate-in fade-in duration-150">
            <div>
              <div className="flex items-center justify-between pb-2 border-b border-[#1A263D] mb-2.5">
                <div className="flex items-center gap-2">
                  <div className={`p-1.5 rounded-lg ${
                    selectedNode.status === 'compromised' ? 'bg-[#EF5350]/20 text-[#EF5350]' : 'bg-[#152338] text-[#16C79A]'
                  }`}>
                    {getNodeIcon(selectedNode.type, 'w-4 h-4')}
                  </div>
                  <div>
                    <h4 className="font-semibold text-[#E8EEF7]">{selectedNode.name}</h4>
                    <span className="font-mono text-[10px] text-[#8E9EB5]">{selectedNode.ip}</span>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="p-1 text-[#8E9EB5] hover:text-[#E8EEF7] rounded"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-2 text-[#8E9EB5]">
                <div className="flex items-center justify-between py-1 border-b border-[#152033]">
                  <span>Status:</span>
                  <span className={`font-semibold capitalize ${
                    selectedNode.status === 'compromised'
                      ? 'text-[#EF5350]'
                      : selectedNode.status === 'isolated'
                      ? 'text-[#F5B942]'
                      : 'text-[#16C79A]'
                  }`}>
                    {selectedNode.status}
                  </span>
                </div>
                <div className="flex items-center justify-between py-1 border-b border-[#152033]">
                  <span>Operating System:</span>
                  <span className="text-[#E8EEF7]">{selectedNode.os || 'Firmware Appliance'}</span>
                </div>
                <div className="flex items-center justify-between py-1 border-b border-[#152033]">
                  <span>Criticality Tier:</span>
                  <span className="text-[#36A3FF] font-medium">{selectedNode.criticalTier || 'Tier 2'}</span>
                </div>
                <div className="flex items-center justify-between py-1 border-b border-[#152033]">
                  <span>Vulnerability Flaws:</span>
                  <span className={`font-mono ${selectedNode.vulnCount ? 'text-[#EF5350]' : 'text-[#16C79A]'}`}>
                    {selectedNode.vulnCount || 0} CVEs
                  </span>
                </div>
                <div className="py-1">
                  <span className="block mb-1">Defense Controls:</span>
                  <div className="flex flex-wrap gap-1">
                    <span className="px-1.5 py-0.5 bg-[#152033] rounded text-[10px] text-[#E8EEF7]">Wazuh Agent</span>
                    <span className="px-1.5 py-0.5 bg-[#152033] rounded text-[10px] text-[#E8EEF7]">FIM Inotify</span>
                    <span className="px-1.5 py-0.5 bg-[#152033] rounded text-[10px] text-[#E8EEF7]">eBPF Probe</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Containment Isolation Button */}
            <div className="pt-2 border-t border-[#1A263D]">
              <button
                onClick={handleToggleIsolation}
                disabled={isProcessing}
                className={`w-full py-2 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-1.5 transition-all ${
                  selectedNode.status === 'isolated'
                    ? 'bg-[#16C79A] text-[#080D17] hover:bg-[#16C79A]/90'
                    : 'bg-[#EF5350] text-white hover:bg-[#EF5350]/90 shadow-lg shadow-[#EF5350]/20'
                }`}
              >
                {selectedNode.status === 'isolated' ? (
                  <>
                    <Unlock className="w-3.5 h-3.5" />
                    Restore Network Access
                  </>
                ) : (
                  <>
                    <Lock className="w-3.5 h-3.5" />
                    Isolate Host from Network
                  </>
                )}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* KPI Stats Bar below topology - exact match to screenshot */}
      <div className="grid grid-cols-4 gap-2 pt-3">
        <div className="p-2.5 bg-[#0B111E] border border-[#152033] rounded-lg">
          <div className="flex items-center gap-1.5 text-xs text-[#8E9EB5] mb-1">
            <span className="w-2 h-2 rounded-full bg-[#36A3FF]"></span>
            <span>Open Incidents</span>
          </div>
          <div className="text-xl font-bold font-mono text-[#E8EEF7]">38</div>
          <div className="text-[10px] text-[#64748B]">Currently Active Cases</div>
        </div>

        <div className="p-2.5 bg-[#0B111E] border border-[#152033] rounded-lg">
          <div className="flex items-center gap-1.5 text-xs text-[#8E9EB5] mb-1">
            <span className="w-2 h-2 rounded-full bg-[#EF5350]"></span>
            <span>Critical Incidents</span>
          </div>
          <div className="text-xl font-bold font-mono text-[#EF5350]">5</div>
          <div className="text-[10px] text-[#64748B]">Immediate Action Required</div>
        </div>

        <div className="p-2.5 bg-[#0B111E] border border-[#152033] rounded-lg">
          <div className="flex items-center gap-1.5 text-xs text-[#8E9EB5] mb-1">
            <span className="w-2 h-2 rounded-full bg-[#16C79A]"></span>
            <span>Resolved Today</span>
          </div>
          <div className="text-xl font-bold font-mono text-[#16C79A]">127</div>
          <div className="text-[10px] text-[#64748B]">Successfully Closed</div>
        </div>

        <div className="p-2.5 bg-[#0B111E] border border-[#152033] rounded-lg">
          <div className="flex items-center gap-1.5 text-xs text-[#8E9EB5] mb-1">
            <span className="w-2 h-2 rounded-full bg-[#F5B942]"></span>
            <span>Avg Time</span>
          </div>
          <div className="text-xl font-bold font-mono text-[#E8EEF7]">12m</div>
          <div className="text-[10px] text-[#64748B]">Mean Time To Respond</div>
        </div>
      </div>
    </div>
  );
};
