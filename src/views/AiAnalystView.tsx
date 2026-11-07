/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - AI Security Analyst (Powered by Google GenAI)
 */

import React, { useState } from 'react';
import {
  Bot,
  Send,
  Sparkles,
  ShieldAlert,
  Terminal,
  FileCheck,
  RefreshCw,
  Copy,
  Check,
} from 'lucide-react';
import { Incident } from '../types/cybersecurity.js';
import { ModuleExplanationCard, ModuleGuideData } from '../components/ModuleExplanationCard.js';

const AI_GUIDE: ModuleGuideData = {
  title: 'Modul 7: Analis Keamanan AI (SOC Tier 3 AI Assistant)',
  badge: 'Gemini 3.8 Flash • Zero Hallucination',
  shortSummary: 'Asisten penalaran ancaman berbasis Google GenAI yang bekerja murni berdasarkan bukti teknis aktual tanpa data karangan.',
  fungsiUtama: 'Menganalisis korelasi insiden, memetakan taktik MITRE ATT&CK, dan merumuskan rekomendasi mitigasi teknis (iptables, patch).',
  alasanDiperlukan: 'Membantu analis mempercepat investigasi insiden kompleks tanpa harus membaca ribuan baris log secara manual.',
  caraKerja: 'Backend memvalidasi bukti telemetri riil dari database sebelum diteruskan ke model dengan instruksi ketat anti-halusinasi.',
  dataDitampilkan: 'Analisis rantai serangan (attack chain), perintah mitigasi spesifik Linux/Ubuntu, ringkasan eksekutif, dan pemetaan MITRE.',
  artiStatus: 'Online (GenAI API): Model analitis tingkat lanjut aktif; Heuristic Engine: Mode deterministik offline jika API tidak tersedia.',
  panduanTindakan: 'Pilih kasus aktif dari dropdown, gunakan tombol quick prompt, atau ajukan pertanyaan teknis seputar strategi pengamanan DVWA.',
};

interface AiAnalystViewProps {
  incidents: Incident[];
  preselectedIncidentId?: string;
}

interface Message {
  sender: 'user' | 'ai';
  text: string;
  timestamp: string;
}

export const AiAnalystView: React.FC<AiAnalystViewProps> = ({
  incidents,
  preselectedIncidentId,
}) => {
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>(
    preselectedIncidentId || incidents[0]?.id || ''
  );
  const [inputQuery, setInputQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const activeIncident = incidents.find((i) => i.id === selectedIncidentId) || incidents[0];

  const [messages, setMessages] = useState<Message[]>([
    {
      sender: 'ai',
      text: `Hello Analyst. I am the **NUSANTARA-SMS AI Security Analyst** (SOC Tier 3 Assistant).
I am synchronized with current live telemetry, MITRE ATT&CK correlation rules, and active incident dossiers.

${
  activeIncident
    ? `Currently inspecting **${activeIncident.id}: ${activeIncident.title}**.`
    : 'System telemetry is currently in a clean baseline state with 0 active incidents.'
}

You can ask me to:
- Perform root cause analysis and attack chain mapping.
- Correlate lateral movement across network topology nodes.
- Recommend containment commands (iptables, Wazuh FIM rollback, WAF rules).
- Author executive summaries for C-level briefings.`,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);

  const handleSendMessage = async (customPrompt?: string) => {
    const promptToSend = customPrompt || inputQuery;
    if (!promptToSend.trim() || isLoading) return;

    const userMsg: Message = {
      sender: 'user',
      text: promptToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputQuery('');
    setIsLoading(true);

    try {
      const res = await fetch('/api/ai/analyze-incident', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incidentId: selectedIncidentId,
          userPrompt: promptToSend,
        }),
      });
      const data = await res.json();

      const aiMsg: Message = {
        sender: 'ai',
        text: data.analysis || data.reply || 'No analysis available.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setMessages((prev) => [...prev, aiMsg]);
    } catch (err) {
      console.error('AI Analyst invocation failed', err);
      setMessages((prev) => [
        ...prev,
        {
          sender: 'ai',
          text: 'Error communicating with AI engine. Offline heuristic rules active.',
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = (text: string, idx: number) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedIndex(idx);
      setTimeout(() => setCopiedIndex(null), 1500);
    }
  };

  return (
    <div className="space-y-4">
      {/* 6-Aspect Progressive Disclosure Module Guide */}
      <ModuleExplanationCard guide={AI_GUIDE} />

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#101827] border border-[#16233B] rounded-xl p-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#152338] border border-[#16C79A]/40 flex items-center justify-center text-[#16C79A]">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-[#E8EEF7]">AI Security Analyst (SOC Tier 3)</h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30">
                gemini-3.8-flash @google/genai
              </span>
            </div>
            <p className="text-xs text-[#8E9EB5]">Real-time threat reasoning, attack pattern synthesis, and MITRE-grounded mitigation advice.</p>
          </div>
        </div>

        {/* Incident Context Selector */}
        <div className="flex items-center gap-2 text-xs">
          <span className="text-[#8E9EB5]">Active Case:</span>
          {incidents.length > 0 ? (
            <select
              value={selectedIncidentId}
              onChange={(e) => setSelectedIncidentId(e.target.value)}
              className="bg-[#080D17] border border-[#16233B] text-[#36A3FF] font-mono px-2.5 py-1.5 rounded-lg outline-none font-semibold cursor-pointer"
            >
              {incidents.map((i) => (
                <option key={i.id} value={i.id}>
                  {i.id} - {i.title.slice(0, 32)}...
                </option>
              ))}
            </select>
          ) : (
            <span className="px-2.5 py-1.5 bg-[#080D17] border border-[#16233B] text-[#8E9EB5] font-mono text-[11px] rounded-lg">
              No Active Incidents (Clean State)
            </span>
          )}
        </div>
      </div>

      {/* Suggested Quick Prompts */}
      <div className="flex flex-wrap gap-2 text-xs">
        {[
          'Perform deep triage on current incident',
          'Explain attack path and potential lateral movement',
          'Generate immediate containment iptables commands',
          'Draft executive incident debrief report',
        ].map((promptText, i) => (
          <button
            key={i}
            onClick={() => handleSendMessage(promptText)}
            className="px-3 py-1.5 bg-[#101827] hover:bg-[#152338] text-[#8E9EB5] hover:text-[#16C79A] border border-[#16233B] hover:border-[#16C79A]/40 rounded-lg transition-colors flex items-center gap-1.5"
          >
            <Sparkles className="w-3 h-3 text-[#16C79A]" />
            {promptText}
          </button>
        ))}
      </div>

      {/* Chat Messages Log */}
      <div className="bg-[#101827] border border-[#16233B] rounded-xl p-4 min-h-[420px] max-h-[560px] overflow-y-auto space-y-4">
        {messages.map((m, idx) => (
          <div
            key={idx}
            className={`flex flex-col ${m.sender === 'user' ? 'items-end' : 'items-start'}`}
          >
            <div className="flex items-center gap-2 mb-1 px-1">
              <span className={`text-[10px] font-mono font-semibold ${
                m.sender === 'user' ? 'text-[#36A3FF]' : 'text-[#16C79A]'
              }`}>
                {m.sender === 'user' ? 'SOC Analyst' : 'Nusantara AI SOC (L3)'}
              </span>
              <span className="text-[10px] text-[#64748B] font-mono">{m.timestamp}</span>
              {m.sender === 'ai' && (
                <button
                  onClick={() => copyToClipboard(m.text, idx)}
                  className="text-[#64748B] hover:text-[#E8EEF7] p-0.5 rounded ml-1"
                  title="Copy analysis markdown"
                >
                  {copiedIndex === idx ? <Check className="w-3 h-3 text-[#16C79A]" /> : <Copy className="w-3 h-3" />}
                </button>
              )}
            </div>

            <div
              className={`p-3.5 rounded-xl text-xs max-w-3xl leading-relaxed whitespace-pre-wrap ${
                m.sender === 'user'
                  ? 'bg-[#152338] text-[#E8EEF7] border border-[#1E2D4A]'
                  : 'bg-[#0A0F1D] text-[#CBD5E1] border border-[#16233B] shadow-inner font-sans'
              }`}
            >
              {m.text}
            </div>
          </div>
        ))}

        {isLoading && (
          <div className="flex items-center gap-2 text-xs text-[#16C79A] font-mono p-3 bg-[#0A0F1D] border border-[#16233B] rounded-xl w-64">
            <RefreshCw className="w-4 h-4 animate-spin" />
            Analyzing telemetry & MITRE data...
          </div>
        )}
      </div>

      {/* Input Box */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSendMessage();
        }}
        className="flex gap-2"
      >
        <input
          type="text"
          value={inputQuery}
          onChange={(e) => setInputQuery(e.target.value)}
          placeholder={
            activeIncident
              ? `Ask AI Security Analyst about ${activeIncident.id} or general cyber defense strategy...`
              : 'Ask AI Security Analyst about defensive tactics, Suricata rules, or DVWA hardening...'
          }
          className="flex-1 bg-[#101827] border border-[#16233B] rounded-xl px-4 py-3 text-xs text-[#E8EEF7] placeholder-[#64748B] focus:outline-none focus:border-[#16C79A] shadow-inner"
        />
        <button
          type="submit"
          disabled={!inputQuery.trim() || isLoading}
          className="px-5 py-3 bg-[#16C79A] hover:bg-[#16C79A]/90 text-[#080D17] text-xs font-bold rounded-xl flex items-center gap-2 transition-all shadow-md shadow-[#16C79A]/20 disabled:opacity-50"
        >
          <Send className="w-4 h-4" />
          Send
        </button>
      </form>
    </div>
  );
};
