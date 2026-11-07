/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Sensors & Endpoints View
 * Zero Dummy Data Policy • Real Telemetry Sensors & Monitored Target Fleet
 */

import React, { useState } from 'react';
import {
  Server,
  Radio,
  FileText,
  GlobeLock,
  Terminal,
  Activity,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  RefreshCw,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  HelpCircle,
  Copy,
  Check,
  Zap,
} from 'lucide-react';
import { SensorStatusRecord, CollectorStatus, ExternalTesterSession } from '../types/cybersecurity.js';

interface SensorsEndpointsViewProps {
  sensors: SensorStatusRecord[];
  collectorStatus?: CollectorStatus | null;
  externalTester?: ExternalTesterSession | null;
  onRefresh?: () => void;
  onProbeDvwa?: () => Promise<void>;
}

export type ValidSensorStatus = 'ONLINE' | 'OFFLINE' | 'WAITING FOR TELEMETRY' | 'NOT CONFIGURED' | 'ERROR';

interface ExtendedSensorDefinition {
  id: string;
  name: string;
  serviceType: string;
  hostIp: string;
  telemetryType: string;
  status: ValidSensorStatus;
  statusDetail: string;
  lastSeen: string | null;
  configPath: string;
  protocol: string;
}

export const SensorsEndpointsView: React.FC<SensorsEndpointsViewProps> = ({
  sensors,
  collectorStatus,
  externalTester,
  onRefresh,
  onProbeDvwa,
}) => {
  const [isProbing, setIsProbing] = useState(false);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(id);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const handleProbe = async () => {
    if (!onProbeDvwa) return;
    setIsProbing(true);
    try {
      await onProbeDvwa();
    } finally {
      setIsProbing(false);
    }
  };

  // Map backend sensors to strict Section 8 sensor specifications
  const suricataRecord = sensors.find((s) => s.id === 'sensor-suricata');
  const dvwaRecord = sensors.find((s) => s.id === 'sensor-dvwa');
  const wafRecord = sensors.find((s) => s.id === 'sensor-waf');

  const determineStatus = (record?: SensorStatusRecord, isWaf?: boolean): ValidSensorStatus => {
    if (!record) return 'NOT CONFIGURED';
    if (record.connectionStatus === 'connected') return 'ONLINE';
    if (record.connectionStatus === 'waiting_telemetry') return 'WAITING FOR TELEMETRY';
    if (record.connectionStatus === 'error') return 'ERROR';
    if (record.connectionStatus === 'disconnected') {
      if (record.id === 'sensor-suricata' && record.eventIngestionCount === 0) {
        return 'WAITING FOR TELEMETRY';
      }
      return 'OFFLINE';
    }
    return 'NOT CONFIGURED';
  };

  const sensorFleet: ExtendedSensorDefinition[] = [
    {
      id: 'sensor-suricata',
      name: 'Suricata Network IDS / IPS Sensor',
      serviceType: 'Network Threat Detection Engine',
      hostIp: '192.168.100.75 (Ubuntu Server)',
      telemetryType: 'Suricata EVE JSON (alerts, flow, http, dns)',
      status: determineStatus(suricataRecord),
      statusDetail: suricataRecord?.lastEventTimestamp
        ? `Menerima ${suricataRecord.eventIngestionCount} event jaringan.`
        : 'Menunggu pengiriman file /var/log/suricata/eve.json melalui collector forwarder.',
      lastSeen: suricataRecord?.lastEventTimestamp || null,
      configPath: '/etc/suricata/suricata.yaml',
      protocol: 'JSON over HTTP POST (/api/ingest/suricata)',
    },
    {
      id: 'sensor-apache',
      name: 'Apache HTTP Server Access Log',
      serviceType: 'Web Server Ingress Telemetry',
      hostIp: '192.168.100.75 (Ubuntu Server)',
      telemetryType: 'Apache Combined Log Format (HTTP transactions, response codes)',
      status: collectorStatus?.apacheFeedActive ? 'ONLINE' : 'WAITING FOR TELEMETRY',
      statusDetail: collectorStatus?.apacheFeedActive
        ? 'Stream log Apache access aktif dari host target.'
        : 'Menunggu forwarder mengirim log /var/log/apache2/access.log ke /api/ingest/dvwa.',
      lastSeen: collectorStatus?.lastHeartbeat || null,
      configPath: '/var/log/apache2/access.log',
      protocol: 'Log Streaming via Forwarder Agent',
    },
    {
      id: 'sensor-waf',
      name: 'Nusantara WAF / ModSecurity Ingress',
      serviceType: 'Web Application Firewall Inspection',
      hostIp: '192.168.100.75 / Ingress Gateway',
      telemetryType: 'OWASP Core Rule Set (CRS) Audit Log & Block Events',
      status: wafRecord?.connectionStatus === 'connected' ? 'ONLINE' : 'WAITING FOR TELEMETRY',
      statusDetail:
        wafRecord?.connectionStatus === 'connected'
          ? 'Inspeksi payload HTTP real-time aktif dengan penolakan 403 Forbidden otomatis.'
          : 'Menunggu telemetry inspeksi WAF aktif.',
      lastSeen: wafRecord?.lastEventTimestamp || null,
      configPath: '/etc/modsecurity/modsecurity.conf',
      protocol: 'WAF Audit JSON over HTTP',
    },
    {
      id: 'sensor-collector',
      name: 'NUSANTARA-SMS Collector Forwarder',
      serviceType: 'Telemetry Agent Daemon (Python/Bash)',
      hostIp: collectorStatus?.collectorIp || '192.168.100.75 (Target Host)',
      telemetryType: 'Unified Heartbeat & Batch Telemetry Ingestion',
      status: collectorStatus?.status === 'ACTIVE' ? 'ONLINE' : 'WAITING FOR TELEMETRY',
      statusDetail: collectorStatus?.status === 'ACTIVE'
        ? `Collector v${collectorStatus.collectorVersion || '1.2.0'} aktif mengirim log. Event diproses: ${collectorStatus.verifiedEventCount}.`
        : 'Forwarder script belum dijalankan pada server Ubuntu target.',
      lastSeen: collectorStatus?.lastHeartbeat || null,
      configPath: '/usr/local/bin/nusantara-collector.py',
      protocol: 'HTTPS POST /api/ingest/* dengan dynamic token',
    },
    {
      id: 'target-dvwa',
      name: 'DVWA Target Host (Damn Vulnerable Web App)',
      serviceType: 'Monitored Critical Asset',
      hostIp: '192.168.100.75:8081',
      telemetryType: 'HTTP Health Probing & Application Response Status',
      status:
        dvwaRecord?.connectionStatus === 'connected'
          ? 'ONLINE'
          : dvwaRecord?.connectionStatus === 'degraded'
          ? 'ERROR'
          : 'WAITING FOR TELEMETRY',
      statusDetail:
        dvwaRecord?.connectionStatus === 'connected'
          ? 'Target DVWA dapat diakses pada port 8081. Respon HTTP 200/302 normal.'
          : 'Konektivitas ke 192.168.100.75:8081 belum terdeteksi dari backend.',
      lastSeen: dvwaRecord?.lastSuccessfulCollection || null,
      configPath: 'http://192.168.100.75:8081',
      protocol: 'HTTP/1.1 Port 8081',
    },
  ];

  const getStatusBadge = (status: ValidSensorStatus) => {
    switch (status) {
      case 'ONLINE':
        return (
          <span className="px-2.5 py-1 rounded-md text-[10px] font-mono font-bold bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/40 flex items-center gap-1.5 shadow-sm">
            <span className="w-1.5 h-1.5 rounded-full bg-[#16C79A] animate-pulse"></span>
            ONLINE
          </span>
        );
      case 'WAITING FOR TELEMETRY':
        return (
          <span className="px-2.5 py-1 rounded-md text-[10px] font-mono font-bold bg-[#36A3FF]/20 text-[#36A3FF] border border-[#36A3FF]/40 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#36A3FF]"></span>
            WAITING FOR TELEMETRY
          </span>
        );
      case 'OFFLINE':
        return (
          <span className="px-2.5 py-1 rounded-md text-[10px] font-mono font-bold bg-[#EF5350]/20 text-[#EF5350] border border-[#EF5350]/40 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#EF5350]"></span>
            OFFLINE
          </span>
        );
      case 'ERROR':
        return (
          <span className="px-2.5 py-1 rounded-md text-[10px] font-mono font-bold bg-[#F5B942]/20 text-[#F5B942] border border-[#F5B942]/40 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#F5B942]"></span>
            ERROR
          </span>
        );
      case 'NOT CONFIGURED':
      default:
        return (
          <span className="px-2.5 py-1 rounded-md text-[10px] font-mono font-bold bg-[#64748B]/20 text-[#8E9EB5] border border-[#64748B]/30 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#64748B]"></span>
            NOT CONFIGURED
          </span>
        );
    }
  };

  const onlineCount = sensorFleet.filter((s) => s.status === 'ONLINE').length;
  const waitingCount = sensorFleet.filter((s) => s.status === 'WAITING FOR TELEMETRY').length;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#101827] border border-[#16233B] rounded-xl p-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#152338] border border-[#16C79A]/30 flex items-center justify-center text-[#16C79A]">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-[#E8EEF7]">Sensors & Endpoints Infrastructure</h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#16C79A]/20 text-[#16C79A] border border-[#16C79A]/30 font-semibold">
                Lab Sensor Fleet
              </span>
            </div>
            <p className="text-xs text-[#8E9EB5]">
              Pemantauan status koneksi dan keaslian telemetry dari Suricata, Apache, WAF, Collector, dan target DVWA.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleProbe}
            disabled={isProbing}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#152338] hover:bg-[#1E2D4A] text-[#36A3FF] border border-[#36A3FF]/40 rounded-lg text-xs font-semibold transition-colors"
          >
            <Zap className={`w-3.5 h-3.5 ${isProbing ? 'animate-spin' : ''}`} />
            {isProbing ? 'Memeriksa DVWA...' : 'Probe Target DVWA'}
          </button>
          {onRefresh && (
            <button
              onClick={onRefresh}
              className="p-2 bg-[#152338] hover:bg-[#1E2D4A] text-[#16C79A] border border-[#16C79A]/30 rounded-lg text-xs transition-colors"
              title="Refresh Status Sensor"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Summary KPI Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3.5 bg-[#101827] border border-[#16233B] rounded-xl">
          <div className="text-xs text-[#8E9EB5]">Total Monitored Sensors</div>
          <div className="text-2xl font-bold font-mono text-[#E8EEF7] my-1">{sensorFleet.length}</div>
          <div className="text-[10px] text-[#64748B]">5 Sensor Spesifikasi Lab</div>
        </div>
        <div className="p-3.5 bg-[#101827] border border-[#16233B] rounded-xl">
          <div className="text-xs text-[#8E9EB5]">Active Telemetry Feeds</div>
          <div className="text-2xl font-bold font-mono text-[#16C79A] my-1">{onlineCount}</div>
          <div className="text-[10px] text-[#64748B]">Status ONLINE</div>
        </div>
        <div className="p-3.5 bg-[#101827] border border-[#16233B] rounded-xl">
          <div className="text-xs text-[#8E9EB5]">Waiting for Telemetry</div>
          <div className="text-2xl font-bold font-mono text-[#36A3FF] my-1">{waitingCount}</div>
          <div className="text-[10px] text-[#64748B]">Menunggu log aktual dari host</div>
        </div>
        <div className="p-3.5 bg-[#101827] border border-[#16233B] rounded-xl">
          <div className="text-xs text-[#8E9EB5]">Target Host</div>
          <div className="text-sm font-bold font-mono text-[#E8EEF7] my-1 truncate">192.168.100.75:8081</div>
          <div className="text-[10px] text-[#64748B]">Ubuntu Home Server</div>
        </div>
      </div>

      {/* Sensor Fleet Table */}
      <div className="bg-[#101827] border border-[#16233B] rounded-xl overflow-hidden shadow-lg">
        <div className="p-3.5 border-b border-[#16233B] flex items-center justify-between">
          <div>
            <h2 className="text-sm font-bold text-[#E8EEF7]">Sensor & Telemetry Sources</h2>
            <p className="text-xs text-[#8E9EB5]">
              Sesuai kebijakan Zero Dummy Data: hanya sensor yang benar-benar mengirim data yang bertatus ONLINE.
            </p>
          </div>
          <span className="text-xs font-mono text-[#16C79A]">Kartika Cyber Hackathon 2026</span>
        </div>

        <div className="divide-y divide-[#152033]">
          {sensorFleet.map((sensor) => (
            <div key={sensor.id} className="p-4 hover:bg-[#152338]/40 transition-colors">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="text-sm font-bold text-[#E8EEF7]">{sensor.name}</h3>
                    <span className="text-[10px] font-mono text-[#8E9EB5] px-2 py-0.5 rounded bg-[#080D17] border border-[#16233B]">
                      {sensor.serviceType}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 text-xs pt-1">
                    <div>
                      <span className="text-[#64748B] block text-[10px]">Host / IP:</span>
                      <span className="font-mono text-[#36A3FF] font-semibold">{sensor.hostIp}</span>
                    </div>
                    <div>
                      <span className="text-[#64748B] block text-[10px]">Jenis Telemetry:</span>
                      <span className="text-[#E8EEF7]">{sensor.telemetryType}</span>
                    </div>
                    <div>
                      <span className="text-[#64748B] block text-[10px]">Terakhir Mengirim Data:</span>
                      <span className="font-mono text-[#8E9EB5]">
                        {sensor.lastSeen ? sensor.lastSeen : 'Belum pernah menerima data'}
                      </span>
                    </div>
                  </div>

                  <p className="text-xs text-[#8E9EB5] pt-1">
                    <span className="text-[#64748B]">Keterangan: </span>
                    {sensor.statusDetail}
                  </p>
                </div>

                <div className="flex flex-col items-start md:items-end justify-between shrink-0 gap-2">
                  {getStatusBadge(sensor.status)}
                  <div className="text-[10px] font-mono text-[#64748B]">
                    Protocol: <span className="text-[#8E9EB5]">{sensor.protocol}</span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* External Tester Information Card */}
      <div className="bg-[#0B111E] border border-[#152033] rounded-xl p-4">
        <div className="flex items-start gap-3">
          <div className="w-9 h-9 rounded-lg bg-[#152338] border border-[#36A3FF]/40 flex items-center justify-center text-[#36A3FF] shrink-0 mt-0.5">
            <Terminal className="w-5 h-5" />
          </div>
          <div className="space-y-1.5 flex-1 text-xs">
            <div className="flex items-center gap-2">
              <h3 className="font-bold text-[#E8EEF7]">External Tester Station: Kali Linux</h3>
              <span className="px-2 py-0.2 rounded text-[10px] font-mono bg-[#36A3FF]/20 text-[#36A3FF] border border-[#36A3FF]/30">
                PENTEST ENGINE
              </span>
            </div>
            <p className="text-[#8E9EB5]">
              Pengujian keamanan dijalankan langsung dari terminal mesin Kali Linux eksternal menuju IP target{' '}
              <span className="font-mono text-[#36A3FF]">http://192.168.100.75:8081</span>. NUSANTARA-SMS tidak
              menjalankan simulasi serangan lokal yang memalsukan counter pertahanan.
            </p>
            <div className="flex flex-wrap items-center gap-4 pt-1 font-mono text-[11px] text-[#8E9EB5]">
              <div>
                Tester IP:{' '}
                <span className="text-[#16C79A] font-bold">
                  {externalTester?.sourceIp || collectorStatus?.externalTesterIp || '192.168.100.88 (Kali Linux)'}
                </span>
              </div>
              <div>
                Target Port: <span className="text-[#36A3FF]">8081 (DVWA HTTP)</span>
              </div>
              <div>
                Status: <span className="text-[#16C79A]">Listening on Suricata sensor</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
