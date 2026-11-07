/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Primary Application Shell
 * One Platform. Layered Defense. National Cyber Resilience.
 */

import React, { useEffect, useState } from 'react';
import { LeftNavigation, NavTab } from './components/LeftNavigation.js';
import { TopBar, ThemeMode } from './components/TopBar.js';
import { OverviewView } from './views/OverviewView.js';
import { SocConsoleView } from './views/SocConsoleView.js';
import { LiveThreatMonitoringView } from './views/LiveThreatMonitoringView.js';
import { NetworkDefenseView } from './views/NetworkDefenseView.js';
import { WebApplicationDefenseView } from './views/WebApplicationDefenseView.js';
import { EndpointSecurityView } from './views/EndpointSecurityView.js';
import { MitreMatrixView } from './views/MitreMatrixView.js';
import { ThreatIntelligenceView } from './views/ThreatIntelligenceView.js';
import { VulnerabilityManagementView } from './views/VulnerabilityManagementView.js';
import { IncidentResponseView } from './views/IncidentResponseView.js';
import { AiAnalystView } from './views/AiAnalystView.js';
import { SecurityReportsView } from './views/SecurityReportsView.js';
import { SystemHealthView } from './views/SystemHealthView.js';
import { SecurityEventsView } from './views/SecurityEventsView.js';
import { SettingsView } from './views/SettingsView.js';
import { BlockedIpsView } from './views/BlockedIpsView.js';
import { SensorsEndpointsView } from './views/SensorsEndpointsView.js';
import { ThreatAnalysisView } from './views/ThreatAnalysisView.js';
import { SystemLogsView } from './views/SystemLogsView.js';
import {
  SecurityEvent,
  SecurityAlert,
  Incident,
  NetworkNode,
  MitreTactic,
  ThreatIntelIoc,
  VulnerabilityItem,
  IntegrationAdapter,
  AuditLogItem,
  SensorStatusRecord,
  CollectorStatus,
  ExternalTesterSession,
  BlockedIpRecord,
} from './types/cybersecurity.js';
import { AlertCircle, X, ShieldAlert } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('overview');

  // Multi-Theme State (Dark, Light, System Default)
  const [theme, setTheme] = useState<ThemeMode>(() => {
    return (localStorage.getItem('nusantara_theme') as ThemeMode) || 'dark';
  });
  const [isMobileNavOpen, setIsMobileNavOpen] = useState(false);

  // Synchronize Theme & System Scheme
  useEffect(() => {
    localStorage.setItem('nusantara_theme', theme);
    const root = document.documentElement;

    const applyTheme = (isDark: boolean) => {
      if (isDark) {
        root.classList.remove('light');
        root.classList.add('dark');
        root.setAttribute('data-theme', 'dark');
      } else {
        root.classList.remove('dark');
        root.classList.add('light');
        root.setAttribute('data-theme', 'light');
      }
    };

    if (theme === 'system') {
      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      applyTheme(mediaQuery.matches);
      const handler = (e: MediaQueryListEvent) => applyTheme(e.matches);
      mediaQuery.addEventListener('change', handler);
      return () => mediaQuery.removeEventListener('change', handler);
    } else {
      applyTheme(theme === 'dark');
    }
  }, [theme]);

  // Top Bar Filter State
  const [selectedTeam, setSelectedTeam] = useState('Global SOC');
  const [selectedRegion, setSelectedRegion] = useState('Asia Pacific');
  const [selectedTimeRange, setSelectedTimeRange] = useState('Last 24 Hours');
  const [selectedThreatFilter, setSelectedThreatFilter] = useState('MITRE ATT&CK');
  const [searchQuery, setSearchQuery] = useState('');
  const [activeUser, setActiveUser] = useState('Sarah Chen (Lead Analyst)');

  // Real Defensive Datasets (Zero Dummy Data)
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [nodes, setNodes] = useState<NetworkNode[]>([]);
  const [mitreTactics, setMitreTactics] = useState<MitreTactic[]>([]);
  const [sensors, setSensors] = useState<SensorStatusRecord[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [collectorStatus, setCollectorStatus] = useState<CollectorStatus | null>(null);
  const [externalTester, setExternalTester] = useState<ExternalTesterSession | null>(null);
  const [blockedIps, setBlockedIps] = useState<BlockedIpRecord[]>([]);

  // Real-Time SSE Stream State
  const [isStreamConnected, setIsStreamConnected] = useState(false);
  const [isStreamPaused, setIsStreamPaused] = useState(false);
  const [activeAlertToast, setActiveAlertToast] = useState<{ title: string; message: string; severity: string } | null>(null);

  // Selected Incident for AI / Deep Inspection
  const [preselectedIncidentId, setPreselectedIncidentId] = useState<string>('');

  // Fetch initial data from backend
  const fetchAllData = async () => {
    try {
      const [
        eventsRes,
        alertsRes,
        incidentsRes,
        nodesRes,
        mitreRes,
        sensorsRes,
        auditRes,
        collectorRes,
        testerRes,
        blockedIpsRes,
      ] = await Promise.all([
        fetch('/api/events'),
        fetch('/api/alerts'),
        fetch('/api/incidents'),
        fetch('/api/network-topology'),
        fetch('/api/mitre'),
        fetch('/api/sensors'),
        fetch('/api/audit-logs'),
        fetch('/api/collector/status'),
        fetch('/api/collector/external-tester'),
        fetch('/api/blocked-ips'),
      ]);

      if (eventsRes.ok) setEvents(await eventsRes.json());
      if (alertsRes.ok) setAlerts(await alertsRes.json());
      if (incidentsRes.ok) setIncidents(await incidentsRes.json());
      if (nodesRes.ok) setNodes(await nodesRes.json());
      if (mitreRes.ok) {
        const mData = await mitreRes.json();
        setMitreTactics(mData.tactics || []);
      }
      if (sensorsRes.ok) setSensors(await sensorsRes.json());
      if (auditRes.ok) setAuditLogs(await auditRes.json());
      if (collectorRes.ok) setCollectorStatus(await collectorRes.json());
      if (testerRes.ok) setExternalTester(await testerRes.json());
      if (blockedIpsRes.ok) setBlockedIps(await blockedIpsRes.json());
    } catch (err) {
      console.error('Failed to load initial cybersecurity datasets', err);
    }
  };

  useEffect(() => {
    fetchAllData();
  }, []);

  // Connect to SSE stream for live real-time ingestion
  useEffect(() => {
    const sse = new EventSource('/api/events/stream');

    sse.onopen = () => {
      setIsStreamConnected(true);
    };

    sse.addEventListener('security_event', (event) => {
      if (isStreamPaused) return;
      try {
        const newEvt: SecurityEvent = JSON.parse(event.data);
        setEvents((prev) => [newEvt, ...prev.filter((e) => e.id !== newEvt.id)]);
      } catch (e) {
        console.error('Error parsing SSE event data', e);
      }
    });

    sse.addEventListener('security_alert', (event) => {
      try {
        const newAlert: SecurityAlert = JSON.parse(event.data);
        setAlerts((prev) => {
          const idx = prev.findIndex((a) => a.id === newAlert.id);
          if (idx >= 0) {
            const copy = [...prev];
            copy[idx] = newAlert;
            return copy;
          }
          return [newAlert, ...prev];
        });

        // Trigger Real-Time Toast Notification
        setActiveAlertToast({
          title: `[REAL DETECTION] ${newAlert.attackName}`,
          message: `${newAlert.detectionSource} flagged ${newAlert.requestUri} from ${newAlert.sourceIp} (${newAlert.detectionRule})`,
          severity: newAlert.severity,
        });

        // Update incidents if new incident generated
        fetch('/api/incidents')
          .then((r) => r.json())
          .then((data) => setIncidents(data));
      } catch (e) {
        console.error('Error parsing SSE alert data', e);
      }
    });

    sse.addEventListener('pipeline_reset', () => {
      setEvents([]);
      setAlerts([]);
      setIncidents([]);
      setBlockedIps([]);
      setActiveAlertToast({
        title: 'Pipeline Reset',
        message: 'All security events, alerts, and blocked IPs have been reset to 0.',
        severity: 'low',
      });
    });

    sse.addEventListener('blocked_ip_update', (event) => {
      try {
        const item: BlockedIpRecord = JSON.parse(event.data);
        setBlockedIps((prev) => [item, ...prev.filter((b) => b.ipAddress !== item.ipAddress)]);
      } catch (e) {
        console.error('Error parsing SSE blocked_ip_update', e);
      }
    });

    sse.addEventListener('sensor_update', (event) => {
      try {
        const data = JSON.parse(event.data);
        setSensors(data);
      } catch (e) {
        console.error('Error parsing sensor update', e);
      }
    });

    sse.addEventListener('collector_heartbeat', (event) => {
      try {
        const status: CollectorStatus = JSON.parse(event.data);
        setCollectorStatus(status);
      } catch (e) {
        console.error('Error parsing collector heartbeat', e);
      }
    });

    sse.onerror = () => {
      setIsStreamConnected(false);
    };

    return () => {
      sse.close();
    };
  }, [isStreamPaused]);

  // Host Isolation Handler
  const handleIsolateNode = async (nodeId: string) => {
    try {
      const res = await fetch(`/api/network-topology/node/${nodeId}/isolate`, {
        method: 'PATCH',
      });
      if (res.ok) {
        const updatedNode: NetworkNode = await res.json();
        setNodes((prev) => prev.map((n) => (n.id === updatedNode.id ? updatedNode : n)));
      }
    } catch (err) {
      console.error('Error isolating host node', err);
    }
  };

  // Incident Status Update Handler
  const handleUpdateIncidentStatus = async (
    id: string,
    status: Incident['status'],
    note: string
  ) => {
    try {
      const res = await fetch(`/api/incidents/${id}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, note }),
      });
      if (res.ok) {
        const updated = await res.json();
        setIncidents((prev) => prev.map((i) => (i.id === updated.id ? updated : i)));
      }
    } catch (err) {
      console.error('Error updating incident status', err);
    }
  };

  // Trigger real probe to DVWA
  const handleProbeDvwa = async () => {
    try {
      await fetch('/api/dvwa/probe-health', { method: 'POST' });
      const sensorsRes = await fetch('/api/sensors');
      if (sensorsRes.ok) setSensors(await sensorsRes.json());
    } catch (err) {
      console.error('Error probing DVWA', err);
    }
  };

  // Send authorized test probe through detection engine
  const handleTestProbe = async (type: string) => {
    try {
      const res = await fetch('/api/test/dvwa-probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ testType: type }),
      });
      const data = await res.json();
      if (data.evaluatedEvent) {
        setEvents((prev) => [data.evaluatedEvent, ...prev]);
      }
      if (data.generatedAlert) {
        setAlerts((prev) => [data.generatedAlert, ...prev.filter((a) => a.id !== data.generatedAlert.id)]);
      }
      fetchAllData();
    } catch (err) {
      console.error('Error sending test probe', err);
    }
  };

  // Reset pipeline back to clean zero state
  const handleResetPipeline = async () => {
    try {
      await fetch('/api/pipeline/reset', { method: 'POST' });
      setEvents([]);
      setAlerts([]);
      setIncidents([]);
      fetchAllData();
    } catch (err) {
      console.error('Error resetting pipeline', err);
    }
  };

  const handleTriggerAiAnalysis = (incidentId: string) => {
    setPreselectedIncidentId(incidentId);
    setActiveTab('ai_assistant');
  };

  return (
    <div className="flex h-screen w-screen bg-[#080D17] text-[#E8EEF7] overflow-hidden font-sans select-none">
      {/* Left Vertical Dock Navigation */}
      <LeftNavigation
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        openIncidentsCount={incidents.filter((i) => i.status !== 'closed').length}
        activeAlertsCount={alerts.length}
        blockedIpsCount={blockedIps.filter((b) => b.blockStatus === 'ACTIVE').length}
        isMobileOpen={isMobileNavOpen}
        onCloseMobile={() => setIsMobileNavOpen(false)}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 h-full overflow-hidden">
        {/* Top Header Bar */}
        <TopBar
          selectedTeam={selectedTeam}
          setSelectedTeam={setSelectedTeam}
          selectedRegion={selectedRegion}
          setSelectedRegion={setSelectedRegion}
          selectedTimeRange={selectedTimeRange}
          setSelectedTimeRange={setSelectedTimeRange}
          selectedThreatFilter={selectedThreatFilter}
          setSelectedThreatFilter={setSelectedThreatFilter}
          searchQuery={searchQuery}
          setSearchQuery={setSearchQuery}
          activeUser={activeUser}
          setActiveUser={setActiveUser}
          recentEvents={events}
          isStreamConnected={isStreamConnected}
          theme={theme}
          setTheme={setTheme}
          onToggleMobileNav={() => setIsMobileNavOpen(!isMobileNavOpen)}
        />

        {/* Viewport Content with Scroll */}
        <main className="flex-1 overflow-y-auto p-4 md:p-6 bg-[#080D17] relative">
          {activeTab === 'overview' && (
            <OverviewView
              alerts={alerts}
              events={events}
              incidents={incidents}
              nodes={nodes}
              sensors={sensors}
              blockedIps={blockedIps}
              onIsolateNode={handleIsolateNode}
              onRefresh={fetchAllData}
              onSelectIncident={(inc) => {
                setPreselectedIncidentId(inc.id);
                setActiveTab('alerts');
              }}
              onNavigateToTab={(tab) => setActiveTab(tab)}
              onTriggerAiAnalysis={handleTriggerAiAnalysis}
              onProbeDvwa={handleProbeDvwa}
              onTestProbe={handleTestProbe}
              onResetPipeline={handleResetPipeline}
            />
          )}

          {activeTab === 'monitoring' && (
            <LiveThreatMonitoringView
              events={events}
              isStreamPaused={isStreamPaused}
              setIsStreamPaused={setIsStreamPaused}
              collectorStatus={collectorStatus}
              externalTester={externalTester}
              onInspectEvent={(evt) => console.log('Inspect event', evt)}
            />
          )}

          {activeTab === 'alerts' && (
            <IncidentResponseView
              incidents={incidents}
              auditLogs={auditLogs}
              onUpdateIncidentStatus={handleUpdateIncidentStatus}
              onTriggerAiAnalysis={handleTriggerAiAnalysis}
            />
          )}

          {activeTab === 'threat_intel' && (
            <ThreatIntelligenceView iocs={[]} />
          )}

          {activeTab === 'blocked_ips' && (
            <BlockedIpsView
              blockedIps={blockedIps}
              events={events}
              onRefresh={fetchAllData}
              onNavigateToEvent={(eventId) => {
                setActiveTab('events');
              }}
            />
          )}

          {activeTab === 'web_protection' && (
            <WebApplicationDefenseView
              events={events}
              alerts={alerts}
              collectorStatus={collectorStatus}
              externalTester={externalTester}
            />
          )}

          {activeTab === 'network_security' && (
            <NetworkDefenseView
              events={events}
              alerts={alerts}
            />
          )}

          {activeTab === 'events' && (
            <SecurityEventsView
              events={events}
              alerts={alerts}
              onInspectAlert={(id) => {
                setPreselectedIncidentId(id);
                setActiveTab('alerts');
              }}
            />
          )}

          {activeTab === 'threat_analysis' && (
            <ThreatAnalysisView
              alerts={alerts}
              events={events}
              onNavigateToTab={(tab) => setActiveTab(tab as NavTab)}
            />
          )}

          {activeTab === 'reports' && (
            <SecurityReportsView
              incidents={incidents}
              vulnerabilities={[]}
              auditLogs={auditLogs}
            />
          )}

          {activeTab === 'system_logs' && (
            <SystemLogsView
              auditLogs={auditLogs}
              onRefresh={fetchAllData}
            />
          )}

          {activeTab === 'sensors' && (
            <SensorsEndpointsView
              sensors={sensors}
              collectorStatus={collectorStatus}
              externalTester={externalTester}
              onRefresh={fetchAllData}
              onProbeDvwa={handleProbeDvwa}
            />
          )}

          {activeTab === 'health' && <SystemHealthView />}

          {activeTab === 'ai_assistant' && (
            <AiAnalystView
              incidents={incidents}
              preselectedIncidentId={preselectedIncidentId}
            />
          )}

          {activeTab === 'settings' && (
            <SettingsView
              onResetPipeline={handleResetPipeline}
              onRefreshData={fetchAllData}
              theme={theme}
              setTheme={setTheme}
            />
          )}
        </main>
      </div>

      {/* Real-time Alert Toast Notification Popover */}
      {activeAlertToast && (
        <div className="fixed bottom-5 right-5 max-w-sm bg-[#101827] border border-[#EF5350]/60 rounded-xl p-3.5 shadow-2xl z-50 animate-in slide-in-from-bottom duration-200">
          <div className="flex items-start justify-between gap-2">
            <div className="flex items-start gap-2.5">
              <div className="p-1.5 rounded-lg bg-[#EF5350]/20 text-[#EF5350] shrink-0 mt-0.5">
                <ShieldAlert className="w-4 h-4" />
              </div>
              <div>
                <span className="text-[10px] font-mono text-[#EF5350] font-bold block uppercase">
                  {activeAlertToast.severity} ALERT DETECTED
                </span>
                <h4 className="text-xs font-bold text-[#E8EEF7] leading-snug">{activeAlertToast.title}</h4>
                <p className="text-[11px] text-[#8E9EB5] mt-0.5">{activeAlertToast.message}</p>
              </div>
            </div>
            <button
              onClick={() => setActiveAlertToast(null)}
              className="text-[#64748B] hover:text-[#E8EEF7] p-1 rounded"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
