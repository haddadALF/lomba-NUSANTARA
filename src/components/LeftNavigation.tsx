/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Left Navigation Dock & Collapsible Sidebar
 * 5 Categories Architecture (Kartika Cyber Hackathon 2026)
 */

import React, { useState } from 'react';
import {
  LayoutDashboard,
  Radio,
  Bell,
  Flame,
  ShieldX,
  GlobeLock,
  Network,
  Layers,
  Crosshair,
  BarChart3,
  ScrollText,
  Server,
  HeartPulse,
  Bot,
  Sliders,
  ChevronLeft,
  ChevronRight,
  X,
  Shield,
  CircleDot,
} from 'lucide-react';

export type NavTab =
  | 'overview'           // OVERVIEW: Dashboard
  | 'monitoring'         // PROTECTION: Live Monitoring
  | 'alerts'             // PROTECTION: Security Alerts
  | 'threat_intel'       // PROTECTION: Threat Intelligence
  | 'blocked_ips'        // PROTECTION: Blocked IPs
  | 'web_protection'     // PROTECTION: Web Protection
  | 'network_security'   // PROTECTION: Network Security
  | 'events'             // INVESTIGATION: Security Events
  | 'threat_analysis'    // INVESTIGATION: Threat Analysis
  | 'reports'            // INVESTIGATION: Analytics & Reports
  | 'system_logs'        // INVESTIGATION: System Logs
  | 'sensors'            // INFRASTRUCTURE: Sensors & Endpoints
  | 'health'             // INFRASTRUCTURE: System Health
  | 'ai_assistant'       // MANAGEMENT: AI Security Assistant
  | 'settings';          // MANAGEMENT: Settings

export interface NavCategory {
  title: string;
  items: {
    id: NavTab;
    label: string;
    description: string;
    icon: React.ComponentType<{ className?: string }>;
    badge?: number;
    badgeColor?: string;
  }[];
}

interface LeftNavigationProps {
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  openIncidentsCount: number;
  activeAlertsCount?: number;
  blockedIpsCount?: number;
  isMobileOpen?: boolean;
  onCloseMobile?: () => void;
}

export const LeftNavigation: React.FC<LeftNavigationProps> = ({
  activeTab,
  setActiveTab,
  openIncidentsCount,
  activeAlertsCount = 0,
  blockedIpsCount = 0,
  isMobileOpen = false,
  onCloseMobile,
}) => {
  const [isCollapsed, setIsCollapsed] = useState<boolean>(() => {
    return localStorage.getItem('nusantara_nav_collapsed') === 'true';
  });

  const toggleCollapsed = () => {
    setIsCollapsed((prev) => {
      const next = !prev;
      localStorage.setItem('nusantara_nav_collapsed', String(next));
      return next;
    });
  };

  const navCategories: NavCategory[] = [
    {
      title: 'OVERVIEW',
      items: [
        {
          id: 'overview',
          label: 'Dashboard',
          description: 'Ringkasan kondisi keamanan sistem.',
          icon: LayoutDashboard,
        },
      ],
    },
    {
      title: 'PROTECTION',
      items: [
        {
          id: 'monitoring',
          label: 'Live Monitoring',
          description: 'Memantau aktivitas keamanan secara langsung.',
          icon: Radio,
        },
        {
          id: 'alerts',
          label: 'Security Alerts',
          description: 'Daftar peringatan keamanan yang terdeteksi.',
          icon: Bell,
          badge: activeAlertsCount > 0 ? activeAlertsCount : undefined,
          badgeColor: 'bg-[#EF5350]',
        },
        {
          id: 'threat_intel',
          label: 'Threat Intelligence',
          description: 'Informasi dan analisis ancaman.',
          icon: Flame,
        },
        {
          id: 'blocked_ips',
          label: 'Blocked IPs',
          description: 'Daftar alamat IP yang benar-benar berhasil diblokir.',
          icon: ShieldX,
          badge: blockedIpsCount > 0 ? blockedIpsCount : undefined,
          badgeColor: 'bg-[#EF5350]',
        },
        {
          id: 'web_protection',
          label: 'Web Protection',
          description: 'Monitoring perlindungan aplikasi web.',
          icon: GlobeLock,
        },
        {
          id: 'network_security',
          label: 'Network Security',
          description: 'Monitoring aktivitas dan keamanan jaringan.',
          icon: Network,
        },
      ],
    },
    {
      title: 'INVESTIGATION',
      items: [
        {
          id: 'events',
          label: 'Security Events',
          description: 'Riwayat aktivitas yang diterima dari sensor.',
          icon: Layers,
        },
        {
          id: 'threat_analysis',
          label: 'Threat Analysis',
          description: 'Detail analisis ancaman.',
          icon: Crosshair,
        },
        {
          id: 'reports',
          label: 'Analytics & Reports',
          description: 'Statistik dan laporan berdasarkan data asli.',
          icon: BarChart3,
        },
        {
          id: 'system_logs',
          label: 'System Logs',
          description: 'Log aplikasi dan komponen keamanan.',
          icon: ScrollText,
        },
      ],
    },
    {
      title: 'INFRASTRUCTURE',
      items: [
        {
          id: 'sensors',
          label: 'Sensors & Endpoints',
          description: 'Status sensor dan perangkat yang dipantau.',
          icon: Server,
        },
        {
          id: 'health',
          label: 'System Health',
          description: 'Kesehatan komponen NUSANTARA-SMS.',
          icon: HeartPulse,
        },
      ],
    },
    {
      title: 'MANAGEMENT',
      items: [
        {
          id: 'ai_assistant',
          label: 'AI Security Assistant',
          description: 'Membantu menjelaskan event dan rekomendasi pertahanan.',
          icon: Bot,
        },
        {
          id: 'settings',
          label: 'Settings',
          description: 'Pengaturan sistem dan kebijakan keamanan.',
          icon: Sliders,
        },
      ],
    },
  ];

  const handleSelectTab = (tabId: NavTab) => {
    setActiveTab(tabId);
    if (onCloseMobile) onCloseMobile();
  };

  return (
    <>
      {/* Mobile Drawer Backdrop */}
      {isMobileOpen && (
        <div
          onClick={onCloseMobile}
          className="fixed inset-0 bg-black/70 backdrop-blur-sm z-40 md:hidden animate-in fade-in"
        />
      )}

      {/* Main Sidebar */}
      <aside
        className={`fixed md:static inset-y-0 left-0 bg-[#0B111E] border-r border-[#152033] flex flex-col shrink-0 z-50 select-none transition-all duration-200 ${
          isMobileOpen
            ? 'translate-x-0 w-72'
            : `-translate-x-full md:translate-x-0 ${isCollapsed ? 'md:w-18' : 'md:w-68'}`
        }`}
      >
        {/* Brand Header */}
        <div className="h-16 border-b border-[#152033] px-3.5 flex items-center justify-between">
          <div
            onClick={() => handleSelectTab('overview')}
            className="cursor-pointer group flex items-center gap-2.5 overflow-hidden"
            title="NUSANTARA-SMS — National Cyber Defense Platform"
          >
            <div className="w-9 h-9 rounded-xl bg-[#101827] border border-[#16C79A]/40 flex items-center justify-center shrink-0 group-hover:border-[#16C79A] transition-colors shadow-lg shadow-[#16C79A]/10">
              <Shield className="w-5 h-5 text-[#16C79A]" />
            </div>
            {(!isCollapsed || isMobileOpen) && (
              <div className="min-w-0 flex-1 animate-in fade-in duration-150">
                <div className="flex items-center gap-1.5">
                  <span className="text-xs font-mono font-bold text-[#16C79A] tracking-wider truncate">
                    NUSANTARA-SMS
                  </span>
                  <span className="w-1.5 h-1.5 rounded-full bg-[#16C79A] animate-pulse"></span>
                </div>
                <span className="text-[10px] text-[#8E9EB5] block truncate">
                  Detect • Prevent • Analyze • Respond
                </span>
              </div>
            )}
          </div>

          {/* Close Button on Mobile, Collapse Toggle on Desktop */}
          {isMobileOpen ? (
            <button
              onClick={onCloseMobile}
              className="p-1.5 rounded-lg bg-[#152338] text-[#8E9EB5] hover:text-[#E8EEF7]"
              aria-label="Tutup Menu"
            >
              <X className="w-5 h-5" />
            </button>
          ) : (
            <button
              onClick={toggleCollapsed}
              className="hidden md:flex p-1 rounded-md text-[#64748B] hover:text-[#E8EEF7] hover:bg-[#152338] transition-colors"
              title={isCollapsed ? 'Perluas Sidebar' : 'Ciutkan Sidebar'}
            >
              {isCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
            </button>
          )}
        </div>

        {/* Navigation Categories and Items */}
        <nav className="flex-1 w-full overflow-y-auto px-2 py-3 space-y-4 scrollbar-thin scrollbar-thumb-[#152033]">
          {navCategories.map((category) => (
            <div key={category.title} className="space-y-1">
              {/* Category Header (Shown when expanded or on mobile) */}
              {(!isCollapsed || isMobileOpen) ? (
                <div className="px-2.5 py-1 text-[10px] font-mono font-bold text-[#64748B] tracking-wider uppercase">
                  {category.title}
                </div>
              ) : (
                <div className="my-1 border-t border-[#152033]" />
              )}

              {/* Items in category */}
              <div className="space-y-0.5">
                {category.items.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeTab === item.id;

                  return (
                    <div key={item.id} className="relative group">
                      <button
                        onClick={() => handleSelectTab(item.id)}
                        className={`w-full rounded-xl flex items-center transition-all duration-150 ${
                          isCollapsed && !isMobileOpen
                            ? 'h-11 justify-center px-0'
                            : 'px-2.5 py-2 justify-start gap-2.5'
                        } ${
                          isActive
                            ? 'bg-[#152338] text-[#16C79A] border border-[#16C79A]/40 shadow-sm font-semibold'
                            : 'text-[#8E9EB5] hover:text-[#E8EEF7] hover:bg-[#101827] border border-transparent'
                        }`}
                        aria-label={item.label}
                      >
                        <Icon
                          className={`w-4.5 h-4.5 shrink-0 ${
                            isActive ? 'text-[#16C79A] stroke-[2.2]' : 'text-[#8E9EB5] group-hover:text-[#E8EEF7]'
                          }`}
                        />

                        {/* Label and Indonesian Description (Expanded view) */}
                        {(!isCollapsed || isMobileOpen) && (
                          <div className="text-left min-w-0 flex-1">
                            <div className="flex items-center justify-between gap-1.5">
                              <span className="text-xs font-semibold leading-tight truncate">
                                {item.label}
                              </span>
                              {item.badge !== undefined && (
                                <span
                                  className={`px-1.5 py-0.2 rounded-full ${
                                    item.badgeColor || 'bg-[#EF5350]'
                                  } text-white text-[9px] font-mono font-bold shrink-0`}
                                >
                                  {item.badge}
                                </span>
                              )}
                            </div>
                            <span className="text-[10px] text-[#64748B] block truncate leading-tight mt-0.5">
                              {item.description}
                            </span>
                          </div>
                        )}

                        {/* Collapsed Badge Pill */}
                        {isCollapsed && !isMobileOpen && item.badge !== undefined && (
                          <span
                            className={`absolute -top-1 -right-1 px-1.5 py-0.2 min-w-4 h-4 rounded-full ${
                              item.badgeColor || 'bg-[#EF5350]'
                            } text-white text-[9px] font-mono font-bold flex items-center justify-center border border-[#0B111E]`}
                          >
                            {item.badge}
                          </span>
                        )}
                      </button>

                      {/* Tooltip on Collapsed Desktop View */}
                      {isCollapsed && !isMobileOpen && (
                        <div className="hidden md:block absolute left-full top-1/2 -translate-y-1/2 ml-2.5 px-3 py-2 rounded-lg bg-[#101827] border border-[#1E2D4A] text-[#E8EEF7] opacity-0 pointer-events-none group-hover:opacity-100 transition-opacity z-50 whitespace-nowrap shadow-2xl">
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] font-mono text-[#16C79A] uppercase">
                              {category.title}
                            </span>
                            {item.badge !== undefined && (
                              <span className="px-1.5 py-0.2 rounded bg-[#EF5350] text-white text-[9px] font-mono font-bold">
                                {item.badge}
                              </span>
                            )}
                          </div>
                          <div className="text-xs font-bold text-[#E8EEF7] mt-0.5">{item.label}</div>
                          <div className="text-[11px] text-[#8E9EB5] mt-0.5 max-w-[220px]">
                            {item.description}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Footer: System Status Indicator */}
        <div className="border-t border-[#152033] p-3 shrink-0">
          {(!isCollapsed || isMobileOpen) ? (
            <div className="flex items-center justify-between bg-[#080D17] border border-[#16233B] rounded-lg p-2">
              <div className="flex items-center gap-2 min-w-0">
                <CircleDot className="w-3.5 h-3.5 text-[#16C79A] animate-pulse shrink-0" />
                <div className="min-w-0">
                  <span className="text-[10px] font-mono text-[#E8EEF7] font-semibold block truncate">
                    DEFENSE ENGINE
                  </span>
                  <span className="text-[9px] text-[#16C79A] block truncate">
                    REAL TELEMETRY MODE
                  </span>
                </div>
              </div>
              <span className="text-[9px] font-mono text-[#64748B]">v2.0</span>
            </div>
          ) : (
            <div className="flex justify-center" title="Defense Engine: Real Telemetry Mode">
              <CircleDot className="w-4 h-4 text-[#16C79A] animate-pulse" />
            </div>
          )}
        </div>
      </aside>
    </>
  );
};
