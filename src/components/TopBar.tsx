/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * NUSANTARA-SMS - Top Bar Navigation with Multi-Theme Switcher & Mobile Menu
 */

import React, { useState } from 'react';
import {
  Search,
  Bell,
  ChevronDown,
  Radio,
  CheckCircle2,
  AlertTriangle,
  User,
  Shield,
  Clock,
  Layers,
  Sun,
  Moon,
  Monitor,
  Menu,
} from 'lucide-react';
import { SecurityEvent } from '../types/cybersecurity.js';

export type ThemeMode = 'dark' | 'light' | 'system';

interface TopBarProps {
  selectedTeam: string;
  setSelectedTeam: (team: string) => void;
  selectedRegion: string;
  setSelectedRegion: (region: string) => void;
  selectedTimeRange: string;
  setSelectedTimeRange: (range: string) => void;
  selectedThreatFilter: string;
  setSelectedThreatFilter: (filter: string) => void;
  searchQuery: string;
  setSearchQuery: (query: string) => void;
  activeUser: string;
  setActiveUser: (user: string) => void;
  recentEvents: SecurityEvent[];
  isStreamConnected: boolean;
  theme: ThemeMode;
  setTheme: (t: ThemeMode) => void;
  onToggleMobileNav?: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({
  selectedTeam,
  setSelectedTeam,
  selectedRegion,
  setSelectedRegion,
  selectedTimeRange,
  setSelectedTimeRange,
  selectedThreatFilter,
  setSelectedThreatFilter,
  searchQuery,
  setSearchQuery,
  activeUser,
  setActiveUser,
  recentEvents,
  isStreamConnected,
  theme,
  setTheme,
  onToggleMobileNav,
}) => {
  const [showNotifications, setShowNotifications] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [showThemeMenu, setShowThemeMenu] = useState(false);

  const criticalRecent = recentEvents.filter((e) => e.severity === 'critical' || e.severity === 'high');

  const themeIcons = {
    dark: <Moon className="w-4 h-4 text-[#36A3FF]" />,
    light: <Sun className="w-4 h-4 text-[#F5B942]" />,
    system: <Monitor className="w-4 h-4 text-[#16C79A]" />,
  };

  return (
    <header className="h-14 bg-[#0B111E] border-b border-[#152033] px-3 sm:px-4 flex items-center justify-between gap-2 sm:gap-3 text-sm z-20 shrink-0">
      {/* Mobile Drawer Button + Left Filter Island */}
      <div className="flex items-center gap-2 overflow-x-auto py-1">
        {onToggleMobileNav && (
          <button
            onClick={onToggleMobileNav}
            className="md:hidden w-8 h-8 rounded-lg bg-[#101827] border border-[#19263E] flex items-center justify-center text-[#8E9EB5] hover:text-[#E8EEF7]"
            title="Navigasi Menu (10 Modul)"
            aria-label="Toggle Navigation"
          >
            <Menu className="w-4 h-4" />
          </button>
        )}

        {/* Team Dropdown */}
        <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1.5 bg-[#101827] border border-[#19263E] rounded-lg text-xs text-[#8E9EB5]">
          <Shield className="w-3.5 h-3.5 text-[#36A3FF]" />
          <span className="text-[#8E9EB5] hidden md:inline">Team:</span>
          <select
            value={selectedTeam}
            onChange={(e) => setSelectedTeam(e.target.value)}
            className="bg-transparent text-[#E8EEF7] font-medium outline-none cursor-pointer text-xs"
          >
            <option value="Global SOC">Global SOC</option>
            <option value="Cyber Command ID">Cyber Command ID</option>
            <option value="Tactical Incident CERT">Tactical Incident CERT</option>
          </select>
        </div>

        {/* Region Dropdown */}
        <div className="hidden lg:flex items-center gap-1.5 px-2.5 py-1.5 bg-[#101827] border border-[#19263E] rounded-lg text-xs text-[#8E9EB5]">
          <span className="text-[#8E9EB5]">Region:</span>
          <select
            value={selectedRegion}
            onChange={(e) => setSelectedRegion(e.target.value)}
            className="bg-transparent text-[#E8EEF7] font-medium outline-none cursor-pointer text-xs"
          >
            <option value="Asia Pacific">Asia Pacific</option>
            <option value="Europe Central">Europe Central</option>
            <option value="US East">US East</option>
          </select>
        </div>

        {/* Time Range */}
        <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1.5 bg-[#101827] border border-[#19263E] rounded-lg text-xs text-[#8E9EB5]">
          <Clock className="w-3.5 h-3.5 text-[#8E9EB5]" />
          <select
            value={selectedTimeRange}
            onChange={(e) => setSelectedTimeRange(e.target.value)}
            className="bg-transparent text-[#E8EEF7] font-medium outline-none cursor-pointer text-xs"
          >
            <option value="Last 24 Hours">Last 24 Hours</option>
            <option value="Last 12 Hours">Last 12 Hours</option>
            <option value="Last 1 Hour">Last 1 Hour</option>
            <option value="Live Stream">Live Stream</option>
          </select>
        </div>

        {/* Threat Framework Filter */}
        <div className="flex items-center gap-1.5 px-2.5 py-1.5 bg-[#101827] border border-[#19263E] rounded-lg text-xs text-[#8E9EB5]">
          <Layers className="w-3.5 h-3.5 text-[#16C79A]" />
          <select
            value={selectedThreatFilter}
            onChange={(e) => setSelectedThreatFilter(e.target.value)}
            className="bg-transparent text-[#E8EEF7] font-medium outline-none cursor-pointer text-xs"
          >
            <option value="MITRE ATT&CK">MITRE ATT&CK</option>
            <option value="OWASP Top 10">OWASP Top 10</option>
            <option value="Critical CVEs">Critical CVEs</option>
          </select>
        </div>
      </div>

      {/* Right Controls - Search, Theme Switcher, Notifications, Profile */}
      <div className="flex items-center gap-2 sm:gap-3 shrink-0">
        {/* Search Bar */}
        <div className="relative hidden md:block w-48 lg:w-64">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-[#64748B]" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search IP, CVE, Technique..."
            className="w-full bg-[#101827] border border-[#19263E] rounded-lg pl-8 pr-3 py-1.5 text-xs text-[#E8EEF7] placeholder-[#64748B] focus:outline-none focus:border-[#16C79A] transition-colors"
          />
        </div>

        {/* Real-time SSE Connection Indicator */}
        <div
          title={isStreamConnected ? 'Live Sensor Ingestion Active' : 'Connecting to Sensor Stream...'}
          className="hidden xl:flex items-center gap-1.5 px-2 py-1 bg-[#101827] border border-[#19263E] rounded-lg text-xs font-mono"
        >
          <span
            className={`w-2 h-2 rounded-full ${
              isStreamConnected ? 'bg-[#16C79A]' : 'bg-[#F5B942]'
            }`}
          ></span>
          <span className="text-[10px] text-[#8E9EB5]">{isStreamConnected ? 'LIVE FEED' : 'CONNECTING'}</span>
        </div>

        {/* Theme Switcher Popover */}
        <div className="relative">
          <button
            onClick={() => setShowThemeMenu(!showThemeMenu)}
            className="w-8 h-8 sm:w-9 sm:h-9 rounded-lg bg-[#101827] border border-[#19263E] flex items-center justify-center hover:border-[#16C79A]/40 transition-colors"
            title={`Mode Tampilan: ${theme.toUpperCase()}`}
            aria-label="Theme Switcher"
          >
            {themeIcons[theme]}
          </button>

          {showThemeMenu && (
            <div className="absolute right-0 mt-2 w-44 bg-[#101827] border border-[#1F2E4A] rounded-xl shadow-2xl p-1.5 z-50">
              <div className="px-2 py-1 text-[10px] text-[#64748B] font-semibold uppercase tracking-wider">
                Tema Antarmuka
              </div>
              <button
                onClick={() => {
                  setTheme('dark');
                  setShowThemeMenu(false);
                }}
                className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs transition-colors ${
                  theme === 'dark' ? 'bg-[#152338] text-[#36A3FF] font-semibold' : 'text-[#8E9EB5] hover:bg-[#151F30]'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Moon className="w-3.5 h-3.5 text-[#36A3FF]" />
                  <span>Dark Mode</span>
                </div>
                {theme === 'dark' && <CheckCircle2 className="w-3.5 h-3.5 text-[#36A3FF]" />}
              </button>

              <button
                onClick={() => {
                  setTheme('light');
                  setShowThemeMenu(false);
                }}
                className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs transition-colors ${
                  theme === 'light' ? 'bg-[#152338] text-[#078A69] font-semibold' : 'text-[#8E9EB5] hover:bg-[#151F30]'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Sun className="w-3.5 h-3.5 text-[#F5B942]" />
                  <span>Light Mode</span>
                </div>
                {theme === 'light' && <CheckCircle2 className="w-3.5 h-3.5 text-[#078A69]" />}
              </button>

              <button
                onClick={() => {
                  setTheme('system');
                  setShowThemeMenu(false);
                }}
                className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg text-xs transition-colors ${
                  theme === 'system' ? 'bg-[#152338] text-[#16C79A] font-semibold' : 'text-[#8E9EB5] hover:bg-[#151F30]'
                }`}
              >
                <div className="flex items-center gap-2">
                  <Monitor className="w-3.5 h-3.5 text-[#16C79A]" />
                  <span>System Default</span>
                </div>
                {theme === 'system' && <CheckCircle2 className="w-3.5 h-3.5 text-[#16C79A]" />}
              </button>
            </div>
          )}
        </div>

        {/* Notification Bell */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="w-8 h-8 sm:w-9 sm:h-9 rounded-lg bg-[#101827] border border-[#19263E] flex items-center justify-center text-[#8E9EB5] hover:text-[#E8EEF7] transition-colors relative"
            title="Active Security Notifications"
          >
            <Bell className="w-4 h-4" />
            {criticalRecent.length > 0 && (
              <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-[#EF5350]"></span>
            )}
          </button>

          {/* Notifications Dropdown Popover */}
          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 bg-[#101827] border border-[#1F2E4A] rounded-xl shadow-2xl p-3 z-50">
              <div className="flex items-center justify-between pb-2 border-b border-[#1A263D] mb-2">
                <span className="text-xs font-semibold text-[#E8EEF7]">Recent Threat Alerts</span>
                <span className="text-[10px] text-[#16C79A] font-mono">{criticalRecent.length} Critical/High</span>
              </div>
              <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                {criticalRecent.length === 0 ? (
                  <div className="text-center py-4 text-xs text-[#8E9EB5]">
                    Tidak ada notifikasi ancaman aktif.
                  </div>
                ) : (
                  criticalRecent.slice(0, 5).map((evt) => (
                    <div
                      key={evt.id}
                      className="p-2 bg-[#080D17] border border-[#152033] rounded-lg text-xs"
                    >
                      <div className="flex items-center justify-between gap-1 mb-1">
                        <span className="font-semibold text-[#EF5350] truncate">{evt.title}</span>
                        <span className="text-[10px] text-[#64748B] font-mono">{evt.timestamp.slice(11, 16)}</span>
                      </div>
                      <div className="text-[11px] text-[#8E9EB5] flex items-center justify-between">
                        <span>{evt.affectedAsset}</span>
                        <span className="font-mono text-[#36A3FF]">{evt.mitreTechniqueId}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* User Profile Avatar & Menu */}
        <div className="relative">
          <button
            onClick={() => setShowUserMenu(!showUserMenu)}
            className="flex items-center gap-1.5 sm:gap-2 p-1 pl-1.5 sm:pl-2 bg-[#101827] border border-[#19263E] rounded-lg hover:border-[#16C79A]/50 transition-colors"
          >
            <div className="w-6 h-6 sm:w-7 sm:h-7 rounded-md bg-[#152338] border border-[#16C79A]/40 flex items-center justify-center text-[11px] sm:text-xs font-bold text-[#16C79A]">
              {activeUser.split(' ')[0][0]}{activeUser.split(' ')[1]?.[0] || 'S'}
            </div>
            <div className="hidden sm:block text-left pr-1">
              <div className="text-xs font-semibold text-[#E8EEF7] truncate max-w-[100px]">{activeUser.split(' ')[0]}</div>
              <div className="text-[9px] text-[#16C79A] font-medium leading-tight">Tier 3 Analyst</div>
            </div>
            <ChevronDown className="w-3.5 h-3.5 text-[#64748B]" />
          </button>

          {showUserMenu && (
            <div className="absolute right-0 mt-2 w-56 bg-[#101827] border border-[#1F2E4A] rounded-xl shadow-2xl p-2 z-50">
              <div className="px-2 py-1 text-[10px] text-[#64748B] font-semibold uppercase tracking-wider">
                Ganti Peran Operator SOC
              </div>
              {[
                { name: 'Sarah Chen', role: 'Lead SOC Analyst L3' },
                { name: 'Alex Morgan', role: 'SecOps Engineer L2' },
                { name: 'David Lee', role: 'Threat Hunter & Intel L3' },
              ].map((u) => (
                <button
                  key={u.name}
                  onClick={() => {
                    setActiveUser(`${u.name} (${u.role.split(' ')[0]})`);
                    setShowUserMenu(false);
                  }}
                  className={`w-full text-left px-2.5 py-2 rounded-lg text-xs transition-colors flex items-center justify-between ${
                    activeUser.startsWith(u.name) ? 'bg-[#152338] text-[#16C79A]' : 'text-[#8E9EB5] hover:bg-[#152033] hover:text-[#E8EEF7]'
                  }`}
                >
                  <div>
                    <div className="font-medium text-[#E8EEF7]">{u.name}</div>
                    <div className="text-[10px] text-[#64748B]">{u.role}</div>
                  </div>
                  {activeUser.startsWith(u.name) && <CheckCircle2 className="w-4 h-4 text-[#16C79A]" />}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
