'use client';

import React, { useState } from 'react';
import { 
  Shield, 
  Globe, 
  FileSearch, 
  HardDrive, 
  Radio, 
  Sparkles, 
  AlertTriangle 
} from 'lucide-react';
import { UsbInterceptModal } from '@/components/usb/UsbInterceptModal';
import { useUsbWatcher } from '@/hooks/useUsbWatcher';
import { UrlScanner } from '@/components/scanners/UrlScanner';
import { FileScanner } from '@/components/scanners/FileScanner';

export default function DashboardPage() {
  const [activeTab, setActiveTab] = useState<'url' | 'file' | 'usb'>('url');
  const { isConnected, simulateUsbInsert } = useUsbWatcher();

  return (
    <main className="min-h-screen bg-[#090A0F] text-zinc-100 flex flex-col font-sans selection:bg-indigo-500/30 selection:text-white">
      
      {/* Top Navigation Bar */}
      <header className="border-b border-white/[0.06] bg-[#0D0E14]/80 backdrop-blur-xl sticky top-0 z-40">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          
          {/* Brand Identity */}
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-xl bg-indigo-600/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 shadow-inner">
              <Shield className="h-5 w-5"/>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-semibold tracking-tight text-white">Lookout</h1>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                  v2.4
                </span>
              </div>
              <p className="text-[11px] text-zinc-400">Zero-Trust Unified Threat Intelligence</p>
            </div>
          </div>

          {/* Sentinel Status & Simulation Trigger */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/[0.03] border border-white/[0.08] text-xs">
              <span className="relative flex h-2 w-2">
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${isConnected ? 'bg-emerald-400' : 'bg-amber-400'}`} />
                <span className={`relative inline-flex rounded-full h-2 w-2 ${isConnected ? 'bg-emerald-500' : 'bg-amber-500'}`} />
              </span>
              <span className="text-zinc-300 font-mono text-[11px]">
                {isConnected ? 'Daemon Online' : 'Hardware Sentinel: Standby'}
              </span>
            </div>

            <button
              onClick={() => simulateUsbInsert()}
              className="flex items-center gap-1.5 text-xs font-medium text-white bg-indigo-600 hover:bg-indigo-500 px-3.5 py-1.5 rounded-lg shadow-sm transition-all active:scale-95"
            >
              <Sparkles className="h-3.5 w-3.5"/>
              Simulate USB Insert
            </button>
          </div>

        </div>
      </header>

      {/* Main Workspace */}
      <div className="max-w-5xl mx-auto w-full px-6 py-8 flex-1 flex flex-col">
        
        {/* Navigation Tabs */}
        <div className="flex items-center justify-center mb-8">
          <div className="flex items-center gap-1 bg-[#12131A] border border-white/[0.08] p-1 rounded-xl shadow-lg">
            <button
              onClick={() => setActiveTab('url')}
              className={`flex items-center gap-2 px-5 py-2 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'url'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.04]'
              }`}
            >
              <Globe className="h-3.5 w-3.5"/>
              URL Scanner
            </button>

            <button
              onClick={() => setActiveTab('file')}
              className={`flex items-center gap-2 px-5 py-2 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'file'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.04]'
              }`}
            >
              <FileSearch className="h-3.5 w-3.5"/>
              File Scanner
            </button>

            <button
              onClick={() => setActiveTab('usb')}
              className={`flex items-center gap-2 px-5 py-2 rounded-lg text-xs font-medium transition-all ${
                activeTab === 'usb'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.04]'
              }`}
            >
              <HardDrive className="h-3.5 w-3.5"/>
              USB Sentinel
            </button>
          </div>
        </div>

        {/* Tab 1: URL Scanner View */}
        {activeTab === 'url' && (
          <div className="animate-in fade-in duration-200">
            <UrlScanner/>
          </div>
        )}

        {/* Tab 2: File Scanner View */}
        {activeTab === 'file' && (
          <div className="animate-in fade-in duration-200">
            <FileScanner/>
          </div>
        )}

        {/* Tab 3: USB Sentinel View */}
        {activeTab === 'usb' && (
          <div className="animate-in fade-in duration-200 space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              
              <div className="p-4 rounded-xl bg-[#12131A] border border-white/[0.06]">
                <div className="flex items-center justify-between text-xs text-zinc-400 mb-2">
                  <span>USB SENTINEL</span>
                  <HardDrive className="h-4 w-4 text-indigo-400"/>
                </div>
                <div className="text-xl font-semibold text-white tracking-tight">Listening...</div>
                <p className="text-xs text-zinc-400 mt-1">CIM/WMI device arrival interrupt active</p>
              </div>

              <div className="p-4 rounded-xl bg-[#12131A] border border-white/[0.06]">
                <div className="flex items-center justify-between text-xs text-zinc-400 mb-2">
                  <span>ACTIVE THREATS</span>
                  <AlertTriangle className="h-4 w-4 text-amber-400"/>
                </div>
                <div className="text-xl font-semibold text-white tracking-tight">0 Detected</div>
                <p className="text-xs text-zinc-400 mt-1">All mounted volumes quarantined/clean</p>
              </div>

              <div className="p-4 rounded-xl bg-[#12131A] border border-white/[0.06]">
                <div className="flex items-center justify-between text-xs text-zinc-400 mb-2">
                  <span>IPC STATUS</span>
                  <Radio className="h-4 w-4 text-emerald-400"/>
                </div>
                <div className="text-xl font-semibold text-white tracking-tight">Port 48201</div>
                <p className="text-xs text-zinc-400 mt-1">Bidirectional WebSocket link standby</p>
              </div>

            </div>

            <div className="p-6 rounded-2xl bg-white/[0.02] border border-white/[0.06] text-center">
              <h3 className="text-sm font-semibold text-white">Live Hardware Emulation Mode</h3>
              <p className="text-xs text-zinc-400 mt-1 max-w-md mx-auto">
                Cloud deployments cannot physically touch local USB ports due to W3C sandboxing. Click below to simulate instant hardware insertion, live traversal, and quarantine mechanics.
              </p>
              <button
                onClick={() => simulateUsbInsert()}
                className="mt-4 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium transition-all"
              >
                Trigger USB Hardware Intercept
              </button>
            </div>
          </div>
        )}

      </div>

      {/* Global USB Interception Modal */}
      <UsbInterceptModal/>

    </main>
  );
}
