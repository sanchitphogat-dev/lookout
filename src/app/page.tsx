'use client';

import React from 'react';
import { Shield, ShieldAlert, Cpu, HardDrive } from 'lucide-react';
import { UsbInterceptModal } from '@/components/usb/UsbInterceptModal';
import { useUsbWatcher } from '@/hooks/useUsbWatcher';

export default function Home() {
  const {
    isDaemonConnected,
    detectedDrive,
    isInterceptOpen,
    scanState,
    simulateMockUsb,
    closeIntercept,
    startScan,
    progress,
    scanResult,
    threatsFound,
    quarantineThreats,
    openDriveInExplorer,
  } = useUsbWatcher();

  return (
    <main className="min-h-screen p-8 max-w-6xl mx-auto">
      <header className="flex items-center justify-between pb-6 border-b border-white/10 mb-8">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-[#5E6AD2]/10 border border-[#5E6AD2]/30 text-[#5E6AD2]">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-white tracking-tight">Lookout Dashboard</h1>
            <p className="text-sm text-[#8A8F98]">Unified Cybersecurity Threat Detection Platform</p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium bg-[#141519] border border-white/10">
            <span
              className={`w-2 h-2 rounded-full ${
                isDaemonConnected ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
              }`}
            />
            <span className="text-zinc-300">
              {isDaemonConnected ? 'Daemon Online' : 'Daemon Offline'}
            </span>
          </div>
          <button
            onClick={simulateMockUsb}
            className="px-3.5 py-1.5 rounded-lg text-xs font-medium bg-[#5E6AD2] hover:bg-[#4F46E5] text-white transition-colors"
          >
            ⚡ Simulate USB Insert
          </button>
        </div>
      </header>

      <section className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="p-5 rounded-xl bg-[#141519] border border-white/10">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">USB Sentinel</span>
            <HardDrive className="w-4 h-4 text-[#5E6AD2]" />
          </div>
          <div className="text-2xl font-bold text-white mb-1">
            {detectedDrive ? detectedDrive.driveLetter || 'Active' : 'Listening...'}
          </div>
          <p className="text-xs text-zinc-400">
            {detectedDrive ? detectedDrive.volumeName || 'External device attached' : 'No external drives mounted'}
          </p>
        </div>

        <div className="p-5 rounded-xl bg-[#141519] border border-white/10">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">Active Threats</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold text-white mb-1">
            {threatsFound?.length || 0}
          </div>
          <p className="text-xs text-zinc-400">Threats identified in current session</p>
        </div>

        <div className="p-5 rounded-xl bg-[#141519] border border-white/10">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">Daemon Status</span>
            <Cpu className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold text-white mb-1">
            {isDaemonConnected ? 'Active' : 'Standby'}
          </div>
          <p className="text-xs text-zinc-400">Real-time telemetry & background scanning</p>
        </div>
      </section>

      {/* USB Intercept Modal */}
      <UsbInterceptModal
        isOpen={isInterceptOpen}
        drive={detectedDrive}
        scanState={scanState}
        progress={progress}
        scanProgress={progress}
        scanResult={scanResult}
        threatsFound={threatsFound}
        onClose={closeIntercept}
        onScan={startScan}
        onQuarantine={quarantineThreats}
        openDriveInExplorer={openDriveInExplorer}
      />
    </main>
  );
}
