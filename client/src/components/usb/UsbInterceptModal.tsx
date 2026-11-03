'use client';

import React from 'react';
import { HardDrive, X, ShieldAlert, CheckCircle2, Loader2, ShieldCheck, Trash2 } from 'lucide-react';
import { useUsbWatcher } from '@/hooks/useUsbWatcher';

export interface UsbInterceptModalProps {
  isOpen?: boolean;
  drive?: any;
  scanState?: string;
  progress?: any;
  scanProgress?: any;
  scanResult?: any;
  threatsFound?: any[];
  threats?: any[];
  onClose?: () => void;
  onScan?: () => void;
  onQuarantine?: () => void;
  openDriveInExplorer?: () => void;
}

export function UsbInterceptModal({
  isOpen: propIsOpen,
  drive: propDrive,
  scanState: propScanState,
  progress: propProgress,
  scanProgress: propScanProgress,
  scanResult: propScanResult,
  threatsFound: propThreatsFound,
  threats: propThreats,
  onClose,
  onScan,
  onQuarantine,
  openDriveInExplorer: propOpenDriveInExplorer,
}: UsbInterceptModalProps = {}) {
  const watcher = useUsbWatcher();

  const isInterceptOpen = propIsOpen !== undefined ? propIsOpen : watcher.isInterceptOpen;
  const detectedDrive = propDrive !== undefined ? propDrive : watcher.detectedDrive;
  const scanState = propScanState !== undefined ? propScanState : watcher.scanState;
  const scanProgress = propScanProgress !== undefined 
    ? propScanProgress 
    : (propProgress !== undefined ? propProgress : ((watcher as any).scanProgress || watcher.progress));
  const scanResult = propScanResult !== undefined ? propScanResult : watcher.scanResult;
  const threatsFound = propThreatsFound !== undefined 
    ? propThreatsFound 
    : (propThreats !== undefined ? propThreats : (watcher.threatsFound?.length ? watcher.threatsFound : (scanResult?.threats || [])));

  const startUsbScan = onScan || watcher.startUsbScan || watcher.startScan;
  const quarantineThreats = onQuarantine || watcher.quarantineThreats;

  const handleClose = () => {
    if (onClose) {
      onClose();
    }
    if (watcher.setIsInterceptOpen) {
      watcher.setIsInterceptOpen(false);
    } else if (watcher.closeIntercept) {
      watcher.closeIntercept();
    }
  };

  const setIsInterceptOpen = (open: boolean) => {
    if (!open) {
      handleClose();
    } else if (watcher.setIsInterceptOpen) {
      watcher.setIsInterceptOpen(true);
    }
  };

  const openDriveInExplorer = () => {
    if (propOpenDriveInExplorer) {
      propOpenDriveInExplorer();
    } else if (watcher.openDriveInExplorer) {
      watcher.openDriveInExplorer();
    } else {
      setIsInterceptOpen(false);
    }
  };

  if (!isInterceptOpen || !detectedDrive) return null;

  const totalFiles = scanProgress?.totalFiles || scanProgress?.totalDiscovered;
  const progressPercent = totalFiles && totalFiles > 0
    ? Math.min(100, Math.round(((scanProgress?.scannedFiles || 0) / totalFiles) * 100))
    : 65;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-md animate-in fade-in duration-150">
      <div className="relative w-full max-w-sm rounded-2xl bg-[#0D0E12] border border-white/[0.08] p-5 shadow-2xl overflow-hidden">
        
        {/* Close Button (Hidden during active scan) */}
        {scanState !== 'scanning' && (
          <button
            onClick={() => setIsInterceptOpen(false)}
            className="absolute top-4 right-4 text-zinc-500 hover:text-zinc-300 transition-colors"
            aria-label="Close"
          >
            <X className="h-4 w-4"/>
          </button>
        )}

        {/* ---------------- STATE 1: IDLE / PROMPT ---------------- */}
        {scanState === 'idle' && (
          <div>
            <div className="flex items-center gap-3 mb-3">
              <div className="h-9 w-9 rounded-xl bg-white/[0.04] border border-white/[0.08] flex items-center justify-center text-zinc-300">
                <HardDrive className="h-4 w-4"/>
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white tracking-tight">
                  USB Drive Connected
                </h3>
                <p className="text-xs text-zinc-400">
                  Scan files before opening to verify drive integrity.
                </p>
              </div>
            </div>

            <div className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-3 my-4">
              <div className="flex items-center justify-between text-xs mb-2">
                <div className="flex items-center gap-1.5">
                  <span className="font-medium text-zinc-200">
                    {detectedDrive.volumeName || 'USB Drive'}
                  </span>
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-white/[0.06] text-zinc-400">
                    {detectedDrive.driveLetter}
                  </span>
                </div>
                <span className="text-zinc-400 text-[11px] tabular-nums">
                  {detectedDrive.freeGb || detectedDrive.freeSpace || '0 GB'} free of {detectedDrive.totalGb || detectedDrive.size || '0 GB'}
                </span>
              </div>
              <div className="h-1.5 w-full bg-white/[0.06] rounded-full overflow-hidden">
                <div
                  className="h-full bg-indigo-500 rounded-full transition-all duration-300"
                  style={{ width: `${detectedDrive.usedPercentage || 40}%` }}
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-1">
              <button
                onClick={() => setIsInterceptOpen(false)}
                className="text-xs font-medium text-zinc-400 hover:text-zinc-200 px-3 py-1.5 rounded-lg hover:bg-white/[0.04] transition-colors"
              >
                Ignore
              </button>
              <button
                onClick={() => startUsbScan()}
                className="text-xs font-medium text-white bg-indigo-600 hover:bg-indigo-500 px-3.5 py-1.5 rounded-lg shadow-sm transition-all"
              >
                Scan Drive ➔
              </button>
            </div>
          </div>
        )}

        {/* ---------------- STATE 2: ACTIVE SCANNING ---------------- */}
        {scanState === 'scanning' && (
          <div className="py-2 text-center">
            <div className="relative mx-auto mb-3 h-10 w-10 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400">
              <span className="absolute inset-0 rounded-xl bg-indigo-500/20 animate-ping opacity-75" />
              <Loader2 className="relative h-5 w-5 animate-spin"/>
            </div>
            <h3 className="text-sm font-semibold text-white tracking-tight">
              Scanning Volume {detectedDrive.driveLetter}
            </h3>
            <p className="text-xs text-zinc-400 mt-1 tabular-nums">
              Inspecting files... {scanProgress?.scannedFiles || 0} checked
            </p>

            {/* Dynamic Progress Bar */}
            <div className="my-4 h-1.5 w-full bg-white/[0.06] rounded-full overflow-hidden">
              <div
                className="h-full bg-indigo-500 rounded-full transition-all duration-150"
                style={{
                  width: `${progressPercent}%`
                }}
              />
            </div>

            {/* Truncated File Stream Preview */}
            <div className="rounded-lg bg-black/40 border border-white/[0.04] px-3 py-2 text-[11px] font-mono text-zinc-500 truncate text-left">
              {scanProgress?.currentFile || 'Traversing directory structure...'}
            </div>
          </div>
        )}

        {/* ---------------- STATE 3: CLEAN CLEARANCE ---------------- */}
        {scanState === 'clean' && (
          <div className="text-center py-1">
            <div className="mx-auto mb-3 h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
              <ShieldCheck className="h-5 w-5"/>
            </div>
            <h3 className="text-sm font-semibold text-white tracking-tight">
              Drive Cleared & Safe
            </h3>
            <p className="text-xs text-zinc-400 mt-1">
              Zero malicious droppers, execution hooks, or spoofed payloads detected.
            </p>

            <div className="bg-white/[0.02] border border-white/[0.06] rounded-xl p-3 my-4 text-xs flex justify-around text-zinc-300">
              <div>
                <span className="text-[10px] uppercase text-zinc-500 block">Files Checked</span>
                <span className="font-semibold tabular-nums">
                  {scanResult?.scannedFiles || scanProgress?.scannedFiles || 0}
                </span>
              </div>
              <div className="border-r border-white/[0.06]" />
              <div>
                <span className="text-[10px] uppercase text-zinc-500 block">Integrity</span>
                <span className="font-semibold text-emerald-400">100% Clean</span>
              </div>
            </div>

            {/* Dual Functional Actions */}
            <div className="flex items-center gap-2 pt-1">
              <button
                onClick={() => setIsInterceptOpen(false)}
                className="w-1/3 text-xs font-medium text-zinc-400 hover:text-zinc-200 py-2 rounded-lg hover:bg-white/[0.04] transition-colors"
              >
                Dismiss
              </button>
              <button
                onClick={() => openDriveInExplorer()}
                className="w-2/3 text-xs font-medium text-white bg-emerald-600 hover:bg-emerald-500 py-2 rounded-lg shadow-sm transition-all flex items-center justify-center gap-1.5"
              >
                Open in Explorer ↗
              </button>
            </div>
          </div>
        )}

        {/* ---------------- STATE 4: THREAT DETECTED ---------------- */}
        {(scanState === 'threat_detected' || scanState === 'quarantined') && (
          <div className="py-1">
            <div className="flex items-center gap-3 mb-3">
              <div className="h-9 w-9 rounded-xl bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-400">
                <ShieldAlert className="h-4 w-4"/>
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white tracking-tight">
                  {scanState === 'quarantined' ? 'Threats Neutralized' : 'Threats Intercepted'}
                </h3>
                <p className="text-xs text-red-400">
                  {scanState === 'quarantined'
                    ? 'All malicious vectors isolated and quarantined.'
                    : `${threatsFound.length} malicious vector(s) identified on volume.`}
                </p>
              </div>
            </div>

            {/* Scrollable Threat List */}
            <div className="max-h-36 overflow-y-auto space-y-1.5 my-3 pr-1">
              {threatsFound.map((threat: any, idx: number) => (
                <div
                  key={idx}
                  className="bg-red-500/[0.05] border border-red-500/20 rounded-lg p-2 text-xs flex items-center justify-between"
                >
                  <span className="font-mono text-zinc-200 truncate max-w-[180px]">
                    {threat.name || threat.path}
                  </span>
                  <span className="text-[10px] font-bold text-red-400 uppercase bg-red-500/10 px-1.5 py-0.5 rounded">
                    {threat.type || 'MALWARE'}
                  </span>
                </div>
              ))}
            </div>

            <div className="flex items-center gap-2 pt-1">
              <button
                onClick={() => setIsInterceptOpen(false)}
                className="w-1/3 text-xs font-medium text-zinc-400 hover:text-zinc-200 py-2 rounded-lg hover:bg-white/[0.04] transition-colors"
              >
                Dismiss
              </button>
              {scanState !== 'quarantined' ? (
                <button
                  onClick={() => quarantineThreats()}
                  className="w-2/3 text-xs font-medium text-white bg-red-600 hover:bg-red-500 py-2 rounded-lg shadow-sm transition-all flex items-center justify-center gap-1.5"
                >
                  <Trash2 className="h-3.5 w-3.5"/>
                  Quarantine Threats
                </button>
              ) : (
                <button
                  onClick={() => setIsInterceptOpen(false)}
                  className="w-2/3 text-xs font-medium text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 py-2 rounded-lg shadow-sm transition-all flex items-center justify-center gap-1.5"
                >
                  <CheckCircle2 className="h-3.5 w-3.5"/>
                  Quarantined
                </button>
              )}
            </div>
          </div>
        )}

      </div>
    </div>
  );
}

export default UsbInterceptModal;
