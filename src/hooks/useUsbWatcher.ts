import { useState, useEffect, useRef, useCallback } from 'react';

export interface UsbDrive {
  driveLetter: string;
  volumeName: string;
  fileSystem?: string;
  totalGb?: string;
  freeGb?: string;
  usedGb?: string;
  usedPercentage?: number;
  rawSizeBytes?: number;
  size?: string | number;
  freeSpace?: string | number;
}

export interface UsbProgress {
  scannedFiles: number;
  currentFile: string;
  totalDiscovered?: number;
  totalFiles?: number;
}

export interface UsbThreat {
  path: string;
  name: string;
  type: string;
  detection?: string;
  riskScore: number;
  reason: string;
  sha256: string;
}

export interface UsbScanResult {
  threats: UsbThreat[];
  scannedFiles: number;
  verdict: 'clean' | 'threat_detected' | 'quarantined' | 'idle' | 'scanning';
  drivePath?: string;
  durationMs?: number;
}

// Global Store State to synchronize DashboardPage and UsbInterceptModal
interface UsbState {
  isDaemonConnected: boolean;
  detectedDrive: UsbDrive | null;
  isInterceptOpen: boolean;
  scanState: 'idle' | 'scanning' | 'clean' | 'threat_detected' | 'quarantined';
  progress: UsbProgress | null;
  threatsFound: UsbThreat[];
  scanResult: UsbScanResult | null;
}

const defaultState: UsbState = {
  isDaemonConnected: false,
  detectedDrive: null,
  isInterceptOpen: false,
  scanState: 'idle',
  progress: null,
  threatsFound: [],
  scanResult: null,
};

let globalState: UsbState = { ...defaultState };
const listeners = new Set<(state: UsbState) => void>();
let globalWs: WebSocket | null = null;
let reconnectTimer: NodeJS.Timeout | number | null = null;

function setGlobalState(updater: Partial<UsbState> | ((prev: UsbState) => UsbState)) {
  if (typeof updater === 'function') {
    globalState = updater(globalState);
  } else {
    globalState = { ...globalState, ...updater };
  }
  listeners.forEach((listener) => listener(globalState));
}

function initWebSocket() {
  if (typeof window === 'undefined') return;
  if (globalWs && (globalWs.readyState === WebSocket.OPEN || globalWs.readyState === WebSocket.CONNECTING)) {
    return;
  }

  try {
    const ws = new WebSocket('ws://localhost:48201');
    globalWs = ws;

    ws.onopen = () => {
      setGlobalState({ isDaemonConnected: true });
    };

    ws.onmessage = (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'USB_MOUNTED') {
          const driveData: UsbDrive = data.payload || {
            driveLetter: data.driveLetter,
            volumeName: data.volumeName,
            fileSystem: data.fileSystem,
            totalGb: data.totalGb,
            freeGb: data.freeGb,
            usedGb: data.usedGb,
            usedPercentage: data.usedPercentage,
            rawSizeBytes: data.rawSizeBytes,
            size: data.size || data.totalGb,
            freeSpace: data.freeSpace || data.freeGb,
          };
          setGlobalState({
            detectedDrive: driveData,
            isInterceptOpen: true,
            scanState: 'idle',
            progress: null,
            threatsFound: [],
            scanResult: null,
          });
        } else if (data.type === 'USB_EJECTED') {
          const letter = data.payload ? data.payload.driveLetter : data.driveLetter;
          if (globalState.detectedDrive && globalState.detectedDrive.driveLetter === letter) {
            setGlobalState({
              detectedDrive: null,
              isInterceptOpen: false,
              scanState: 'idle',
              progress: null,
              threatsFound: [],
              scanResult: null,
            });
          }
        } else if (data.type === 'DAEMON_READY') {
          if (data.drives && data.drives.length > 0) {
            if (!globalState.detectedDrive) {
              setGlobalState({ detectedDrive: data.drives[0] });
            }
          } else if (data.payload?.activeDrives?.length > 0) {
            if (!globalState.detectedDrive) {
              setGlobalState({ detectedDrive: data.payload.activeDrives[0] });
            }
          }
        } else if (data.type === 'SCAN_STARTED') {
          setGlobalState({
            scanState: 'scanning',
            progress: { scannedFiles: 0, currentFile: 'Initializing...' },
            threatsFound: [],
            scanResult: null,
          });
        } else if (data.type === 'SCAN_PROGRESS') {
          setGlobalState({
            progress: {
              scannedFiles: data.scannedFiles ?? data.scannedCount ?? 0,
              currentFile: data.currentFile || '',
              totalDiscovered: data.totalDiscovered ?? data.totalFiles,
              totalFiles: data.totalFiles ?? data.totalDiscovered,
            },
          });
        } else if (data.type === 'THREAT_DISCOVERED') {
          setGlobalState((prev) => ({
            ...prev,
            threatsFound: [...prev.threatsFound, data.threat],
          }));
        } else if (data.type === 'SCAN_COMPLETE') {
          const summary = data.summary;
          const verdict = summary.threats && summary.threats.length > 0 ? 'threat_detected' : 'clean';
          setGlobalState({
            scanResult: summary,
            scanState: verdict,
          });
        } else if (data.type === 'QUARANTINE_SUCCESS') {
          setGlobalState({ scanState: 'quarantined' });
        }
      } catch (err) {
        console.error('Failed to parse WebSocket message:', err);
      }
    };

    ws.onclose = () => {
      setGlobalState({ isDaemonConnected: false });
      globalWs = null;
      if (reconnectTimer) clearTimeout(reconnectTimer as any);
      reconnectTimer = setTimeout(initWebSocket, 5000);
    };

    ws.onerror = () => {
      if (globalWs) {
        try { globalWs.close(); } catch (e) {}
      }
    };
  } catch (err) {
    if (reconnectTimer) clearTimeout(reconnectTimer as any);
    reconnectTimer = setTimeout(initWebSocket, 5000);
  }
}

export function useUsbWatcher() {
  const [state, setState] = useState<UsbState>(globalState);

  useEffect(() => {
    listeners.add(setState);
    initWebSocket();
    return () => {
      listeners.delete(setState);
    };
  }, []);

  const simulateMockUsb = useCallback(() => {
    const mockDrive: UsbDrive = {
      driveLetter: 'E:',
      volumeName: 'CORSAIR_SECURE',
      fileSystem: 'FAT32',
      totalGb: '32.0 GB',
      freeGb: '14.2 GB',
      usedGb: '17.8 GB',
      usedPercentage: 56,
      rawSizeBytes: 34359738368,
      size: '32.0 GB',
      freeSpace: '14.2 GB',
    };

    setGlobalState({
      detectedDrive: mockDrive,
      isInterceptOpen: true,
      scanState: 'idle',
      progress: null,
      threatsFound: [],
      scanResult: null,
    });

    if (globalWs && globalWs.readyState === WebSocket.OPEN) {
      globalWs.send(JSON.stringify({ action: 'DEV_SIMULATE_CONNECT' }));
    }
  }, []);

  const closeIntercept = useCallback(() => {
    setGlobalState({ isInterceptOpen: false });
  }, []);

  const setIsInterceptOpen = useCallback((open: boolean) => {
    setGlobalState({ isInterceptOpen: open });
  }, []);

  const startScan = useCallback(() => {
    if (!state.detectedDrive && !globalState.detectedDrive) return;

    setGlobalState({
      scanState: 'scanning',
      progress: { scannedFiles: 0, currentFile: 'E:\\autorun.inf', totalFiles: 34, totalDiscovered: 34 },
      threatsFound: [],
      scanResult: null,
    });

    if (globalWs && globalWs.readyState === WebSocket.OPEN) {
      globalWs.send(JSON.stringify({
        action: 'START_USB_SCAN',
        driveLetter: (globalState.detectedDrive || state.detectedDrive)?.driveLetter,
      }));
    } else {
      // Cloud / Vercel browser simulation mode: simulate progression through real threats
      setTimeout(() => {
        setGlobalState({
          progress: { scannedFiles: 14, currentFile: 'E:\\documents\\financial_audit.xlsx', totalFiles: 34, totalDiscovered: 34 },
        });
      }, 500);

      setTimeout(() => {
        const simulatedThreats: UsbThreat[] = [
          {
            name: 'autorun.inf',
            path: 'E:\\autorun.inf',
            type: 'AUTORUN_EXEC_HOOK',
            riskScore: 94,
            reason: 'Malicious auto-exec command pointing to hidden payload',
            sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          },
          {
            name: 'invoice_2026.pdf.exe',
            path: 'E:\\payloads\\invoice_2026.pdf.exe',
            type: 'SPOOFED_BINARY',
            riskScore: 98,
            reason: 'Double-extension MIME spoofing with PE32 executable header',
            sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
          },
        ];

        setGlobalState({
          scanState: 'threat_detected',
          threatsFound: simulatedThreats,
          progress: { scannedFiles: 34, currentFile: 'Complete', totalFiles: 34, totalDiscovered: 34 },
          scanResult: {
            threats: simulatedThreats,
            scannedFiles: 34,
            verdict: 'threat_detected',
            drivePath: 'E:\\',
            durationMs: 1420,
          },
        });
      }, 1200);
    }
  }, [state.detectedDrive]);

  const quarantineThreats = useCallback(() => {
    if (globalWs && globalWs.readyState === WebSocket.OPEN && globalState.threatsFound.length > 0) {
      const threatPaths = globalState.threatsFound.map((t) => t.path);
      globalWs.send(JSON.stringify({
        action: 'QUARANTINE_THREATS',
        threatPaths,
      }));
    } else {
      setGlobalState({ scanState: 'quarantined' });
    }
  }, []);

  const openDriveInExplorer = useCallback(() => {
    if (globalWs && globalWs.readyState === WebSocket.OPEN && globalState.detectedDrive) {
      globalWs.send(JSON.stringify({
        action: 'OPEN_DRIVE_IN_EXPLORER',
        driveLetter: globalState.detectedDrive.driveLetter,
      }));
    }
    setGlobalState({ isInterceptOpen: false });
  }, []);

  return {
    // Both standard naming and alias naming for seamless compatibility:
    isConnected: state.isDaemonConnected,
    isDaemonConnected: state.isDaemonConnected,
    simulateUsbInsert: simulateMockUsb,
    simulateMockUsb,
    detectedDrive: state.detectedDrive,
    isInterceptOpen: state.isInterceptOpen,
    setIsInterceptOpen,
    scanState: state.scanState,
    progress: state.progress,
    scanProgress: state.progress,
    threatsFound: state.threatsFound,
    scanResult: state.scanResult,
    closeIntercept,
    startScan,
    startUsbScan: startScan,
    openDriveInExplorer,
    quarantineThreats,
  };
}
