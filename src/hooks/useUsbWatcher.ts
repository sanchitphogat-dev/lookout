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

export function useUsbWatcher() {
  const [isDaemonConnected, setIsDaemonConnected] = useState<boolean>(false);
  const [detectedDrive, setDetectedDrive] = useState<UsbDrive | null>(null);
  const [isInterceptOpen, setIsInterceptOpen] = useState<boolean>(false);
  const [scanState, setScanState] = useState<'idle' | 'scanning' | 'clean' | 'threat_detected' | 'quarantined'>('idle');
  
  const [progress, setProgress] = useState<UsbProgress | null>(null);
  const [threatsFound, setThreatsFound] = useState<UsbThreat[]>([]);
  const [scanResult, setScanResult] = useState<UsbScanResult | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | number | null>(null);
  const isMountedRef = useRef<boolean>(true);

  const connect = useCallback(() => {
    if (wsRef.current && (wsRef.current.readyState === WebSocket.OPEN || wsRef.current.readyState === WebSocket.CONNECTING)) {
      return;
    }

    try {
      const ws = new WebSocket('ws://localhost:48201');
      wsRef.current = ws;

      ws.onopen = () => {
        if (isMountedRef.current) {
          setIsDaemonConnected(true);
        }
      };

      ws.onmessage = (event: MessageEvent) => {
        if (!isMountedRef.current) return;
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
              freeSpace: data.freeSpace || data.freeGb
            };
            setDetectedDrive(driveData);
            setIsInterceptOpen(true);
            setScanState('idle');
            setProgress(null);
            setThreatsFound([]);
            setScanResult(null);
          } else if (data.type === 'USB_EJECTED') {
            const letter = data.payload ? data.payload.driveLetter : data.driveLetter;
            setDetectedDrive((currentDrive) => {
              if (currentDrive && currentDrive.driveLetter === letter) {
                setIsInterceptOpen(false);
                setScanState('idle');
                setProgress(null);
                setThreatsFound([]);
                setScanResult(null);
                return null;
              }
              return currentDrive;
            });
          } else if (data.type === 'DAEMON_READY') {
            if (data.drives && data.drives.length > 0) {
              setDetectedDrive((currentDrive) => (!currentDrive ? data.drives[0] : currentDrive));
            } else if (data.payload?.activeDrives?.length > 0) {
              setDetectedDrive((currentDrive) => (!currentDrive ? data.payload.activeDrives[0] : currentDrive));
            }
          } else if (data.type === 'SCAN_STARTED') {
            setScanState('scanning');
            setProgress({ scannedFiles: 0, currentFile: '' });
            setThreatsFound([]);
            setScanResult(null);
          } else if (data.type === 'SCAN_PROGRESS') {
            setProgress({
              scannedFiles: data.scannedFiles ?? data.scannedCount ?? 0,
              currentFile: data.currentFile || '',
              totalDiscovered: data.totalDiscovered ?? data.totalFiles,
              totalFiles: data.totalFiles ?? data.totalDiscovered
            });
          } else if (data.type === 'THREAT_DISCOVERED') {
            setThreatsFound(prev => [...prev, data.threat]);
          } else if (data.type === 'SCAN_COMPLETE') {
            setScanResult(data.summary);
            const verdict = (data.summary.threats && data.summary.threats.length > 0) ? 'threat_detected' : 'clean';
            setScanState(verdict);
          } else if (data.type === 'QUARANTINE_SUCCESS') {
            setScanState('quarantined');
          }
        } catch (err) {
          console.error("Failed to parse WebSocket message:", err);
        }
      };

      ws.onclose = () => {
        if (!isMountedRef.current) return;
        setIsDaemonConnected(false);
        wsRef.current = null;
        
        if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current as any);
        reconnectTimeoutRef.current = setTimeout(connect, 5000);
      };

      ws.onerror = () => {
        if (wsRef.current) {
          try { wsRef.current.close(); } catch (e) {}
        }
      };
    } catch (err) {
      if (isMountedRef.current) {
        if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current as any);
        reconnectTimeoutRef.current = setTimeout(connect, 5000);
      }
    }
  }, []);

  useEffect(() => {
    isMountedRef.current = true;
    connect();

    return () => {
      isMountedRef.current = false;
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current as any);
      if (wsRef.current) {
        wsRef.current.onclose = null; // Prevent reconnect scheduling on unmount
        try { wsRef.current.close(); } catch (e) {}
        wsRef.current = null;
      }
    };
  }, [connect]);

  const simulateMockUsb = useCallback(() => {
    setDetectedDrive({
      driveLetter: "E:",
      volumeName: "USB Drive",
      fileSystem: "FAT32",
      totalGb: "28.6 GB",
      freeGb: "11.0 GB",
      usedGb: "17.6 GB",
      usedPercentage: 61,
      rawSizeBytes: 30707816857,
      size: "28.6 GB",
      freeSpace: "11.0 GB"
    });
    setScanState('idle');
    setIsInterceptOpen(true);
    setProgress(null);
    setThreatsFound([]);
    setScanResult(null);

    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: 'DEV_SIMULATE_CONNECT' }));
    }
  }, []);

  const closeIntercept = useCallback(() => {
    setIsInterceptOpen(false);
  }, []);

  const startScan = useCallback(() => {
    if (!detectedDrive) return;
    setScanState('scanning');
    setProgress({ scannedFiles: 0, currentFile: 'Initializing...' });
    setThreatsFound([]);
    setScanResult(null);
    
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        action: 'START_USB_SCAN',
        driveLetter: detectedDrive.driveLetter
      }));
    }
  }, [detectedDrive]);

  const socketRef = wsRef;

  const openDriveInExplorer = useCallback(() => {
    if (!socketRef.current || !detectedDrive) return;
    socketRef.current.send(JSON.stringify({
      action: 'OPEN_DRIVE_IN_EXPLORER',
      driveLetter: detectedDrive.driveLetter
    }));
    setIsInterceptOpen(false); // Close the modal cleanly after launch
  }, [detectedDrive]);

  const quarantineThreats = useCallback(() => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN && threatsFound.length > 0) {
      const threatPaths = threatsFound.map(t => t.path);
      wsRef.current.send(JSON.stringify({
        action: 'QUARANTINE_THREATS',
        threatPaths
      }));
    }
  }, [threatsFound]);

  return {
    isDaemonConnected,
    detectedDrive,
    isInterceptOpen,
    setIsInterceptOpen,
    scanState,
    progress,
    scanProgress: progress,
    threatsFound,
    scanResult,
    simulateMockUsb,
    closeIntercept,
    startScan,
    startUsbScan: startScan,
    openDriveInExplorer,
    quarantineThreats
  };
}
