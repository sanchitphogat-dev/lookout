import { useState, useEffect, useRef, useCallback } from 'react';
import { logUsbScan, triggerNativeToast } from '../services/api';

export function useUsbWatcher() {
  const [isDaemonConnected, setIsDaemonConnected] = useState(false);
  const [detectedDrive, setDetectedDrive] = useState(null);
  const [isInterceptOpen, setIsInterceptOpen] = useState(false);
  const [scanState, setScanState] = useState('idle'); // 'idle' | 'scanning' | 'clean' | 'threat_detected'
  
  const [progress, setProgress] = useState(null);
  const [threatsFound, setThreatsFound] = useState([]);
  const [scanResult, setScanResult] = useState(null);

  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const isMountedRef = useRef(true);

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

      ws.onmessage = (event) => {
        if (!isMountedRef.current) return;
        try {
          const data = JSON.parse(event.data);
          
          if (data.type === 'USB_MOUNTED') {
            const driveData = data.payload || {
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
              setDetectedDrive((currentDrive) => {
                if (!currentDrive) return data.drives[0];
                return currentDrive;
              });
            } else if (data.payload && data.payload.activeDrives && data.payload.activeDrives.length > 0) {
              setDetectedDrive((currentDrive) => {
                if (!currentDrive) return data.payload.activeDrives[0];
                return currentDrive;
              });
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
            
            setDetectedDrive(currentDrive => {
              if (currentDrive) {
                const threatCount = data.summary.threats ? data.summary.threats.length : 0;
                const record = {
                  id: `usb-${Date.now()}`,
                  type: 'usb',
                  target: currentDrive.volumeName ? `${currentDrive.volumeName} (${currentDrive.driveLetter})` : (currentDrive.driveLetter || 'Removable Media / USB'),
                  driveLetter: currentDrive.driveLetter,
                  verdict: verdict,
                  riskScore: threatCount > 0 ? 85 : 0,
                  threatCount: threatCount,
                  filesScanned: data.summary.scannedFiles || 0,
                  threats: data.summary.threats || [],
                  timestamp: new Date().toISOString()
                };
                window.dispatchEvent(new CustomEvent('usb-scan-logged', { detail: record }));
                logUsbScan(record).catch(console.error);
              }
              return currentDrive;
            });
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
        
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = setTimeout(connect, 5000);
      };

      ws.onerror = () => {
        if (wsRef.current) {
          try { wsRef.current.close(); } catch (e) {}
        }
      };
    } catch (err) {
      if (isMountedRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = setTimeout(connect, 5000);
      }
    }
  }, []);

  useEffect(() => {
    isMountedRef.current = true;
    connect();

    return () => {
      isMountedRef.current = false;
      clearTimeout(reconnectTimeoutRef.current);
      if (wsRef.current) {
        // Clear onclose handler to prevent unmounted reconnect leak
        wsRef.current.onclose = null;
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

    // Trigger Native OS Toast
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: 'DEV_SIMULATE_CONNECT' }));
    } else {
      triggerNativeToast({
        title: "Lookout Sentinel Intercept",
        message: "Removable drive attached. Please scan before opening files.",
        isWarning: false
      });
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

  const scanViaBrowser = useCallback(async () => {
    try {
      const dirHandle = await window.showDirectoryPicker();
      
      setDetectedDrive({
        driveLetter: dirHandle.name,
        volumeName: "Browser Managed USB",
        size: "Unknown",
        freeSpace: "Unknown"
      });
      setIsInterceptOpen(true);
      setScanState('scanning');
      setProgress({ scannedFiles: 0, currentFile: 'Initializing Browser Scan...' });
      setThreatsFound([]);
      setScanResult(null);

      const filesToScan = [];
      
      async function traverse(currentHandle, depth = 0) {
        if (depth > 15) return;
        for await (const entry of currentHandle.values()) {
          if (['System Volume Information', '.Trashes', '$RECYCLE.BIN'].includes(entry.name)) continue;
          if (entry.kind === 'directory') {
            await traverse(await currentHandle.getDirectoryHandle(entry.name), depth + 1);
          } else if (entry.kind === 'file') {
            filesToScan.push({ handle: await currentHandle.getFileHandle(entry.name) });
          }
        }
      }
      
      await traverse(dirHandle);

      let scannedCount = 0;
      const localThreats = [];

      for (const fileObj of filesToScan) {
        try {
          const file = await fileObj.handle.getFile();
          setProgress({ scannedFiles: scannedCount, currentFile: file.name, totalDiscovered: filesToScan.length });
          
          const sizeToRead = Math.min(file.size, 10 * 1024 * 1024);
          const buffer = await file.slice(0, sizeToRead).arrayBuffer();
          const scanBlob = new Blob([buffer], { type: file.type || 'application/octet-stream' });
          const formDataFile = new File([scanBlob], file.name, { type: file.type || 'application/octet-stream' });
          
          const formData = new FormData();
          formData.append('payload', formDataFile);

          const res = await fetch('/api/scan/file', {
            method: 'POST',
            body: formData
          });

          if (res.ok) {
            const data = await res.json();
            if (data.riskScore > 50) {
              const threatObj = {
                path: file.name,
                name: file.name,
                type: 'Heuristic Detection',
                riskScore: data.riskScore,
                reason: data.explanation || 'Malicious Payload',
                sha256: data.sha256 || data.hash || 'UNKNOWN'
              };
              localThreats.push(threatObj);
              setThreatsFound(prev => [...prev, threatObj]);
            }
          }
        } catch (e) {
          console.error("Browser scan error on file:", e);
        }
        scannedCount++;
      }

      const verdict = localThreats.length > 0 ? 'threat_detected' : 'clean';
      setScanState(verdict);
      const summaryResult = {
        threats: localThreats,
        scannedFiles: scannedCount,
        verdict
      };
      setScanResult(summaryResult);

      const record = {
        id: `usb-${Date.now()}`,
        type: 'usb',
        target: dirHandle.name ? `${dirHandle.name} (Browser USB)` : 'Browser Managed USB',
        driveLetter: dirHandle.name,
        verdict: verdict,
        riskScore: localThreats.length > 0 ? 85 : 0,
        threatCount: localThreats.length,
        filesScanned: scannedCount,
        threats: localThreats,
        timestamp: new Date().toISOString()
      };
      window.dispatchEvent(new CustomEvent('usb-scan-logged', { detail: record }));
      logUsbScan(record).catch(console.error);

      if (localThreats.length > 0) {
        if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
          wsRef.current.send(JSON.stringify({ action: 'THREAT_ALERT' }));
        } else {
          triggerNativeToast({
            title: "Lookout Security Alert",
            message: "Malicious vectors intercepted on external media!",
            isWarning: true
          });
        }
      }

    } catch (e) {
      console.error(e);
      setScanState('idle');
      setIsInterceptOpen(false);
    }
  }, []);

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
    scanViaBrowser,
    quarantineThreats
  };
}
