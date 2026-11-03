import { createContext, useContext, useState, useEffect, useCallback } from "react";
import { getReportStats } from "../services/api";

const TelemetryContext = createContext({
  isTelemetryOpen: false,
  openTelemetry: () => {},
  closeTelemetry: () => {},
  toggleTelemetry: () => {},
  stats: null,
  loadingStats: false,
  refreshStats: () => {},
  scanData: null,
  totalScansProcessed: 0,
  threatsNeutralized: 0,
  lastVectorScanned: "Binaries & Files",
  recordScanMetrics: () => {},
});

export function TelemetryProvider({ children }) {
  const [isTelemetryOpen, setIsTelemetryOpen] = useState(false);
  const [stats, setStats] = useState(null);
  const [loadingStats, setLoadingStats] = useState(false);
  const [scanData, setScanData] = useState(null);
  const [totalScansProcessed, setTotalScansProcessed] = useState(0);
  const [threatsNeutralized, setThreatsNeutralized] = useState(0);
  const [lastVectorScanned, setLastVectorScanned] = useState("Binaries & Files");

  const refreshStats = useCallback(async () => {
    setLoadingStats(true);
    try {
      const data = await getReportStats();
      setStats(data);
    } catch {
      // Fallback
    } finally {
      setLoadingStats(false);
    }
  }, []);

  useEffect(() => {
    if (stats) {
      setTotalScansProcessed(stats.total || 0);
      const high = stats.byRisk?.find((r) => r.level === "high")?.count || 0;
      const med = stats.byRisk?.find((r) => r.level === "medium")?.count || 0;
      setThreatsNeutralized(high + med);
      if (stats.recent && stats.recent.length > 0) {
        const mostRecent = stats.recent[0];
        if (mostRecent.type === 'usb') setLastVectorScanned("USB Storage");
        else if (mostRecent.type === 'url') setLastVectorScanned("Web Endpoints");
        else setLastVectorScanned("Binaries & Files");
      }
    }
  }, [stats]);

  const recordScanMetrics = useCallback((record) => {
    if (!record) return;
    setTotalScansProcessed((prev) => prev + 1);

    const isThreat = (record.riskScore >= 51) || (record.threatCount > 0) || (record.threats && record.threats.length > 0);
    if (isThreat) {
      setThreatsNeutralized((prev) => prev + (record.threatCount || 1));
    }

    const vectorLabel = record.type === 'usb'
      ? 'USB Storage'
      : record.type === 'url'
      ? 'Web Endpoints'
      : 'Binaries & Files';
    setLastVectorScanned(vectorLabel);

    // Optimistically update stats breakdown for instant UI response
    setStats((prev) => {
      if (!prev) return prev;
      const newTotal = (prev.total || 0) + 1;
      const targetType = record.type || 'usb';
      const byType = [...(prev.byType || [])];
      const typeIdx = byType.findIndex((t) => t.type === targetType);
      if (typeIdx >= 0) {
        byType[typeIdx] = { ...byType[typeIdx], count: byType[typeIdx].count + 1 };
      } else {
        byType.push({ type: targetType, count: 1 });
      }

      const isSuspicious = record.riskScore >= 16 && record.riskScore < 51;
      const riskLevel = isThreat ? 'high' : isSuspicious ? 'medium' : 'low';
      const byRisk = [...(prev.byRisk || [])];
      const riskIdx = byRisk.findIndex((r) => r.level === riskLevel);
      if (riskIdx >= 0) {
        byRisk[riskIdx] = { ...byRisk[riskIdx], count: byRisk[riskIdx].count + 1 };
      } else {
        byRisk.push({ level: riskLevel, count: 1 });
      }

      return {
        ...prev,
        total: newTotal,
        byType,
        byRisk,
      };
    });
  }, []);

  useEffect(() => {
    const handleUsbLog = (e) => {
      if (e.detail) {
        recordScanMetrics(e.detail);
        refreshStats();
      }
    };
    window.addEventListener('usb-scan-logged', handleUsbLog);
    return () => window.removeEventListener('usb-scan-logged', handleUsbLog);
  }, [recordScanMetrics, refreshStats]);

  useEffect(() => {
    refreshStats();
  }, [refreshStats]);

  const openTelemetry = useCallback((data = null) => {
    if (data && !data.nativeEvent) setScanData(data);
    setIsTelemetryOpen(true);
  }, []);

  const closeTelemetry = useCallback(() => {
    setIsTelemetryOpen(false);
  }, []);

  const toggleTelemetry = useCallback(() => {
    setIsTelemetryOpen((prev) => !prev);
  }, []);

  // Keyboard shortcut listener: 'T' or 't' or Cmd+K / Ctrl+K to toggle, ESC to close
  useEffect(() => {
    const handleKeyDown = (e) => {
      const target = e.target;
      const isInput =
        target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.tagName === "SELECT" ||
        target.isContentEditable;

      if (e.key === "Escape") {
        setIsTelemetryOpen(false);
        return;
      }

      // Check for Cmd+K / Ctrl+K
      if ((e.metaKey || e.ctrlKey) && (e.key === "k" || e.key === "K")) {
        e.preventDefault();
        setIsTelemetryOpen((prev) => !prev);
        return;
      }

      // Check for 'T' / 't' when not typing in form controls
      if (!isInput && !e.metaKey && !e.ctrlKey && !e.altKey && (e.key === "t" || e.key === "T")) {
        e.preventDefault();
        setIsTelemetryOpen((prev) => !prev);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  return (
    <TelemetryContext.Provider
      value={{
        isTelemetryOpen,
        openTelemetry,
        closeTelemetry,
        toggleTelemetry,
        stats,
        loadingStats,
        refreshStats,
        scanData,
        totalScansProcessed,
        threatsNeutralized,
        lastVectorScanned,
        recordScanMetrics,
      }}
    >
      {children}
    </TelemetryContext.Provider>
  );
}

export function useTelemetry() {
  return useContext(TelemetryContext);
}

export default TelemetryContext;
