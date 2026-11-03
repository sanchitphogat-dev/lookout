import { useState, useEffect, useCallback } from "react";
import { Link } from "react-router-dom";
import { FileCode, Globe, HardDrive, ArrowUpRight } from "lucide-react";
import UnifiedScanHub from "../components/UnifiedScanHub";
import { getReports } from "../services/api";
import { useTelemetry } from "../context/TelemetryContext";

export default function Dashboard() {
  const [recentScans, setRecentScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const { 
    stats, 
    loadingStats, 
    refreshStats, 
    totalScansProcessed, 
    threatsNeutralized, 
    lastVectorScanned, 
    openTelemetry 
  } = useTelemetry();

  const getTypeCount = (type) => stats?.byType?.find((i) => i.type === type)?.count || 0;
  const fileScans = getTypeCount("file");
  const urlScans = getTypeCount("url");
  const usbScans = getTypeCount("usb");

  const loadData = useCallback(() => {
    return getReports({ limit: 8 })
      .then((reportsData) => {
        if (reportsData?.scans?.length > 0) {
          setRecentScans(reportsData.scans);
        } else {
          setRecentScans([]);
        }
      })
      .catch(() => {
        setRecentScans([]);
      });
  }, []);

  useEffect(() => {
    loadData().finally(() => setLoading(false));

    const handleUsbLog = (e) => {
      setRecentScans((prev) => {
        // Prevent duplicate IDs
        if (prev.some(scan => scan.id === e.detail.id)) return prev;
        // Format to match backend response structure
        const newScan = {
          ...e.detail,
          created_at: e.detail.timestamp,
          risk_score: e.detail.riskScore
        };
        return [newScan, ...prev].slice(0, 5);
      });
      refreshStats();
    };

    window.addEventListener('usb-scan-logged', handleUsbLog);
    return () => window.removeEventListener('usb-scan-logged', handleUsbLog);
  }, [loadData, refreshStats]);

  const handleScanCompleted = (completedScan) => {
    if (completedScan) {
      const payload = completedScan.data || completedScan;
      const optimisticEntry = {
        id: payload.id || `scan-${Date.now()}`,
        type: completedScan.type || (payload.normalizedUrl || payload.url ? "url" : "file"),
        target: payload.normalizedUrl || payload.target || payload.url || "Scanned Target",
        risk_score: payload.riskScore ?? payload.risk_score ?? 0,
        verdict: payload.verdict,
        created_at: payload.scannedAt || payload.created_at || new Date().toISOString(),
      };
      setRecentScans((prev) => [
        optimisticEntry,
        ...prev.filter((item) => item.id !== optimisticEntry.id),
      ]);
    }
    loadData();
    refreshStats();
  };

  const formatTimestamp = (dateStr) => {
    if (!dateStr) return "Just now";
    const date = new Date(dateStr);
    const now = new Date();
    const diffSec = Math.floor((now - date) / 1000);
    if (diffSec < 60) return "Just now";
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    return date.toLocaleDateString([], { month: "short", day: "numeric" });
  };

  return (
    <div className="max-w-[760px] mx-auto mt-4 sm:mt-10 mb-16">
      {/* 1. Header: Modern Geometric Title */}
      <div className="text-center mb-6">
        <h1 className="text-zinc-900 dark:text-zinc-100 font-bold tracking-tight text-2xl">
          Threat Detection
        </h1>
        <p className="text-zinc-500 dark:text-zinc-400 text-[13px] mt-1 max-w-sm mx-auto">
          Deep heuristic analysis for files, URLs, and storage drives.
        </p>
      </div>

      {/* 2. Global Metric Counters Ribbon */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-6">
        <div 
          onClick={() => openTelemetry()}
          className="glass-card p-3.5 flex flex-col justify-between cursor-pointer hover:border-black/20 dark:hover:border-white/20 transition-colors group"
        >
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold tracking-tight uppercase text-zinc-500">
              Threats Blocked
            </span>
            <span className={`w-2 h-2 rounded-full ${threatsNeutralized > 0 ? "bg-rose-500 animate-pulse" : "bg-emerald-500"}`} />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className={`text-2xl font-bold tracking-tight font-mono ${threatsNeutralized > 0 ? "text-rose-500" : "text-zinc-900 dark:text-zinc-100"}`}>
              {loadingStats ? "—" : threatsNeutralized}
            </span>
            <span className="text-[11px] text-zinc-400 font-mono">Neutralized</span>
          </div>
        </div>

        <div 
          onClick={() => openTelemetry()}
          className="glass-card p-3.5 flex flex-col justify-between cursor-pointer hover:border-black/20 dark:hover:border-white/20 transition-colors group"
        >
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold tracking-tight uppercase text-zinc-500">
              Total Scans
            </span>
            <span className="text-[10px] font-mono text-zinc-400 group-hover:text-indigo-400 transition-colors">LIVE</span>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight font-mono text-zinc-900 dark:text-zinc-100">
              {loadingStats ? "—" : totalScansProcessed}
            </span>
            <span className="text-[11px] text-zinc-400 font-mono">Processed</span>
          </div>
        </div>

        <div 
          onClick={() => openTelemetry()}
          className="glass-card p-3.5 flex flex-col justify-between cursor-pointer hover:border-black/20 dark:hover:border-white/20 transition-colors group"
        >
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold tracking-tight uppercase text-zinc-500">
              Vector Distribution
            </span>
            <span className="text-[10px] font-mono text-indigo-500 font-medium">
              {lastVectorScanned}
            </span>
          </div>
          <div className="mt-2 flex items-center justify-between text-xs font-mono">
            <span className="flex items-center gap-1 text-zinc-600 dark:text-zinc-400" title="Binaries & Files">
              <FileCode className="w-3 h-3 text-zinc-400" /> {fileScans}
            </span>
            <span className="flex items-center gap-1 text-zinc-600 dark:text-zinc-400" title="Web Endpoints">
              <Globe className="w-3 h-3 text-indigo-400" /> {urlScans}
            </span>
            <span className="flex items-center gap-1 text-zinc-600 dark:text-zinc-400" title="Removable Media / USB">
              <HardDrive className="w-3 h-3 text-emerald-400" /> {usbScans}
            </span>
          </div>
        </div>
      </div>

      {/* 3. The Centered Hero Scan Console (The Spotlight) */}
      <UnifiedScanHub onScanCompleted={handleScanCompleted} />

      {/* 3. Streamlined Activity Feed (Directly Below Hero, max 3-4 items) */}
      <div className="space-y-3 pt-2 mt-10">
        <div className="flex items-center justify-between px-1">
          <span className="text-xs font-semibold tracking-[-0.02em] uppercase text-zinc-500 dark:text-zinc-100">
            Recent Verifications
          </span>
          <Link
            to="/reports"
            className="text-xs text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-zinc-200 transition-colors flex items-center gap-1 group font-semibold tracking-[-0.01em]"
          >
            <span>View all</span>
            <span className="group-hover:translate-x-0.5 transition-transform">→</span>
          </Link>
        </div>

        <div className="glass-card overflow-hidden">
          {loading ? (
            <div className="py-10 text-center text-xs font-mono text-zinc-400 dark:text-zinc-500">
              Loading recent verifications...
            </div>
          ) : recentScans.length === 0 ? (
            <div className="py-10 text-center space-y-1">
              <p className="text-xs text-zinc-600 dark:text-zinc-400 font-medium">
                No recent verifications recorded
              </p>
              <p className="text-[11px] text-zinc-400 dark:text-zinc-500">
                Execute a scan above to populate audit logs
              </p>
            </div>
          ) : (
            <div className="divide-y divide-black/[0.04] dark:divide-white/[0.04]">
              {recentScans.slice(0, 5).map((scan) => {
                const score = scan.risk_score ?? scan.riskScore ?? 0;
                const isMalicious = score >= 51;
                const isSuspicious = score >= 16 && score < 51;

                return (
                  <Link
                    key={scan.id}
                    to={`/reports/${scan.id}`}
                    className="flex items-center justify-between py-3.5 px-4 sm:px-5 bg-white/[0.02] hover:bg-black/[0.02] dark:hover:bg-white/[0.04] transition-colors duration-150 text-xs gap-3 group"
                  >
                    {/* Source Icon + Target Name */}
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <div className="w-7 h-7 rounded-lg bg-black/[0.03] dark:bg-white/[0.04] border border-black/[0.06] dark:border-white/[0.08] flex items-center justify-center text-zinc-500 dark:text-zinc-400 shrink-0">
                        {scan.type === "url" ? (
                          <Globe className="w-3.5 h-3.5 text-indigo-400" />
                        ) : scan.type === "usb" ? (
                          <HardDrive className="w-3.5 h-3.5" />
                        ) : (
                          <FileCode className="w-3.5 h-3.5" />
                        )}
                      </div>

                      <span
                        className="font-mono text-xs text-zinc-800 dark:text-zinc-200 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 truncate max-w-[200px] sm:max-w-xs md:max-w-md transition-colors"
                        title={scan.target}
                      >
                        {scan.target}
                      </span>
                    </div>

                    {/* Timestamp + Status Badge */}
                    <div className="flex items-center gap-3 sm:gap-4 shrink-0">
                      <span className="font-mono text-[11px] text-zinc-400 dark:text-zinc-500">
                        {formatTimestamp(scan.created_at)}
                      </span>

                      {isMalicious ? (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold tracking-tight bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20">
                          <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                          <span>{score} · Malicious</span>
                        </span>
                      ) : isSuspicious ? (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold tracking-tight bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20">
                          <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
                          <span>{score} · Suspicious</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold tracking-tight bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                          <span>{score} · Clean</span>
                        </span>
                      )}

                      <ArrowUpRight className="w-3.5 h-3.5 text-zinc-400 group-hover:text-zinc-700 dark:group-hover:text-zinc-200 opacity-60 group-hover:opacity-100 transition-all shrink-0" />
                    </div>
                  </Link>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
