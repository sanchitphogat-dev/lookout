import { useState, useEffect } from "react";
import UnifiedScanHub from "../components/UnifiedScanHub";
import ScanHistoryTable from "../components/ScanHistoryTable";
import { getReports } from "../services/api";

export default function UrlScan() {
  const [urlScans, setUrlScans] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchRecent = (completedScan) => {
    if (completedScan) {
      const payload = completedScan.data || completedScan;
      const optimisticEntry = {
        id: payload.id || `scan-${Date.now()}`,
        type: "url",
        target: payload.normalizedUrl || payload.target || payload.url || "Scanned Target",
        risk_score: payload.riskScore ?? payload.risk_score ?? 0,
        created_at: payload.scannedAt || payload.created_at || new Date().toISOString(),
      };
      setUrlScans((prev) => [
        optimisticEntry,
        ...prev.filter((item) => item.id !== optimisticEntry.id),
      ]);
    }
    getReports({ type: "url", limit: 6 })
      .then((data) => setUrlScans(data.scans || []))
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchRecent();
  }, []);

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-black/[0.06] dark:border-white/[0.06] pb-3">
        <h1 className="text-xl font-bold tracking-[-0.03em] text-zinc-900 dark:text-zinc-100">
          URL Scan
        </h1>
      </div>

      {/* Main Unified Hub */}
      <UnifiedScanHub initialTab="url" onScanCompleted={fetchRecent} />

      {/* Recent URL Scans */}
      <div className="space-y-3">
        <div className="flex items-center justify-between px-0.5">
          <span className="text-xs font-semibold tracking-[-0.02em] uppercase text-zinc-500 dark:text-zinc-400">
            Recent Activity
          </span>
          <span className="text-xs font-mono font-semibold tracking-tight text-zinc-400 dark:text-zinc-500">
            {urlScans.length}
          </span>
        </div>

        <div className="glass-card overflow-hidden">
          {loading ? (
            <div className="py-12 text-center text-xs font-mono text-zinc-500">
              Loading...
            </div>
          ) : (
            <ScanHistoryTable scans={urlScans} />
          )}
        </div>
      </div>
    </div>
  );
}
