import { useState, useEffect } from "react";
import UnifiedScanHub from "../components/UnifiedScanHub";
import ScanHistoryTable from "../components/ScanHistoryTable";
import { getReports } from "../services/api";

export default function FileScan() {
  const [fileScans, setFileScans] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchRecent = () => {
    getReports({ type: "file", limit: 6 })
      .then((data) => setFileScans(data.scans || []))
      .catch(() => setFileScans([]))
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
          File Scan
        </h1>
      </div>

      {/* Main Unified Hub */}
      <UnifiedScanHub initialTab="file" onScanCompleted={fetchRecent} />

      {/* Recent File Scans */}
      <div className="space-y-3">
        <div className="flex items-center justify-between px-0.5">
          <span className="text-xs font-semibold tracking-[-0.02em] uppercase text-zinc-500 dark:text-zinc-400">
            Recent Activity
          </span>
          <span className="text-xs font-mono font-semibold tracking-tight text-zinc-400 dark:text-zinc-500">
            {fileScans.length}
          </span>
        </div>

        <div className="glass-card overflow-hidden">
          {loading ? (
            <div className="py-12 text-center text-xs font-mono text-zinc-500">
              Loading...
            </div>
          ) : (
            <ScanHistoryTable scans={fileScans} />
          )}
        </div>
      </div>
    </div>
  );
}
