import { useState, useEffect } from "react";
import { Download, ChevronLeft, ChevronRight, Filter } from "lucide-react";
import ScanHistoryTable from "../components/ScanHistoryTable";
import { getReports } from "../services/api";

export default function Reports() {
  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState("");
  const [riskFilter, setRiskFilter] = useState("");

  const fetchScans = (targetPage = page) => {
    setLoading(true);
    const params = { page: targetPage };
    if (typeFilter) params.type = typeFilter;
    if (riskFilter) params.risk = riskFilter;
    getReports(params)
      .then((data) => {
        setScans(data.scans || []);
        setTotal(data.total || 0);
        setPages(data.pages || 1);
        setPage(data.page || 1);
      })
      .catch(() => setScans([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchScans(1);
  }, [typeFilter, riskFilter]);

  const exportCsv = () => {
    const escapeCsv = (val) => {
      const str = String(val);
      if (str.includes('"') || str.includes(",") || str.includes("\n")) {
        return `"${str.replace(/"/g, '""')}"`;
      }
      return str;
    };
    const headers = ["Type", "Target", "Risk Score", "Date", "ID"];
    const rows = scans.map((s) => [s.type, escapeCsv(s.target), s.risk_score, s.created_at, s.id]);
    const csv = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "lookout-reports.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-black/[0.06] dark:border-white/[0.06] pb-3">
        <h1 className="text-xl font-bold tracking-[-0.03em] text-zinc-900 dark:text-zinc-100">
          Reports
        </h1>
        <button
          onClick={exportCsv}
          className="inline-flex items-center gap-1.5 bg-black/[0.04] dark:bg-white/[0.04] hover:bg-black/[0.07] dark:hover:bg-white/[0.08] border border-black/[0.08] dark:border-white/[0.08] text-zinc-900 dark:text-zinc-200 text-xs font-semibold tracking-[-0.01em] px-3.5 py-1.5 rounded-lg transition-colors cursor-pointer"
        >
          <Download className="w-3.5 h-3.5 text-zinc-400 dark:text-zinc-500" strokeWidth={1.5} />
          <span>Export</span>
        </button>
      </div>

      {/* Filter Row */}
      <div className="flex items-center gap-2.5 flex-wrap">
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="bg-black/[0.03] dark:bg-black/40 border border-black/[0.08] dark:border-white/[0.08] focus:border-[#5E6AD2] focus:ring-1 focus:ring-[#5E6AD2]/50 rounded-lg px-3 py-1.5 text-xs text-zinc-900 dark:text-zinc-200 focus:outline-none transition-colors"
        >
          <option value="">All Vectors</option>
          <option value="file">File</option>
          <option value="url">URL</option>
          <option value="usb">USB</option>
        </select>
        <select
          value={riskFilter}
          onChange={(e) => setRiskFilter(e.target.value)}
          className="bg-black/[0.03] dark:bg-black/40 border border-black/[0.08] dark:border-white/[0.08] focus:border-[#5E6AD2] focus:ring-1 focus:ring-[#5E6AD2]/50 rounded-lg px-3 py-1.5 text-xs text-zinc-900 dark:text-zinc-200 focus:outline-none transition-colors"
        >
          <option value="">All Tiers</option>
          <option value="high">Threat</option>
          <option value="medium">Warning</option>
          <option value="low">Clean</option>
        </select>
      </div>

      {/* Table Container */}
      <div className="glass-card overflow-hidden">
        {loading ? (
          <div className="text-center py-14 text-xs font-mono text-zinc-500">
            Loading...
          </div>
        ) : (
          <ScanHistoryTable scans={scans} />
        )}
      </div>

      {/* Pagination */}
      {pages > 1 && (
        <div className="flex items-center justify-between text-xs text-zinc-500">
          <button
            onClick={() => fetchScans(page - 1)}
            disabled={page <= 1 || loading}
            className="flex items-center gap-1 bg-black/[0.03] dark:bg-white/[0.04] border border-black/[0.08] dark:border-white/[0.08] disabled:opacity-40 text-zinc-900 dark:text-zinc-200 px-3 py-1.5 rounded-lg text-xs font-semibold tracking-[-0.01em] transition-colors cursor-pointer disabled:cursor-not-allowed"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
            Previous
          </button>
          <span className="font-mono text-[11px] font-semibold tracking-tight">
            {page} / {pages}
          </span>
          <button
            onClick={() => fetchScans(page + 1)}
            disabled={page >= pages || loading}
            className="flex items-center gap-1 bg-black/[0.03] dark:bg-white/[0.04] border border-black/[0.08] dark:border-white/[0.08] disabled:opacity-40 text-zinc-900 dark:text-zinc-200 px-3 py-1.5 rounded-lg text-xs font-semibold tracking-[-0.01em] transition-colors cursor-pointer disabled:cursor-not-allowed"
          >
            Next
            <ChevronRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}
    </div>
  );
}
