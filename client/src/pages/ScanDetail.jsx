import { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft, Check } from "lucide-react";
import RiskScoreCard from "../components/RiskScoreCard";
import { getReportById } from "../services/api";

export default function ScanDetail() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getReportById(id)
      .then(setScan)
      .catch(() => setScan(null))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) {
    return (
      <div className="py-20 text-center text-xs font-mono text-zinc-500">
        Loading...
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="py-20 text-center space-y-3">
        <p className="text-xs text-zinc-500">Scan record not found</p>
        <Link
          to="/reports"
          className="text-xs text-[#5E6AD2] hover:underline"
        >
          &larr; Back to reports
        </Link>
      </div>
    );
  }

  const findings = Array.isArray(scan.findings_json)
    ? scan.findings_json
    : scan.findings_json?.findings || [];

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      <Link
        to="/reports"
        className="inline-flex items-center gap-1.5 text-xs font-semibold tracking-[-0.01em] text-zinc-400 hover:text-zinc-800 dark:text-zinc-500 dark:hover:text-zinc-200 transition-colors"
      >
        <ArrowLeft className="w-3.5 h-3.5" strokeWidth={1.5} />
        Back
      </Link>

      <div className="border-b border-black/[0.06] dark:border-white/[0.06] pb-3">
        <h1 className="text-xl font-bold tracking-[-0.03em] text-zinc-900 dark:text-zinc-100">
          Record
        </h1>
        <p className="font-mono text-[11px] text-zinc-400 dark:text-zinc-500 mt-0.5 break-all">
          {id}
        </p>
      </div>

      <div className="glass-card p-6">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-5 text-xs">
          <div>
            <span className="text-zinc-400 dark:text-zinc-500 block mb-1">Type</span>
            <span className="font-mono uppercase text-zinc-900 dark:text-zinc-100">{scan.type}</span>
          </div>
          <div className="sm:col-span-2">
            <span className="text-zinc-400 dark:text-zinc-500 block mb-1">Target</span>
            <span className="font-mono text-zinc-900 dark:text-zinc-100 break-all">{scan.target}</span>
          </div>
          <div>
            <span className="text-zinc-400 dark:text-zinc-500 block mb-1">Date</span>
            <span className="font-mono text-zinc-600 dark:text-zinc-400">
              {new Date(scan.created_at).toLocaleString([], {
                dateStyle: "medium",
                timeStyle: "short",
              })}
            </span>
          </div>
        </div>
      </div>

      <RiskScoreCard
        score={scan.risk_score}
        level={scan.risk_score >= 51 ? "high" : scan.risk_score >= 16 ? "medium" : "low"}
        explanation={scan.explanation}
      />

      <div className="glass-card p-6 space-y-3">
        <span className="text-xs uppercase tracking-[-0.02em] text-zinc-500 dark:text-zinc-400 block font-semibold">
          Findings ({findings.length})
        </span>
        {findings.length === 0 ? (
          <p className="text-xs text-emerald-500 flex items-center gap-1.5 font-medium tracking-tight">
            <Check className="w-3.5 h-3.5" strokeWidth={1.5} />
            Verified safe.
          </p>
        ) : (
          <div className="space-y-2">
            {findings.map((f, i) => (
              <div
                key={i}
                className="p-3 rounded-lg bg-black/[0.02] dark:bg-white/[0.02] border border-black/[0.06] dark:border-white/[0.04] text-xs flex items-baseline gap-2"
              >
                <span
                  className={`font-mono text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded ${
                    f.severity === "high" || f.severity === "critical"
                      ? "bg-rose-500/10 text-rose-400"
                      : f.severity === "medium"
                      ? "bg-amber-500/10 text-amber-400"
                      : "bg-emerald-500/10 text-emerald-400"
                  }`}
                >
                  {f.severity}
                </span>
                <span className="text-zinc-900 dark:text-zinc-200">{f.detail}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {scan.recommendation && (
        <div className="glass-card p-6 space-y-2">
          <span className="text-xs uppercase tracking-[-0.02em] text-zinc-500 dark:text-zinc-400 block font-semibold">
            Recommendation
          </span>
          <p className="text-xs font-normal tracking-[-0.01em] text-zinc-600 dark:text-zinc-400 leading-relaxed">
            {scan.recommendation}
          </p>
        </div>
      )}
    </div>
  );
}
