import { Link } from "react-router-dom";
import RiskScoreCard from "./RiskScoreCard";
import { ArrowUpRight } from "lucide-react";

function getRiskLevel(score) {
  if (score >= 51) return "high";
  if (score >= 16) return "medium";
  return "low";
}

export default function ScanHistoryTable({ scans = [] }) {
  if (scans.length === 0) {
    return (
      <div className="text-center py-12 text-xs font-mono text-zinc-400 dark:text-[#5F6368]">
        No scans recorded yet.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs font-sans">
        <thead>
          <tr className="border-b border-black/[0.06] dark:border-white/[0.07] bg-zinc-50/50 dark:bg-white/[0.01] text-[11px] font-semibold tracking-wider uppercase text-zinc-500 dark:text-zinc-400">
            <th className="py-3 px-5 font-semibold">Type</th>
            <th className="py-3 px-5 font-semibold">Target</th>
            <th className="py-3 px-5 font-semibold">Verdict</th>
            <th className="py-3 px-5 font-semibold">Date</th>
            <th className="py-3 px-5 text-right font-semibold">Details</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-black/[0.06] dark:divide-white/[0.07]">
          {scans.map((scan) => (
            <tr
              key={scan.id}
              className="hover:bg-black/[0.02] dark:hover:bg-white/[0.015] transition-colors duration-150"
            >
              <td className="py-3.5 px-5 font-mono text-[11px] uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                {scan.type}
              </td>
              <td className="py-3.5 px-5 font-mono text-xs text-zinc-900 dark:text-zinc-100 max-w-sm truncate" title={scan.target}>
                {scan.target}
              </td>
              <td className="py-3.5 px-5">
                <RiskScoreCard
                  score={scan.risk_score}
                  level={getRiskLevel(scan.risk_score)}
                  compact
                />
              </td>
              <td className="py-3.5 px-5 font-mono text-xs text-zinc-400 dark:text-zinc-500">
                {new Date(scan.created_at).toLocaleDateString([], {
                  month: "short",
                  day: "numeric",
                  year: "numeric",
                })}
              </td>
              <td className="py-3.5 px-5 text-right">
                <Link
                  to={`/reports/${scan.id}`}
                  className="inline-flex items-center gap-1 text-xs font-semibold tracking-[-0.01em] text-zinc-400 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white transition-colors"
                >
                  <span>View</span>
                  <ArrowUpRight className="w-3 h-3" strokeWidth={1.5} />
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
