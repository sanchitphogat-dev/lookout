const colorMap = {
  low: {
    text: "text-emerald-500",
    pill: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20",
    bar: "bg-[#34D399]",
    dot: "bg-emerald-400",
  },
  medium: {
    text: "text-amber-500",
    pill: "bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20",
    bar: "bg-[#FBBF24]",
    dot: "bg-amber-400",
  },
  high: {
    text: "text-rose-500",
    pill: "bg-rose-500/10 text-rose-500 dark:text-rose-400 border border-rose-500/20",
    bar: "bg-[#F87171]",
    dot: "bg-rose-400",
  },
  critical: {
    text: "text-rose-500",
    pill: "bg-rose-500/10 text-rose-500 dark:text-rose-400 border border-rose-500/20",
    bar: "bg-[#F87171]",
    dot: "bg-rose-400",
  },
};

export default function RiskScoreCard({
  score = 0,
  level = "low",
  explanation = "",
  compact = false,
}) {
  const colors = colorMap[level] || colorMap.low;

  if (compact) {
    return (
      <span
        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold tracking-tight ${colors.pill}`}
      >
        <span className={`w-1.5 h-1.5 rounded-full ${colors.dot}`} />
        <span>{score}</span>
        <span className="capitalize">{level}</span>
      </span>
    );
  }

  return (
    <div className="glass-card p-5 sm:p-6 space-y-4">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold tracking-[-0.02em] uppercase text-zinc-500 dark:text-zinc-400">
          Risk Score
        </span>
        <span
          className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold tracking-tight capitalize ${colors.pill}`}
        >
          <span className={`w-1.5 h-1.5 rounded-full ${colors.dot}`} />
          {level}
        </span>
      </div>

      <div className="flex items-baseline gap-2">
        <span className="text-3xl font-bold tracking-tight text-zinc-900 dark:text-white">
          {score}
        </span>
        <span className="text-xs font-mono text-zinc-400 dark:text-zinc-500">/ 100</span>
      </div>

      <div className="w-full bg-zinc-200 dark:bg-white/[0.06] rounded-full h-1.5 overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-300 ${colors.bar}`}
          style={{ width: `${Math.max(score, 2)}%` }}
        />
      </div>

      {explanation && (
        <p className="text-xs font-normal tracking-[-0.01em] text-zinc-600 dark:text-zinc-400 leading-relaxed pt-2 border-t border-black/[0.04] dark:border-white/[0.04]">
          {explanation}
        </p>
      )}
    </div>
  );
}
