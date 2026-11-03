import { useLocation } from "react-router-dom";
import { BarChart3, Info, X } from "lucide-react";
import ThemeToggle from "./ThemeToggle";
import { useTelemetry } from "../context/TelemetryContext";
import { useUsbWatcher } from "../hooks/useUsbWatcher";
import { useState } from "react";

export default function Navbar() {
  const location = useLocation();
  const { toggleTelemetry, isTelemetryOpen, stats } = useTelemetry();
  const { isDaemonConnected } = useUsbWatcher();
  const [showTroubleshoot, setShowTroubleshoot] = useState(false);

  const getBreadcrumb = () => {
    const path = location.pathname;
    if (path.startsWith("/scan/file")) return "File Scan";
    if (path.startsWith("/scan/url")) return "URL Scan";
    if (path.startsWith("/scan/usb")) return "USB Media";
    if (path.startsWith("/reports/")) return "Record";
    if (path.startsWith("/reports")) return "Reports";
    if (path.startsWith("/settings")) return "Settings";
    return "Overview";
  };

  const getRiskCount = (arr, level) => arr?.find((i) => i.level === level)?.count || 0;
  const activeThreats = (getRiskCount(stats?.byRisk || [], "high") + getRiskCount(stats?.byRisk || [], "medium"));

  return (
    <>
      <header className="h-13 bg-white/80 dark:bg-[#0B0C0E]/80 backdrop-blur-md border-b border-black/[0.06] dark:border-white/[0.06] flex items-center justify-between px-5 sm:px-7 sticky top-0 z-30 select-none transition-colors duration-150">
        {/* Breadcrumb Path */}
        <div className="flex items-center gap-2">
          <span className="text-[12px] font-medium tracking-[-0.01em] text-zinc-400 dark:text-zinc-500">
            Lookout
          </span>
          <span className="text-[12px] text-zinc-300 dark:text-zinc-600">/</span>
          <span className="text-[12px] font-semibold tracking-[-0.015em] text-zinc-900 dark:text-zinc-100">
            {getBreadcrumb()}
          </span>
        </div>

        {/* Right Navigation Controls */}
        <div className="flex items-center gap-3">
          {/* Sleek Minimal Telemetry Trigger */}
          <button
            type="button"
            onClick={toggleTelemetry}
            aria-expanded={isTelemetryOpen}
            aria-label="Toggle Telemetry Drawer"
            className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg text-xs font-semibold tracking-[-0.01em] transition-all duration-150 cursor-pointer group ${
              isTelemetryOpen
                ? "bg-[#5E6AD2]/10 text-[#5E6AD2] border border-[#5E6AD2]/30 dark:border-[#5E6AD2]/40"
                : "text-zinc-600 dark:text-zinc-300 hover:text-zinc-900 dark:hover:text-white bg-black/[0.03] dark:bg-white/[0.04] hover:bg-black/[0.06] dark:hover:bg-white/[0.07] border border-black/[0.06] dark:border-white/[0.08]"
            }`}
            title="Open Telemetry Drawer (T or ⌘K)"
          >
            <BarChart3 className="w-3.5 h-3.5 text-[#5E6AD2] group-hover:scale-110 transition-transform" strokeWidth={1.5} />
            <span>Telemetry</span>

            {activeThreats > 0 && (
              <span className="w-1.5 h-1.5 rounded-full bg-rose-500 shrink-0" />
            )}

            <kbd className="hidden sm:inline-flex items-center px-1.5 py-0.2 text-[10px] font-mono text-zinc-400 dark:text-zinc-500 bg-black/[0.04] dark:bg-white/[0.06] border border-black/[0.06] dark:border-white/[0.08] rounded">
              T
            </kbd>
          </button>

          {/* Live System Status Pill */}
          {isDaemonConnected ? (
            <div 
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20"
              title="Local hardware daemon listening for removable media mounts"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse shrink-0" />
              <span className="text-[11px] font-medium tracking-tight text-emerald-700 dark:text-emerald-400">
                USB Sentinel: Active (Port 48201)
              </span>
            </div>
          ) : (
            <button 
              onClick={() => setShowTroubleshoot(true)}
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-500/10 border border-amber-500/20 cursor-pointer hover:bg-amber-500/20 transition-colors"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-amber-500 shrink-0" />
              <span className="text-[11px] font-medium tracking-tight text-amber-700 dark:text-amber-400">
                USB Sentinel: Offline (Web Fallback Ready)
              </span>
            </button>
          )}

          <div className="h-3.5 w-[1px] bg-black/[0.06] dark:border-white/[0.06]" />

          <ThemeToggle />
        </div>
      </header>

      {/* Troubleshooting Drawer / Modal */}
      {showTroubleshoot && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
          <div className="bg-white dark:bg-[#121316] border border-black/10 dark:border-white/10 rounded-xl p-6 max-w-md w-full shadow-2xl relative">
            <button 
              onClick={() => setShowTroubleshoot(false)}
              className="absolute top-4 right-4 text-zinc-400 hover:text-zinc-900 dark:hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-amber-500/10 flex items-center justify-center">
                <Info className="w-5 h-5 text-amber-600 dark:text-amber-400" />
              </div>
              <h3 className="text-lg font-semibold text-zinc-900 dark:text-white">Sentinel Offline</h3>
            </div>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 mb-4 leading-relaxed">
              The Lookout local hardware daemon is not connected. This daemon is required to automatically detect and scan USB drives when they are plugged in.
            </p>
            <div className="bg-zinc-100 dark:bg-zinc-900 p-4 rounded-lg font-mono text-sm text-zinc-800 dark:text-zinc-200 border border-zinc-200 dark:border-zinc-800">
              <div className="text-xs text-zinc-500 mb-1">Run this command in your terminal:</div>
              npm run usb:watch
            </div>
            <div className="mt-6 flex justify-end">
              <button 
                onClick={() => setShowTroubleshoot(false)}
                className="px-4 py-2 bg-zinc-900 dark:bg-white text-white dark:text-black font-medium text-sm rounded-lg hover:bg-zinc-800 dark:hover:bg-zinc-100 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
