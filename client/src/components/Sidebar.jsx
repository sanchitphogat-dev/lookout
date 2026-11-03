import { NavLink } from "react-router-dom";
import {
  LayoutGrid,
  ShieldCheck,
  FileUp,
  Link2,
  HardDrive,
  SlidersHorizontal,
} from "lucide-react";
import ThemeToggle from "./ThemeToggle";
import { LookoutLogo } from "./LookoutLogo";

export { LookoutLogo };

const links = [
  { to: "/", label: "Dashboard", icon: LayoutGrid },
  { to: "/reports", label: "Reports", icon: ShieldCheck },
  { to: "/scan/file", label: "File Scan", icon: FileUp },
  { to: "/scan/url", label: "URL Scan", icon: Link2 },
  { to: "/scan/usb", label: "USB Media", icon: HardDrive },
  { to: "/settings", label: "Settings", icon: SlidersHorizontal },
];

export default function Sidebar() {
  return (
    <aside className="w-56 min-h-screen bg-white dark:bg-[#0E0F12] border-r border-black/[0.06] dark:border-white/[0.06] flex flex-col sticky top-0 h-screen z-20 select-none transition-colors duration-150">
      {/* Brand Header: Seamless flow into the #0E0F12 sidebar canvas, no enclosing borders */}
      <NavLink
        to="/"
        className="group px-3.5 py-4 mb-2 flex items-center gap-2.5 focus:outline-none"
      >
        <LookoutLogo className="w-5 h-5" />
        <span
          style={{ fontFamily: '"Plus Jakarta Sans", "DM Sans", sans-serif' }}
          className="text-[18px] font-bold tracking-[-0.03em] text-zinc-900 dark:text-[#FFFFFF] leading-none transition-all duration-200 group-hover:text-zinc-700 dark:group-hover:text-white/90 group-hover:brightness-110"
        >
          Lookout
        </span>
      </NavLink>

      {/* Essential Navigation Links */}
      <nav className="flex-1 px-3 py-2 space-y-1 overflow-y-auto">
        {links.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            end={link.to === "/"}
            className={({ isActive }) =>
              `group flex items-center gap-3 px-3 py-2 rounded-lg text-[13.5px] transition-colors duration-150 select-none ${
                isActive
                  ? "bg-black/[0.04] dark:bg-white/[0.06] border border-black/[0.06] dark:border-white/[0.08] text-zinc-900 dark:text-white font-semibold"
                  : "border border-transparent text-zinc-500 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-200 hover:bg-black/[0.03] dark:hover:bg-white/[0.03] font-medium"
              }`
            }
          >
            {({ isActive }) => (
              <>
                <link.icon
                  className={`w-[15px] h-[15px] shrink-0 transition-colors duration-150 ${
                    isActive
                      ? "text-zinc-900 dark:text-white"
                      : "text-zinc-400 dark:text-zinc-400 group-hover:text-zinc-800 dark:group-hover:text-zinc-200"
                  }`}
                  strokeWidth={1.5}
                />
                <span className="truncate tracking-[-0.015em]">{link.label}</span>
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* Sidebar Bottom: Minimal, compact footer row */}
      <div className="p-3 border-t border-black/[0.06] dark:border-white/[0.06] flex items-center justify-center">
        <ThemeToggle compact />
      </div>
    </aside>
  );
}
