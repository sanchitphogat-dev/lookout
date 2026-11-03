import { Sun, Moon } from "lucide-react";
import { useTheme } from "../context/ThemeContext";

export default function ThemeToggle({ className = "", compact = false }) {
  const { theme, toggleTheme, setTheme } = useTheme();
  const isDark = theme === "dark";

  return (
    <div
      role="radiogroup"
      aria-label="Theme toggle"
      className={`inline-flex items-center p-0.5 rounded-full bg-zinc-200/80 dark:bg-[#141519] border border-zinc-300/80 dark:border-[rgba(255,255,255,0.08)] relative select-none transition-colors duration-150 ${className}`}
    >
      {/* Sliding Indicator Pill with 150ms ease-out transition */}
      <div
        className={`absolute top-0.5 bottom-0.5 w-6 rounded-full bg-white dark:bg-[#222328] shadow-xs transition-transform duration-150 ease-out pointer-events-none ${
          isDark ? "translate-x-6" : "translate-x-0"
        }`}
      />

      {/* Light Option (Sun) */}
      <button
        type="button"
        role="radio"
        aria-checked={!isDark}
        aria-label="Light mode"
        onClick={() => setTheme("light")}
        className={`relative z-10 w-6 h-6 flex items-center justify-center rounded-full transition-colors duration-150 cursor-pointer ${
          !isDark
            ? "text-zinc-900"
            : "text-zinc-500 hover:text-zinc-700 dark:text-[#5F6368] dark:hover:text-[#8A8F98]"
        }`}
        title="Switch to Light mode"
      >
        <Sun className="w-3.5 h-3.5" strokeWidth={1.5} />
      </button>

      {/* Dark Option (Moon) */}
      <button
        type="button"
        role="radio"
        aria-checked={isDark}
        aria-label="Dark mode"
        onClick={() => setTheme("dark")}
        className={`relative z-10 w-6 h-6 flex items-center justify-center rounded-full transition-colors duration-150 cursor-pointer ${
          isDark
            ? "text-[#EDEDED]"
            : "text-zinc-500 hover:text-zinc-700 dark:text-[#5F6368] dark:hover:text-[#8A8F98]"
        }`}
        title="Switch to Linear Dark mode"
      >
        <Moon className="w-3.5 h-3.5" strokeWidth={1.5} />
      </button>
    </div>
  );
}
