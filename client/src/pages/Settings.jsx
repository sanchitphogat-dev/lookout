import { useState, useEffect } from "react";
import { Plus, X } from "lucide-react";
import { getSettings, saveSettings } from "../services/api";
import { useTheme } from "../context/ThemeContext";
import ThemeToggle from "../components/ThemeToggle";

export default function Settings() {
  const { theme, setTheme } = useTheme();
  const [extensions, setExtensions] = useState([]);
  const [hashes, setHashes] = useState([]);
  const [keywords, setKeywords] = useState([]);
  const [newExt, setNewExt] = useState("");
  const [newHash, setNewHash] = useState("");
  const [newKeyword, setNewKeyword] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveMsg, setSaveMsg] = useState("");

  useEffect(() => {
    getSettings()
      .then((data) => {
        setExtensions(data.extensions || []);
        setHashes(data.hashes || []);
        setKeywords(data.keywords || []);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const addExtension = () => {
    if (newExt && !extensions.includes(newExt)) {
      setExtensions([...extensions, newExt]);
      setNewExt("");
    }
  };

  const removeExtension = (ext) => {
    setExtensions(extensions.filter((e) => e !== ext));
  };

  const addHash = () => {
    if (newHash && !hashes.includes(newHash)) {
      setHashes([...hashes, newHash]);
      setNewHash("");
    }
  };

  const removeHash = (hash) => {
    setHashes(hashes.filter((h) => h !== hash));
  };

  const addKeyword = () => {
    if (newKeyword && !keywords.includes(newKeyword)) {
      setKeywords([...keywords, newKeyword]);
      setNewKeyword("");
    }
  };

  const removeKeyword = (kw) => {
    setKeywords(keywords.filter((k) => k !== kw));
  };

  const handleSave = async () => {
    setSaving(true);
    setSaveMsg("");
    try {
      await saveSettings({ extensions, hashes, keywords });
      setSaveMsg("Settings saved.");
      setTimeout(() => setSaveMsg(""), 3000);
    } catch {
      setSaveMsg("Save failed.");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="py-20 text-center text-xs font-mono text-zinc-500">
        Loading...
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-3xl mx-auto">
      <div className="flex items-center justify-between border-b border-black/[0.06] dark:border-white/[0.06] pb-3">
        <h1 className="text-xl font-bold tracking-[-0.03em] text-zinc-900 dark:text-zinc-100">
          Settings
        </h1>
        <button
          onClick={handleSave}
          disabled={saving}
          className="bg-[#5E6AD2] hover:bg-[#4F46E5] disabled:bg-zinc-200 dark:disabled:bg-white/[0.05] disabled:text-zinc-400 dark:disabled:text-zinc-600 text-white font-semibold tracking-[-0.01em] text-xs px-4 py-2 rounded-lg transition-all duration-150 cursor-pointer disabled:cursor-not-allowed shadow-xs"
        >
          {saving ? "Saving..." : "Save"}
        </button>
      </div>

      {saveMsg && (
        <div
          className={`p-3 rounded-lg text-xs font-mono border ${
            saveMsg.includes("failed")
              ? "bg-rose-500/10 border-rose-500/20 text-rose-500"
              : "bg-emerald-500/10 border-emerald-500/20 text-emerald-500"
          }`}
        >
          {saveMsg}
        </div>
      )}

      {/* Interface Theme */}
      <div className="glass-card p-6 flex items-center justify-between">
        <div>
          <span className="text-xs font-semibold tracking-[-0.02em] uppercase text-zinc-700 dark:text-zinc-300 block">
            Theme
          </span>
          <p className="text-xs font-normal tracking-[-0.01em] text-zinc-400 dark:text-zinc-500 mt-0.5 leading-relaxed">
            {theme === "dark" ? "Dark Mode" : "Light Mode"}
          </p>
        </div>
        <ThemeToggle />
      </div>

      {/* Restricted Extensions */}
      <div className="glass-card p-6 space-y-4">
        <span className="text-xs font-semibold tracking-[-0.02em] uppercase text-zinc-700 dark:text-zinc-300 block">
          Restricted Extensions
        </span>
        <div className="flex gap-2">
          <input
            type="text"
            value={newExt}
            onChange={(e) => setNewExt(e.target.value)}
            placeholder=".dll, .exe, .sh"
            className="flex-1 bg-black/[0.02] dark:bg-black/30 border border-black/[0.08] dark:border-white/[0.08] focus:border-[#5E6AD2] focus:ring-1 focus:ring-[#5E6AD2]/50 rounded-lg px-3 py-1.5 text-xs font-mono text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-600 focus:outline-none transition-colors"
            onKeyDown={(e) => e.key === "Enter" && addExtension()}
          />
          <button
            onClick={addExtension}
            className="bg-black/[0.04] dark:bg-white/[0.04] hover:bg-black/[0.08] dark:hover:bg-white/[0.08] border border-black/[0.08] dark:border-white/[0.08] text-zinc-900 dark:text-zinc-200 px-3.5 py-1.5 rounded-lg text-xs font-semibold tracking-[-0.01em] transition-colors cursor-pointer"
          >
            Add
          </button>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {extensions.map((ext) => (
            <span
              key={ext}
              className="inline-flex items-center gap-1.5 bg-black/[0.03] dark:bg-white/[0.03] border border-black/[0.06] dark:border-white/[0.06] rounded-md px-2.5 py-1 text-xs font-mono text-zinc-900 dark:text-zinc-200"
            >
              {ext}
              <button
                onClick={() => removeExtension(ext)}
                className="text-zinc-400 hover:text-rose-400 transition-colors cursor-pointer"
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
        </div>
      </div>

      {/* Known-Bad Hashes */}
      <div className="glass-card p-6 space-y-4">
        <span className="text-xs font-semibold tracking-[-0.02em] uppercase text-zinc-700 dark:text-zinc-300 block">
          Known-Bad Hashes (SHA-256)
        </span>
        <div className="flex gap-2">
          <input
            type="text"
            value={newHash}
            onChange={(e) => setNewHash(e.target.value)}
            placeholder="64-character SHA-256 hash..."
            className="flex-1 bg-black/[0.02] dark:bg-black/30 border border-black/[0.08] dark:border-white/[0.08] focus:border-[#5E6AD2] focus:ring-1 focus:ring-[#5E6AD2]/50 rounded-lg px-3 py-1.5 text-xs font-mono text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-600 focus:outline-none transition-colors"
            onKeyDown={(e) => e.key === "Enter" && addHash()}
          />
          <button
            onClick={addHash}
            className="bg-black/[0.04] dark:bg-white/[0.04] hover:bg-black/[0.08] dark:hover:bg-white/[0.08] border border-black/[0.08] dark:border-white/[0.08] text-zinc-900 dark:text-zinc-200 px-3.5 py-1.5 rounded-lg text-xs font-semibold tracking-[-0.01em] transition-colors cursor-pointer"
          >
            Add
          </button>
        </div>
        <div className="space-y-1.5 max-h-48 overflow-y-auto">
          {hashes.map((hash) => (
            <div
              key={hash}
              className="flex items-center justify-between bg-black/[0.02] dark:bg-white/[0.02] border border-black/[0.06] dark:border-white/[0.06] rounded-lg px-3 py-2 text-xs font-mono text-zinc-600 dark:text-zinc-400"
            >
              <span className="break-all">{hash}</span>
              <button
                onClick={() => removeHash(hash)}
                className="text-zinc-400 hover:text-rose-400 ml-2 shrink-0 transition-colors cursor-pointer"
              >
                <X className="w-3 h-3" />
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Suspicious Keywords */}
      <div className="glass-card p-6 space-y-4">
        <span className="text-xs font-semibold tracking-[-0.02em] uppercase text-zinc-700 dark:text-zinc-300 block">
          Suspicious Keywords
        </span>
        <div className="flex gap-2">
          <input
            type="text"
            value={newKeyword}
            onChange={(e) => setNewKeyword(e.target.value)}
            placeholder="keylogger, trojan, crack"
            className="flex-1 bg-black/[0.02] dark:bg-black/30 border border-black/[0.08] dark:border-white/[0.08] focus:border-[#5E6AD2] focus:ring-1 focus:ring-[#5E6AD2]/50 rounded-lg px-3 py-1.5 text-xs font-mono text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-600 focus:outline-none transition-colors"
            onKeyDown={(e) => e.key === "Enter" && addKeyword()}
          />
          <button
            onClick={addKeyword}
            className="bg-black/[0.04] dark:bg-white/[0.04] hover:bg-black/[0.08] dark:hover:bg-white/[0.08] border border-black/[0.08] dark:border-white/[0.08] text-zinc-900 dark:text-zinc-200 px-3.5 py-1.5 rounded-lg text-xs font-semibold tracking-[-0.01em] transition-colors cursor-pointer"
          >
            Add
          </button>
        </div>
        <div className="flex flex-wrap gap-1.5">
          {keywords.map((kw) => (
            <span
              key={kw}
              className="inline-flex items-center gap-1.5 bg-black/[0.03] dark:bg-white/[0.03] border border-black/[0.06] dark:border-white/[0.06] rounded-md px-2.5 py-1 text-xs font-mono text-zinc-900 dark:text-zinc-200"
            >
              {kw}
              <button
                onClick={() => removeKeyword(kw)}
                className="text-zinc-400 hover:text-rose-400 transition-colors cursor-pointer"
              >
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
