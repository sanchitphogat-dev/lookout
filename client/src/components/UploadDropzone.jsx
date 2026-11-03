import { useState, useCallback } from "react";
import { FileUp, Check } from "lucide-react";

export default function UploadDropzone({ onFileSelect, disabled = false }) {
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);

  const handleDrag = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDragIn = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  }, []);

  const handleDragOut = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault();
      e.stopPropagation();
      setIsDragging(false);
      if (disabled) return;
      const files = e.dataTransfer.files;
      if (files && files.length > 0) {
        setSelectedFile(files[0]);
        onFileSelect?.(files[0]);
      }
    },
    [onFileSelect, disabled]
  );

  const handleFileInput = useCallback(
    (e) => {
      const files = e.target.files;
      if (files && files.length > 0) {
        setSelectedFile(files[0]);
        onFileSelect?.(files[0]);
      }
    },
    [onFileSelect]
  );

  return (
    <div
      onDragEnter={handleDragIn}
      onDragLeave={handleDragOut}
      onDragOver={handleDrag}
      onDrop={handleDrop}
      className={`group relative border border-dashed rounded-xl p-8 text-center transition-colors duration-200 cursor-pointer ${
        isDragging
          ? "border-indigo-500/60 bg-indigo-500/[0.04]"
          : selectedFile
          ? "border-emerald-500/40 bg-emerald-500/[0.02]"
          : "border-zinc-300 dark:border-white/[0.09] hover:border-indigo-500/40 dark:hover:border-indigo-500/40 bg-zinc-50/60 dark:bg-[#141519]"
      } ${disabled ? "opacity-50 cursor-not-allowed" : ""}`}
    >
      <input
        type="file"
        onChange={handleFileInput}
        disabled={disabled}
        className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
      />
      {selectedFile ? (
        <div className="flex flex-col items-center">
          <div className="w-11 h-11 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-500 group-hover:-translate-y-1 transition-transform duration-200">
            <Check className="w-5 h-5" strokeWidth={1.5} />
          </div>
          <p className="text-[15px] font-mono font-semibold text-zinc-900 dark:text-zinc-100 tracking-tight mt-3">
            {selectedFile.name}
          </p>
          <p className="text-[12px] font-mono text-zinc-500 mt-1">
            {(selectedFile.size / 1024).toFixed(1)} KB
          </p>
        </div>
      ) : (
        <div className="flex flex-col items-center">
          <div className="w-11 h-11 rounded-xl bg-black/[0.03] dark:bg-white/[0.03] border border-black/[0.06] dark:border-white/[0.06] flex items-center justify-center text-zinc-400 group-hover:-translate-y-1 transition-transform duration-200">
            <FileUp className="w-5 h-5" strokeWidth={1.5} />
          </div>
          <p className="text-[15px] font-semibold text-zinc-900 dark:text-zinc-100 tracking-tight mt-3">
            Drop files to analyze
          </p>
          <p className="text-[12px] text-zinc-500 mt-1">
            Supports binaries, archives, documents up to 100MB
          </p>
        </div>
      )}
    </div>
  );
}
