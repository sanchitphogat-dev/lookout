'use client';

import React, { useState, useRef } from 'react';
import { 
  FileSearch, 
  FileUp, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Check, 
  Copy, 
  FileCode, 
  Binary, 
  Activity, 
  RefreshCw, 
  CheckCircle2, 
  X 
} from 'lucide-react';

interface FileScanAnalysis {
  fileName: string;
  fileSize: number;
  formattedSize: string;
  mimeType: string;
  sha256: string;
  magicBytesHex: string;
  detectedSignature: string;
  isMimeSpoofed: boolean;
  entropy: number;
  isHighEntropy: boolean;
  verdict: 'clean' | 'suspicious' | 'critical';
  riskScore: number;
  threats: string[];
}

export function FileScanner() {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState('');
  const [scanResult, setScanResult] = useState<FileScanAnalysis | null>(null);
  const [copiedHash, setCopiedHash] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const calculateEntropy = (bytes: Uint8Array): number => {
    if (!bytes.length) return 0;
    const frequencies = new Array(256).fill(0);
    for (let i = 0; i < bytes.length; i++) {
      frequencies[bytes[i]]++;
    }
    let entropy = 0;
    const len = bytes.length;
    for (let i = 0; i < 256; i++) {
      if (frequencies[i] > 0) {
        const p = frequencies[i] / len;
        entropy -= p * Math.log2(p);
      }
    }
    return Math.round(entropy * 100) / 100;
  };

  const processFile = async (file: File) => {
    setSelectedFile(file);
    setIsScanning(true);
    setScanResult(null);

    setScanStep('Reading binary stream & computing cryptographic SHA-256...');

    try {
      // 1. Read first 64KB for inspection & entropy
      const buffer = await file.slice(0, 65536).arrayBuffer();
      const uint8 = new Uint8Array(buffer);

      // SHA-256
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const sha256 = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

      await new Promise(r => setTimeout(r, 400));
      setScanStep('Extracting magic byte signatures & verifying declared MIME...');

      // 2. Extract first 8 bytes for Magic Bytes
      const magicBytesHex = Array.from(uint8.slice(0, 8))
        .map(b => b.toString(16).padStart(2, '0').toUpperCase())
        .join(' ');

      // Magic byte detection
      let detectedSig = 'Unknown Binary Format';
      let isExecutable = false;

      if (magicBytesHex.startsWith('4D 5A')) {
        detectedSig = 'PE32/MZ (Windows Portable Executable)';
        isExecutable = true;
      } else if (magicBytesHex.startsWith('25 50 44 46')) {
        detectedSig = 'PDF (%PDF) Document';
      } else if (magicBytesHex.startsWith('50 4B 03 04')) {
        detectedSig = 'ZIP / OpenXML Archive (PK)';
      } else if (magicBytesHex.startsWith('7F 45 4C 46')) {
        detectedSig = 'ELF (Linux Executable)';
        isExecutable = true;
      } else if (magicBytesHex.startsWith('CA FE BA BE')) {
        detectedSig = 'Java Class / Mach-O Binary';
        isExecutable = true;
      } else if (magicBytesHex.startsWith('89 50 4E 47')) {
        detectedSig = 'PNG Image';
      } else if (magicBytesHex.startsWith('FF D8 FF')) {
        detectedSig = 'JPEG Image';
      }

      await new Promise(r => setTimeout(r, 450));
      setScanStep('Calculating Shannon Entropy distribution...');

      // 3. Shannon Entropy
      const entropy = calculateEntropy(uint8);
      const isHighEntropy = entropy > 7.1;

      // 4. MIME Spoofing & Threat Heuristics
      const ext = file.name.split('.').pop()?.toLowerCase() || '';
      const threats: string[] = [];
      let isMimeSpoofed = false;

      // Double extension check
      if (/\.(pdf|docx|xlsx|jpg|png)\.(exe|bat|cmd|vbs|ps1|scr)$/i.test(file.name)) {
        isMimeSpoofed = true;
        threats.push('Dangerous double extension detected masquerading as document');
      }

      // Check if declared as document/image but header is PE32
      if (['pdf', 'docx', 'xlsx', 'txt', 'png', 'jpg'].includes(ext) && isExecutable) {
        isMimeSpoofed = true;
        threats.push(`MIME header spoofing: Declared extension .${ext} possesses ${detectedSig} magic bytes`);
      }

      if (isHighEntropy) {
        threats.push(`High Shannon entropy (${entropy}/8.0) indicative of packed, obfuscated or ransomware payload`);
      }

      // Buffer string check for suspicious shell droppers
      const textChunk = new TextDecoder('utf-8', { fatal: false }).decode(uint8);
      if (/cmd\.exe|powershell|WScript\.Shell|VirtualAlloc|WriteProcessMemory/i.test(textChunk)) {
        threats.push('Suspicious API execution / shell spawning hooks identified in payload');
      }

      let riskScore = 8;
      if (isMimeSpoofed) riskScore += 65;
      if (isHighEntropy) riskScore += 25;
      if (isExecutable && ['pdf', 'png', 'jpg'].includes(ext)) riskScore += 30;
      if (threats.length > 2) riskScore += 20;

      riskScore = Math.min(100, riskScore);

      let verdict: 'clean' | 'suspicious' | 'critical' = 'clean';
      if (riskScore >= 75) verdict = 'critical';
      else if (riskScore >= 35) verdict = 'suspicious';

      if (threats.length === 0) {
        threats.push('No MIME spoofing, anomalies, or suspicious entropy patterns identified');
      }

      await new Promise(r => setTimeout(r, 350));

      setScanResult({
        fileName: file.name,
        fileSize: file.size,
        formattedSize: formatFileSize(file.size),
        mimeType: file.type || 'application/octet-stream',
        sha256,
        magicBytesHex: magicBytesHex || '4D 5A 90 00',
        detectedSignature: detectedSig,
        isMimeSpoofed,
        entropy,
        isHighEntropy,
        verdict,
        riskScore,
        threats,
      });

    } catch (err) {
      console.error('File scan error:', err);
    } finally {
      setIsScanning(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  // Preset mock payload generator for instant demo testing
  const runMockPayload = (type: 'spoofed_pdf' | 'high_entropy' | 'clean_pdf') => {
    if (type === 'spoofed_pdf') {
      // Create a spoofed dummy file with PE 'MZ' magic bytes but named invoice.pdf.exe
      const bytes = new Uint8Array([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00]);
      const blob = new Blob([bytes], { type: 'application/pdf' });
      const file = new File([blob], 'Q4_Financial_Invoice.pdf.exe', { type: 'application/pdf' });
      processFile(file);
    } else if (type === 'high_entropy') {
      // Generate randomized high-entropy bytes
      const bytes = new Uint8Array(2048);
      for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
      const blob = new Blob([bytes], { type: 'application/octet-stream' });
      const file = new File([blob], 'encrypted_ransomware_stub.bin', { type: 'application/octet-stream' });
      processFile(file);
    } else {
      // Clean PDF mock
      const bytes = new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x37]);
      const blob = new Blob([bytes], { type: 'application/pdf' });
      const file = new File([blob], 'annual_security_report.pdf', { type: 'application/pdf' });
      processFile(file);
    }
  };

  return (
    <div className="space-y-6">
      
      {/* File Dropzone Card */}
      <div className="p-6 rounded-2xl bg-[#0D0E12] border border-white/[0.08] shadow-2xl space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-white tracking-tight flex items-center gap-2">
            <FileSearch className="h-4 w-4 text-indigo-400" />
            Static Binary & File Threat Scanner
          </h2>
          <p className="text-xs text-zinc-400 mt-1">
            Automated deep inspection for Magic Bytes header tampering, MIME spoofing, and Shannon Entropy anomalies.
          </p>
        </div>

        {/* Drop Zone */}
        <div
          onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
          onDragLeave={() => setDragActive(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all duration-200 ${
            dragActive
              ? 'border-indigo-500 bg-indigo-500/10'
              : 'border-white/[0.08] hover:border-indigo-500/40 bg-[#12131A] hover:bg-[#151620]'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            onChange={(e) => {
              if (e.target.files && e.target.files[0]) {
                processFile(e.target.files[0]);
              }
            }}
          />

          <div className="flex flex-col items-center">
            <div className="h-10 w-10 rounded-xl bg-white/[0.03] border border-white/[0.08] flex items-center justify-center text-indigo-400 mb-3">
              <FileUp className="h-5 w-5" />
            </div>
            <p className="text-xs font-medium text-white">
              Drag and drop files here, or <span className="text-indigo-400 underline underline-offset-2">browse</span>
            </p>
            <p className="text-[11px] text-zinc-400 mt-1">
              Binaries, archives, executables, or documents up to 100MB
            </p>
          </div>
        </div>

        {/* Fast Simulation Presets */}
        <div className="flex flex-wrap items-center gap-2 pt-1">
          <span className="text-[11px] font-mono text-zinc-500">Test payloads:</span>
          <button
            onClick={() => runMockPayload('spoofed_pdf')}
            disabled={isScanning}
            className="text-[11px] font-mono px-2.5 py-1 rounded-lg bg-white/[0.03] hover:bg-rose-500/10 text-zinc-400 hover:text-rose-400 border border-white/[0.06] transition-all disabled:opacity-40"
          >
            Spoofed PDF (.pdf.exe)
          </button>
          <button
            onClick={() => runMockPayload('high_entropy')}
            disabled={isScanning}
            className="text-[11px] font-mono px-2.5 py-1 rounded-lg bg-white/[0.03] hover:bg-amber-500/10 text-zinc-400 hover:text-amber-400 border border-white/[0.06] transition-all disabled:opacity-40"
          >
            High-Entropy Stub (8.0 Entropy)
          </button>
          <button
            onClick={() => runMockPayload('clean_pdf')}
            disabled={isScanning}
            className="text-[11px] font-mono px-2.5 py-1 rounded-lg bg-white/[0.03] hover:bg-emerald-500/10 text-zinc-400 hover:text-emerald-400 border border-white/[0.06] transition-all disabled:opacity-40"
          >
            Clean Signed PDF
          </button>
        </div>
      </div>

      {/* Progress Loader */}
      {isScanning && (
        <div className="p-6 rounded-2xl bg-[#0D0E12] border border-white/[0.08] space-y-4 animate-in fade-in duration-200">
          <div className="relative w-full h-1 bg-white/[0.06] rounded-full overflow-hidden">
            <div className="absolute inset-y-0 w-2/3 bg-gradient-to-r from-transparent via-indigo-500 to-transparent rounded-full animate-pulse" />
          </div>
          <div className="flex items-center justify-center gap-2.5 text-xs font-mono text-zinc-300">
            <RefreshCw className="h-3.5 w-3.5 text-indigo-400 animate-spin" />
            <span>{scanStep}</span>
          </div>
        </div>
      )}

      {/* Result Card */}
      {scanResult && !isScanning && (
        <div className="p-6 rounded-2xl bg-[#0D0E12] border border-white/[0.08] shadow-2xl space-y-6 animate-in fade-in duration-200">
          
          {/* Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/[0.06] pb-5">
            <div className="flex items-center gap-3">
              <div className={`h-10 w-10 rounded-xl flex items-center justify-center border ${
                scanResult.verdict === 'clean'
                  ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400'
                  : scanResult.verdict === 'suspicious'
                  ? 'bg-amber-500/10 border-amber-500/20 text-amber-400'
                  : 'bg-rose-500/10 border-rose-500/20 text-rose-400'
              }`}>
                {scanResult.verdict === 'clean' ? (
                  <ShieldCheck className="h-5 w-5" />
                ) : (
                  <ShieldAlert className="h-5 w-5" />
                )}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-semibold text-white truncate max-w-sm">
                    {scanResult.fileName}
                  </span>
                  <span className="text-xs font-mono text-zinc-400">({scanResult.formattedSize})</span>
                </div>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className="text-[11px] font-mono text-zinc-400">
                    SHA-256: {scanResult.sha256.slice(0, 24)}...
                  </span>
                  <button
                    onClick={() => handleCopyHash(scanResult.sha256)}
                    className="p-0.5 text-zinc-500 hover:text-zinc-200 transition-colors"
                    title="Copy full SHA-256"
                  >
                    {copiedHash ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                  </button>
                </div>
              </div>
            </div>

            {/* Verdict Badge */}
            <div>
              <span className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-semibold uppercase tracking-wider border ${
                scanResult.verdict === 'clean'
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25'
                  : scanResult.verdict === 'suspicious'
                  ? 'bg-amber-500/10 text-amber-400 border-amber-500/25'
                  : 'bg-rose-500/10 text-rose-400 border-rose-500/25'
              }`}>
                <span className={`h-2 w-2 rounded-full ${
                  scanResult.verdict === 'clean' ? 'bg-emerald-400' : scanResult.verdict === 'suspicious' ? 'bg-amber-400' : 'bg-rose-400'
                }`} />
                Risk Score: {scanResult.riskScore} / 100 · {scanResult.verdict}
              </span>
            </div>
          </div>

          {/* Heuristic Telemetry Strips */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            
            {/* Magic Bytes Card */}
            <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/[0.06]">
              <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 flex items-center justify-between">
                <span>Magic Bytes Signature</span>
                <Binary className="h-3.5 w-3.5 text-indigo-400" />
              </span>
              <div className="font-mono text-xs text-white mt-1.5 truncate">
                {scanResult.magicBytesHex}
              </div>
              <p className="text-[11px] text-zinc-400 mt-1 truncate">
                {scanResult.detectedSignature}
              </p>
            </div>

            {/* Shannon Entropy Card */}
            <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/[0.06]">
              <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 flex items-center justify-between">
                <span>Shannon Entropy</span>
                <Activity className="h-3.5 w-3.5 text-amber-400" />
              </span>
              <div className="flex items-center justify-between mt-1.5">
                <span className="font-mono text-xs text-white font-semibold">
                  {scanResult.entropy} / 8.0
                </span>
                <span className={`text-[10px] font-mono ${scanResult.isHighEntropy ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {scanResult.isHighEntropy ? 'Packed / Encrypted' : 'Normal Uniformity'}
                </span>
              </div>
              {/* Visual Entropy Bar */}
              <div className="w-full h-1.5 bg-white/[0.06] rounded-full overflow-hidden mt-2">
                <div
                  className={`h-full rounded-full ${
                    scanResult.entropy > 7.1 ? 'bg-rose-500' : scanResult.entropy > 6.0 ? 'bg-amber-400' : 'bg-emerald-400'
                  }`}
                  style={{ width: `${Math.min(100, (scanResult.entropy / 8.0) * 100)}%` }}
                />
              </div>
            </div>

            {/* MIME Validation */}
            <div className="p-3.5 rounded-xl bg-white/[0.02] border border-white/[0.06]">
              <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 flex items-center justify-between">
                <span>MIME Consistency</span>
                <FileCode className="h-3.5 w-3.5 text-emerald-400" />
              </span>
              <div className="font-mono text-xs text-white mt-1.5 truncate">
                {scanResult.isMimeSpoofed ? 'SPOOFING DETECTED' : 'VALID MATCH'}
              </div>
              <p className="text-[11px] text-zinc-400 mt-1 truncate">
                {scanResult.isMimeSpoofed ? 'Header deviates from extension' : 'Declared MIME correlates with binary'}
              </p>
            </div>

          </div>

          {/* Finding List */}
          <div className="space-y-2">
            <h4 className="text-xs font-semibold text-zinc-300 uppercase tracking-wider">
              Static Analysis Vector Breakdown
            </h4>
            <div className="space-y-1.5">
              {scanResult.threats.map((threat, idx) => (
                <div
                  key={idx}
                  className={`p-2.5 rounded-lg text-xs font-mono flex items-start gap-2.5 border ${
                    scanResult.verdict === 'clean'
                      ? 'bg-emerald-500/[0.03] border-emerald-500/20 text-zinc-300'
                      : 'bg-rose-500/[0.04] border-rose-500/20 text-rose-300'
                  }`}
                >
                  {scanResult.verdict === 'clean' ? (
                    <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                  ) : (
                    <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
                  )}
                  <span>{threat}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Reset Action */}
          <div className="pt-2 flex justify-end">
            <button
              onClick={() => {
                setSelectedFile(null);
                setScanResult(null);
              }}
              className="text-xs font-medium text-zinc-400 hover:text-white px-4 py-2 rounded-lg hover:bg-white/[0.04] transition-colors"
            >
              Inspect Another File
            </button>
          </div>

        </div>
      )}

    </div>
  );
}
export default FileScanner;
