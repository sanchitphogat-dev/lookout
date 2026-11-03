/**
 * Lookout File Threat Scanning Engine
 * Architecture: Hash-First + Local Heuristics
 *   Layer 1 — VirusTotal v3 threat-intelligence hash query
 *   Layer 2 — Binary heuristics (magic bytes, Shannon entropy, exploit strings)
 *   Layer 3 — Consensus scoring & verdict classification
 *
 * @module fileScanner
 */

"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// ─── Environment Loading ──────────────────────────────────────────────────────

function isPlaceholderKey(val) {
  if (!val || typeof val !== "string") return true;
  const t = val.trim();
  return (
    !t ||
    t === "undefined" ||
    t === "null" ||
    t.startsWith("your_") ||
    t.includes("_key_here") ||
    t === "REPLACE_ME"
  );
}

function loadEnvConfig() {
  const candidates = [
    path.resolve(__dirname, "..", "..", ".env"),
    path.resolve(__dirname, "..", "..", ".env.local"),
    path.resolve(__dirname, "..", ".env"),
    path.resolve(__dirname, "..", ".env.local"),
  ];

  for (const envPath of candidates) {
    try {
      if (!fs.existsSync(envPath)) continue;
      const lines = fs.readFileSync(envPath, "utf-8").split(/\r?\n/);
      for (const raw of lines) {
        const line = raw.trim().replace(/^export\s+/i, "");
        if (!line || line.startsWith("#")) continue;
        const eq = line.indexOf("=");
        if (eq === -1) continue;
        const key = line.slice(0, eq).trim();
        let val = line.slice(eq + 1).trim();
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.slice(1, -1).trim();
        }
        if (!key || !val) continue;
        if (!isPlaceholderKey(val) || !process.env[key]) {
          process.env[key] = val;
        }
      }
    } catch {
      // silent
    }
  }

  // Alias resolution
  const vtAliases = [
    process.env.VIRUSTOTAL_API_KEY,
    process.env.VITE_VIRUSTOTAL_API_KEY,
    process.env.VT_API_KEY,
    process.env.VIRUS_TOTAL_API_KEY,
  ];
  const validVt = vtAliases.find((v) => !isPlaceholderKey(v));
  if (validVt) process.env.VIRUSTOTAL_API_KEY = validVt.trim();
}

loadEnvConfig();

// ─── Constants ────────────────────────────────────────────────────────────────

const VT_TIMEOUT_MS = 5000;
const MAX_STRING_SCAN_BYTES = 256 * 1024; // 256 KB
const HIGH_ENTROPY_THRESHOLD = 7.3;

const IMAGE_SIGNATURES = {
  png: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
  jpg: [0xFF, 0xD8, 0xFF],
  jpeg: [0xFF, 0xD8, 0xFF],
  gif: [0x47, 0x49, 0x46, 0x38],
  webp: [0x52, 0x49, 0x46, 0x46] // Followed by 'WEBP' at offset 8
};

function isValidImageHeader(buffer, ext) {
  if (!buffer || !ext) return false;
  const cleanExt = ext.replace('.', '').toLowerCase();
  const signature = IMAGE_SIGNATURES[cleanExt];
  if (!signature) return false;
  if (buffer.length < signature.length) return false;

  for (let i = 0; i < signature.length; i++) {
    if (buffer[i] !== signature[i]) return false;
  }
  if (cleanExt === 'webp' && buffer.length >= 12) {
    if (
      buffer[8] !== 0x57 ||
      buffer[9] !== 0x45 ||
      buffer[10] !== 0x42 ||
      buffer[11] !== 0x50
    ) {
      return false;
    }
  }
  return true;
}

const IMAGE_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp"
]);

const EXCLUDED_MEDIA_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico", ".mp4"
]);

const ALLOWED_SCRIPT_EXTENSIONS = new Set([
  ".bat", ".cmd", ".vbs", ".ps1", ".js", ".sh", ".htm", ".html", ".svg", ".xml"
]);

/** File extensions considered non-archive for entropy flagging (exempts compressed media) */
const NON_ARCHIVE_EXTENSIONS = new Set([
  ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
  ".txt", ".csv", ".html", ".htm", ".js", ".ts", ".py", ".sh",
  ".bat", ".ps1", ".vbs",
  ".exe", ".dll", ".sys",
]);

/** Extensions considered "safe" that should NOT have executable magic bytes */
const EXPECTED_NON_EXECUTABLE_EXTENSIONS = new Set([
  ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt",
  ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
  ".txt", ".csv", ".html", ".htm",
]);

/** Suspicious exploit strings for binary content scanning */
const PDF_EXPLOIT_STRINGS = ["/JavaScript", "/Launch", "/EmbeddedFiles", "/OpenAction"];
const SCRIPT_EXPLOIT_STRINGS = [
  "powershell.exe -enc",
  "WScript.Shell",
  "AutoOpen()",
  "cmd.exe /c",
  "mshta.exe",
  "regsvr32.exe",
  "certutil.exe -decode",
  "bitsadmin /transfer",
];

/**
 * Dropper detection: remote-download triggers (must have ≥1 to qualify).
 * These indicate the file retrieves a secondary payload from a remote host.
 */
const DROPPER_DOWNLOAD_TRIGGERS = [
  "ServerXMLHTTP",
  "XMLHTTP",
  "Invoke-WebRequest",
  "wget ",
  "curl ",
  "bitsadmin",
  "URLDownloadToFile",
  "DownloadFile(",
  "Net.WebClient",
];

/**
 * Dropper detection: local execution triggers (must have ≥1 to qualify).
 * These indicate the file spawns a shell or interpreter after download.
 */
const DROPPER_EXEC_TRIGGERS = [
  "WScript.Shell",
  "Shell(",
  "cmd.exe",
  "powershell -enc",
  "powershell.exe -enc",
  "CreateObject(\"Wscript",
  "CreateObject('Wscript",
  "ShellExecute",
  "mshta.exe",
  "regsvr32.exe",
  "rundll32.exe",
  "cscript.exe",
  "wscript.exe",
];

// ─── Cryptographic Hash Calculation ──────────────────────────────────────────

/**
 * Compute SHA-256 and MD5 digests from a Buffer.
 * @param {Buffer} buffer
 * @returns {{ sha256: string, md5: string }}
 */
function computeHashes(buffer) {
  const sha256 = crypto.createHash("sha256").update(buffer).digest("hex");
  const md5 = crypto.createHash("md5").update(buffer).digest("hex");
  return { sha256, md5 };
}

// ─── Layer 1: VirusTotal Threat Intelligence ──────────────────────────────────

/**
 * Query VirusTotal v3 /files endpoint by SHA-256.
 * Falls back gracefully on 404 (unknown file) or 429 (rate limit).
 *
 * @param {string} sha256
 * @returns {Promise<{
 *   queried: boolean,
 *   rateLimited: boolean,
 *   notInDatabase: boolean,
 *   malicious: number,
 *   suspicious: number,
 *   harmless: number,
 *   undetected: number,
 *   total: number,
 *   threatName: string|null,
 *   vtStatus: string,
 * }>}
 */
async function queryVirusTotal(sha256) {
  const VT_BASE = {
    queried: false,
    rateLimited: false,
    notInDatabase: false,
    known: false,
    malicious: 0,
    suspicious: 0,
    harmless: 0,
    undetected: 0,
    total: 0,
    threatName: null,
    vtStatus: "Not Queried",
  };

  const vtKey = 
    process.env.VIRUSTOTAL_API_KEY || 
    process.env.VT_API_KEY || 
    process.env.NEXT_PUBLIC_VIRUSTOTAL_API_KEY;

  console.log("[Lookout File Scan] VT Key configured:", !!vtKey && !isPlaceholderKey(vtKey));

  if (isPlaceholderKey(vtKey)) {
    return { ...VT_BASE, vtStatus: "API Key Not Configured" };
  }
  
  const apiKey = vtKey;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), VT_TIMEOUT_MS);

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${sha256}`, {
      method: "GET",
      headers: { "x-apikey": apiKey },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (response.status === 404) {
      return { ...VT_BASE, queried: true, notInDatabase: true, known: false, vtStatus: "Not in VT Database" };
    }

    if (response.status === 429) {
      return { ...VT_BASE, queried: true, rateLimited: true, known: false, vtStatus: "Rate Limited (429)" };
    }

    if (!response.ok) {
      return { ...VT_BASE, queried: true, known: false, vtStatus: `VT Error (HTTP ${response.status})` };
    }

    const json = await response.json();
    const attrs = json?.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};

    const malicious = stats.malicious ?? 0;
    const suspicious = stats.suspicious ?? 0;
    const harmless = stats.harmless ?? 0;
    const undetected = stats.undetected ?? 0;
    const total = malicious + suspicious + harmless + undetected;

    // Extract top threat name from last_analysis_results
    let threatName = null;
    const results = attrs.last_analysis_results || {};
    for (const engine of Object.values(results)) {
      if (engine.category === "malicious" && engine.result) {
        threatName = engine.result;
        break;
      }
    }

    return {
      queried: true,
      known: true,
      rateLimited: false,
      notInDatabase: false,
      malicious,
      suspicious,
      harmless,
      undetected,
      total,
      threatName,
      vtStatus: malicious > 0 ? `${malicious} Engines Flagged` : "Clean (VT)",
    };
  } catch (err) {
    clearTimeout(timeoutId);
    if (err.name === "AbortError") {
      return { ...VT_BASE, queried: true, known: false, vtStatus: "VT Timeout (5s)" };
    }
    return { ...VT_BASE, queried: true, known: false, vtStatus: "VT Network Error" };
  }
}

// ─── Layer 2A: Magic Bytes / MIME Inspection ──────────────────────────────────

/**
 * Scan a buffer slice for null bytes (0x00), which are absent in valid UTF-8
 * plain-text / script content.
 * @param {Buffer} slice
 * @returns {boolean} true if NO null bytes were found
 */
function hasNoNullBytes(slice) {
  for (let i = 0; i < slice.length; i++) {
    if (slice[i] === 0x00) return false;
  }
  return true;
}

/**
 * Detected file type from magic bytes and content heuristics.
 * Order matters — binary signatures are checked first; plaintext last.
 *
 * @param {Buffer} buffer
 * @returns {string} Detected type: 'PE'|'ELF'|'PDF'|'ZIP'|'JPEG'|'PNG'|'GIF'|'PLAINTEXT'|'UNKNOWN'
 */
function detectMagicType(buffer) {
  if (buffer.length < 4) return "UNKNOWN";

  // Windows PE / DOS MZ executable
  if (buffer[0] === 0x4d && buffer[1] === 0x5a) return "PE";
  // ELF executable (Linux/Unix)
  if (buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46) return "ELF";
  // PDF
  if (buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46) return "PDF";
  // ZIP / DOCX / XLSX (PK\x03\x04)
  if (buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04) return "ZIP";
  // JPEG
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return "JPEG";
  // PNG
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47) return "PNG";
  // GIF
  if (buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46) return "GIF";
  // WebP (RIFF....WEBP)
  if (
    buffer.length >= 12 &&
    buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46 &&
    buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50
  ) return "WEBP";

  // ── Plaintext / Script heuristic ─────────────────────────────────────────
  // Inspect up to 4 KB. If the slice contains no null bytes AND decodes as
  // valid UTF-8, this is a text stream (source code, script, macro, config).
  const headSlice = buffer.slice(0, Math.min(buffer.length, 4096));
  if (hasNoNullBytes(headSlice)) {
    try {
      // TextDecoder throws on invalid UTF-8 sequences when fatal:true
      new TextDecoder("utf-8", { fatal: true }).decode(headSlice);
      return "PLAINTEXT";
    } catch {
      // Contains invalid UTF-8 bytes — treat as unknown binary
    }
  }

  return "UNKNOWN";
}

/**
 * Returns a human-readable label for the detected magic type.
 * @param {string} magicType
 * @returns {string}
 */
function magicTypeLabel(magicType) {
  const labels = {
    PE: "Windows PE Executable (MZ)",
    ELF: "ELF Executable (Linux/Unix)",
    PDF: "PDF Document",
    ZIP: "ZIP / Office Archive",
    JPEG: "JPEG Image",
    PNG: "PNG Image",
    GIF: "GIF Image",
    WEBP: "WebP Image",
    PLAINTEXT: "Plaintext / Script",
    UNKNOWN: "Unknown Binary",
  };
  return labels[magicType] || "Unknown Binary";
}

/**
 * Check if the file extension and its actual magic type are consistent.
 * Returns true if extension matches the detected magic type.
 */
function isMagicMatch(ext, magicType) {
  const extMap = {
    ".exe": ["PE"],
    ".dll": ["PE"],
    ".scr": ["PE"],
    ".sys": ["PE"],
    ".com": ["PE"],
    ".so":  ["ELF"],
    ".pdf": ["PDF"],
    ".docx": ["ZIP"],
    ".xlsx": ["ZIP"],
    ".pptx": ["ZIP"],
    ".zip":  ["ZIP"],
    ".jar":  ["ZIP"],
    ".apk":  ["ZIP"],
    ".jpg":  ["JPEG"],
    ".jpeg": ["JPEG"],
    ".png":  ["PNG"],
    ".gif":  ["GIF"],
    ".webp": ["WEBP"],
    // Text / script extensions — only consistent when magic is PLAINTEXT
    ".txt":  ["PLAINTEXT"],
    ".sh":   ["PLAINTEXT"],
    ".bash": ["PLAINTEXT"],
    ".zsh":  ["PLAINTEXT"],
    ".bat":  ["PLAINTEXT"],
    ".cmd":  ["PLAINTEXT"],
    ".ps1":  ["PLAINTEXT"],
    ".psm1": ["PLAINTEXT"],
    ".vbs":  ["PLAINTEXT"],
    ".js":   ["PLAINTEXT"],
    ".ts":   ["PLAINTEXT"],
    ".py":   ["PLAINTEXT"],
    ".rb":   ["PLAINTEXT"],
    ".csv":  ["PLAINTEXT"],
    ".html": ["PLAINTEXT"],
    ".htm":  ["PLAINTEXT"],
    ".xml":  ["PLAINTEXT"],
    ".json": ["PLAINTEXT"],
    ".yml":  ["PLAINTEXT"],
    ".yaml": ["PLAINTEXT"],
    ".ini":  ["PLAINTEXT"],
    ".conf": ["PLAINTEXT"],
  };

  const expectedTypes = extMap[ext];
  if (!expectedTypes) return true; // Unknown extension — no mismatch we can detect
  return expectedTypes.includes(magicType);
}

// ─── Layer 2B: Shannon Entropy ────────────────────────────────────────────────

/**
 * Calculate Shannon entropy of a buffer.
 * H(X) = -Σ P(x) * log₂(P(x))
 * Range: [0.0, 8.0]
 *
 * @param {Buffer} buffer
 * @returns {number} Entropy value rounded to 4 decimal places
 */
function shannonEntropy(buffer) {
  if (!buffer || buffer.length === 0) return 0;

  const freq = new Array(256).fill(0);
  for (let i = 0; i < buffer.length; i++) {
    freq[buffer[i]]++;
  }

  let entropy = 0;
  const len = buffer.length;
  for (let i = 0; i < 256; i++) {
    if (freq[i] === 0) continue;
    const p = freq[i] / len;
    entropy -= p * Math.log2(p);
  }

  return Math.round(entropy * 10000) / 10000;
}

// ─── Layer 2C: Suspicious String Matching ────────────────────────────────────

/**
 * Scan the first MAX_STRING_SCAN_BYTES of the buffer for exploit strings.
 * Scoped strictly to script and document files; excluded on raw media.
 *
 * @param {Buffer} buffer
 * @param {string} ext - File extension (lowercase)
 * @returns {string[]} Array of matched exploit strings
 */
function findExploitStrings(buffer, ext) {
  if (!buffer || buffer.length === 0) return [];
  const cleanExt = (ext || "").toLowerCase();

  // Excluded targets: do NOT execute plain-text exploit/dropper scanning on raw compressed media
  if (EXCLUDED_MEDIA_EXTENSIONS.has(cleanExt) || isValidImageHeader(buffer, cleanExt)) {
    return [];
  }

  // Only run on allowed script or document extensions
  const isAllowedScript = ALLOWED_SCRIPT_EXTENSIONS.has(cleanExt);
  const isPdf = cleanExt === ".pdf";
  const isDoc = [".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"].includes(cleanExt);

  if (!isAllowedScript && !isPdf && !isDoc) {
    return [];
  }

  const slice = buffer.slice(0, Math.min(buffer.length, MAX_STRING_SCAN_BYTES));
  // Convert to Latin-1 string (covers ASCII + extended printable ranges)
  const text = slice.toString("latin1");
  const matches = [];

  const patterns = isPdf
    ? PDF_EXPLOIT_STRINGS
    : isAllowedScript
    ? [...SCRIPT_EXPLOIT_STRINGS, ...PDF_EXPLOIT_STRINGS]
    : SCRIPT_EXPLOIT_STRINGS;

  for (const pattern of patterns) {
    if (text.includes(pattern)) {
      matches.push(pattern);
    }
  }

  return matches;
}

// ─── Layer 3: Consensus Scoring ───────────────────────────────────────────────

/**
 * Score thresholds per spec:
 *  - VT Malicious 1-2 engines: 40 (Suspicious)
 *  - VT Malicious 3+: 90 (Critical Malicious)
 *  - Hidden Executable (spoofing): 95 (Critical Exploit)
 *  - High Entropy + Exploit Strings: 70 (High Risk)
 *  - Clean: 0
 */

/**
 * @typedef {Object} ScanResult
 * @property {string} fileName
 * @property {number} fileSize
 * @property {string} sha256
 * @property {string} md5
 * @property {string} mimeType
 * @property {number} riskScore
 * @property {string} verdict - 'clean' | 'suspicious' | 'malicious' | 'critical'
 * @property {Object} vtStats
 * @property {Object} heuristics
 * @property {Array}  findings
 * @property {string} explanation
 * @property {string} recommendation
 * @property {string} scannedAt
 */

/**
 * Perform full multi-layer file threat scan on an in-memory Buffer.
 *
 * @param {Buffer} buffer - Raw file bytes
 * @param {string} originalName - Original filename (for extension detection)
 * @returns {Promise<ScanResult>}
 */
async function scanFileBuffer(buffer, originalName) {
  if (!buffer || !Buffer.isBuffer(buffer) || buffer.length === 0) {
    const err = new Error("File buffer cannot be empty or null.");
    err.statusCode = 400;
    throw err;
  }

  const ext = path.extname(originalName || "").toLowerCase();
  const fileSize = buffer.length;
  const scannedAt = new Date().toISOString();

  // ── Hashes ──────────────────────────────────────────────────────────────────
  const { sha256, md5 } = computeHashes(buffer);

  // ── Layer 1: VirusTotal ──────────────────────────────────────────────────────
  const vt = await queryVirusTotal(sha256);

  // ── Layer 2A: Magic Bytes ────────────────────────────────────────────────────
  const magicType = detectMagicType(buffer);
  const magicMatch = isMagicMatch(ext, magicType);

  const isImageExt = IMAGE_EXTENSIONS.has(ext);
  const isVerifiedImage = isImageExt && isValidImageHeader(buffer, ext);
  const hasMzHeader = buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a;
  const hasShellHeader = buffer.length >= 2 && buffer[0] === 0x23 && buffer[1] === 0x21; // #!
  const isSpoofedImage = isImageExt && !isVerifiedImage && (hasMzHeader || hasShellHeader || magicType === "PE" || magicType === "ELF");

  const isHiddenExecutable =
    isSpoofedImage ||
    (!magicMatch &&
      EXPECTED_NON_EXECUTABLE_EXTENSIONS.has(ext) &&
      (magicType === "PE" || magicType === "ELF" || hasMzHeader));

  // ── Layer 2C: Exploit Strings ────────────────────────────────────────────────
  const exploitMatches = findExploitStrings(buffer, ext);
  const hasExploitStrings = exploitMatches.length > 0;

  // ── Layer 2B: Entropy ────────────────────────────────────────────────────────
  const entropy = shannonEntropy(buffer);

  let isHighEntropy = false;
  let entropyStatus = "Normal";
  
  const isCompressedDoc = magicType === "PDF" || magicType === "ZIP";
  const isExec = magicType === "PE" || magicType === "ELF";
  const isText = magicType === "PLAINTEXT";

  if (isVerifiedImage && !hasMzHeader) {
    // Exempt verified media from compression entropy flags
    // DO NOT flag high Shannon entropy (> 7.2) as malicious (compressed streams naturally range 7.4-7.99)
    // Only flag if entropy is literally > 7.999
    if (entropy > 7.999) {
      isHighEntropy = true;
      entropyStatus = "Extreme Entropy (> 7.999)";
    } else {
      isHighEntropy = false;
      entropyStatus = "Normal for compressed image";
    }
  } else if (entropy > 7.5) {
    if (isCompressedDoc && !hasExploitStrings) {
      isHighEntropy = false;
      entropyStatus = "Normal for compressed document";
    } else if (isCompressedDoc && hasExploitStrings) {
      isHighEntropy = true;
      entropyStatus = "High Entropy + Suspicious Keywords";
    } else if (isExec || isText) {
      isHighEntropy = true;
      entropyStatus = "High Entropy";
    } else {
      isHighEntropy = true;
      entropyStatus = "High Entropy";
    }
  } else if (entropy > HIGH_ENTROPY_THRESHOLD && !isCompressedDoc && NON_ARCHIVE_EXTENSIONS.has(ext)) {
    isHighEntropy = true;
    entropyStatus = "High Entropy";
  }

  // ── Layer 2D: Dropper Pattern Detection ─────────────────────────────────────
  // A "dropper" concurrently carries BOTH a remote-retrieval primitive AND a
  // local execution primitive — the hallmark of a staged payload delivery script.
  let hasDownloadTrigger = false;
  let hasExecTrigger = false;
  let isDropper = false;

  const isScriptOrDoc = (ALLOWED_SCRIPT_EXTENSIONS.has(ext) || [".pdf", ".doc", ".docx", ".xls", ".xlsx"].includes(ext)) &&
                        !EXCLUDED_MEDIA_EXTENSIONS.has(ext) &&
                        !isVerifiedImage;

  if (isScriptOrDoc && hasExploitStrings) {
    const contentText = buffer.slice(0, Math.min(buffer.length, MAX_STRING_SCAN_BYTES)).toString("latin1");
    hasDownloadTrigger = DROPPER_DOWNLOAD_TRIGGERS.some((t) => contentText.includes(t));
    hasExecTrigger     = DROPPER_EXEC_TRIGGERS.some((t) => contentText.includes(t));
    isDropper          = hasDownloadTrigger && hasExecTrigger;
  }

  // ── Heuristic Flags ──────────────────────────────────────────────────────────
  const flags = [];
  if (isHiddenExecutable || isSpoofedImage) flags.push("MIME_TYPE_SPOOFING");
  if (isHighEntropy)      flags.push("HIGH_ENTROPY_PACKED_OR_ENCRYPTED");
  if (isDropper)          flags.push("DROPPER BEHAVIOR DETECTED");
  else if (hasExecTrigger) flags.push("EXECUTION_HOOK_DETECTED");
  else if (hasExploitStrings) flags.push("EXPLOIT_STRING_DETECTED");

  // ── Consensus Scoring ────────────────────────────────────────────────────────
  let riskScore = 0;
  let verdict = "clean";
  const findings = [];

  // Priority 1: Hidden executable (extension spoofing) — highest risk
  if (isHiddenExecutable || isSpoofedImage) {
    riskScore = isSpoofedImage ? 90 : 95;
    verdict = "critical";
    findings.push({
      type: "MIME_TYPE_SPOOFING",
      severity: "critical",
      detail: `CRITICAL: File extension "${ext}" does not match binary header "${magicTypeLabel(magicType)}". Hidden executable detected — potential exploit delivery attempt.`,
    });
  }

  // Priority 2: VirusTotal detections
  if (vt.malicious >= 3) {
    const vtScore = 90;
    if (vtScore > riskScore) {
      riskScore = vtScore;
      verdict = "malicious";
    }
    findings.push({
      type: "VT_MALICIOUS_DETECTION",
      severity: "critical",
      detail: `VirusTotal: ${vt.malicious} engines flagged as malicious${vt.threatName ? ` (${vt.threatName})` : ""}. ${vt.suspicious} suspicious. ${vt.total} total engines queried.`,
    });
  } else if (vt.malicious >= 1) {
    const vtScore = 40;
    if (vtScore > riskScore) {
      riskScore = vtScore;
      verdict = "suspicious";
    }
    findings.push({
      type: "VT_SUSPICIOUS_DETECTION",
      severity: "high",
      detail: `VirusTotal: ${vt.malicious} engine(s) flagged as malicious${vt.threatName ? ` (${vt.threatName})` : ""}. Treat with caution.`,
    });
  }

  // Priority 3: High entropy + exploit strings
  if (isHighEntropy && hasExploitStrings) {
    const heuristicScore = 70;
    if (heuristicScore > riskScore) {
      riskScore = heuristicScore;
      verdict = "malicious";
    }
    findings.push({
      type: "HIGH_ENTROPY_WITH_EXPLOIT_STRINGS",
      severity: "high",
      detail: `High entropy (${entropy.toFixed(2)}) combined with exploit patterns [${exploitMatches.slice(0, 3).join(", ")}]. Possible obfuscated/packed payload.`,
    });
  } else if (isHighEntropy) {
    const entropyScore = 50;
    if (entropyScore > riskScore) {
      riskScore = entropyScore;
      if (verdict === "clean") verdict = "suspicious";
    }
    findings.push({
      type: "HIGH_ENTROPY_PACKED_OR_ENCRYPTED",
      severity: "medium",
      detail: `File entropy ${entropy.toFixed(2)}/8.0 exceeds threshold ${HIGH_ENTROPY_THRESHOLD}. Possible packed, encrypted, or obfuscated payload.`,
    });
  } else if (hasExploitStrings) {
    if (isDropper) {
      // Concurrent download + execution primitives → staged dropper behaviour
      const dropperScore = 70;
      if (dropperScore > riskScore) {
        riskScore = dropperScore;
        verdict = "malicious";
      }
      findings.push({
        type: "DROPPER_BEHAVIOR_DETECTED",
        severity: "high",
        title: "Potential Macro/Dropper Script Detected",
        detail:
          "Identified automated execution sequence (AutoOpen) coupled with external HTTP retrieval and shell execution primitives.",
      });
    } else if (hasExecTrigger) {
      // Execution hook / dropper execution primitives flagged
      const execScore = 65;
      if (execScore > riskScore) {
        riskScore = execScore;
        if (verdict === "clean") verdict = "suspicious";
      }
      findings.push({
        type: "EXECUTION_HOOK_DETECTED",
        severity: "high",
        title: "Execution Hook Caught",
        detail: `Dropper execution primitives flagged: [${exploitMatches.join(", ")}].`,
      });
    } else {
      // Exploit strings present but no paired download primitive → suspicious
      const stringScore = 45;
      if (stringScore > riskScore) {
        riskScore = stringScore;
        if (verdict === "clean") verdict = "suspicious";
      }
      findings.push({
        type: "EXPLOIT_STRING_DETECTED",
        severity: "medium",
        detail: `Exploit/suspicious string patterns found in file content: [${exploitMatches.slice(0, 4).join(", ")}].`,
      });
    }
  }

  // Informational findings
  if (vt.rateLimited) {
    findings.push({
      type: "VT_RATE_LIMITED",
      severity: "low",
      detail: "VirusTotal API rate limit reached. Hash lookup skipped — relying on heuristic analysis only.",
    });
  }

  if (vt.notInDatabase && vt.queried) {
    findings.push({
      type: "VT_NOT_IN_DATABASE",
      severity: "low",
      detail: "File hash not found in VirusTotal database. This is a new or rare file — heuristic analysis is the primary indicator.",
    });
  }

  // ── Step 4 Guarantee: Clean Verified Media Heuristics ─────────────────────────
  // For valid images (isValidImageHeader === true and no executable MZ headers detected):
  // Risk Score MUST evaluate to 0 (Clean).
  // Heuristic flags array MUST remain empty.
  if (isVerifiedImage && !hasMzHeader && entropy <= 7.999) {
    flags.length = 0;
    if (vt.malicious === 0) {
      riskScore = 0;
      verdict = "clean";
      const vtFindings = findings.filter((f) => f.type.startsWith("VT_"));
      findings.length = 0;
      findings.push(...vtFindings);
    }
  }

  // Clamp score
  riskScore = Math.min(100, Math.max(0, riskScore));

  // ── Verdict refinement ───────────────────────────────────────────────────────
  if (riskScore === 0 || findings.length === 0) {
    verdict = "clean";
  } else if (riskScore >= 80 && verdict !== "critical") {
    verdict = "malicious";
  }

  // ── MIME type string ─────────────────────────────────────────────────────────
  const mimeTypeMap = {
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".zip": "application/zip",
    ".txt": "text/plain",
    ".html": "text/html",
    ".htm": "text/html",
    ".js": "text/javascript",
    ".py": "text/x-python",
    ".sh": "text/x-sh",
    ".bat": "application/x-bat",
    ".ps1": "application/x-powershell",
    ".exe": "application/x-msdownload",
    ".dll": "application/x-msdownload",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
  };
  const mimeType = mimeTypeMap[ext] || "application/octet-stream";

  // ── Explanation & Recommendation ─────────────────────────────────────────────
  let explanation;
  let recommendation;

  if (riskScore === 0) {
    explanation = isVerifiedImage
      ? `Hash verified (${vt.vtStatus}). Binary inspection: verified valid ${ext.replace('.', '').toUpperCase()} image header, entropy ${entropy.toFixed(2)}/8.0 (normal for compressed media), zero threat indicators.`
      : `Hash verified against VirusTotal (${vt.vtStatus}). Binary inspection: no executable header spoofing, entropy ${entropy.toFixed(2)}/8.0 (normal), no exploit string patterns detected.`;
    recommendation = "File appears safe. No action required.";
  } else if (verdict === "critical") {
    explanation = `CRITICAL THREAT: ${findings[0]?.detail || "Critical threat indicators detected."}`;
    recommendation = "DO NOT open or execute this file. Quarantine immediately and escalate to your security team.";
  } else if (verdict === "malicious") {
    explanation = `HIGH RISK: ${findings[0]?.detail || "Multiple threat indicators detected."} ${findings.length > 1 ? `(+${findings.length - 1} additional indicators)` : ""}`;
    recommendation = "HIGH RISK — Do not open or execute. Quarantine and investigate. Report to your security team.";
  } else if (verdict === "suspicious") {
    explanation = `SUSPICIOUS: ${findings[0]?.detail || "Anomalous indicators detected."} Treat with caution.`;
    recommendation = "CAUTION — Exercise extreme care. Verify source integrity and consider scanning with additional tools before proceeding.";
  } else {
    explanation = "No threat indicators detected across all scan layers.";
    recommendation = "File appears safe. Always verify file sources before opening.";
  }

  return {
    fileName: originalName,
    fileSize,
    sha256,
    md5,
    mimeType,
    detectedType: magicTypeLabel(magicType),
    riskScore,
    verdict,
    vtStats: {
      queried: vt.queried,
      known: vt.known !== undefined ? vt.known : (!vt.notInDatabase && vt.queried),
      malicious: vt.malicious,
      suspicious: vt.suspicious,
      harmless: vt.harmless,
      undetected: vt.undetected,
      total: vt.total,
      clean: vt.harmless + vt.undetected,
      threatName: vt.threatName,
      vtStatus: vt.vtStatus,
      rateLimited: vt.rateLimited,
      notInDatabase: vt.notInDatabase,
    },
    heuristics: {
      magicType,
      magicTypeLabel: magicTypeLabel(magicType),
      magicMatch,
      isHiddenExecutable: isHiddenExecutable || isSpoofedImage,
      isValidImageHeader: isVerifiedImage,
      entropy,
      isHighEntropy: isVerifiedImage && !hasMzHeader && entropy <= 7.999 ? false : isHighEntropy,
      entropyStatus,
      exploitStrings: exploitMatches,
      hasExploitStrings,
      isDropper,
      hasDownloadTrigger,
      hasExecTrigger,
      flags,
    },
    findings,
    explanation,
    recommendation,
    scannedAt,
  };
}

/**
 * Synchronous/defensive file scanner helper for local files.
 * Supports file paths and raw Buffers.
 */
function scanFile(filePathOrBuffer, originalName) {
  try {
    let buffer;
    let filename;
    if (Buffer.isBuffer(filePathOrBuffer)) {
      buffer = filePathOrBuffer;
      filename = originalName || "file.bin";
    } else if (typeof filePathOrBuffer === "string") {
      buffer = fs.readFileSync(filePathOrBuffer);
      filename = originalName || filePathOrBuffer;
    } else {
      throw new Error("Invalid input to scanFile: expected Buffer or file path string.");
    }

    const ext = path.extname(filename).toLowerCase();
    const hashes = computeHashes(buffer);
    const magic = detectMagicType(buffer);
    const findings = [];
    let riskScore = 0;

    const isImage = IMAGE_EXTENSIONS.has(ext);
    const validImage = isImage && isValidImageHeader(buffer, ext);
    const hasMz = buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a;
    const hasShell = buffer.length >= 2 && buffer[0] === 0x23 && buffer[1] === 0x21; // #!
    const isExecHeader = hasMz || magic === "PE" || magic === "ELF";

    if (isImage) {
      if (validImage && !hasMz && !isExecHeader) {
        // Valid image: format-aware heuristic check
        // DO NOT flag high Shannon entropy (> 7.2) as malicious (streams range from 7.4 to 7.99)
        // Only flag if entropy is literally > 7.999
        const ent = shannonEntropy(buffer);
        if (ent > 7.999) {
          riskScore = 50;
          findings.push({
            type: "EXTREME_ENTROPY",
            severity: "medium",
            detail: `Abnormally extreme entropy (${ent.toFixed(2)}) for image file.`,
          });
        } else {
          riskScore = 0;
        }
      } else if (hasMz || isExecHeader || hasShell) {
        // Case B: Header does NOT match and begins with MZ or shell script headers
        riskScore = 90;
        findings.push({
          type: "MIME_TYPE_SPOOFING",
          severity: "critical",
          detail: `CRITICAL: File extension "${ext}" does not match binary header. Hidden executable or script header detected in image file.`,
        });
      }
    } else {
      if ((magic === "PE" || magic === "ELF" || hasMz) && EXPECTED_NON_EXECUTABLE_EXTENSIONS.has(ext)) {
        riskScore = 90;
        findings.push({
          type: "MIME_TYPE_SPOOFING",
          severity: "critical",
          detail: `Hidden executable detected in ${filename}`,
        });
      }
    }

    const verdict = riskScore >= 80 ? "threat_detected" : (riskScore > 0 ? "suspicious" : "clean");

    return {
      findings,
      riskScore,
      verdict,
      sha256: hashes.sha256,
      md5: hashes.md5,
    };
  } catch (err) {
    return { findings: [], riskScore: 0, verdict: "error", error: err.message };
  }
}

module.exports = { 
  scanFileBuffer, 
  computeHashes, 
  queryVirusTotal, 
  detectMagicType, 
  shannonEntropy,
  scanFile,
  IMAGE_SIGNATURES,
  isValidImageHeader,
};
