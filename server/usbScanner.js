const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const crypto = require('crypto');
const { computeHashes, queryVirusTotal, detectMagicType, shannonEntropy, isValidImageHeader, IMAGE_SIGNATURES } = require('./services/fileScanner');

const IGNORED_DIRS = new Set([
  'system volume information',
  '$recycle.bin',
  '.trashes',
  '.spotlight-v100',
  '.fseventsd'
]);
const IGNORED_FILES = new Set(['thumbs.db', '.ds_store']);
const MAX_TRAVERSAL_DEPTH = 15;
const MAX_DEPTH = MAX_TRAVERSAL_DEPTH;

const LARGE_MEDIA_ARCHIVE_EXTENSIONS = new Set([
  '.mp4', '.mkv', '.iso', '.zip', '.tar'
]);

const EXECUTABLE_EXTENSIONS = new Set([
  '.exe', '.dll', '.sys', '.com', '.scr', '.vbs', '.bat', '.cmd', '.ps1', '.js', '.wsf', '.msi', '.hta', '.cpl'
]);

const SPOOFED_EXTENSIONS = new Set([
  '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.webp', '.mp4', '.mkv',
  '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv'
]);

const STREAM_HASH_SIZE_LIMIT = 50 * 1024 * 1024; // 50 MB

/**
 * Normalizes input drive path across Windows and POSIX systems.
 * Guarantees Windows drive letters (e.g., 'E:', 'E:\', 'E:/', 'e:\') are resolved
 * to a standardized root with trailing separator (e.g. 'E:\'), preventing malformed
 * relative concatenations like 'E:autorun.inf'.
 *
 * @param {string} drivePath
 * @returns {string}
 */
function normalizeDrivePath(drivePath) {
  if (!drivePath || typeof drivePath !== 'string') return '';
  const cleaned = drivePath.trim();

  // Match Windows drive root patterns: 'E:', 'E:\', 'E:/', 'e:\'
  if (/^[a-zA-Z]:[/\\]?$/.test(cleaned)) {
    return cleaned[0].toUpperCase() + ':\\';
  }

  return path.resolve(cleaned);
}

/**
 * Resolves a scan path safely ensuring proper root boundaries.
 *
 * @param {string} rootPath
 * @param {string} subPath
 * @returns {string}
 */
function resolveScanPath(rootPath, subPath) {
  const normalizedRoot = normalizeDrivePath(rootPath);
  return path.join(normalizedRoot, subPath);
}

/**
 * Size-capped header inspection: Reads at most the first 8 KB (8192 bytes) of a file.
 * Guaranteed leak-free by ensuring the file descriptor is closed in all execution paths.
 *
 * @param {string} filePath
 * @returns {Promise<Buffer|null>}
 */
async function readFileHeader(filePath) {
  const buffer = Buffer.alloc(8192);
  let fd = null;
  try {
    fd = await fsSync.promises.open(filePath, 'r');
    const res = await fd.read(buffer, 0, 8192, 0);
    return buffer.subarray(0, res.bytesRead);
  } catch {
    return null;
  } finally {
    if (fd) {
      try { await fd.close(); } catch {}
    }
  }
}

/**
 * Computes SHA-256 checksum for a file via streams to prevent memory bloat on large files.
 *
 * @param {string} filePath
 * @returns {Promise<string>} Hex-encoded SHA-256 digest
 */
function computeStreamSha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fsSync.createReadStream(filePath);
    stream.on('error', (err) => {
      try { stream.destroy(); } catch {}
      reject(err);
    });
    hash.on('error', (err) => {
      try { stream.destroy(); } catch {}
      reject(err);
    });
    hash.on('finish', () => resolve(hash.digest('hex')));
    stream.pipe(hash);
  });
}

/**
 * Validates whether the buffer begins with known media magic bytes:
 * PNG (89 50 4E 47), JPG (FF D8 FF), GIF (47 49 46 38), MP4 (ftyp at offset 4), MKV (1A 45 DF A3), WebP (RIFF...WEBP).
 *
 * @param {Buffer} buffer
 * @returns {boolean}
 */
function hasValidMediaHeader(buffer) {
  if (!buffer || buffer.length < 3) return false;

  // PNG: 89 50 4E 47
  if (buffer.length >= 4 && buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47) {
    return true;
  }
  // JPG / JPEG: FF D8 FF
  if (buffer.length >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
    return true;
  }
  // GIF: 47 49 46 38 ("GIF8")
  if (buffer.length >= 4 && buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x38) {
    return true;
  }
  // MP4: offset 4 contains 'ftyp' (0x66, 0x74, 0x79, 0x70)
  if (buffer.length >= 8 && buffer[4] === 0x66 && buffer[5] === 0x74 && buffer[6] === 0x79 && buffer[7] === 0x70) {
    return true;
  }
  // MKV / WebM: EBML ID 1A 45 DF A3
  if (buffer.length >= 4 && buffer[0] === 0x1a && buffer[1] === 0x45 && buffer[2] === 0xdf && buffer[3] === 0xa3) {
    return true;
  }
  // WebP: RIFF....WEBP
  if (buffer.length >= 12 &&
      buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46 &&
      buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50) {
    return true;
  }

  return false;
}

/**
 * Scans an external removable drive or directory path for security threats.
 *
 * @param {string} drivePath - Target root path to scan
 * @param {Function} [onProgress] - Progress callback (currentFile, scannedCount, totalFiles)
 * @param {Function} [onThreatFound] - Threat callback ({ threat })
 * @param {Object|Function} [options] - Options or isCancelled function.
 * @returns {Promise<Object>} Scan results summary
 */
async function scanUsbDrive(drivePath, onProgress, onThreatFound, options = {}) {
  const startTime = Date.now();
  let totalDiscovered = 0;
  let scannedFilesCount = 0;
  const threats = [];
  const filesToScan = [];
  const fileResults = [];

  const shouldAbort = typeof options === 'function'
    ? options
    : (options?.isCancelled || (() => options?.signal?.aborted || false));

  // Step 1: Strictly resolve driveTarget to live Windows drive root
  let targetRoot = normalizeDrivePath(drivePath);
  if (/^[a-zA-Z]:$/.test(targetRoot)) {
    targetRoot = `${targetRoot}\\`;
  } else if (/^[a-zA-Z]:\\?$/.test(targetRoot)) {
    targetRoot = targetRoot.endsWith('\\') ? targetRoot : `${targetRoot}\\`;
  }

  try {
    const stat = await fs.stat(targetRoot);
    if (!stat.isDirectory()) {
      return {
        drivePath: targetRoot,
        totalFiles: 0,
        scannedFiles: 0,
        threats: [],
        fileResults: [],
        verdict: 'clean',
        durationMs: Date.now() - startTime
      };
    }
  } catch (err) {
    console.warn(`[Lookout USB Scanner] Target path "${targetRoot}" does not exist or is inaccessible (${err.code || err.message}).`);
    return {
      drivePath: targetRoot,
      totalFiles: 0,
      scannedFiles: 0,
      threats: [],
      fileResults: [],
      verdict: 'clean',
      durationMs: Date.now() - startTime
    };
  }

  const visitedRealPaths = new Set();

  async function traverse(currentPath, depth = 0) {
    if (depth > MAX_TRAVERSAL_DEPTH) return;
    if (shouldAbort && shouldAbort()) return;

    try {
      // Symlink & Cycle Guard: Detect circular loops and recursion traps
      let realCurrent;
      try {
        realCurrent = await fs.realpath(currentPath);
      } catch (e) {
        realCurrent = path.resolve(currentPath);
      }

      const normKey = realCurrent.toLowerCase();
      if (visitedRealPaths.has(normKey)) {
        console.warn(`[Lookout USB Scanner] Traversal cycle detected at "${currentPath}". Skipping to avoid recursion loop.`);
        return;
      }
      visitedRealPaths.add(normKey);

      const entries = await fs.readdir(currentPath, { withFileTypes: true });
      for (const entry of entries) {
        if (shouldAbort && shouldAbort()) return;

        const entryName = entry.name;
        const lowerName = entryName.toLowerCase();
        if (IGNORED_DIRS.has(lowerName) || IGNORED_FILES.has(lowerName)) continue;

        const fullPath = path.join(currentPath, entryName);

        // Handle symlinks, junctions, and directories defensively
        if (entry.isSymbolicLink()) {
          try {
            const stat = await fs.stat(fullPath);
            if (stat.isDirectory()) {
              await traverse(fullPath, depth + 1);
            } else if (stat.isFile()) {
              totalDiscovered++;
              filesToScan.push({ path: fullPath, name: entryName, root: depth === 0 });
            }
          } catch (e) {
            console.warn(`[Lookout USB Scanner] Skipping inaccessible symlink "${fullPath}": ${e.code || e.message}`);
          }
        } else if (entry.isDirectory()) {
          await traverse(fullPath, depth + 1);
        } else if (entry.isFile()) {
          totalDiscovered++;
          filesToScan.push({ path: fullPath, name: entryName, root: depth === 0 });
        }
      }
    } catch (err) {
      console.warn(`[Lookout USB Scanner] Traversal warning on "${currentPath}": ${err.code || err.message}. Skipping directory.`);
    }
  }

  await traverse(targetRoot);

  if (filesToScan.length === 0) {
    return {
      drivePath: targetRoot,
      totalFiles: 0,
      scannedFiles: 0,
      threats: [],
      fileResults: [],
      verdict: 'clean',
      durationMs: Date.now() - startTime
    };
  }

  const BATCH_SIZE = 10;
  for (let i = 0; i < filesToScan.length; i += BATCH_SIZE) {
    if (shouldAbort && shouldAbort()) {
      console.warn('[Lookout USB Scanner] Scan aborted due to client disconnection.');
      break;
    }
    const batch = filesToScan.slice(i, i + BATCH_SIZE);
    
    await Promise.all(batch.map(async (fileObj) => {
      let threat = null;
      let riskScore = 0;
      const reason = [];
      let sha256 = '';

      try {
        const stat = await fs.stat(fileObj.path);
        const ext = path.extname(fileObj.name).toLowerCase();
        const isBin = EXECUTABLE_EXTENSIONS.has(ext);
        const isLnk = ext === '.lnk';
        const isLargeSafeMedia = stat.size > STREAM_HASH_SIZE_LIMIT && LARGE_MEDIA_ARCHIVE_EXTENSIONS.has(ext);

        // Step 2: Size-Capped Header Inspection (reads first 8 KB only)
        const headerBuffer = await readFileHeader(fileObj.path);
        if (headerBuffer === null) {
          console.warn(`[Lookout USB Scanner] Skipping inaccessible/locked file "${fileObj.path}": locked or inaccessible`);
          fileResults.push({
            name: fileObj.name,
            path: fileObj.path,
            riskScore: 0,
            inaccessible: true,
            status: 'locked_or_inaccessible',
            sha256: ''
          });
          scannedFilesCount++;
          if (onProgress) {
            onProgress(fileObj.name, scannedFilesCount, filesToScan.length);
          }
          return;
        }

        // Step 3: Heuristics & Signature Inspections on Header & Metadata
        // 1. RTLO Masking
        const rtlo = /\u202E/.test(fileObj.name);
        if (rtlo) {
          riskScore += 90;
          reason.push('RTLO character used to mask extension');
        }

        // 2. Double Extension Masking (e.g. *.docx.exe, *.pdf.vbs)
        if (/\.(pdf|docx|xlsx|doc|xls|txt|jpg|jpeg|png|gif|mp4|zip|rar|7z)\.(exe|vbs|bat|cmd|js|wsf|scr|com|ps1|hta|pif)$/i.test(fileObj.name)) {
          riskScore += 90;
          reason.push('Double extension masking executable');
        }

        // 3. Autorun hooks in autorun.inf
        if (fileObj.name.toLowerCase() === 'autorun.inf') {
          const content = headerBuffer.toString('utf8').toLowerCase();
          if (content.includes('open=') || content.includes('shellexecute=') || content.includes('action=')) {
            riskScore += 100;
            reason.push('Malicious Autorun Hijack');
          }
        }

        // 4. LNK shortcut targets PowerShell, CMD, WScript, or remote URLs
        if (isLnk) {
          const contentStr = headerBuffer.toString('utf16le').toLowerCase() + ' ' + headerBuffer.toString('utf8').toLowerCase();
          const suspCmds = [
            'powershell.exe',
            'powershell',
            'cmd.exe',
            'wscript.exe',
            'cscript.exe',
            'mshta.exe',
            'http://',
            'https://'
          ];
          if (suspCmds.some(cmd => contentStr.includes(cmd))) {
            riskScore += 90;
            reason.push('LNK_EXECUTION_HOOK: Suspicious LNK Dropper');
          }
        }

        // 5. Format-Aware Magic Byte & Media Header Verification
        const hasMz = headerBuffer.length >= 2 && headerBuffer[0] === 0x4D && headerBuffer[1] === 0x5A;
        const hasShell = headerBuffer.length >= 2 && headerBuffer[0] === 0x23 && headerBuffer[1] === 0x21; // #!
        const validMedia = hasValidMediaHeader(headerBuffer);

        // MIME Spoofing: Header is MZ (4D 5A) but disguised as document or image
        if (hasMz && SPOOFED_EXTENSIONS.has(ext)) {
          riskScore += 90;
          reason.push(`MIME_SPOOFING: Executable MZ header disguised as ${ext}`);
        } else if (hasShell && (validMedia || SPOOFED_EXTENSIONS.has(ext))) {
          riskScore += 90;
          reason.push(`MIME_TYPE_SPOOFING: Shell script header detected in ${ext} file`);
        }

        // Shannon Entropy check:
        // Format-aware media whitelist: If file has valid media magic bytes, NEVER flag for high entropy
        if (validMedia) {
          // Whitelisted media naturally has high compression entropy (7.4 - 7.99) -> Never flag
        } else if (isBin && headerBuffer.length > 0) {
          const ent = shannonEntropy(headerBuffer);
          if (ent > 7.2) {
            riskScore += 40;
            reason.push(`High entropy (${ent.toFixed(2)}) indicating packed/encrypted payload`);
          }
        }

        // Step 2: Selective Crypto Hashing
        // If file > 50 MB and has safe media extension, DO NOT compute SHA-256 unless executable heuristics triggered.
        // For all executables, scripts, shortcuts, and files under 50 MB, compute SHA-256 via streams.
        const shouldComputeSha256 = !isLargeSafeMedia || riskScore > 0;
        if (shouldComputeSha256) {
          try {
            sha256 = await computeStreamSha256(fileObj.path);
          } catch (hashErr) {
            console.warn(`[Lookout USB Scanner] Failed to compute stream hash for "${fileObj.path}": ${hashErr.message}`);
          }
        }

        // VirusTotal query for binaries triggering heuristics
        if (isBin && riskScore > 0 && sha256) {
          const vt = await queryVirusTotal(sha256);
          if (vt && vt.malicious > 0) {
            riskScore = 100;
            reason.push(`VirusTotal detected malicious (${vt.malicious}/${vt.total})`);
          }
        }

        fileResults.push({
          name: fileObj.name,
          path: fileObj.path,
          riskScore,
          sha256
        });

        if (riskScore > 50) {
          const isLnkHook = reason.some(r => r.includes('LNK_EXECUTION_HOOK'));
          const isMimeSpoof = reason.some(r => r.includes('MIME'));
          threat = {
            path: fileObj.path,
            name: fileObj.name,
            type: isLnkHook ? 'LNK_EXECUTION_HOOK' : (isMimeSpoof ? 'MIME_SPOOFING' : 'Heuristic Detection'),
            detection: isLnkHook ? 'LNK_EXECUTION_HOOK' : (isMimeSpoof ? 'MIME_SPOOFING' : 'HEURISTIC'),
            rule: isLnkHook ? 'LNK_EXECUTION_HOOK' : (isMimeSpoof ? 'MIME_SPOOFING' : undefined),
            riskScore: Math.min(riskScore, 100),
            reason: reason.join(', '),
            sha256
          };
          threats.push(threat);
          if (onThreatFound) onThreatFound(threat);
        }

      } catch (err) {
        console.warn(`[Lookout USB Scanner] Skipping inaccessible/locked file "${fileObj.path}": ${err.code || err.message}`);
        fileResults.push({
          name: fileObj.name,
          path: fileObj.path,
          riskScore: 0,
          inaccessible: true,
          status: 'locked_or_inaccessible',
          error: err.code || err.message,
          sha256: ''
        });
      }

      scannedFilesCount++;
      if (onProgress) {
        onProgress(fileObj.name, scannedFilesCount, filesToScan.length);
      }

    }));
  }

  const durationMs = Date.now() - startTime;
  return {
    drivePath: targetRoot,
    totalFiles: filesToScan.length,
    scannedFiles: scannedFilesCount,
    threats,
    fileResults,
    verdict: threats.length > 0 ? 'threat_detected' : 'clean',
    durationMs
  };
}

/**
 * Quarantines target files atomically with collision timestamping resilience.
 *
 * @param {string[]} filePaths - Array of file paths to isolate
 * @param {string} [customQuarantineDir] - Optional custom directory
 * @returns {Promise<{ quarantinedCount: number, errors: Array, quarantineDir: string }>}
 */
async function quarantineFiles(filePaths, customQuarantineDir) {
  let quarantinedCount = 0;
  const errors = [];
  let resolvedQuarantineDir = customQuarantineDir;

  for (const filePath of filePaths) {
    try {
      // Check file existence
      const stat = await fs.stat(filePath);
      if (!stat.isFile()) continue;

      // Determine quarantine folder
      const parsed = path.parse(filePath);
      const quarantineDir = customQuarantineDir || path.join(parsed.dir || parsed.root, '.lookout_quarantine');
      resolvedQuarantineDir = quarantineDir;

      // Create quarantine folder if it doesn't exist
      if (!fsSync.existsSync(quarantineDir)) {
        await fs.mkdir(quarantineDir, { recursive: true });
      }

      // Prepare isolated file name with collision timestamping
      const fileName = path.basename(filePath);
      let isolatedName = `${fileName}.isolated`;
      let isolatedPath = path.join(quarantineDir, isolatedName);

      // Collision resilience: If destination exists, generate collision timestamped filename
      if (fsSync.existsSync(isolatedPath)) {
        const timestamp = Date.now();
        isolatedName = `${fileName}.${timestamp}.isolated`;
        isolatedPath = path.join(quarantineDir, isolatedName);
        let counter = 1;
        while (fsSync.existsSync(isolatedPath)) {
          isolatedName = `${fileName}.${timestamp}_${counter}.isolated`;
          isolatedPath = path.join(quarantineDir, isolatedName);
          counter++;
        }
      }

      // Move the file atomically
      await fs.rename(filePath, isolatedPath);

      // Write audit log atomically
      const manifestPath = path.join(quarantineDir, 'manifest.json');
      const manifestEntry = {
        originalPath: filePath,
        timestamp: new Date().toISOString(),
        isolatedPath: isolatedPath
      };

      let manifest = [];
      if (fsSync.existsSync(manifestPath)) {
        try {
          const existingData = await fs.readFile(manifestPath, 'utf8');
          manifest = JSON.parse(existingData);
          if (!Array.isArray(manifest)) manifest = [];
        } catch (e) {
          manifest = [];
        }
      }
      manifest.push(manifestEntry);

      // Write atomically via temporary file to prevent JSON corruption
      const tempManifestPath = path.join(quarantineDir, `manifest.${Date.now()}_${Math.random().toString(36).slice(2, 6)}.tmp`);
      await fs.writeFile(tempManifestPath, JSON.stringify(manifest, null, 2), 'utf8');
      await fs.rename(tempManifestPath, manifestPath);

      quarantinedCount++;
    } catch (err) {
      console.warn(`[Lookout USB Scanner] Quarantine error for "${filePath}": ${err.message}`);
      errors.push({ path: filePath, error: err.message });
    }
  }

  return { quarantinedCount, errors, quarantineDir: resolvedQuarantineDir };
}

module.exports = {
  scanUsbDrive,
  quarantineFiles,
  normalizeDrivePath,
  resolveScanPath,
  readFileHeader,
  computeStreamSha256,
  hasValidMediaHeader,
  MAX_TRAVERSAL_DEPTH,
  MAX_DEPTH
};
