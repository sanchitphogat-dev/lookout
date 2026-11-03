/**
 * Lookout Security Platform — Master End-to-End System Integration Audit Runner
 *
 * Comprehensive audit suite verifying all three core threat vectors:
 *   1. URL Threat Pipeline (Sanitization, Whitelist, Typosquatting, Direct Malicious)
 *   2. File Threat Pipeline (Clean Baseline, Magic Spoofing, Droppers, VT Upstream Hash)
 *   3. USB Storage Pipeline (Path Normalization, OS Junk Bypass, Attack Vectors, Quarantine, Dead Socket)
 */

"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const { spawn } = require("child_process");
const WebSocket = require("ws");

// Import target threat pipeline modules
const urlScanner = require("./urlScanner");
const fileScanner = require("./fileScanner");
const usbScanner = require("./usbScanner");

// Helper to remove directory tree safely
function safeRmDir(dirPath) {
  try {
    if (fs.existsSync(dirPath)) {
      try {
        const entries = fs.readdirSync(dirPath, { withFileTypes: true });
        for (const entry of entries) {
          const p = path.join(dirPath, entry.name);
          if (entry.isSymbolicLink()) {
            try { fs.unlinkSync(p); } catch {}
          }
        }
      } catch {}
      fs.rmSync(dirPath, { recursive: true, force: true });
    }
  } catch {}
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. URL Threat Pipeline Tests
// ─────────────────────────────────────────────────────────────────────────────

async function testUrlCleanApex() {
  const t0 = Date.now();
  const testUrls = ["https://www.instagram.com/login", "https://wikipedia.org"];

  for (const targetUrl of testUrls) {
    const result = await urlScanner.performFullUrlScan(targetUrl);

    if (result.riskScore !== 0) {
      throw new Error(
        `Expected risk score 0 for trusted apex domain ${targetUrl}, got ${result.riskScore}`
      );
    }

    if (result.verdict !== "clean") {
      throw new Error(
        `Expected clean verdict for ${targetUrl}, got "${result.verdict}"`
      );
    }

    if (Array.isArray(result.findings) && result.findings.length > 0) {
      throw new Error(
        `Expected 0 false-positive findings for ${targetUrl}, got ${result.findings.length} findings`
      );
    }

    if (result.heuristics && result.heuristics.isTyposquat) {
      throw new Error(`False-positive typosquatting flag triggered on ${targetUrl}`);
    }
  }

  const latency = Date.now() - t0;
  return {
    subsystem: "URL Scanner",
    vector: "Clean Apex (instagram.com)",
    status: "✅ PASS",
    latency: `${latency} ms`,
    detail: "Zero False Positive",
  };
}

async function testUrlTyposquatting() {
  const t0 = Date.now();
  const targetUrl = "http://paypa1.com";
  const result = await urlScanner.performFullUrlScan(targetUrl);

  const hasTyposquatFlag =
    Boolean(result.heuristics?.isTyposquat) ||
    (Array.isArray(result.findings) &&
      result.findings.some(
        (f) =>
          f.type === "typosquatting_homoglyph" ||
          (f.detail && f.detail.toLowerCase().includes("typosquatting"))
      ));

  if (!hasTyposquatFlag) {
    throw new Error(
      `Homoglyph/typosquatting heuristic failed to flag impersonation target: ${targetUrl}`
    );
  }

  if (result.riskScore <= 60) {
    throw new Error(
      `Expected elevated risk score > 60 for typosquatting vector, got ${result.riskScore}`
    );
  }

  const latency = Date.now() - t0;
  return {
    subsystem: "URL Scanner",
    vector: "Typosquatting (paypa1.com)",
    status: "✅ PASS",
    latency: `${latency} ms`,
    detail: "Homoglyph Flagged",
  };
}

async function testUrlSanitizerAndResiliency() {
  const t0 = Date.now();
  const injectionInput = "[link](http://192.168.1.1:8080/admin/utm_source=<script>)";

  // Test 1: Sanitization logic
  const sanitized = urlScanner.sanitizeTargetUrl(injectionInput);
  if (!sanitized) {
    throw new Error("Sanitization produced empty string for valid wrapped URL input");
  }

  if (
    sanitized.includes("<script>") ||
    sanitized.includes("</script>") ||
    sanitized.includes("[link]") ||
    sanitized.includes("<") ||
    sanitized.includes(">")
  ) {
    throw new Error(
      `Sanitization failed to strip script or markdown tags safely: "${sanitized}"`
    );
  }

  // Test 2: Full scan pipeline resiliency under malformed injection input
  let scanResult;
  try {
    scanResult = await urlScanner.performFullUrlScan(injectionInput);
  } catch (err) {
    throw new Error(`performFullUrlScan threw unhandled exception: ${err.message}`);
  }

  if (!scanResult || typeof scanResult.riskScore !== "number") {
    throw new Error("performFullUrlScan returned malformed scan result for injection target");
  }

  // Test 3: Direct Malicious Vector verification (Known malware test vector without 500)
  const malwareVector = "http://malware.testing.google.test/testing/malware/";
  let malwareResult;
  try {
    malwareResult = await urlScanner.performFullUrlScan(malwareVector);
  } catch (err) {
    throw new Error(`Direct malicious vector threw unhandled exception: ${err.message}`);
  }

  if (!malwareResult || (malwareResult.riskScore < 50 && !malwareResult.googleSafeBrowsing?.flagged)) {
    throw new Error("Direct malicious vector was not flagged by SafeBrowsing / Heuristics");
  }

  const latency = Date.now() - t0;
  return {
    subsystem: "URL Scanner",
    vector: "Sanitizer & Resiliency",
    status: "✅ PASS",
    latency: `${latency} ms`,
    detail: "Sanitized Gracefully",
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. File Threat Pipeline Tests
// ─────────────────────────────────────────────────────────────────────────────

async function testFileCleanBaseline() {
  const t0 = Date.now();
  const cleanContent =
    "Lookout Security Platform - Operations Report\nStatus: All Systems Operational\nNo security breaches recorded.";
  const cleanBuffer = Buffer.from(cleanContent, "utf-8");

  const result = await fileScanner.scanFileBuffer(cleanBuffer, "report.txt");

  if (result.riskScore !== 0) {
    throw new Error(`Expected clean document risk score 0, got ${result.riskScore}`);
  }

  if (result.verdict !== "clean") {
    throw new Error(`Expected verdict "clean", got "${result.verdict}"`);
  }

  const actionableFindings = (result.findings || []).filter(
    (f) => f.severity === "high" || f.severity === "critical"
  );
  if (actionableFindings.length > 0) {
    throw new Error(
      `Clean document triggered false-positive actionable findings: ${JSON.stringify(actionableFindings)}`
    );
  }

  const latency = Date.now() - t0;
  return {
    subsystem: "File Scanner",
    vector: "Clean Document Baseline",
    status: "✅ PASS",
    latency: `${latency} ms`,
    detail: "Risk: 0 Clean",
  };
}

async function testFileMagicSpoofing() {
  const t0 = Date.now();
  // Construct a buffer disguised with .pdf extension containing MZ executable header (0x4D 0x5A)
  const mzHeader = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
  const fakeBody = Buffer.from("MZ disguised payload disguised as PDF document");
  const spoofedBuffer = Buffer.concat([mzHeader, fakeBody]);

  const result = await fileScanner.scanFileBuffer(spoofedBuffer, "quarterly_financials.pdf");

  const spoofFlagged =
    (result.heuristics?.flags && result.heuristics.flags.includes("MIME_TYPE_SPOOFING")) ||
    (result.findings && result.findings.some((f) => f.type === "MIME_TYPE_SPOOFING"));

  if (!spoofFlagged) {
    throw new Error(
      'MIME_TYPE_SPOOFING was not detected for .pdf file with MZ header'
    );
  }

  if (result.riskScore < 80) {
    throw new Error(
      `Expected elevated risk score (>= 80) for executable spoofing, got ${result.riskScore}`
    );
  }

  const latency = Date.now() - t0;
  return {
    subsystem: "File Scanner",
    vector: "Magic Bytes Spoofing (.pdf/MZ)",
    status: "✅ PASS",
    latency: `${latency} ms`,
    detail: "MIME Anomaly Detected",
  };
}

async function testFileExploitDropper() {
  const t0 = Date.now();
  // Construct dropper script payload with powershell.exe -enc and WScript.Shell execution primitives
  const dropperScript = `
    Dim objShell
    Set objShell = CreateObject("WScript.Shell")
    objShell.Run "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...", 0, False
  `;
  const dropperBuffer = Buffer.from(dropperScript, "utf-8");

  const result = await fileScanner.scanFileBuffer(dropperBuffer, "invoice_attachment.vbs");

  const hookCaught =
    Boolean(result.heuristics?.hasExecTrigger) ||
    (result.heuristics?.flags &&
      (result.heuristics.flags.includes("EXECUTION_HOOK_DETECTED") ||
        result.heuristics.flags.includes("DROPPER BEHAVIOR DETECTED"))) ||
    (result.findings &&
      result.findings.some(
        (f) =>
          f.type === "EXECUTION_HOOK_DETECTED" ||
          f.type === "DROPPER_BEHAVIOR_DETECTED" ||
          (f.detail && f.detail.toLowerCase().includes("execution"))
      ));

  if (!hookCaught) {
    throw new Error(
      "Dropper execution primitives (powershell -enc / WScript.Shell) were not caught"
    );
  }

  if (result.riskScore < 50) {
    throw new Error(
      `Expected elevated risk score (>= 50) for dropper execution primitives, got ${result.riskScore}`
    );
  }

  const latency = Date.now() - t0;
  return {
    subsystem: "File Scanner",
    vector: "Exploit Dropper Strings",
    status: "✅ PASS",
    latency: `${latency} ms`,
    detail: "Execution Hook Caught",
  };
}

async function testFileVirusTotalHash() {
  const t0 = Date.now();
  // Standard EICAR test buffer
  const eicarString = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
  const eicarBuffer = Buffer.from(eicarString, "utf-8");

  const result = await fileScanner.scanFileBuffer(eicarBuffer, "eicar_test.com");

  // Verify SHA-256 computation
  const expectedSha256 =
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
  if (result.sha256.toLowerCase() !== expectedSha256) {
    throw new Error(
      `SHA-256 mismatch for EICAR buffer: expected ${expectedSha256}, got ${result.sha256}`
    );
  }

  // Verify VirusTotal response or graceful fallback
  if (!result.vtStats || typeof result.vtStats.queried !== "boolean") {
    throw new Error("VirusTotal stats object missing from scan result");
  }

  // Verify 404 handler graceful return
  const unknownHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  const vt404Result = await fileScanner.queryVirusTotal(unknownHash);
  if (!vt404Result || vt404Result.malicious > 0) {
    throw new Error("VirusTotal 404 handler returned unexpected malicious flags");
  }

  // Verify empty buffer protection (must throw 400 Bad Request error)
  let emptyRejected = false;
  try {
    await fileScanner.scanFileBuffer(Buffer.alloc(0), "empty.dat");
  } catch (err) {
    if (err.statusCode === 400 || err.message.includes("empty")) {
      emptyRejected = true;
    }
  }
  if (!emptyRejected) {
    throw new Error("Empty buffer was not rejected with 400 Bad Request");
  }

  const latency = Date.now() - t0;
  return {
    subsystem: "File Scanner",
    vector: "VirusTotal Upstream Hash",
    status: "✅ PASS",
    latency: `${latency} ms`,
    detail: "Live / Cached Match",
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. USB Storage Pipeline Tests
// ─────────────────────────────────────────────────────────────────────────────

async function testUsbPathNormalization() {
  const t0 = Date.now();
  const normalize = usbScanner.normalizeDrivePath;

  const testInputs = [
    { input: "E:", expectedRoot: "E:\\" },
    { input: "E:\\", expectedRoot: "E:\\" },
    { input: "E:/", expectedRoot: "E:\\" },
    { input: "e:\\", expectedRoot: "E:\\" },
  ];

  for (const { input, expectedRoot } of testInputs) {
    const normalized = normalize(input);
    if (normalized !== expectedRoot) {
      throw new Error(
        `normalizeDrivePath("${input}") expected "${expectedRoot}", got "${normalized}"`
      );
    }

    const testFile = path.join(normalized, "autorun.inf");
    if (/^[a-zA-Z]:autorun\.inf$/i.test(testFile)) {
      throw new Error(
        `Path join on normalized root produced malformed relative path "${testFile}" without separator`
      );
    }
  }

  // Relative path normalization test
  const relativeInput = "./relative/scan/path";
  const normalizedRel = normalize(relativeInput);
  if (!path.isAbsolute(normalizedRel)) {
    throw new Error(`Relative path "${relativeInput}" did not normalize to absolute path`);
  }

  const latency = Date.now() - t0;
  return {
    subsystem: "USB Subsystem",
    vector: "Root Path Normalization",
    status: "✅ PASS",
    latency: `${latency} ms`,
    detail: "Canonical E:\\ Handled",
  };
}

async function testUsbSystemJunkBypass() {
  const t0 = Date.now();
  const tmpDir = path.join(os.tmpdir(), `lookout_audit_junk_${Date.now()}`);
  fs.mkdirSync(tmpDir, { recursive: true });

  const recycleDir = path.join(tmpDir, "$RECYCLE.BIN");
  fs.mkdirSync(recycleDir, { recursive: true });
  fs.writeFileSync(path.join(recycleDir, "trashed.dat"), "Recycled OS junk");

  const sysVolDir = path.join(tmpDir, "System Volume Information");
  fs.mkdirSync(sysVolDir, { recursive: true });
  fs.writeFileSync(path.join(sysVolDir, "indexer.dat"), "System volume index");

  fs.writeFileSync(path.join(tmpDir, "document.txt"), "Legitimate user text file");

  try {
    const result = await usbScanner.scanUsbDrive(tmpDir);

    const junkScanned = (result.threats || []).some(
      (t) =>
        t.path.toLowerCase().includes("$recycle.bin") ||
        t.path.toLowerCase().includes("system volume information")
    );

    if (junkScanned) {
      throw new Error("OS system junk files were flagged as threats instead of being ignored");
    }

    if (result.scannedFiles > 1) {
      throw new Error(
        `Expected only 1 non-junk file scanned, but scannedFiles count was ${result.scannedFiles}`
      );
    }
  } finally {
    safeRmDir(tmpDir);
  }

  const latency = Date.now() - t0;
  return {
    subsystem: "USB Subsystem",
    vector: "System Junk Bypass ($RECYCLE)",
    status: "✅ PASS",
    latency: `${latency} ms`,
    detail: "OS Folders Skipped",
  };
}

async function testUsbAttackVectors() {
  const t0 = Date.now();
  const tmpDir = path.join(os.tmpdir(), `lookout_audit_vectors_${Date.now()}`);
  fs.mkdirSync(tmpDir, { recursive: true });

  // 1. autorun.inf execution hook
  fs.writeFileSync(
    path.join(tmpDir, "autorun.inf"),
    "[autorun]\r\nopen=malware.exe\r\naction=Open Folder"
  );

  // 2. Double extension masked executable
  fs.writeFileSync(
    path.join(tmpDir, "document.pdf.exe"),
    "MZ\x90\x00Mock executable masked as PDF"
  );

  // 3. .lnk shortcut dropper
  const lnkBuffer = Buffer.from(
    "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3... -WindowStyle Hidden",
    "utf-8"
  );
  fs.writeFileSync(path.join(tmpDir, "invoice.lnk"), lnkBuffer);

  // 4. Benign file
  fs.writeFileSync(path.join(tmpDir, "clean.txt"), "Clean file content");

  try {
    const result = await usbScanner.scanUsbDrive(tmpDir);
    const threats = result.threats || [];

    const autorunCaught = threats.some((t) => t.name.toLowerCase() === "autorun.inf");
    const doubleExtCaught = threats.some((t) => t.name.toLowerCase() === "document.pdf.exe");
    const lnkCaught = threats.some((t) => t.name.toLowerCase() === "invoice.lnk");

    if (!autorunCaught) {
      throw new Error("Malicious autorun.inf execution hook was not flagged");
    }
    if (!doubleExtCaught) {
      throw new Error("Double extension masking executable (document.pdf.exe) was not flagged");
    }
    if (!lnkCaught) {
      throw new Error("LNK shortcut dropper was not flagged");
    }

    const cleanFlagged = threats.some((t) => t.name.toLowerCase() === "clean.txt");
    if (cleanFlagged) {
      throw new Error("Benign file (clean.txt) falsely flagged as a threat");
    }
  } finally {
    safeRmDir(tmpDir);
  }

  const latency = Date.now() - t0;
  return {
    subsystem: "USB Subsystem",
    vector: "USB Vectors (.lnk / autorun)",
    status: "✅ PASS",
    latency: `${latency} ms`,
    detail: "Vectors Intercepted",
  };
}

async function testUsbQuarantineEngine() {
  const t0 = Date.now();
  const tmpDir = path.join(os.tmpdir(), `lookout_audit_quar_${Date.now()}`);
  fs.mkdirSync(tmpDir, { recursive: true });

  const testFile = path.join(tmpDir, "eicar_mock.exe");
  fs.writeFileSync(testFile, "MOCK MALICIOUS BINARY CONTENT");

  try {
    const quarantineResult = await usbScanner.quarantineFiles([testFile]);

    if (quarantineResult.quarantinedCount !== 1) {
      throw new Error(
        `Expected 1 file quarantined, got ${quarantineResult.quarantinedCount}`
      );
    }

    if (fs.existsSync(testFile)) {
      throw new Error("Original file still exists after quarantine rename");
    }

    const quarantineFolder = quarantineResult.quarantineDir;
    if (!fs.existsSync(quarantineFolder)) {
      throw new Error(`Quarantine directory was not created: ${quarantineFolder}`);
    }

    const isolatedFiles = fs
      .readdirSync(quarantineFolder)
      .filter((f) => f.endsWith(".isolated"));
    if (isolatedFiles.length !== 1) {
      throw new Error("Isolated file does not possess .isolated extension");
    }

    const manifestPath = path.join(quarantineFolder, "manifest.json");
    if (!fs.existsSync(manifestPath)) {
      throw new Error("manifest.json was not generated in quarantine directory");
    }

    const manifestData = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
    if (!Array.isArray(manifestData) || manifestData.length === 0) {
      throw new Error("manifest.json is empty or not an array");
    }

    const entry = manifestData[0];
    if (!entry.originalPath || !entry.isolatedPath || !entry.timestamp) {
      throw new Error("manifest.json entry missing required integrity metadata keys");
    }
  } finally {
    safeRmDir(tmpDir);
  }

  const latency = Date.now() - t0;
  return {
    subsystem: "USB Subsystem",
    vector: "Quarantine & Manifest Atomicity",
    status: "✅ PASS",
    latency: `${latency} ms`,
    detail: "Safely Isolated",
  };
}

async function testUsbDeadSocketResilience() {
  const t0 = Date.now();
  const PORT = 48201;
  let daemonProc = null;

  async function isDaemonUp() {
    return new Promise((resolve) => {
      const ws = new WebSocket(`ws://localhost:${PORT}`);
      ws.on("open", () => {
        try { ws.close(); } catch {}
        resolve(true);
      });
      ws.on("error", () => {
        resolve(false);
      });
    });
  }

  const initialUp = await isDaemonUp();
  let daemonStderr = "";
  if (!initialUp) {
    daemonProc = spawn("node", ["usbDaemon.js"], {
      cwd: __dirname,
      stdio: ["pipe", "pipe", "pipe"],
    });
    daemonProc.stderr.on("data", (d) => {
      daemonStderr += d.toString();
    });
    await new Promise((r) => setTimeout(r, 1500));
  }

  // Create temporary directory tree with multiple files to scan
  const tmpDir = path.join(os.tmpdir(), `lookout_audit_ws_${Date.now()}`);
  fs.mkdirSync(tmpDir, { recursive: true });
  for (let i = 0; i < 25; i++) {
    fs.writeFileSync(path.join(tmpDir, `item_${i}.dat`), `Payload content ${i}`);
  }

  try {
    const ws = new WebSocket(`ws://localhost:${PORT}`);
    await new Promise((resolve, reject) => {
      ws.on("open", resolve);
      ws.on("error", reject);
      setTimeout(() => reject(new Error("Timeout connecting to USB daemon")), 3000);
    });

    // Dispatch scan command
    ws.send(JSON.stringify({ action: "START_USB_SCAN", driveLetter: tmpDir }));

    // Wait briefly for scan traversal to initiate
    await new Promise((resolve) => {
      const msgHandler = (data) => {
        try {
          const parsed = JSON.parse(data.toString());
          if (parsed.type === "SCAN_STARTED" || parsed.type === "SCAN_PROGRESS") {
            ws.removeListener("message", msgHandler);
            resolve();
          }
        } catch {}
      };
      ws.on("message", msgHandler);
      setTimeout(resolve, 300);
    });

    // Abruptly terminate client socket connection mid-traversal
    ws.terminate();

    // Allow daemon time to receive close event and cancel active job
    await new Promise((r) => setTimeout(r, 600));

    if (
      daemonStderr.includes("UnhandledPromiseRejection") ||
      daemonStderr.includes("WebSocket is not open")
    ) {
      throw new Error(`Daemon threw unhandled error: ${daemonStderr}`);
    }

    // Verify daemon is still alive and responsive to new connections
    const stillHealthy = await isDaemonUp();
    if (!stillHealthy) {
      throw new Error("Daemon crashed or became unresponsive after client abruptly disconnected");
    }
  } finally {
    safeRmDir(tmpDir);
    if (daemonProc) {
      try {
        const shutdownWs = new WebSocket(`ws://localhost:${PORT}`);
        await new Promise((resolve) => {
          shutdownWs.on("open", () => {
            shutdownWs.send(JSON.stringify({ action: "SHUTDOWN" }));
            setTimeout(resolve, 200);
          });
          shutdownWs.on("error", resolve);
          setTimeout(resolve, 300);
        });
      } catch {}
      try { daemonProc.kill(); } catch {}
    }
  }

  const latency = Date.now() - t0;
  return {
    subsystem: "USB Subsystem",
    vector: "Dead Socket Client Abortion",
    status: "✅ PASS",
    latency: `${latency} ms`,
    detail: "Handled Gracefully",
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Master Audit Execution Runner
// ─────────────────────────────────────────────────────────────────────────────

function padEnd(str, length) {
  const s = String(str || "");
  return s.length >= length ? s : s + " ".repeat(length - s.length);
}

async function runMasterAudit() {
  const tests = [
    testUrlCleanApex,
    testUrlTyposquatting,
    testUrlSanitizerAndResiliency,
    testFileCleanBaseline,
    testFileMagicSpoofing,
    testFileExploitDropper,
    testFileVirusTotalHash,
    testUsbPathNormalization,
    testUsbSystemJunkBypass,
    testUsbAttackVectors,
    testUsbQuarantineEngine,
    testUsbDeadSocketResilience,
  ];

  const results = [];
  let failures = 0;

  // Suppress internal component logs during test run so report prints cleanly
  const origLog = console.log;
  const origWarn = console.warn;
  console.log = () => {};
  console.warn = () => {};

  for (const testFn of tests) {
    try {
      const res = await testFn();
      results.push(res);
    } catch (err) {
      failures++;
      results.push({
        subsystem: "Error",
        vector: testFn.name,
        status: "❌ FAIL",
        latency: "0 ms",
        detail: err.message.slice(0, 21),
      });
    }
  }

  // Restore console for report output
  console.log = origLog;
  console.warn = origWarn;

  // Render unified audit table
  console.log("========================================================================================================");
  console.log("                               LOOKOUT UNIFIED SYSTEM AUDIT REPORT                                      ");
  console.log("========================================================================================================");
  console.log("| Pipeline / Subsystem | Test Vector                     | Status    | Latency | Audit Detail          |");
  console.log("|----------------------|---------------------------------|-----------|---------|-----------------------|");

  for (const r of results) {
    const colSub = padEnd(r.subsystem, 20);
    const colVec = padEnd(r.vector, 31);
    const colSta = padEnd(r.status, 9);
    const colLat = padEnd(r.latency, 7);
    const colDet = padEnd(r.detail, 21);
    console.log(`| ${colSub} | ${colVec} | ${colSta} | ${colLat} | ${colDet} |`);
  }

  console.log("========================================================================================================");

  if (failures === 0) {
    console.log("Final Verdict: ALL 3 SUBSYSTEMS PRODUCTION OPERATIONAL (0 FAILURES)");
    process.exit(0);
  } else {
    console.log(`Final Verdict: AUDIT FAILED WITH ${failures} FAILED VECTOR(S)`);
    process.exit(1);
  }
}

if (require.main === module) {
  runMasterAudit().catch((err) => {
    console.error("FATAL AUDIT RUNNER EXCEPTION:", err);
    process.exit(1);
  });
}

module.exports = { runMasterAudit };
