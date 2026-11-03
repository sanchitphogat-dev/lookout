const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn } = require('child_process');
const WebSocket = require('ws');

const { scanUsbDrive, quarantineFiles } = require('./usbScanner');

async function runUsbAudit() {
  const report = [];
  const addReport = (module, component, status, latency, detail) => {
    report.push({ module, component, status, latency, detail });
  };

  // Helper to safely clean up directories recursively
  function safeRmDir(dirPath) {
    try {
      if (fs.existsSync(dirPath)) {
        fs.rmSync(dirPath, { recursive: true, force: true });
      }
    } catch (e) {
      // Ignore cleanup error
    }
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Vector 1: Daemon Socket Connectivity
  // Pings ws://localhost:48201 and expects DAEMON_READY handshake
  // ─────────────────────────────────────────────────────────────────────────────
  const v1Start = Date.now();
  let daemonProc = null;
  let wsConnected = false;

  async function connectToDaemon(timeoutMs = 4000) {
    return new Promise((resolve) => {
      let resolved = false;
      const ws = new WebSocket('ws://localhost:48201');

      const timer = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          try { ws.terminate(); } catch (e) {}
          resolve({ ok: false, error: 'Connection timeout' });
        }
      }, timeoutMs);

      ws.on('open', () => {
        // Connected, waiting for DAEMON_READY handshake
      });

      ws.on('message', (data) => {
        try {
          const parsed = JSON.parse(data.toString());
          if (parsed.type === 'DAEMON_READY') {
            if (!resolved) {
              resolved = true;
              clearTimeout(timer);
              try { ws.close(); } catch (e) {}
              resolve({ ok: true, data: parsed });
            }
          }
        } catch (e) {
          // ignore parsing error
        }
      });

      ws.on('error', (err) => {
        if (!resolved) {
          resolved = true;
          clearTimeout(timer);
          resolve({ ok: false, error: err.message });
        }
      });
    });
  }

  try {
    // Attempt connecting to live daemon first
    let res = await connectToDaemon(1500);

    // If live daemon wasn't already running, spawn it in the background
    if (!res.ok) {
      daemonProc = spawn('node', ['usbDaemon.js'], {
        cwd: __dirname,
        stdio: 'pipe'
      });

      // Allow 2 seconds for daemon boot
      await new Promise((r) => setTimeout(r, 1200));
      res = await connectToDaemon(3000);
    }

    const v1Latency = Date.now() - v1Start;
    if (res.ok) {
      wsConnected = true;
      addReport('WebSocket Bridge', 'Local Daemon (Port 48201)', 'PASS', v1Latency, 'Connected');
    } else {
      addReport('WebSocket Bridge', 'Local Daemon (Port 48201)', 'FAIL', v1Latency, res.error || 'Failed handshake');
    }
  } catch (err) {
    addReport('WebSocket Bridge', 'Local Daemon (Port 48201)', 'FAIL', Date.now() - v1Start, err.message);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Vector 2: Recursive Traversal & OS Junk Filter
  // Creates a temporary synthetic directory tree containing $RECYCLE.BIN/corrupt.bin
  // and verifies that the junk folder is completely excluded.
  // ─────────────────────────────────────────────────────────────────────────────
  const v2Start = Date.now();
  const testJunkDir = path.join(os.tmpdir(), `lookout_usb_junk_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`);

  try {
    fs.mkdirSync(testJunkDir, { recursive: true });

    // Legitimate files
    fs.writeFileSync(path.join(testJunkDir, 'document.docx'), 'Benign word document payload');
    fs.writeFileSync(path.join(testJunkDir, 'readme.txt'), 'Legitimate plain text instructions');

    // OS junk directories that must be skipped
    const recycleDir = path.join(testJunkDir, '$RECYCLE.BIN');
    const sysVolDir = path.join(testJunkDir, 'System Volume Information');
    fs.mkdirSync(recycleDir, { recursive: true });
    fs.mkdirSync(sysVolDir, { recursive: true });

    fs.writeFileSync(path.join(recycleDir, 'corrupt.bin'), 'Simulated recycled corrupt executable');
    fs.writeFileSync(path.join(sysVolDir, 'indexer.dat'), 'Simulated volume tracking database');

    const result = await scanUsbDrive(testJunkDir);

    const scannedPaths = (result.threats || []).map(t => t.path || t.name);
    const recycledScanned = scannedPaths.some(p => p.includes('$RECYCLE.BIN') || p.includes('System Volume Information'));
    const isExcluded = !recycledScanned && result.scannedFiles === 2;

    const v2Latency = Date.now() - v2Start;
    if (isExcluded) {
      addReport('Junk Exclusion', 'Recycle/System Volume Skip', 'PASS', v2Latency, 'Excluded');
    } else {
      addReport('Junk Exclusion', 'Recycle/System Volume Skip', 'FAIL', v2Latency, `Recycled files not skipped (files=${result.scannedFiles})`);
    }
  } catch (err) {
    addReport('Junk Exclusion', 'Recycle/System Volume Skip', 'FAIL', Date.now() - v2Start, err.message);
  } finally {
    safeRmDir(testJunkDir);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Vector 3: LNK Shortcut Exploit Vector
  // Tests a synthetic .lnk buffer containing powershell.exe -enc and asserts detection LNK_EXECUTION_HOOK
  // ─────────────────────────────────────────────────────────────────────────────
  const v3Start = Date.now();
  const testLnkDir = path.join(os.tmpdir(), `lookout_usb_lnk_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`);

  try {
    fs.mkdirSync(testLnkDir, { recursive: true });

    // Create synthetic LNK payload containing powershell.exe -enc
    const lnkPayload = Buffer.from(
      '\x00\x00\x00\x00powershell.exe -enc SQBFAFgAKAAuLi4p -WindowStyle Hidden',
      'utf8'
    );
    const lnkPath = path.join(testLnkDir, 'invoice_tracking.lnk');
    fs.writeFileSync(lnkPath, lnkPayload);

    const lnkScanResult = await scanUsbDrive(testLnkDir);

    const foundHook = (lnkScanResult.threats || []).some(t => 
      t.type === 'LNK_EXECUTION_HOOK' ||
      t.detection === 'LNK_EXECUTION_HOOK' ||
      (t.reason && t.reason.includes('LNK_EXECUTION_HOOK')) ||
      (t.reason && t.reason.includes('LNK Dropper'))
    );

    const v3Latency = Date.now() - v3Start;
    if (foundHook && lnkScanResult.verdict === 'threat_detected') {
      addReport('USB Heuristics', 'LNK PowerShell Dropper', 'PASS', v3Latency, 'Intercepted');
    } else {
      addReport('USB Heuristics', 'LNK PowerShell Dropper', 'FAIL', v3Latency, 'LNK hook not detected');
    }
  } catch (err) {
    addReport('USB Heuristics', 'LNK PowerShell Dropper', 'FAIL', Date.now() - v3Start, err.message);
  } finally {
    safeRmDir(testLnkDir);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Vector 4: Quarantine Engine Verification
  // Tests quarantineFiles(), verifies target file moves to .lookout_quarantine/ with .isolated extension and updates manifest.json
  // ─────────────────────────────────────────────────────────────────────────────
  const v4Start = Date.now();
  const testQuarantineDir = path.join(os.tmpdir(), `lookout_usb_quar_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`);

  try {
    fs.mkdirSync(testQuarantineDir, { recursive: true });
    const targetFile = path.join(testQuarantineDir, 'trojan_payload.exe');
    fs.writeFileSync(targetFile, 'MALICIOUS_SIMULATED_TEST_PAYLOAD');

    const quarantineResult = await quarantineFiles([targetFile]);

    const targetQuarantineFolder = quarantineResult.quarantineDir || path.join(testQuarantineDir, '.lookout_quarantine');
    const isolatedFile = path.join(targetQuarantineFolder, 'trojan_payload.exe.isolated');
    const manifestFile = path.join(targetQuarantineFolder, 'manifest.json');

    const originalRemoved = !fs.existsSync(targetFile);
    const isolatedExists = fs.existsSync(isolatedFile);
    let manifestValid = false;

    if (fs.existsSync(manifestFile)) {
      try {
        const manifestData = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
        manifestValid = Array.isArray(manifestData) && manifestData.some(entry => entry.originalPath === targetFile);
      } catch (e) {
        manifestValid = false;
      }
    }

    const v4Latency = Date.now() - v4Start;
    const isQuarantineSuccess = quarantineResult.quarantinedCount === 1 && originalRemoved && isolatedExists && manifestValid;

    if (isQuarantineSuccess) {
      addReport('Quarantine Engine', 'File Isolation & Rename', 'PASS', v4Latency, 'Verified');
    } else {
      addReport('Quarantine Engine', 'File Isolation & Rename', 'FAIL', v4Latency, 
        `isolated=${isolatedExists}, manifest=${manifestValid}, origRemoved=${originalRemoved}`);
    }
  } catch (err) {
    addReport('Quarantine Engine', 'File Isolation & Rename', 'FAIL', Date.now() - v4Start, err.message);
  } finally {
    safeRmDir(testQuarantineDir);
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Vector 5: Fallback Resilience
  // Simulates an unmounted drive letter and asserts graceful error handling without terminating the process
  // ─────────────────────────────────────────────────────────────────────────────
  const v5Start = Date.now();
  try {
    const unmountedDrive = `Z:\\VIRTUAL_UNMOUNTED_${Date.now()}`;
    const fallbackResult = await scanUsbDrive(unmountedDrive);

    const v5Latency = Date.now() - v5Start;
    const isResilient = fallbackResult && typeof fallbackResult === 'object' && fallbackResult.verdict !== undefined;

    if (isResilient) {
      addReport('Fail-Safe Engine', 'Unmounted Drive Fallback', 'PASS', v5Latency, 'Resilient');
    } else {
      addReport('Fail-Safe Engine', 'Unmounted Drive Fallback', 'FAIL', v5Latency, 'Unexpected result format');
    }
  } catch (err) {
    // If it threw an unhandled crash
    addReport('Fail-Safe Engine', 'Unmounted Drive Fallback', 'FAIL', Date.now() - v5Start, err.message);
  }

  // Cleanup background daemon process if spawned by this audit runner
  if (daemonProc) {
    try {
      daemonProc.kill();
    } catch (e) {}
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // Render Output Summary Table (Exact format matching audit.js)
  // ─────────────────────────────────────────────────────────────────────────────
  console.log('========================================================================================');
  console.log('                           USB PIPELINE DIAGNOSTIC SUMMARY                              ');
  console.log('========================================================================================');
  console.log('| Module / Vector   | Component Tested            | Status    | Latency | Detail      |');
  console.log('|-------------------|-----------------------------|-----------|---------|-------------|');

  let totalPass = 0;
  let totalFail = 0;

  for (const r of report) {
    const isPass = r.status === 'PASS';
    const statusCol = isPass ? '✅ PASS  ' : '❌ FAIL  ';
    const latCol = `${r.latency} ms`.padEnd(7);
    const detailCol = (r.detail || '').slice(0, 11).padEnd(11);

    console.log(`| ${r.module.padEnd(17)} | ${r.component.padEnd(27)} | ${statusCol} | ${latCol} | ${detailCol} |`);

    if (isPass) totalPass++;
    else totalFail++;
  }

  console.log('========================================================================================');
  const summaryMsg = totalFail === 0 ? '✅ ALL CHECKS PASSED' : `⚠️  ${totalFail} CHECK(S) FAILED`;
  console.log(`Result: ${totalPass} PASS / ${totalFail} FAIL — ${summaryMsg}`);

  if (totalFail > 0) {
    process.exit(1);
  }
}

runUsbAudit().catch((err) => {
  console.error('[Lookout USB Audit Failure]', err);
  process.exit(1);
});
