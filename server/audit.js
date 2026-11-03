const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

async function runAudit() {
  console.log("╔══════════════════════════════════════════════════════════════════╗");
  console.log("║   Lookout Security Backend — Phase 4 Diagnostic Audit Suite     ║");
  console.log("╚══════════════════════════════════════════════════════════════════╝\n");

  const report = [];
  const addReport = (module, component, status, latency, rootCause) => {
    report.push({ module, component, status, latency, rootCause });
  };

  const startTime = Date.now();

  // ── Environment Secret Ingestion ────────────────────────────────────────────
  let envFile = path.join(__dirname, '.env.local');
  let envContent = '';
  if (fs.existsSync(envFile)) {
    envContent = fs.readFileSync(envFile, 'utf8');
  } else if (fs.existsSync(path.join(__dirname, '..', '.env.local'))) {
    envFile = path.join(__dirname, '..', '.env.local');
    envContent = fs.readFileSync(envFile, 'utf8');
  }

  const gsbMatch = envContent.match(/GOOGLE_SAFE_BROWSING_API_KEY=["']?([^"'\n]+)/);
  const vtMatch = envContent.match(/VIRUSTOTAL_API_KEY=["']?([^"'\n]+)/);

  const gsbKey = gsbMatch ? gsbMatch[1] : null;
  const vtKey = vtMatch ? vtMatch[1] : null;

  const isPlaceholder = (val) =>
    !val || val.startsWith('your_') || val.includes('_key_here') || val === 'REPLACE_ME';

  const gsbKeyLive = gsbKey && !isPlaceholder(gsbKey);
  const vtKeyLive = vtKey && !isPlaceholder(vtKey);

  let envStatus = 'PASS';
  let envMsg = '';
  if (!gsbKeyLive) {
    envStatus = 'FAIL';
    envMsg += 'GSB Key missing or placeholder. ';
  }
  if (!vtKeyLive) {
    envStatus = 'FAIL';
    envMsg += 'VT Key missing or placeholder. ';
  }
  addReport('Environment', 'Secret Ingestion', envStatus, Date.now() - startTime, envMsg || 'Both GSB + VT keys loaded');

  // ── Spawn server on port 5001 ───────────────────────────────────────────────
  envContent += '\nPORT=5001';
  const tmpEnvPath = path.join(__dirname, '.env.local.tmp');
  fs.writeFileSync(tmpEnvPath, envContent);

  console.log("  ⏳ Spawning server on :5001 …");
  const serverProc = spawn('node', ['--env-file=' + tmpEnvPath, 'server.js'], {
    cwd: __dirname,
    stdio: 'pipe'
  });

  serverProc.stderr.on('data', data => {
    const msg = data.toString().trim();
    if (msg) console.error("  SERVER ERR:", msg);
  });

  let serverReady = false;
  await new Promise(resolve => {
    const timeout = setTimeout(() => {
      console.log("  ⚠  Timeout waiting for server start (3 s).");
      resolve();
    }, 3000);
    serverProc.stdout.on('data', data => {
      if (data.toString().includes('running on http')) {
        serverReady = true;
        clearTimeout(timeout);
        console.log("  ✓  Server ready.\n");
        resolve();
      }
    });
  });

  if (!serverReady) {
    addReport('Infrastructure', 'Server Boot', 'FAIL', Date.now() - startTime, 'Server did not start within 3 s');
  }

  // ── URL Pipeline Tests ──────────────────────────────────────────────────────
  const testUrl = async (name, url, expectedChecks) => {
    const st = Date.now();
    try {
      const res = await fetch('http://localhost:5001/api/scan/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      const data = await res.json();
      const latency = Date.now() - st;
      const pass = expectedChecks(data, res.status);
      addReport('URL Pipeline', name, pass ? 'PASS' : 'FAIL', latency,
        pass ? 'Ok' : 'Expected conditions not met');
      return data;
    } catch (err) {
      addReport('URL Pipeline', name, 'FAIL', Date.now() - st, err.message);
      return null;
    }
  };

  // 1. Clean URL — zero false positives
  await testUrl('Clean Vector (wikipedia.org)',
    'https://www.wikipedia.org',
    (d) => d.success && d.data.riskScore < 15 && d.data.verdict.toLowerCase() === 'clean');

  // 2. Typosquatting heuristic
  await testUrl('Typosquatting Detection (paypa1.com)',
    'http://paypa1.com/login-verification',
    (d) => d.success && d.data.riskScore > 0 && d.data.findings?.some(f => f.type === 'typosquatting_homoglyph'));

  // 3. Live GSB Malicious Test — must score high AND come from live API (not fallback)
  const gsbTestResult = await testUrl('GSB Malware Signature (heuristic)',
    'http://malware.testing.google.test/testing/malware/',
    (d) => d.success && d.data.riskScore > 75);

  // Dedicated GSB live upstream check
  const gsbSt = Date.now();
  if (gsbTestResult && gsbKeyLive) {
    const gsbR = gsbTestResult.data?.gsbResult || gsbTestResult.gsbResult;
    const gsbLive = gsbR && gsbR.fallback === false && gsbR.flagged === true;
    addReport('Cloud Service', 'Google Safe Browsing (Live Upstream)',
      gsbLive ? 'PASS' : 'FAIL', Date.now() - gsbSt,
      gsbLive ? 'Live API ping verified — not fallback' : `fallback=${gsbR?.fallback}, flagged=${gsbR?.flagged}`);
  } else if (!gsbKeyLive) {
    addReport('Cloud Service', 'Google Safe Browsing (Live Upstream)',
      'FAIL', 0, 'API key not configured — running in heuristic fallback mode');
  } else {
    addReport('Cloud Service', 'Google Safe Browsing (Live Upstream)',
      'FAIL', Date.now() - gsbSt, 'GSB test request failed');
  }

  // 4. Resiliency / malformed input
  await testUrl('Resiliency (Malformed Input)',
    '[link](http://192.168.1.1:8080/admin/utm_source=track)',
    (d, status) => d.success && !d.apiError && status !== 500);

  // ── File Pipeline Tests ─────────────────────────────────────────────────────
  const testFile = async (name, filename, buffer, expectedChecks) => {
    const st = Date.now();
    try {
      const formData = new FormData();
      formData.append('file', new Blob([buffer]), filename);
      const res = await fetch('http://localhost:5001/api/scan/file', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      const latency = Date.now() - st;
      const pass = expectedChecks(data, res.status);
      addReport('File Pipeline', name, pass ? 'PASS' : 'FAIL', latency,
        pass ? 'Ok' : 'Expected conditions not met');
      return data;
    } catch (err) {
      addReport('File Pipeline', name, 'FAIL', Date.now() - st, err.message);
      return null;
    }
  };

  // 5. Clean document — zero false positives
  await testFile('Clean Document (sample.txt)',
    'sample.txt',
    Buffer.from('Hello world this is a clean file.'),
    (d) => d.success && d.data.riskScore < 50);

  // 6. Magic bytes mismatch (MZ header in .pdf extension)
  const mzBuffer = Buffer.concat([Buffer.from('4D5A', 'hex'), Buffer.from('some other data to make it look like a pdf')]);
  await testFile('Magic Bytes Spoofing (.pdf with MZ header)',
    'contract.pdf', mzBuffer,
    (d) => d.success && d.data.riskScore > 0 && d.data.findings?.some(f => f.type.toLowerCase().includes('mime')));

  // 7. Exploit string detection
  await testFile('Exploit String Detection',
    'script.txt',
    Buffer.from('powershell.exe -enc WScript.Shell Net.WebClient'),
    (d) => d.success && d.data.riskScore >= 50);

  // 8. EICAR test file — VirusTotal hash cloud lookup
  const eicarString = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
  const eicarResult = await testFile('EICAR Hash (VT Cloud Lookup)',
    'eicar.txt',
    Buffer.from(eicarString),
    (d) => d.success);

  // Dedicated VT live upstream check using EICAR result
  const vtSt = Date.now();
  if (eicarResult && vtKeyLive) {
    const vtStats = eicarResult.data?.vtStats;
    const vtLive = vtStats && vtStats.queried === true && vtStats.malicious > 0;
    addReport('Cloud Service', 'VirusTotal Hash Lookup (Live Upstream)',
      vtLive ? 'PASS' : 'FAIL', Date.now() - vtSt,
      vtLive
        ? `Live EICAR detection: ${vtStats.malicious} engines flagged malicious`
        : `queried=${vtStats?.queried}, malicious=${vtStats?.malicious}, status=${vtStats?.vtStatus}`);
  } else if (!vtKeyLive) {
    addReport('Cloud Service', 'VirusTotal Hash Lookup (Live Upstream)',
      'FAIL', 0, 'API key not configured — running in heuristic fallback mode');
  } else {
    addReport('Cloud Service', 'VirusTotal Hash Lookup (Live Upstream)',
      'FAIL', Date.now() - vtSt, 'EICAR test request failed');
  }

  // ── Cleanup ─────────────────────────────────────────────────────────────────
  serverProc.kill();

  // ── Phase 4 Diagnostic Summary Table ────────────────────────────────────────
  console.log("\n╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════╗");
  console.log("║                              PHASE 4 DIAGNOSTIC SUMMARY TABLE                                              ║");
  console.log("╠══════════════════════════════════════════════════════════════════════════════════════════════════════════════╣");
  console.log('| Module / Vector       | Component Tested                        | Status         | Latency  | Root Cause / Detail                          |');
  console.log('|-----------------------|-----------------------------------------|----------------|----------|----------------------------------------------|');

  let totalPass = 0;
  let totalFail = 0;

  for (const r of report) {
    const icon = r.status === 'PASS' ? '✅' : '⚠️';
    const mod = r.module.padEnd(21);
    const comp = r.component.padEnd(39);
    const stat = (icon + ' ' + r.status).padEnd(14);
    const lat = (r.latency + 'ms').padEnd(8);
    const cause = (r.rootCause || '').slice(0, 44);
    console.log(`| ${mod} | ${comp} | ${stat} | ${lat} | ${cause} |`);
    if (r.status === 'PASS') totalPass++;
    else totalFail++;
  }

  console.log("╠══════════════════════════════════════════════════════════════════════════════════════════════════════════════╣");
  const overall = totalFail === 0 ? '✅ ALL CHECKS PASSED' : `⚠️  ${totalFail} CHECK(S) FAILED`;
  console.log(`║  Result: ${totalPass} PASS / ${totalFail} FAIL — ${overall}`.padEnd(110) + '║');
  console.log(`║  Total Audit Time: ${Date.now() - startTime}ms`.padEnd(110) + '║');
  console.log("╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n");
}

runAudit().catch(console.error);
