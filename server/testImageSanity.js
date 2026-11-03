"use strict";

const assert = require("assert");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const { scanFile, scanFileBuffer, isValidImageHeader, IMAGE_SIGNATURES } = require("./fileScanner");

console.log("================================================================================");
console.log("             LOOKOUT IMAGE HEURISTICS SANITY & ANTI-SPOOFING AUDIT             ");
console.log("================================================================================");

let totalTests = 0;
let passedTests = 0;

function runTest(testName, testFn) {
  totalTests++;
  try {
    testFn();
    passedTests++;
    console.log(`  [PASS] ${testName}`);
  } catch (err) {
    console.error(`  [FAIL] ${testName}`);
    console.error(`         Error: ${err.message}`);
  }
}

async function runAsyncTest(testName, testFn) {
  totalTests++;
  try {
    await testFn();
    passedTests++;
    console.log(`  [PASS] ${testName}`);
  } catch (err) {
    console.error(`  [FAIL] ${testName}`);
    console.error(`         Error: ${err.message}`);
  }
}

async function main() {
  // ── Step 1: Magic Bytes Helper Verification ──────────────────────────────────
  runTest("1. isValidImageHeader recognizes standard image signatures", () => {
    const pngHeader = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
    const jpgHeader = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0]);
    const gifHeader = Buffer.from([0x47, 0x49, 0x46, 0x38, 0x39, 0x61]);
    const webpHeader = Buffer.concat([
      Buffer.from([0x52, 0x49, 0x46, 0x46]),
      Buffer.from([0x20, 0x00, 0x00, 0x00]),
      Buffer.from([0x57, 0x45, 0x42, 0x50])
    ]);
    const mzHeader = Buffer.from([0x4D, 0x5A, 0x90, 0x00]);

    assert.strictEqual(isValidImageHeader(pngHeader, ".png"), true, "Valid PNG header should return true");
    assert.strictEqual(isValidImageHeader(jpgHeader, ".jpg"), true, "Valid JPG header should return true");
    assert.strictEqual(isValidImageHeader(jpgHeader, ".jpeg"), true, "Valid JPEG header should return true");
    assert.strictEqual(isValidImageHeader(gifHeader, ".gif"), true, "Valid GIF header should return true");
    assert.strictEqual(isValidImageHeader(webpHeader, ".webp"), true, "Valid WEBP header should return true");

    assert.strictEqual(isValidImageHeader(mzHeader, ".png"), false, "MZ header with .png extension should return false");
    assert.strictEqual(isValidImageHeader(mzHeader, ".jpg"), false, "MZ header with .jpg extension should return false");
  });

  // ── Step 5: Primary Specification Tests with scanFile() ──────────────────────
  // 1. Create a 100-byte valid PNG buffer (starting with 89 50 4E 47 0D 0A 1A 0A followed by random high-entropy bytes)
  const pngMagic = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  const randomHighEntropyBytes = crypto.randomBytes(100 - pngMagic.length);
  const validPngBuffer = Buffer.concat([pngMagic, randomHighEntropyBytes]);

  // 2. Create a spoofed PNG buffer (starting with 4D 5A MZ header)
  const mzMagic = Buffer.from([0x4D, 0x5A, 0x90, 0x00]);
  const fakePayload = crypto.randomBytes(100 - mzMagic.length);
  const spoofedPngBuffer = Buffer.concat([mzMagic, fakePayload]);

  runTest("2. Assert Valid PNG through scanFile(): verdict === 'clean', riskScore === 0", () => {
    const validPngResult = scanFile(validPngBuffer, "legitimate_image.png");

    assert.strictEqual(
      validPngResult.verdict,
      "clean",
      `Expected verdict to be 'clean', got '${validPngResult.verdict}'`
    );
    assert.strictEqual(
      validPngResult.riskScore,
      0,
      `Expected riskScore to be 0, got ${validPngResult.riskScore}`
    );
    assert.strictEqual(
      validPngResult.findings.length,
      0,
      `Expected 0 findings for clean PNG, got ${validPngResult.findings.length}`
    );
  });

  runTest("3. Assert Spoofed PNG through scanFile(): verdict === 'threat_detected', riskScore >= 80", () => {
    const spoofedPngResult = scanFile(spoofedPngBuffer, "malware_disguised.png");

    assert.strictEqual(
      spoofedPngResult.verdict,
      "threat_detected",
      `Expected verdict to be 'threat_detected', got '${spoofedPngResult.verdict}'`
    );
    assert.ok(
      spoofedPngResult.riskScore >= 80,
      `Expected riskScore >= 80, got ${spoofedPngResult.riskScore}`
    );
    assert.ok(
      spoofedPngResult.findings.some((f) => f.type === "MIME_TYPE_SPOOFING"),
      "Expected findings to include MIME_TYPE_SPOOFING"
    );
  });

  // ── Additional Format Coverage (JPEG & Disk File Scanning) ───────────────────
  runTest("4. Assert Valid JPEG through scanFile(): verdict === 'clean', riskScore === 0", () => {
    const jpgMagic = Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46]);
    const validJpgBuffer = Buffer.concat([jpgMagic, crypto.randomBytes(100 - jpgMagic.length)]);
    const validJpgResult = scanFile(validJpgBuffer, "wallpaper.jpg");

    assert.strictEqual(validJpgResult.verdict, "clean");
    assert.strictEqual(validJpgResult.riskScore, 0);
  });

  runTest("5. Assert Spoofed JPEG through scanFile(): verdict === 'threat_detected', riskScore >= 80", () => {
    const spoofedJpgBuffer = Buffer.concat([Buffer.from([0x4D, 0x5A]), crypto.randomBytes(98)]);
    const spoofedJpgResult = scanFile(spoofedJpgBuffer, "invoice.jpg");

    assert.strictEqual(spoofedJpgResult.verdict, "threat_detected");
    assert.ok(spoofedJpgResult.riskScore >= 80);
  });

  runTest("6. On-Disk file path scanning through scanFile()", () => {
    const tmpValidPath = path.join(__dirname, "temp_test_valid.png");
    const tmpSpoofedPath = path.join(__dirname, "temp_test_spoofed.png");

    fs.writeFileSync(tmpValidPath, validPngBuffer);
    fs.writeFileSync(tmpSpoofedPath, spoofedPngBuffer);

    try {
      const validFileResult = scanFile(tmpValidPath, "temp_test_valid.png");
      assert.strictEqual(validFileResult.verdict, "clean");
      assert.strictEqual(validFileResult.riskScore, 0);

      const spoofedFileResult = scanFile(tmpSpoofedPath, "temp_test_spoofed.png");
      assert.strictEqual(spoofedFileResult.verdict, "threat_detected");
      assert.ok(spoofedFileResult.riskScore >= 80);
    } finally {
      try { fs.unlinkSync(tmpValidPath); } catch {}
      try { fs.unlinkSync(tmpSpoofedPath); } catch {}
    }
  });

  // ── Full Multi-Layer Async Scan (scanFileBuffer) ─────────────────────────────
  await runAsyncTest("7. Full Async Pipeline (scanFileBuffer) - Valid PNG is clean with empty flags", async () => {
    const result = await scanFileBuffer(validPngBuffer, "screenshot.png");

    assert.strictEqual(result.verdict, "clean", `Expected verdict 'clean', got '${result.verdict}'`);
    assert.strictEqual(result.riskScore, 0, `Expected riskScore 0, got ${result.riskScore}`);
    assert.deepStrictEqual(result.heuristics.flags, [], "Expected heuristics.flags to remain empty");
    assert.strictEqual(result.heuristics.isHighEntropy, false, "Expected isHighEntropy to be false");
    assert.strictEqual(result.heuristics.isValidImageHeader, true, "Expected isValidImageHeader to be true");
  });

  await runAsyncTest("8. Full Async Pipeline (scanFileBuffer) - Spoofed PNG triggers MIME_TYPE_SPOOFING", async () => {
    const result = await scanFileBuffer(spoofedPngBuffer, "trojan.png");

    assert.ok(result.riskScore >= 80, `Expected riskScore >= 80, got ${result.riskScore}`);
    assert.ok(
      result.heuristics.flags.includes("MIME_TYPE_SPOOFING"),
      "Expected heuristics.flags to include MIME_TYPE_SPOOFING"
    );
  });

  await runAsyncTest("9. Raw binary noise with accidental dropper strings does NOT flag clean PNG", async () => {
    // Inject substrings that would otherwise trigger dropper detectors into PNG body
    const noisyBytes = Buffer.from(
      "random image data with powershell.exe -enc and WScript.Shell and cmd.exe /c and curl http://malicious.com"
    );
    const noisyPng = Buffer.concat([pngMagic, noisyBytes, crypto.randomBytes(64)]);
    const result = await scanFileBuffer(noisyPng, "photo_with_noise.png");

    assert.strictEqual(result.verdict, "clean");
    assert.strictEqual(result.riskScore, 0);
    assert.strictEqual(result.heuristics.hasExploitStrings, false);
    assert.strictEqual(result.heuristics.isDropper, false);
    assert.deepStrictEqual(result.heuristics.flags, []);
  });

  console.log("================================================================================");
  console.log(`Final Result: ${passedTests}/${totalTests} tests passed`);
  console.log("================================================================================");

  if (passedTests !== totalTests) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Test runner encountered unhandled error:", err);
  process.exit(1);
});
