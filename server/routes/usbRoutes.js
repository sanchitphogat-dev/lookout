const express = require("express");
const { v4: uuidv4 } = require("uuid");
const { simulateUsbScan } = require("../services/usbScanner");
const { calculateRisk } = require("../services/riskEngine");
const { getDb, run } = require("../db");

const { sendNativeOsToast } = require("../usbDaemon");

const router = express.Router();

router.post("/", async (req, res) => {
  try {
    await getDb();

    // If payload contains completed scan details from WebSocket daemon or browser picker:
    if (req.body && (req.body.target || req.body.threats || req.body.filesScanned !== undefined || req.body.scannedFiles !== undefined)) {
      const id = req.body.id || uuidv4();
      const target = req.body.target || req.body.driveLetter || "Removable Media / USB";
      const findings = req.body.findings || req.body.threats || [];
      const riskScore = req.body.riskScore !== undefined ? req.body.riskScore : (findings.length > 0 ? 85 : 0);
      const explanation = req.body.explanation || (findings.length > 0 ? `${findings.length} malicious vector(s) intercepted` : "Clean file system");
      const recommendation = req.body.recommendation || (findings.length > 0 ? "Quarantine infected partitions immediately" : "Safe to access");
      const scannedFiles = req.body.scannedFiles || req.body.filesScanned || 0;

      run(
        `INSERT INTO scans (id, type, target, risk_score, findings_json, explanation, recommendation, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
        [id, "usb", target, riskScore, JSON.stringify(findings), explanation, recommendation]
      );

      return res.json({
        id,
        type: "usb",
        target,
        riskScore,
        riskLevel: riskScore >= 51 ? "high" : riskScore >= 16 ? "medium" : "low",
        scannedFiles,
        findings,
        explanation,
        recommendation
      });
    }

    const { scannedFiles, findings } = simulateUsbScan();
    const risk = calculateRisk(findings);

    const id = uuidv4();
    run(
      `INSERT INTO scans (id, type, target, risk_score, findings_json, explanation, recommendation, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
      [id, "usb", "Simulated USB Device", risk.score, JSON.stringify(findings), risk.explanation, risk.recommendation]
    );

    res.json({
      id,
      type: "usb",
      target: "Simulated USB Device",
      riskScore: risk.score,
      riskLevel: risk.level,
      scannedFiles,
      findings,
      explanation: risk.explanation,
      recommendation: risk.recommendation,
    });
  } catch (err) {
    console.error("USB scan error:", err);
    res.status(500).json({ error: "Scan failed" });
  }
});

router.post("/toast", (req, res) => {
  try {
    const { title, message, isWarning } = req.body || {};
    sendNativeOsToast(
      title || "Lookout Sentinel Intercept",
      message || "Removable drive attached. Please scan before opening files.",
      !!isWarning
    );
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
