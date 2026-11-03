"use strict";

const express = require("express");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");
const { scanFileBuffer } = require("../services/fileScanner");
const { getDb, run } = require("../db");

const router = express.Router();

//  Multer: in-memory storage, 32 MB cap 
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 32 * 1024 * 1024 }, // 32 MB
  fileFilter: (_req, _file, cb) => {
    // Accept all file types — binary inspection handles classification
    cb(null, true);
  },
});

// ─── POST /api/scan/file ──────────────────────────────────────────────────────



router.post("/", upload.single("file"), async (req, res) => {
  try {
    await getDb();

    if (!req.file) {
      return res.status(400).json({
        success: false,
        error: "No file uploaded. Send a multipart/form-data request with a 'file' field.",
      });
    }

    const { originalname, buffer, mimetype } = req.file;

    // Guard against empty buffers
    if (!buffer || buffer.length === 0) {
      return res.status(400).json({
        success: false,
        error: "Uploaded file is empty.",
      });
    }

    // ── Run the full multi-layer scan ──────────────────────────────────────────
    const scanData = await scanFileBuffer(buffer, originalname);

    // ── Persist to database ───────────────────────────────────────────────────
    const id = uuidv4();

    // Merge findings into a flat DB-friendly representation
    const findingsForDb = scanData.findings;
    const explanationForDb = scanData.explanation;
    const recommendationForDb = scanData.recommendation;

    run(
      `INSERT INTO scans (id, type, target, risk_score, findings_json, explanation, recommendation, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
      [
        id,
        "file",
        originalname,
        scanData.riskScore,
        JSON.stringify(findingsForDb),
        explanationForDb,
        recommendationForDb,
      ]
    );

    // ── Standardized Response ─────────────────────────────────────────────────
    return res.json({
      success: true,
      data: {
        id,
        type: "file",
        fileName: scanData.fileName,
        fileSize: scanData.fileSize,
        sha256: scanData.sha256,
        md5: scanData.md5,
        mimeType: scanData.mimeType,
        detectedType: scanData.detectedType,
        riskScore: scanData.riskScore,
        verdict: scanData.verdict,
        vtStats: scanData.vtStats,
        heuristics: scanData.heuristics,
        findings: scanData.findings,
        explanation: scanData.explanation,
        recommendation: scanData.recommendation,
        scannedAt: scanData.scannedAt,
        // Legacy compat fields (used by existing UnifiedScanHub)
        target: originalname,
        hash: scanData.sha256,
        riskLevel: scanData.riskScore >= 80 ? "high" : scanData.riskScore >= 40 ? "medium" : "low",
      },
    });
  } catch (err) {
    console.error("[FileRoute] Scan error:", err);
    if (err && err.statusCode === 400) {
      return res.status(400).json({
        success: false,
        error: err.message,
      });
    }
    return res.status(500).json({
      success: false,
      error: "File scan failed due to an internal error. Please try again.",
    });
  }
});

module.exports = router;
