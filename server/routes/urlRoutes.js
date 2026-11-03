const express = require("express");
const { v4: uuidv4 } = require("uuid");
const {
  performFullUrlScan,
  sanitizeTargetUrl,
  buildZeroCrashFallbackResult,
} = require("../services/urlScanner");
const { getDb, run } = require("../db");

const router = express.Router();

router.post("/", async (req, res) => {
  const rawUrl = req.body?.url || "";
  try {
    const sanitizedUrl = sanitizeTargetUrl(rawUrl);
    if (!sanitizedUrl) {
      return res.status(400).json({
        success: false,
        error: "Please provide a valid URL string to analyze.",
      });
    }

    const scanData = await performFullUrlScan(sanitizedUrl);
    const { gsbResult, vtResult } = scanData;

    console.log("[Lookout Scan]", { gsbResult, vtResult });

    const id = uuidv4();
    const createdAt = scanData.scannedAt || new Date().toISOString();

    try {
      await getDb();
      run(
        `INSERT INTO scans (id, type, target, risk_score, findings_json, explanation, recommendation, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          id,
          "url",
          scanData.normalizedUrl,
          scanData.riskScore,
          JSON.stringify(scanData.findings || []),
          scanData.summary,
          scanData.recommendation,
          createdAt,
        ]
      );
    } catch (dbErr) {
      console.warn("URL scan DB persistence skipped:", dbErr?.message || dbErr);
    }

    const unifiedData = {
      id,
      url: scanData.url,
      targetUrl: scanData.targetUrl || scanData.normalizedUrl,
      normalizedUrl: scanData.normalizedUrl,
      hash: scanData.hash,
      riskScore: scanData.riskScore,
      verdict: scanData.verdict,
      apiError: Boolean(scanData.apiError),
      fallback: Boolean(scanData.fallback),
      vtStatus: scanData.vtStatus || vtResult?.status || "Analyzed",
      engines: scanData.engines || vtResult?.engines || "0 / 72 Flagged",
      summary: scanData.summary,
      stats: scanData.stats,
      threats: scanData.threats,
      googleSafeBrowsing: scanData.googleSafeBrowsing,
      heuristics: scanData.heuristics,
      gsbResult,
      vtResult,
      findings: scanData.findings,
      explanation: scanData.summary,
      recommendation: scanData.recommendation,
      scannedAt: createdAt,
    };

    return res.json({
      success: true,
      apiError: Boolean(scanData.apiError),
      fallback: Boolean(scanData.fallback),
      data: unifiedData,
      id,
      type: "url",
      target: scanData.normalizedUrl,
      risk_score: scanData.riskScore,
      created_at: createdAt,
      ...unifiedData,
    });
  } catch (err) {
    console.error("URL scan pipeline fallback:", err?.message || err);
    const fallbackData = buildZeroCrashFallbackResult(rawUrl || "https://unknown.local/");
    const id = uuidv4();
    const createdAt = new Date().toISOString();
    const unifiedFallback = {
      id,
      ...fallbackData,
      scannedAt: createdAt,
    };
    return res.status(200).json({
      success: true,
      fallback: true,
      data: unifiedFallback,
      id,
      type: "url",
      target: fallbackData.normalizedUrl,
      risk_score: fallbackData.riskScore,
      created_at: createdAt,
      ...unifiedFallback,
    });
  }
});

module.exports = router;
