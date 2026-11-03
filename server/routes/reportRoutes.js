const express = require("express");
const { getDb, queryAll, queryOne } = require("../db");

const router = express.Router();

router.get("/", async (req, res) => {
  try {
    await getDb();
    const { type, risk, page = "1", limit = "20" } = req.query;

    let query = "SELECT * FROM scans";
    const conditions = [];
    const params = [];

    if (type) {
      conditions.push("type = ?");
      params.push(type);
    }

    if (risk) {
      if (risk === "high" || risk === "malicious") {
        conditions.push("risk_score >= 51");
      } else if (risk === "medium" || risk === "suspicious") {
        conditions.push("risk_score >= 16 AND risk_score < 51");
      } else if (risk === "low" || risk === "clean") {
        conditions.push("risk_score <= 15");
      }
    }

    if (conditions.length > 0) {
      query += " WHERE " + conditions.join(" AND ");
    }

    const countQuery = query.replace("SELECT *", "SELECT COUNT(*) as count");
    const totalRow = queryOne(countQuery, params);
    const total = totalRow ? totalRow.count : 0;

    query += " ORDER BY created_at DESC";

    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const pageSize = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
    const offset = (pageNum - 1) * pageSize;

    query += " LIMIT ? OFFSET ?";
    params.push(pageSize, offset);

    const scans = queryAll(query, params).map((scan) => {
      try {
        scan.findings_json = JSON.parse(scan.findings_json);
      } catch {
        scan.findings_json = [];
      }
      return scan;
    });
    res.json({ scans, total, page: pageNum, limit: pageSize, pages: Math.ceil(total / pageSize) });
  } catch (err) {
    console.error("Reports error:", err);
    res.status(500).json({ error: "Failed to fetch reports" });
  }
});

router.get("/stats", async (req, res) => {
  try {
    await getDb();
    const totalRow = queryOne("SELECT COUNT(*) as count FROM scans");
    const total = totalRow.count;
    const byType = queryAll("SELECT type, COUNT(*) as count FROM scans GROUP BY type");
    const byRisk = queryAll(`
      SELECT
        CASE
          WHEN risk_score >= 51 THEN 'high'
          WHEN risk_score >= 16 THEN 'medium'
          ELSE 'low'
        END as level,
        COUNT(*) as count
      FROM scans GROUP BY level
    `);
    const recent = queryAll("SELECT * FROM scans ORDER BY created_at DESC LIMIT 5");

    res.json({ total, byType, byRisk, recent });
  } catch (err) {
    console.error("Stats error:", err);
    res.status(500).json({ error: "Failed to fetch stats" });
  }
});

router.get("/:id", async (req, res) => {
  try {
    await getDb();
    const scan = queryOne("SELECT * FROM scans WHERE id = ?", [req.params.id]);
    if (!scan) {
      return res.status(404).json({ error: "Scan not found" });
    }
    try {
      scan.findings_json = JSON.parse(scan.findings_json);
    } catch {
      scan.findings_json = [];
    }
    res.json(scan);
  } catch (err) {
    console.error("Scan detail error:", err);
    res.status(500).json({ error: "Failed to fetch scan detail" });
  }
});

module.exports = router;
