const express = require("express");
const fs = require("fs");
const path = require("path");

const router = express.Router();

const DATA_DIR = path.join(__dirname, "..", "data");
const EXT_FILE = path.join(DATA_DIR, "blacklistExtensions.json");
const HASH_FILE = path.join(DATA_DIR, "knownBadHashes.json");
const KEYWORD_FILE = path.join(DATA_DIR, "suspiciousKeywords.json");

function readJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
  } catch {
    return [];
  }
}

function writeJson(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + "\n");
}

router.get("/", (req, res) => {
  try {
    res.json({
      extensions: readJson(EXT_FILE),
      hashes: readJson(HASH_FILE),
      keywords: readJson(KEYWORD_FILE),
    });
  } catch (err) {
    console.error("Settings read error:", err);
    res.status(500).json({ error: "Failed to read settings" });
  }
});

router.put("/", (req, res) => {
  try {
    const { extensions, hashes, keywords } = req.body;

    if (extensions && Array.isArray(extensions)) {
      writeJson(EXT_FILE, extensions);
    }

    if (hashes && Array.isArray(hashes)) {
      writeJson(HASH_FILE, hashes);
    }

    if (keywords && Array.isArray(keywords)) {
      writeJson(KEYWORD_FILE, keywords);
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Settings write error:", err);
    res.status(500).json({ error: "Failed to save settings" });
  }
});

module.exports = router;
