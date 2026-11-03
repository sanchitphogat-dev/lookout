const { scanFile } = require("./fileScanner");
const path = require("path");
const fs = require("fs");
const os = require("os");

const MOCK_USB_FILES = [
  { name: "document.pdf", content: "normal pdf content" },
  { name: "photo.jpg", content: Buffer.from([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00]) },
  { name: "resume.docx", content: "normal doc content" },
  { name: "autorun.exe", content: "suspicious executable" },
  { name: "setup.bat", content: "batch script content" },
  { name: "readme.txt", content: "normal text content" },
  { name: "install.msi", content: "installer content" },
  { name: "notes.txt", content: "normal text content" },
];

function simulateUsbScan() {
  const findings = [];
  const scannedFiles = [];
  const tmpDir = path.join(os.tmpdir(), "lookout-usb-scan");

  if (!fs.existsSync(tmpDir)) {
    fs.mkdirSync(tmpDir, { recursive: true });
  }

  for (const file of MOCK_USB_FILES) {
    const tmpFilePath = path.join(tmpDir, file.name);
    fs.writeFileSync(tmpFilePath, file.content);

    try {
      const result = scanFile(tmpFilePath, file.name);
      scannedFiles.push({
        name: file.name,
        findings: result.findings,
      });
      findings.push(...result.findings);
    } finally {
      try {
        fs.unlinkSync(tmpFilePath);
      } catch {}
    }
  }

  try {
    fs.rmdirSync(tmpDir);
  } catch {}

  return { scannedFiles, findings };
}

module.exports = { simulateUsbScan };
