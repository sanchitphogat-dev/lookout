const fs = require('fs');
const path = require('path');
const readline = require('readline');

const args = process.argv.slice(2);
if (args.length === 0) {
  console.error("Please provide a target drive letter. Example: node createTestUsb.js E:");
  process.exit(1);
}

let driveLetter = args[0];
// Normalize drive letter (e.g., E, E:, e: -> E:)
if (driveLetter.length === 1) {
  driveLetter = driveLetter.toUpperCase() + ':';
} else if (driveLetter.length === 2 && driveLetter[1] === ':') {
  driveLetter = driveLetter.toUpperCase();
} else if (driveLetter.length > 2 && driveLetter[1] === ':') {
  driveLetter = driveLetter.substring(0, 2).toUpperCase();
} else {
  driveLetter = driveLetter.charAt(0).toUpperCase() + ':';
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl.question(`Target drive: ${driveLetter}\\. Generate non-destructive demo threats? (y/n) `, (answer) => {
  if (answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes') {
    const vaultPath = path.join(driveLetter + '\\', 'Lookout_Demo_Vault');
    
    try {
      if (!fs.existsSync(vaultPath)) {
        fs.mkdirSync(vaultPath, { recursive: true });
      }

      // Vector A (EICAR Standard AV Test File)
      const eicarPath = path.join(vaultPath, 'eicar_test.txt');
      fs.writeFileSync(eicarPath, 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*');

      // Vector B (Double Extension Executable)
      const doubleExtPath = path.join(vaultPath, 'Quarterly_Report.pdf.exe');
      fs.writeFileSync(doubleExtPath, 'This is a benign text payload pretending to be an executable to trigger the masking heuristic.');

      // Vector C (Decoy Script Dropper)
      const dropperPath = path.join(vaultPath, 'system_update.bat');
      fs.writeFileSync(dropperPath, 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output Demo"');

      console.log(`[Lookout Test Harness] ✅ Safe test fixtures written to ${vaultPath}. Plug and scan to test live detection.`);
    } catch (err) {
      console.error(`[Error] Failed to write test fixtures: ${err.message}`);
    }
  } else {
    console.log("Operation cancelled.");
  }
  rl.close();
});
