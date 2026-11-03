const WebSocket = require('ws');
const { exec } = require('child_process');

const PORT = 48201;
let wss;
try {
  wss = new WebSocket.Server({ port: PORT });
  wss.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      console.warn(`[Lookout USB Daemon] Port ${PORT} already bound by an existing instance.`);
    } else {
      console.error('[Lookout USB Daemon] WebSocket error:', err);
    }
  });
} catch (e) {
  console.warn(`[Lookout USB Daemon] WebSocket Server initialization note: ${e.message}`);
}

const knownDrives = new Map();

console.log(`[Lookout USB Daemon] Operational on ws://localhost:${PORT}`);

const { scanUsbDrive, quarantineFiles } = require('./usbScanner');

/**
 * Defensive WebSocket transmission helper to guarantee no uncaught
 * "WebSocket is not open" exceptions are thrown.
 *
 * @param {WebSocket} ws
 * @param {Object|string} payload
 * @returns {boolean} Whether send was dispatched
 */
function safeSend(ws, payload) {
  try {
    if (ws && ws.readyState === WebSocket.OPEN) {
      const data = typeof payload === 'string' ? payload : JSON.stringify(payload);
      ws.send(data, (err) => {
        if (err) {
          // Socket write failed during closure, gracefully suppressed
        }
      });
      return true;
    }
  } catch (err) {
    // Suppress "WebSocket is not open" or closed socket writes
  }
  return false;
}

/**
 * Safely broadcasts payload to all connected clients whose state is strictly WebSocket.OPEN.
 *
 * @param {Object|string} message
 */
function safeBroadcast(message) {
  if (wss && wss.clients) {
    wss.clients.forEach(client => {
      if (client && client.readyState === WebSocket.OPEN) {
        safeSend(client, message);
      }
    });
  }
}

const broadcast = safeBroadcast;

function sendNativeOsToast(title, message, isWarning = false) {
  if (process.platform !== 'win32') return;

  const psScript = `
  [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms");
  $objNotifyIcon = New-Object System.Windows.Forms.NotifyIcon;
  $objNotifyIcon.Icon = [System.Drawing.SystemIcons]::Shield;
  $objNotifyIcon.BalloonTipIcon = "${isWarning ? 'Warning' : 'Info'}";
  $objNotifyIcon.BalloonTipTitle = "${title.replace(/"/g, '`"')}";
  $objNotifyIcon.BalloonTipText = "${message.replace(/"/g, '`"')}";
  $objNotifyIcon.Visible = $True;
  $objNotifyIcon.ShowBalloonTip(4000);
  Start-Sleep -Seconds 4;
  $objNotifyIcon.Dispose();
  `;

  try {
    const encoded = Buffer.from(psScript, 'utf16le').toString('base64');
    const child = exec(`powershell -NoProfile -WindowStyle Hidden -EncodedCommand ${encoded}`, (err) => {
      if (err) {
        // debug logging if needed
      }
    });
    if (child && child.unref) {
      child.unref();
    }
  } catch (e) {
    // Graceful error suppression
  }
}

if (wss) {
  wss.on('connection', (ws) => {
    safeSend(ws, {
      type: 'DAEMON_READY',
      drives: Array.from(knownDrives.values()),
      payload: {
        activeDrives: Array.from(knownDrives.values())
      }
    });

    let activeScanCancelled = false;

    ws.on('error', (err) => {
      console.warn('[Lookout USB Daemon] Client socket error:', err.message);
    });

    ws.on('message', async (message) => {
      try {
        const data = JSON.parse(message);
        if (data.action === 'START_USB_SCAN') {
          const drive = data.driveLetter;
          activeScanCancelled = false;
          let threatToastFired = false;

          safeBroadcast({ type: 'SCAN_STARTED', driveLetter: drive });

          let lastEmitTime = 0;
          function handleProgress(currentFile, scannedCount, totalFiles) {
            if (activeScanCancelled) return;
            if (typeof currentFile === 'object' && currentFile !== null) {
              scannedCount = currentFile.scannedCount ?? currentFile.scannedFiles ?? 0;
              totalFiles = currentFile.totalFiles ?? currentFile.totalDiscovered ?? 0;
              currentFile = currentFile.currentFile ?? '';
            }
            const now = Date.now();
            // Emit at most once every 100ms or on the final file
            if (now - lastEmitTime > 100 || scannedCount === totalFiles) {
              lastEmitTime = now;
              safeBroadcast({
                type: 'SCAN_PROGRESS',
                currentFile,
                scannedCount,
                scannedFiles: scannedCount,
                totalFiles,
                totalDiscovered: totalFiles
              });
            }
          }

          const onThreatFound = (threatData) => {
            if (!threatToastFired) {
              threatToastFired = true;
              sendNativeOsToast("Lookout Security Alert", "Malicious vectors intercepted on external media!", true);
            }
            if (!activeScanCancelled) {
              // High-confidence threat: bypass throttle and emit THREAT_DISCOVERED immediately
              safeBroadcast({ type: 'THREAT_DISCOVERED', threat: threatData });
            }
          };

          const scanResult = await scanUsbDrive(drive, handleProgress, onThreatFound, {
            isCancelled: () => activeScanCancelled || (ws && ws.readyState !== WebSocket.OPEN)
          });

          if (scanResult.threats && scanResult.threats.length > 0 && !threatToastFired) {
            threatToastFired = true;
            sendNativeOsToast("Lookout Security Alert", "Malicious vectors intercepted on external media!", true);
          }

          if (!activeScanCancelled) {
            safeBroadcast({ type: 'SCAN_COMPLETE', summary: scanResult });
          }
        } else if (data.action === 'QUARANTINE_THREATS') {
          const threatPaths = data.threatPaths || [];
          const result = await quarantineFiles(threatPaths);
          safeSend(ws, { type: 'QUARANTINE_SUCCESS', quarantinedCount: result.quarantinedCount });
        } else if (data.action === 'OPEN_DRIVE_IN_EXPLORER' && data.driveLetter) {
          const drive = data.driveLetter.endsWith('\\') ? data.driveLetter : `${data.driveLetter}\\`;
          // Launch native Windows Explorer window at drive root
          exec(`explorer.exe "${drive}"`, (err) => {
            if (err) {
              console.error('[Daemon] Failed to open explorer:', err.message);
            }
          });
        } else if (data.action === 'DEV_SIMULATE_CONNECT') {
          sendNativeOsToast("Lookout Sentinel Intercept", "Removable drive attached. Please scan before opening files.");
        } else if (data.action === 'THREAT_ALERT') {
          sendNativeOsToast("Lookout Security Alert", "Malicious vectors intercepted on external media!", true);
        } else if (data.action === 'SHUTDOWN') {
          safeSend(ws, { type: 'SHUTDOWN_ACK' });
          stopDaemon();
          setTimeout(() => process.exit(0), 100);
        }
      } catch (err) {
        console.error('[Lookout USB Daemon] Error handling message:', err);
      }
    });

    ws.on('close', () => {
      activeScanCancelled = true;
    });
  });
}

const PS_COMMAND = `Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 2 } | Select-Object DeviceID, VolumeName, @{Name='Size';Expression={$_.Size.ToString()}}, @{Name='FreeSpace';Expression={$_.FreeSpace.ToString()}}, FileSystem | ConvertTo-Json -Compress`;

function normalizeDriveTelemetry(raw) {
  const sizeBytes = parseFloat(raw.Size) || 0;
  const freeBytes = parseFloat(raw.FreeSpace) || 0;
  const usedBytes = Math.max(0, sizeBytes - freeBytes);

  const totalGb = sizeBytes > 0 ? (sizeBytes / (1024 ** 3)).toFixed(1) : "0.0";
  const freeGb = freeBytes > 0 ? (freeBytes / (1024 ** 3)).toFixed(1) : "0.0";
  const usedGb = (usedBytes / (1024 ** 3)).toFixed(1);
  const usedPercentage = sizeBytes > 0 ? Math.round((usedBytes / sizeBytes) * 100) : 0;

  const volumeName = (raw.VolumeName && raw.VolumeName.trim().length > 0)
    ? raw.VolumeName.trim()
    : "USB Drive";

  return {
    driveLetter: raw.DeviceID || raw.driveLetter, // e.g., "E:"
    volumeName,
    fileSystem: raw.FileSystem || raw.fileSystem || "exFAT",
    totalGb: `${totalGb} GB`,
    freeGb: `${freeGb} GB`,
    usedGb: `${usedGb} GB`,
    usedPercentage, // Integer percentage for CSS width
    rawSizeBytes: sizeBytes,
    size: `${totalGb} GB`,
    freeSpace: `${freeGb} GB`
  };
}

function formatBytes(bytes) {
  if (bytes === 0 || !bytes) return '0 GB';
  const k = 1000;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

async function getRemovableDrives() {
  if (process.platform !== 'win32') return [];

  return new Promise((resolve) => {
    const cmd = `powershell -NoProfile -Command "${PS_COMMAND}"`;
    
    exec(cmd, (error, stdout) => {
      if (error) {
        resolve([]);
        return;
      }

      const out = stdout.trim();
      if (!out) {
        resolve([]);
        return;
      }

      try {
        const parsed = JSON.parse(out);
        const drivesArray = Array.isArray(parsed) ? parsed : [parsed];
        
        const normalized = drivesArray.map(normalizeDriveTelemetry);
        
        resolve(normalized);
      } catch (err) {
        resolve([]);
      }
    });
  });
}

let isPolling = false;
async function pollDrives() {
  if (isPolling) return;
  isPolling = true;
  try {
    const currentDrivesArray = await getRemovableDrives();
    const currentDrives = new Map();

    for (const drive of currentDrivesArray) {
      currentDrives.set(drive.driveLetter, drive);
      
      if (!knownDrives.has(drive.driveLetter)) {
        const driveInfo = {
          ...drive,
          timestamp: Date.now()
        };
        
        knownDrives.set(drive.driveLetter, driveInfo);

        const message = {
          type: 'USB_MOUNTED',
          payload: driveInfo,
          ...driveInfo
        };

        console.log(`[Lookout USB Daemon] 🟢 Removable drive mounted: ${driveInfo.driveLetter} (${driveInfo.volumeName})`);
        sendNativeOsToast("Lookout Sentinel Intercept", "Removable drive attached. Please scan before opening files.");
        broadcast(message);
      }
    }

    for (const [letter] of knownDrives.entries()) {
      if (!currentDrives.has(letter)) {
        knownDrives.delete(letter);

        const message = {
          type: 'USB_EJECTED',
          driveLetter: letter,
          timestamp: Date.now()
        };

        console.log(`[Lookout USB Daemon] 🔴 Removable drive ejected: ${letter}`);
        broadcast(message);
      }
    }
  } catch (err) {
    console.error('[Lookout USB Daemon] Poll error:', err);
  } finally {
    isPolling = false;
  }
}

let pollInterval = setInterval(pollDrives, 2000);
pollDrives();

let heartbeatInterval = setInterval(() => {
  broadcast({ type: 'HEARTBEAT' });
}, 10000);

function stopDaemon() {
  if (pollInterval) {
    clearInterval(pollInterval);
    pollInterval = null;
  }
  if (heartbeatInterval) {
    clearInterval(heartbeatInterval);
    heartbeatInterval = null;
  }
  if (wss) {
    try {
      wss.close();
    } catch (e) {}
  }
}

process.on('SIGTERM', () => {
  stopDaemon();
  process.exit(0);
});

process.on('SIGINT', () => {
  stopDaemon();
  process.exit(0);
});

module.exports = {
  PS_COMMAND,
  sendNativeOsToast,
  getRemovableDrives,
  normalizeDriveTelemetry,
  knownDrives,
  wss,
  PORT,
  safeSend,
  broadcast,
  safeBroadcast,
  stopDaemon
};
