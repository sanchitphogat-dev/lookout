import { Routes, Route } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Navbar from "./components/Navbar";
import TelemetryDrawer from "./components/TelemetryDrawer";
import { TelemetryProvider } from "./context/TelemetryContext";
import Dashboard from "./pages/Dashboard";
import FileScan from "./pages/FileScan";
import UrlScan from "./pages/UrlScan";
import UsbScan from "./pages/UsbScan";
import Reports from "./pages/Reports";
import ScanDetail from "./pages/ScanDetail";
import Settings from "./pages/Settings";
import { useUsbWatcher } from "./hooks/useUsbWatcher";
import UsbInterceptModal from "./components/usb/UsbInterceptModal";

export default function App() {
  const {
    isDaemonConnected,
    detectedDrive,
    isInterceptOpen,
    scanState,
    simulateMockUsb,
    closeIntercept,
    startScan,
    progress,
    scanResult,
    threatsFound,
    quarantineThreats,
    openDriveInExplorer
  } = useUsbWatcher();

  return (
    <TelemetryProvider>
      <div className="flex min-h-screen bg-[#F8F9FA] dark:bg-[#0B0C0E] text-zinc-600 dark:text-[#8A8F98] font-sans antialiased selection:bg-[#5E6AD2]/20 selection:text-[#5E6AD2] dark:selection:bg-white/10 dark:selection:text-white transition-colors duration-150 relative">
        <Sidebar />
        <div className="flex-1 flex flex-col min-w-0">
          <Navbar />
          <main className="flex-1 p-5 md:p-7 overflow-y-auto">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/scan/file" element={<FileScan />} />
              <Route path="/scan/url" element={<UrlScan />} />
              <Route path="/scan/usb" element={<UsbScan />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/reports/:id" element={<ScanDetail />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          </main>
        </div>
        <TelemetryDrawer />
        
        {/* USB Intercept Modal */}
        <UsbInterceptModal 
          isOpen={isInterceptOpen} 
          drive={detectedDrive} 
          scanState={scanState} 
          progress={progress}
          scanProgress={progress}
          scanResult={scanResult}
          threatsFound={threatsFound}
          onClose={closeIntercept} 
          onScan={startScan}
          onQuarantine={quarantineThreats}
          openDriveInExplorer={openDriveInExplorer} 
        />

        {/* Dev Simulation Trigger */}
        <div className="fixed bottom-4 right-4 z-[60]">
          <button 
            onClick={simulateMockUsb}
            className="text-[10px] uppercase font-bold tracking-wider px-3 py-1.5 rounded-full bg-zinc-800 hover:bg-zinc-700 text-zinc-300 shadow-sm border border-zinc-700/50 transition-colors"
          >
            ⚡ Dev: Simulate USB Connect
          </button>
        </div>
      </div>
    </TelemetryProvider>
  );
}
