import axios from "axios";

const api = axios.create({
  baseURL: "/api",
  timeout: 30000,
});

export async function scanFile(file) {
  const formData = new FormData();
  formData.append("file", file);
  const { data } = await api.post("/scan/file", formData, {
    headers: { "Content-Type": "multipart/form-data" },
    timeout: 30000,
  });
  // Unwrap { success, data: { ... } } envelope and merge to top-level for backwards compat
  if (data?.success && data?.data) {
    return { ...data.data };
  }
  return data;
}

export function sanitizeTargetUrl(rawInput) {
  if (!rawInput || typeof rawInput !== "string") return "";

  // 1. Remove markdown wrappers like [text](url) or trailing ](...)
  let cleaned = rawInput.trim();
  const markdownMatch = cleaned.match(/\((https?:\/\/[^\s)]+)\)/i);
  if (markdownMatch) {
    cleaned = markdownMatch[1];
  } else if (cleaned.includes("](")) {
    const parts = cleaned.split("](");
    const left = (parts[0] || "").replace(/[\[\]\(\)\s`"'<>]/g, "");
    const right = (parts[1] || "").replace(/[\[\]\(\)\s`"'<>]/g, "");
    cleaned = /^https?:\/\//i.test(left) ? left : right || left;
  } else {
    // Strip accidental brackets, parentheses, backticks, quotes, or spaces
    cleaned = cleaned.replace(/[\[\]\(\)\s`"'<>]/g, "");
  }

  // Strip any duplicate concatenated protocol
  const secondProtoIdx = cleaned.slice(8).search(/https?:\/\//i);
  if (secondProtoIdx !== -1) {
    cleaned = cleaned.slice(0, secondProtoIdx + 8);
  }

  // 2. Prepend https:// if protocol is missing
  if (!/^https?:\/\//i.test(cleaned)) {
    cleaned = "https://" + cleaned;
  }

  // 3. Validate URL construction
  try {
    const parsed = new URL(cleaned);
    // Return sanitized absolute URL (hostname lowercase, clean search/path)
    return parsed.href;
  } catch (err) {
    return cleaned; // Fallback to trimmed string
  }
}

export async function scanUrl(url) {
  const cleanUrl = sanitizeTargetUrl(url);
  const { data } = await api.post("/scan/url", { url: cleanUrl });
  return data;
}

export async function scanUsb() {
  const { data } = await api.post("/scan/usb");
  return data;
}

export async function logUsbScan(scanData) {
  const { data } = await api.post("/scan/usb", scanData);
  return data;
}

export async function triggerNativeToast(toastData) {
  try {
    const { data } = await api.post("/scan/usb/toast", toastData);
    return data;
  } catch (err) {
    return null;
  }
}

export async function getReports(params = {}) {
  const { data } = await api.get("/reports", { params });
  return data;
}

export async function getReportStats() {
  const { data } = await api.get("/reports/stats");
  return data;
}

export async function getReportById(id) {
  const { data } = await api.get(`/reports/${id}`);
  return data;
}

export async function getSettings() {
  const { data } = await api.get("/settings");
  return data;
}

export async function saveSettings(settings) {
  const { data } = await api.put("/settings", settings);
  return data;
}

export default api;
