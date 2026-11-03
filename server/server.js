const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const fileRoutes = require("./routes/fileRoutes");
const urlRoutes = require("./routes/urlRoutes");
const usbRoutes = require("./routes/usbRoutes");
const reportRoutes = require("./routes/reportRoutes");
const settingsRoutes = require("./routes/settingsRoutes");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(helmet());
app.use(
  cors({
    origin: ["http://localhost:5173", "http://127.0.0.1:5173"],
    methods: ["GET", "POST", "PUT"],
  })
);
app.use(express.json({ limit: "32mb" }));
app.use(express.urlencoded({ extended: true, limit: "32mb" }));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later" },
});
app.use("/api", limiter);

const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: "Too many upload requests, please try again later" },
});
app.use("/api/scan/file", uploadLimiter);

app.use("/api/scan/file", fileRoutes);
app.use("/api/scan/url", urlRoutes);
app.use("/api/scan/usb", usbRoutes);
app.use("/api/reports", reportRoutes);
app.use("/api/settings", settingsRoutes);

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "Lookout Server" });
});

app.listen(PORT, () => {
  console.log(`Lookout server running on http://localhost:${PORT}`);
});
