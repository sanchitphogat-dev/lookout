# Lookout — Cybersecurity Threat Detection Dashboard (Demo Prototype)

> A unified threat detection dashboard prototype. **This is a DEMO, not a production security tool.**

## Stack

- **Frontend:** React (Vite) + Tailwind CSS
- **Backend:** Node.js + Express
- **Database:** SQLite (better-sqlite3)

## Quick Start

```bash
# Install all dependencies (root + server + client)
npm run install:all

# Run both server and client concurrently
npm run dev
```

- **Client:** http://localhost:5173
- **Server:** http://localhost:5000

## Project Structure

```
/lookout
  /client          — React + Vite + Tailwind frontend
  /server          — Node.js + Express backend
  /server/data     — Mock threat intelligence data (hashes, blacklists)
  /server/routes   — API route handlers
  /server/services — Scanning & risk engine logic
```

## Features

- **Dashboard** — Overview with stat cards, risk breakdown, recent activity
- **File Scan** — Drag-and-drop file upload with hash + extension analysis
- **URL Scan** — Lexical heuristic analysis of submitted URLs
- **USB Scan** — Simulated USB device scan with mock file analysis
- **Reports** — Filterable scan history table with CSV export
- **Scan Detail** — Drill-down view of individual scan findings
- **Settings** — View/edit blacklisted extensions and known-bad hashes
