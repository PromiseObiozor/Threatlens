# ThreatLens frontend

This directory contains the React/Vite interface for ThreatLens.

The UI deliberately uses plain React components, Axios, inline SVG icons, and
normal CSS. It has no component framework, chart library, router, animation
library, or external state-management dependency.

## Main files

- `src/App.jsx`: session, form, scan, report, and history state.
- `src/components/AuthScreen.jsx`: login and registration screen.
- `src/components/ConsoleHeader.jsx`: branding, real history counters, user
  controls, and About link.
- `src/components/EmailInputPanel.jsx`: field/raw tabs, parser, samples, and
  scan form.
- `src/components/ThreatReport.jsx`: gauge, four layer scores, findings, and
  safety guidance.
- `src/components/HistoryPanel.jsx`: saved record selection and confirmed
  deletion.
- `src/components/AboutPage.jsx`: methodology, stack, scoring, and limitations.
- `src/emailParser.js`: raw source and supported Gmail-style text parsing.
- `src/reportUtils.js`: risk copy, counters, grouping, and date formatting.

## Commands

```bash
npm install
npm run dev
npm test
npm run lint
npm run build
```

The API URL is `http://localhost:8000` by default. Override it with
`VITE_API_BASE_URL`.
