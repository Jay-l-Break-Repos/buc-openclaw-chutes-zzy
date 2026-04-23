import express from 'express';
import { createServer } from 'node:http';
import { d as parseOAuthCallbackInput } from './node_modules/openclaw/dist/auth-profiles-DnpV8DWM.js';

const app = express();

// ── Config store ────────────────────────────────────────────────────────────
// Seeded so GET /api/config/export always has at least one <provider> element.
let configStore = [
  { name: 'github', clientId: 'placeholder-id', clientSecret: 'placeholder-secret', callbackUrl: 'http://localhost:9090/auth/callback' }
];

// ── Health ───────────────────────────────────────────────────────────────────
app.get('/', (_req, res) => res.json({ status: 'ok' }));
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ── /vuln ────────────────────────────────────────────────────────────────────
app.post('/vuln', express.json(), (req, res) => {
  const input         = req.body?.input         ?? '';
  const expectedState = req.body?.expectedState  ?? 'legitimate-state-value';
  res.json({ result: parseOAuthCallbackInput(input, expectedState) });
});
app.get('/vuln', (req, res) => {
  const input         = req.query?.input         ?? '';
  const expectedState = req.query?.expectedState  ?? 'legitimate-state-value';
  res.json({ result: parseOAuthCallbackInput(input, expectedState) });
});

// ── POST /api/config/import ──────────────────────────────────────────────────
app.post('/api/config/import', (req, res) => {
  const ct = req.headers['content-type'] || '';
  if (!ct.includes('application/xml') && !ct.includes('text/xml')) {
    return res.status(400).json({ error: 'Content-Type must be application/xml or text/xml' });
  }

  // Collect body chunks manually — no body-parser dependency
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('error', (err) => res.status(500).json({ error: err.message }));
  req.on('end', () => {
    const xml = Buffer.concat(chunks).toString('utf-8').trim();

    if (!xml) {
      return res.status(400).json({ error: 'Request body is empty.' });
    }

    let providers;
    try {
      providers = parseOAuthXml(xml);
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }

    const isDryRun = req.query.dry_run === 'true';
    if (isDryRun) {
      return res.status(200).json({ changes: providers.map((p) => ({ action: 'add', provider: p })) });
    }

    configStore = providers;
    return res.status(200).json({ providers });
  });
});

// ── GET /api/config/export ───────────────────────────────────────────────────
app.get('/api/config/export', (_req, res) => {
  const inner = configStore.map(({ name, ...fields }) => {
    const kids = Object.entries(fields)
      .map(([k, v]) => `    <${k}>${esc(String(v))}</${k}>`)
      .join('\n');
    return `  <provider name="${esc(String(name))}">\n${kids}\n  </provider>`;
  }).join('\n');

  res.set('Content-Type', 'application/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>\n<config>\n${inner}\n</config>`);
});

// ── XML helpers ──────────────────────────────────────────────────────────────
function parseOAuthXml(xml) {
  if (!xml.includes('<config') || !xml.includes('</config>')) {
    throw new Error('Invalid XML: missing <config> root element');
  }
  const m = xml.match(/<config[^>]*>([\s\S]*?)<\/config>/);
  if (!m) throw new Error('Invalid XML: malformed <config>');

  const providers = [];
  const pRe = /<provider([^>]*)>([\s\S]*?)<\/provider>/g;
  let pm;
  while ((pm = pRe.exec(m[1])) !== null) {
    const nm = pm[1].match(/name\s*=\s*["']([^"']*)["']/);
    const p = { name: nm ? nm[1] : '' };
    const fRe = /<([a-zA-Z][a-zA-Z0-9_-]*)>([^<]*)<\/\1>/g;
    let fm;
    while ((fm = fRe.exec(pm[2])) !== null) p[fm[1]] = fm[2].trim();
    providers.push(p);
  }
  return providers;
}

function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

// ── Start ────────────────────────────────────────────────────────────────────
createServer(app).listen(9090, '0.0.0.0', () => {
  console.log('Carrier app listening on http://0.0.0.0:9090');
});
