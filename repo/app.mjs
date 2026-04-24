import express from 'express';
import { d as parseOAuthCallbackInput } from './node_modules/openclaw/dist/auth-profiles-DnpV8DWM.js';

const app = express();
app.use(express.json());

// In-memory config store — seeded so export always has data
let configStore = [
  { name: 'github', clientId: 'placeholder-id', clientSecret: 'placeholder-secret', callbackUrl: 'http://localhost:9090/auth/callback' }
];

app.get('/', (_req, res) => res.json({ status: 'ok' }));

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// /vuln endpoint — demonstrates GHSA-7rcp-mxpq-72pj
// Vulnerability: parseOAuthCallbackInput accepts a bare authorization code
// (no URL, no state param) and returns { code, state } with the expectedState
// injected — bypassing OAuth CSRF state validation entirely.
//
// Triggering example:
//   POST /vuln  {"input": "bare_auth_code_no_url", "expectedState": "legitimate-state-value"}
//   GET  /vuln?input=bare_auth_code_no_url&expectedState=legitimate-state-value
//
// The response will be {"result":{"code":"bare_auth_code_no_url","state":"legitimate-state-value"}}
// proving the attacker-supplied code was accepted without state verification.
app.all('/vuln', (req, res) => {
  const input         = req.body?.input         ?? req.query?.input         ?? '';
  const expectedState = req.body?.expectedState  ?? req.query?.expectedState  ?? 'legitimate-state-value';

  const result = parseOAuthCallbackInput(input, expectedState);
  res.json({ result });
});

// ---------------------------------------------------------------------------
// POST /api/config/import
// Accepts Content-Type: application/xml or text/xml with XML in the request body.
// ?dry_run=true returns { changes: [...] } without persisting.
// ---------------------------------------------------------------------------
app.post('/api/config/import', (req, res) => {
  const ct = req.headers['content-type'] || '';
  if (!ct.includes('application/xml') && !ct.includes('text/xml')) {
    return res.status(400).json({ error: 'Content-Type must be application/xml or text/xml' });
  }

  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
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

    if (req.query.dry_run === 'true') {
      return res.status(200).json({ changes: providers.map((p) => ({ action: 'add', provider: p })) });
    }

    configStore = providers;
    return res.status(200).json({ providers });
  });
});

// ---------------------------------------------------------------------------
// GET /api/config/export
// Returns the current config store as XML.
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Minimal XML parser for OAuth config
// ---------------------------------------------------------------------------
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

app.listen(9090, '0.0.0.0', () => {
  console.log('Carrier app listening on http://0.0.0.0:9090');
});
