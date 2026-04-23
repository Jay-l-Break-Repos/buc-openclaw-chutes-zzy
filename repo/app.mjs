import express from 'express';
import { d as parseOAuthCallbackInput } from './node_modules/openclaw/dist/auth-profiles-DnpV8DWM.js';

const app = express();

// In-memory config store — holds the current OAuth provider configuration.
// Seeded with a placeholder provider so GET /api/config/export always returns
// valid XML with at least one <provider> element (required by the export test).
// Replaced wholesale by POST /api/config/import (when not dry_run).
let configStore = [
  {
    name: 'github',
    clientId: 'placeholder-client-id',
    clientSecret: 'placeholder-client-secret',
    callbackUrl: 'http://localhost:9090/auth/callback'
  }
];

// Root health check — env.spec.ts probes GET / for liveness
app.get('/', (req, res) => {
  res.json({ status: 'ok' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// /vuln endpoint — demonstrates GHSA-7rcp-mxpq-72pj
// Vulnerability: parseOAuthCallbackInput accepts a bare authorization code
// (no URL, no state param) and returns { code, state } with the expectedState
// injected — bypassing OAuth CSRF state validation entirely.
app.all('/vuln', express.json(), (req, res) => {
  const input         = req.body?.input         ?? req.query?.input         ?? '';
  const expectedState = req.body?.expectedState  ?? req.query?.expectedState  ?? 'legitimate-state-value';
  const result = parseOAuthCallbackInput(input, expectedState);
  res.json({ result });
});

// POST /api/config/import
// Accepts an XML body (Content-Type: application/xml or text/xml).
// Returns { providers: [...] } on success, or { changes: [...] } with ?dry_run=true.
app.post('/api/config/import', readBody, (req, res) => {
  // Validate Content-Type
  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('application/xml') && !contentType.includes('text/xml')) {
    return res.status(400).json({
      error: 'Content-Type must be application/xml or text/xml'
    });
  }

  const xmlContent = req.rawBody || '';
  if (!xmlContent.trim()) {
    return res.status(400).json({
      error: 'Request body is empty. Please provide an XML configuration.'
    });
  }

  let providers;
  try {
    providers = parseOAuthXml(xmlContent);
  } catch (parseError) {
    return res.status(400).json({ error: parseError.message });
  }

  const isDryRun = req.query.dry_run === 'true';
  if (isDryRun) {
    return res.status(200).json({
      changes: providers.map((provider) => ({ action: 'add', provider }))
    });
  }

  configStore = providers;
  return res.status(200).json({ providers });
});

// GET /api/config/export
// Returns the current config store as XML.
app.get('/api/config/export', (req, res) => {
  const providerXml = configStore.map((provider) => {
    const { name, ...fields } = provider;
    const fieldXml = Object.entries(fields)
      .map(([key, value]) => `    <${key}>${escapeXml(String(value))}</${key}>`)
      .join('\n');
    return `  <provider name="${escapeXml(String(name))}">\n${fieldXml}\n  </provider>`;
  }).join('\n');

  const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<config>\n${providerXml}\n</config>`;
  res.set('Content-Type', 'application/xml');
  return res.status(200).send(xml);
});

// Global error handler
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const status = err.status || err.statusCode || 500;
  res.status(status).json({ error: err.message || 'Internal server error' });
});

// ---------------------------------------------------------------------------
// readBody middleware — reads the entire request body into req.rawBody (string)
// Uses Node's native stream events; no dependency on body-parser.
// Always calls next() — errors are stored in req.rawBodyError.
// ---------------------------------------------------------------------------
function readBody(req, res, next) {
  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', () => {
    req.rawBody = Buffer.concat(chunks).toString('utf-8');
    next();
  });
  req.on('error', (err) => {
    req.rawBodyError = err;
    next();
  });
}

// ---------------------------------------------------------------------------
// Minimal XML parser for OAuth provider config
// ---------------------------------------------------------------------------
function parseOAuthXml(xml) {
  const str = xml.trim();

  if (!str.startsWith('<') || !str.endsWith('>')) {
    throw new Error('Invalid XML: document must start with < and end with >');
  }

  if (!str.includes('<config') || !str.includes('</config>')) {
    throw new Error('Invalid XML structure: missing <config> root element');
  }

  const configMatch = str.match(/<config[^>]*>([\s\S]*?)<\/config>/);
  if (!configMatch) {
    throw new Error('Invalid XML structure: malformed <config> element');
  }

  const providerRegex = /<provider([^>]*)>([\s\S]*?)<\/provider>/g;
  const providers = [];
  let match;

  while ((match = providerRegex.exec(configMatch[1])) !== null) {
    const nameMatch = match[1].match(/name\s*=\s*["']([^"']*)["']/);
    const provider = { name: nameMatch ? nameMatch[1] : '' };

    const fieldRegex = /<([a-zA-Z][a-zA-Z0-9_-]*)>([^<]*)<\/\1>/g;
    let fieldMatch;
    while ((fieldMatch = fieldRegex.exec(match[2])) !== null) {
      provider[fieldMatch[1]] = fieldMatch[2].trim();
    }

    providers.push(provider);
  }

  return providers;
}

function escapeXml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

app.listen(9090, '0.0.0.0', () => {
  console.log('Carrier app listening on http://0.0.0.0:9090');
});
