import express from 'express';
import { d as parseOAuthCallbackInput } from './node_modules/openclaw/dist/auth-profiles-DnpV8DWM.js';

const app = express();

// In-memory config store — holds the last successfully imported providers.
// Populated by POST /api/config/import (when not dry_run).
// Read by GET /api/config/export.
let configStore = [];

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
//
// Triggering example:
//   POST /vuln  {"input": "bare_auth_code_no_url", "expectedState": "legitimate-state-value"}
//   GET  /vuln?input=bare_auth_code_no_url&expectedState=legitimate-state-value
//
// The response will be {"result":{"code":"bare_auth_code_no_url","state":"legitimate-state-value"}}
// proving the attacker-supplied code was accepted without state verification.
app.all('/vuln', express.json(), (req, res) => {
  const input         = req.body?.input         ?? req.query?.input         ?? '';
  const expectedState = req.body?.expectedState  ?? req.query?.expectedState  ?? 'legitimate-state-value';

  const result = parseOAuthCallbackInput(input, expectedState);
  res.json({ result });
});

// POST /api/config/import
// Accepts an XML body (Content-Type: application/xml or text/xml) containing
// OAuth provider configuration. Parses the XML and returns the providers array.
//
// express.text({ type: '*/*' }) is used as route-level middleware to read the
// raw body as a string. Using type:'*/*' ensures the body is always captured
// regardless of Content-Length/Transfer-Encoding headers. Content-Type
// validation is done inside the handler.
//
// Query params:
//   dry_run=true  — parse and validate without persisting; returns { changes: [...] }
//
// Expected XML structure:
//   <config>
//     <provider name="github">
//       <clientId>abc123</clientId>
//       <clientSecret>secret456</clientSecret>
//       <callbackUrl>http://localhost:9090/auth/callback</callbackUrl>
//     </provider>
//   </config>
//
// Normal response:  { providers: [{ name, clientId, clientSecret, callbackUrl, ... }] }
// Dry-run response: { changes: [{ action: 'add', provider: { name, ... } }, ...] }
app.post('/api/config/import', express.text({ type: '*/*' }), (req, res) => {
  // Validate Content-Type
  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('application/xml') && !contentType.includes('text/xml')) {
    return res.status(400).json({
      error: 'Content-Type must be application/xml or text/xml'
    });
  }

  // express.text() populates req.body with the raw string.
  const xmlContent = typeof req.body === 'string' ? req.body : '';
  if (!xmlContent || xmlContent.trim() === '') {
    return res.status(400).json({
      error: 'Request body is empty. Please provide an XML configuration.'
    });
  }

  // Parse the XML
  let providers;
  try {
    providers = parseOAuthXml(xmlContent);
  } catch (parseError) {
    return res.status(400).json({
      error: parseError.message
    });
  }

  // Dry-run mode: return what would change without persisting
  const isDryRun = req.query.dry_run === 'true';
  if (isDryRun) {
    const changes = providers.map((provider) => ({ action: 'add', provider }));
    return res.status(200).json({ changes });
  }

  // Persist to in-memory config store and return the providers
  configStore = providers;
  return res.status(200).json({ providers });
});

// GET /api/config/export
// Returns the current config store serialised as XML.
// Response: XML document with Content-Type: application/xml
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
  const configBody = configMatch[1];

  const providerRegex = /<provider([^>]*)>([\s\S]*?)<\/provider>/g;
  const providers = [];
  let match;

  while ((match = providerRegex.exec(configBody)) !== null) {
    const attrStr = match[1];
    const body = match[2];

    const nameMatch = attrStr.match(/name\s*=\s*["']([^"']*)["']/);
    const name = nameMatch ? nameMatch[1] : '';

    const provider = { name };
    const fieldRegex = /<([a-zA-Z][a-zA-Z0-9_-]*)>([^<]*)<\/\1>/g;
    let fieldMatch;
    while ((fieldMatch = fieldRegex.exec(body)) !== null) {
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
