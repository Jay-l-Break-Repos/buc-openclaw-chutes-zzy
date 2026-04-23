import express from 'express';
import { XMLParser } from 'fast-xml-parser';
import { d as parseOAuthCallbackInput } from './node_modules/openclaw/dist/auth-profiles-DnpV8DWM.js';

const app = express();
app.use(express.json());

// Parse raw XML bodies for application/xml and text/xml content types
app.use((req, res, next) => {
  const contentType = req.headers['content-type'] || '';
  if (contentType.includes('application/xml') || contentType.includes('text/xml')) {
    let data = '';
    req.setEncoding('utf-8');
    req.on('data', (chunk) => { data += chunk; });
    req.on('end', () => {
      req.rawXml = data;
      next();
    });
    req.on('error', (err) => {
      next(err);
    });
  } else {
    next();
  }
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
app.all('/vuln', (req, res) => {
  const input         = req.body?.input         ?? req.query?.input         ?? '';
  const expectedState = req.body?.expectedState  ?? req.query?.expectedState  ?? 'legitimate-state-value';

  const result = parseOAuthCallbackInput(input, expectedState);
  res.json({ result });
});

// POST /api/config/import
// Accepts an XML body (Content-Type: application/xml or text/xml) containing
// OAuth provider configuration. Parses the XML and returns the providers array.
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
// Response: { providers: [{ name, clientId, clientSecret, callbackUrl, ... }] }
app.post('/api/config/import', (req, res) => {
  // Validate Content-Type
  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('application/xml') && !contentType.includes('text/xml')) {
    return res.status(400).json({
      error: 'Content-Type must be application/xml or text/xml'
    });
  }

  // Ensure we received a body
  const xmlContent = req.rawXml;
  if (!xmlContent || xmlContent.trim() === '') {
    return res.status(400).json({
      error: 'Request body is empty. Please provide an XML configuration.'
    });
  }

  // Parse the XML
  let parsed;
  try {
    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      parseAttributeValue: true,
      parseTagValue: true,
      trimValues: true,
      isArray: (tagName) => tagName === 'provider'  // always treat <provider> as array
    });
    parsed = parser.parse(xmlContent);
  } catch (parseError) {
    return res.status(422).json({
      error: `Failed to parse XML: ${parseError.message}`
    });
  }

  // Validate root element
  if (!parsed || !parsed.config) {
    return res.status(422).json({
      error: 'Invalid XML structure: missing <config> root element'
    });
  }

  // Extract providers — fast-xml-parser returns an array (forced by isArray above)
  // or undefined if no <provider> elements exist
  const rawProviders = parsed.config.provider;
  const providerList = Array.isArray(rawProviders) ? rawProviders : [];

  // Map each provider to a clean object: lift the name attribute and keep child elements
  const providers = providerList.map((p) => {
    const { '@_name': name, ...rest } = p;
    return { name, ...rest };
  });

  return res.status(200).json({ providers });
});

app.listen(9090, '0.0.0.0', () => {
  console.log('Carrier app listening on http://0.0.0.0:9090');
});
