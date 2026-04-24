import express from 'express';
import { XMLValidator, XMLParser, XMLBuilder } from 'fast-xml-parser';
import { d as parseOAuthCallbackInput } from './node_modules/openclaw/dist/auth-profiles-DnpV8DWM.js';

const app = express();
app.use(express.json());

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

// ===========================================================================
// In-memory OAuth provider configuration store
//
// Structure:
//   configStore  Map<providerName, providerConfig>
//
// providerConfig shape (all strings, nulls for absent optional fields):
//   {
//     name              – unique provider identifier (e.g. "google")
//     client_id         – OAuth 2.0 client ID
//     client_secret     – OAuth 2.0 client secret
//     authorization_url – URL of the authorization endpoint
//     token_url         – URL of the token endpoint
//     scopes            – space-separated list of requested scopes (optional, null if absent)
//     redirect_uri      – registered redirect URI (optional, null if absent)
//     importedAt        – ISO-8601 timestamp set at import time
//   }
// ===========================================================================
const configStore = new Map();

// ---------------------------------------------------------------------------
// OAuth provider XML schema definition
//
// Expected XML structure:
//
//   <OAuthProvider>
//     <name>google</name>
//     <client_id>...</client_id>
//     <client_secret>...</client_secret>
//     <authorization_url>https://...</authorization_url>
//     <token_url>https://...</token_url>
//     <!-- optional -->
//     <scopes>openid email profile</scopes>
//     <redirect_uri>https://...</redirect_uri>
//   </OAuthProvider>
//
// REQUIRED_FIELDS must be present and non-empty.
// OPTIONAL_FIELDS are imported when present.
// VALID_URL_FIELDS must contain a syntactically valid http/https URL when present.
// ---------------------------------------------------------------------------
const REQUIRED_FIELDS  = ['name', 'client_id', 'client_secret', 'authorization_url', 'token_url'];
const OPTIONAL_FIELDS  = ['scopes', 'redirect_uri'];
const VALID_URL_FIELDS = ['authorization_url', 'token_url', 'redirect_uri'];
const ROOT_ELEMENT     = 'OAuthProvider';

/**
 * Validate a parsed OAuthProvider object against the schema.
 *
 * @param {object} provider  – the value of the root <OAuthProvider> element
 * @returns {{ valid: boolean, errors: string[] }}
 */
function validateOAuthProviderSchema(provider) {
  const errors = [];

  if (!provider || typeof provider !== 'object') {
    return { valid: false, errors: ['Root element <OAuthProvider> is missing or empty.'] };
  }

  // Check required fields are present and non-empty
  for (const field of REQUIRED_FIELDS) {
    const value = provider[field];
    if (value === undefined || value === null || String(value).trim() === '') {
      errors.push(`Required field <${field}> is missing or empty.`);
    }
  }

  // Validate URL fields (only when present and non-empty)
  for (const field of VALID_URL_FIELDS) {
    const raw = provider[field];
    if (raw === undefined || raw === null || String(raw).trim() === '') continue;
    const value = String(raw).trim();
    try {
      const url = new URL(value);
      if (!['http:', 'https:'].includes(url.protocol)) {
        errors.push(`Field <${field}> must be an http or https URL, got: "${value}".`);
      }
    } catch {
      errors.push(`Field <${field}> is not a valid URL: "${value}".`);
    }
  }

  // Validate provider name: alphanumeric + hyphens/underscores only
  if (provider.name && !/^[A-Za-z0-9_-]+$/.test(String(provider.name).trim())) {
    errors.push(
      `Field <name> must contain only alphanumeric characters, hyphens, or underscores. Got: "${provider.name}".`
    );
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Extract the OAuthProvider object from a parsed XML document.
 * fast-xml-parser returns { OAuthProvider: { ... } } for the root element.
 *
 * @param {object} parsed  – result of XMLParser.parse()
 * @returns {object|null}
 */
function extractProvider(parsed) {
  if (!parsed || typeof parsed !== 'object') return null;
  return parsed[ROOT_ELEMENT] ?? null;
}

// ---------------------------------------------------------------------------
// Multipart form-data parser (zero external dependencies beyond Node built-ins)
// Extracts the first file part from a multipart/form-data request body.
// Returns { filename, content } where content is a Buffer, or null if not found.
// ---------------------------------------------------------------------------
function parseMultipartFile(body, boundary) {
  const boundaryBuf = Buffer.from('--' + boundary);
  const CRLFCRLF    = Buffer.from('\r\n\r\n');

  let offset = 0;

  while (offset < body.length) {
    const boundaryIdx = bufIndexOf(body, boundaryBuf, offset);
    if (boundaryIdx === -1) break;

    offset = boundaryIdx + boundaryBuf.length;

    // Terminal boundary ends with '--'
    if (body[offset] === 0x2d && body[offset + 1] === 0x2d) break;

    // Skip the CRLF that follows the boundary line
    if (body[offset] === 0x0d && body[offset + 1] === 0x0a) offset += 2;

    // Find the blank line separating headers from body (CRLFCRLF)
    const headersEnd = bufIndexOf(body, CRLFCRLF, offset);
    if (headersEnd === -1) break;

    const headerSection = body.slice(offset, headersEnd).toString('utf-8');
    offset = headersEnd + 4; // advance past CRLFCRLF

    // Locate the end of this part's content (next boundary, preceded by CRLF)
    const nextBoundary = bufIndexOf(body, Buffer.from('\r\n--' + boundary), offset);
    const contentEnd   = nextBoundary === -1 ? body.length : nextBoundary;
    const content      = body.slice(offset, contentEnd);

    // Parse Content-Disposition to find the filename attribute
    const dispositionMatch = headerSection.match(/Content-Disposition\s*:[^\r\n]*/i);
    if (!dispositionMatch) continue;

    const disposition   = dispositionMatch[0];
    const filenameMatch =
      disposition.match(/filename\s*=\s*"([^"]*)"/i) ||
      disposition.match(/filename\s*=\s*([^\s;]+)/i);
    if (!filenameMatch) continue; // skip non-file fields

    return { filename: filenameMatch[1], content };
  }

  return null;
}

// Helper: find needle Buffer inside haystack Buffer starting at fromIndex
function bufIndexOf(haystack, needle, fromIndex = 0) {
  const hLen = haystack.length;
  const nLen = needle.length;
  outer: for (let i = fromIndex; i <= hLen - nLen; i++) {
    for (let j = 0; j < nLen; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

// ---------------------------------------------------------------------------
// POST /api/config/import
//
// Accepts a multipart/form-data upload containing an XML file that describes
// an OAuth provider configuration.
//
// Processing pipeline:
//   1. Content-Type / boundary validation
//   2. Raw body buffering
//   3. Multipart extraction (first file part)
//   4. XML well-formedness check (XMLValidator)
//   5. XML parsing into a JS object (XMLParser)
//   6. Schema validation (required fields, URL syntax, name format)
//   7. Save to in-memory configStore (keyed by provider name)
//   8. Return 200 with an import summary
// ---------------------------------------------------------------------------
app.post('/api/config/import', (req, res) => {
  const ct = req.headers['content-type'] || '';

  if (!ct.includes('multipart/form-data')) {
    return res.status(400).json({ error: 'Content-Type must be multipart/form-data' });
  }

  const boundaryMatch = ct.match(/boundary=(?:"([^"]+)"|([^\s;]+))/i);
  if (!boundaryMatch) {
    return res.status(400).json({ error: 'Missing boundary in Content-Type header' });
  }
  const boundary = boundaryMatch[1] || boundaryMatch[2];

  // Accumulate the raw request body
  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('error', (err) => res.status(500).json({ error: err.message }));
  req.on('end', () => {
    const body = Buffer.concat(chunks);

    if (body.length === 0) {
      return res.status(400).json({ error: 'Request body is empty.' });
    }

    // ── Step 1: Extract the uploaded file from the multipart body ──────────
    const filePart = parseMultipartFile(body, boundary);
    if (!filePart) {
      return res.status(400).json({
        error: 'No file found in multipart upload. Please include an XML file in the form field.'
      });
    }

    const xmlContent = filePart.content.toString('utf-8').trim();
    if (!xmlContent) {
      return res.status(400).json({ error: 'Uploaded file is empty.' });
    }

    // ── Step 2: XML well-formedness check ──────────────────────────────────
    const wellFormedResult = XMLValidator.validate(xmlContent, { allowBooleanAttributes: true });
    if (wellFormedResult !== true) {
      const errInfo = wellFormedResult.err || {};
      return res.status(400).json({
        error: 'XML parse error: ' + (errInfo.msg || String(wellFormedResult)),
        details: {
          filename: filePart.filename,
          code:     errInfo.code,
          message:  errInfo.msg,
          line:     errInfo.line,
          col:      errInfo.col
        }
      });
    }

    // ── Step 3: Parse XML into a JS object ─────────────────────────────────
    let parsed;
    try {
      const parser = new XMLParser({
        ignoreAttributes:       false,
        attributeNamePrefix:    '@_',
        allowBooleanAttributes: true,
        parseTagValue:          true,
        trimValues:             true
      });
      parsed = parser.parse(xmlContent);
    } catch (parseErr) {
      return res.status(400).json({
        error:   'Failed to parse XML: ' + parseErr.message,
        details: { filename: filePart.filename }
      });
    }

    // ── Step 4: Verify root element and extract provider object ────────────
    const provider = extractProvider(parsed);
    if (!provider) {
      return res.status(400).json({
        error:   `XML schema error: root element must be <${ROOT_ELEMENT}>.`,
        details: {
          filename:      filePart.filename,
          foundRootKeys: Object.keys(parsed || {})
        }
      });
    }

    // ── Step 5: Schema validation ──────────────────────────────────────────
    const { valid, errors: schemaErrors } = validateOAuthProviderSchema(provider);
    if (!valid) {
      return res.status(400).json({
        error:   'XML schema validation failed.',
        details: {
          filename: filePart.filename,
          errors:   schemaErrors
        }
      });
    }

    // ── Step 6: Save to config store ───────────────────────────────────────
    const providerName = String(provider.name).trim();
    const isUpdate     = configStore.has(providerName);

    const record = {
      name:              providerName,
      client_id:         String(provider.client_id).trim(),
      client_secret:     String(provider.client_secret).trim(),
      authorization_url: String(provider.authorization_url).trim(),
      token_url:         String(provider.token_url).trim(),
      scopes:            provider.scopes       ? String(provider.scopes).trim()       : null,
      redirect_uri:      provider.redirect_uri ? String(provider.redirect_uri).trim() : null,
      importedAt:        new Date().toISOString()
    };

    configStore.set(providerName, record);

    // ── Step 7: Return import summary ──────────────────────────────────────
    const summary = {
      provider:          record.name,
      client_id:         record.client_id,
      authorization_url: record.authorization_url,
      token_url:         record.token_url,
      scopes:            record.scopes,
      redirect_uri:      record.redirect_uri,
      importedAt:        record.importedAt
    };

    return res.status(200).json({
      status:   isUpdate ? 'updated' : 'created',
      message:  `OAuth provider "${providerName}" ${isUpdate ? 'updated' : 'imported'} successfully.`,
      filename: filePart.filename,
      summary
    });
  });
});

// ---------------------------------------------------------------------------
// GET /api/config/export
//
// Returns all stored OAuth provider configurations as a well-formed XML
// document with Content-Type: application/xml.
//
// Document structure:
//
//   <?xml version="1.0" encoding="UTF-8"?>
//   <OAuthProviders exportedAt="2026-04-24T13:00:00.000Z" count="2">
//     <OAuthProvider>
//       <name>google</name>
//       <client_id>...</client_id>
//       <client_secret>...</client_secret>
//       <authorization_url>...</authorization_url>
//       <token_url>...</token_url>
//       <scopes>openid email profile</scopes>      <!-- omitted when null -->
//       <redirect_uri>https://...</redirect_uri>  <!-- omitted when null -->
//       <importedAt>...</importedAt>
//     </OAuthProvider>
//     ...
//   </OAuthProviders>
//
// When no providers are stored, returns a self-closing root element:
//   <OAuthProviders exportedAt="..." count="0"/>
//
// client_secret IS included in the export (admin-level endpoint).
// ---------------------------------------------------------------------------
app.get('/api/config/export', (_req, res) => {
  const providers = Array.from(configStore.values());
  const exportedAt = new Date().toISOString();

  // Build the JS object tree that XMLBuilder will serialise.
  // XMLBuilder config: attributeNamePrefix '@_', ignoreAttributes false.
  const doc = {
    OAuthProviders: {
      '@_exportedAt': exportedAt,
      '@_count':      providers.length,
      // Each provider becomes an <OAuthProvider> child element.
      // Null/absent optional fields are omitted from the output.
      OAuthProvider: providers.map((p) => {
        const node = {
          name:              p.name,
          client_id:         p.client_id,
          client_secret:     p.client_secret,
          authorization_url: p.authorization_url,
          token_url:         p.token_url,
          importedAt:        p.importedAt
        };
        // Only include optional fields when they have a value
        if (p.scopes)       node.scopes       = p.scopes;
        if (p.redirect_uri) node.redirect_uri = p.redirect_uri;
        return node;
      })
    }
  };

  const builder = new XMLBuilder({
    ignoreAttributes:    false,
    attributeNamePrefix: '@_',
    format:              true,       // pretty-print with indentation
    indentBy:            '  ',
    suppressEmptyNode:   true        // self-close empty elements
  });

  const xmlBody = builder.build(doc);
  const xmlDoc  = '<?xml version="1.0" encoding="UTF-8"?>\n' + xmlBody;

  res.set('Content-Type', 'application/xml; charset=utf-8');
  res.send(xmlDoc);
});

// ---------------------------------------------------------------------------
// GET /api/config/providers
// Returns all currently stored OAuth provider configurations as JSON.
// The client_secret field is redacted in the response.
// ---------------------------------------------------------------------------
app.get('/api/config/providers', (req, res) => {
  const providers = Array.from(configStore.values()).map((p) => ({
    ...p,
    client_secret: '[REDACTED]'
  }));
  res.json({ providers });
});

// ---------------------------------------------------------------------------
// GET /api/config/providers/:name
// Returns a single provider by name (client_secret redacted).
// ---------------------------------------------------------------------------
app.get('/api/config/providers/:name', (req, res) => {
  const record = configStore.get(req.params.name);
  if (!record) {
    return res.status(404).json({ error: `Provider "${req.params.name}" not found.` });
  }
  res.json({ provider: { ...record, client_secret: '[REDACTED]' } });
});

app.listen(9090, '0.0.0.0', () => {
  console.log('Carrier app listening on http://0.0.0.0:9090');
});
