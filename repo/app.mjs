import express from 'express';
import { XMLParser, XMLValidator } from 'fast-xml-parser';
import { d as parseOAuthCallbackInput } from './node_modules/openclaw/dist/auth-profiles-DnpV8DWM.js';

const app = express();
app.use(express.json());

// In-memory config store — seeded so export always has at least one <provider>
let configStore = [
  { name: 'github', clientId: 'placeholder-id', clientSecret: 'placeholder-secret', callbackUrl: 'http://localhost:9090/auth/callback' }
];

app.get('/', (_req, res) => res.json({ status: 'ok' }));

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

// /vuln endpoint — demonstrates GHSA-7rcp-mxpq-72pj
app.all('/vuln', (req, res) => {
  const input         = req.body?.input         ?? req.query?.input         ?? '';
  const expectedState = req.body?.expectedState  ?? req.query?.expectedState  ?? 'legitimate-state-value';
  const result = parseOAuthCallbackInput(input, expectedState);
  res.json({ result });
});

// ---------------------------------------------------------------------------
// Multipart form-data parser (zero external dependencies)
// Extracts the first file part from a multipart/form-data request body.
// Returns { filename, content } where content is a Buffer.
// ---------------------------------------------------------------------------
function parseMultipartFile(body, boundary) {
  const boundaryBuf = Buffer.from('--' + boundary);
  const CRLF = Buffer.from('\r\n');
  const CRLFCRLF = Buffer.from('\r\n\r\n');

  let offset = 0;

  // Find each boundary and iterate over parts
  while (offset < body.length) {
    // Find the next boundary
    const boundaryIdx = indexOf(body, boundaryBuf, offset);
    if (boundaryIdx === -1) break;

    offset = boundaryIdx + boundaryBuf.length;

    // Check for terminal boundary (--)
    if (body[offset] === 0x2d && body[offset + 1] === 0x2d) break;

    // Skip CRLF after boundary
    if (body[offset] === 0x0d && body[offset + 1] === 0x0a) offset += 2;

    // Find end of headers (CRLFCRLF)
    const headersEnd = indexOf(body, CRLFCRLF, offset);
    if (headersEnd === -1) break;

    const headerSection = body.slice(offset, headersEnd).toString('utf-8');
    offset = headersEnd + 4; // skip CRLFCRLF

    // Find the next boundary to determine end of part content
    const nextBoundaryIdx = indexOf(body, Buffer.from('\r\n--' + boundary), offset);
    const contentEnd = nextBoundaryIdx === -1 ? body.length : nextBoundaryIdx;
    const content = body.slice(offset, contentEnd);

    // Parse Content-Disposition header
    const dispositionMatch = headerSection.match(/Content-Disposition\s*:[^\r\n]*/i);
    if (!dispositionMatch) continue;

    const disposition = dispositionMatch[0];

    // Only process file parts (those with a filename attribute)
    const filenameMatch = disposition.match(/filename\s*=\s*"([^"]*)"/i)
                       || disposition.match(/filename\s*=\s*([^\s;]+)/i);
    if (!filenameMatch) continue;

    const filename = filenameMatch[1];
    return { filename, content };
  }

  return null;
}

// Helper: find needle Buffer inside haystack Buffer starting at fromIndex
function indexOf(haystack, needle, fromIndex = 0) {
  for (let i = fromIndex; i <= haystack.length - needle.length; i++) {
    let found = true;
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) { found = false; break; }
    }
    if (found) return i;
  }
  return -1;
}

// ---------------------------------------------------------------------------
// POST /api/config/import
// Accepts a multipart/form-data upload containing an XML file.
// Parses and validates the XML; returns 400 with error details if malformed.
// Returns 200 { status: 'ok', message } on success (saving logic TBD).
// ---------------------------------------------------------------------------
app.post('/api/config/import', (req, res) => {
  const ct = req.headers['content-type'] || '';

  if (!ct.includes('multipart/form-data')) {
    return res.status(400).json({
      error: 'Content-Type must be multipart/form-data'
    });
  }

  // Extract boundary from Content-Type header
  const boundaryMatch = ct.match(/boundary=(?:"([^"]+)"|([^\s;]+))/i);
  if (!boundaryMatch) {
    return res.status(400).json({ error: 'Missing boundary in Content-Type header' });
  }
  const boundary = boundaryMatch[1] || boundaryMatch[2];

  // Collect raw request body
  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('error', (err) => res.status(500).json({ error: err.message }));
  req.on('end', () => {
    const body = Buffer.concat(chunks);

    if (body.length === 0) {
      return res.status(400).json({ error: 'Request body is empty.' });
    }

    // Extract the uploaded file from the multipart body
    const filePart = parseMultipartFile(body, boundary);
    if (!filePart) {
      return res.status(400).json({ error: 'No file found in multipart upload. Please include an XML file in the form field.' });
    }

    const xmlContent = filePart.content.toString('utf-8').trim();
    if (!xmlContent) {
      return res.status(400).json({ error: 'Uploaded file is empty.' });
    }

    // Validate that the XML is well-formed using fast-xml-parser's XMLValidator
    const validationResult = XMLValidator.validate(xmlContent, { allowBooleanAttributes: true });
    if (validationResult !== true) {
      // validationResult is an Error-like object: { err: { code, msg, line, col } }
      const errInfo = validationResult.err || {};
      return res.status(400).json({
        error: 'XML parse error: ' + (errInfo.msg || String(validationResult)),
        details: {
          filename: filePart.filename,
          code: errInfo.code,
          message: errInfo.msg,
          line: errInfo.line,
          col: errInfo.col
        }
      });
    }

    // XML is well-formed — return success (saving logic will be added in a follow-up)
    return res.status(200).json({
      status: 'ok',
      message: 'XML file parsed successfully.',
      filename: filePart.filename
    });
  });
});

// GET /api/config/export
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

function esc(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

app.listen(9090, '0.0.0.0', () => {
  console.log('Carrier app listening on http://0.0.0.0:9090');
});
