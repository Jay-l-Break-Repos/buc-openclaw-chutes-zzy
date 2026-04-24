import express from 'express';
import { XMLValidator } from 'fast-xml-parser';
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

// ---------------------------------------------------------------------------
// Multipart form-data parser (zero external dependencies beyond Node built-ins)
// Extracts the first file part from a multipart/form-data request body.
// Returns { filename, content } where content is a Buffer, or null if not found.
// ---------------------------------------------------------------------------
function parseMultipartFile(body, boundary) {
  const boundaryBuf = Buffer.from('--' + boundary);
  const CRLFCRLF = Buffer.from('\r\n\r\n');

  let offset = 0;

  while (offset < body.length) {
    // Locate the next part boundary
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
    const contentEnd = nextBoundary === -1 ? body.length : nextBoundary;
    const content = body.slice(offset, contentEnd);

    // Parse Content-Disposition to find the filename attribute
    const dispositionMatch = headerSection.match(/Content-Disposition\s*:[^\r\n]*/i);
    if (!dispositionMatch) continue;

    const disposition = dispositionMatch[0];
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
// Accepts a multipart/form-data upload containing an XML file.
//   - Returns 400 with structured parse details if the XML is malformed.
//   - Returns 200 { status, message, filename } if the XML is well-formed.
//     (Saving to the config store will be added in a follow-up step.)
// ---------------------------------------------------------------------------
app.post('/api/config/import', (req, res) => {
  const ct = req.headers['content-type'] || '';

  if (!ct.includes('multipart/form-data')) {
    return res.status(400).json({
      error: 'Content-Type must be multipart/form-data'
    });
  }

  // Extract the multipart boundary from the Content-Type header
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

    // Extract the uploaded XML file from the multipart body
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

    // Validate XML well-formedness using fast-xml-parser's XMLValidator
    const validationResult = XMLValidator.validate(xmlContent, { allowBooleanAttributes: true });
    if (validationResult !== true) {
      // On failure, validationResult is { err: { code, msg, line, col } }
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

    // XML is well-formed — return success (saving logic deferred to follow-up)
    return res.status(200).json({
      status: 'ok',
      message: 'XML file parsed successfully.',
      filename: filePart.filename
    });
  });
});

app.listen(9090, '0.0.0.0', () => {
  console.log('Carrier app listening on http://0.0.0.0:9090');
});
