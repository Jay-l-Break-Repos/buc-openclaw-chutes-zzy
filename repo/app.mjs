import express from 'express';
import multer from 'multer';
import { XMLParser } from 'fast-xml-parser';
import { d as parseOAuthCallbackInput } from './node_modules/openclaw/dist/auth-profiles-DnpV8DWM.js';

const app = express();
app.use(express.json());

// Configure multer to store uploaded files in memory
const upload = multer({ storage: multer.memoryStorage() });

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
// Accepts a multipart/form-data file upload containing an XML configuration file.
// Parses the XML and returns the parsed data in the response.
// Future steps will add schema validation and persistence to the config store.
app.post('/api/config/import', upload.single('file'), (req, res) => {
  // Ensure a file was uploaded
  if (!req.file) {
    return res.status(400).json({
      success: false,
      error: 'No file uploaded. Please provide an XML file in the "file" field.'
    });
  }

  // Ensure the uploaded file is XML (by MIME type or extension)
  const mimeType = req.file.mimetype || '';
  const originalName = req.file.originalname || '';
  const isXmlMime = mimeType === 'application/xml' || mimeType === 'text/xml';
  const isXmlExt = originalName.toLowerCase().endsWith('.xml');

  if (!isXmlMime && !isXmlExt) {
    return res.status(400).json({
      success: false,
      error: 'Uploaded file does not appear to be XML. Please upload a valid XML configuration file.'
    });
  }

  // Parse the XML content
  const xmlContent = req.file.buffer.toString('utf-8');

  let parsedData;
  try {
    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_',
      parseAttributeValue: true,
      parseTagValue: true,
      trimValues: true
    });
    parsedData = parser.parse(xmlContent);
  } catch (parseError) {
    return res.status(422).json({
      success: false,
      error: `Failed to parse XML: ${parseError.message}`
    });
  }

  // Return success with the parsed data
  return res.status(200).json({
    success: true,
    message: 'XML configuration file parsed successfully.',
    filename: req.file.originalname,
    size: req.file.size,
    data: parsedData
  });
});

app.listen(9090, '0.0.0.0', () => {
  console.log('Carrier app listening on http://0.0.0.0:9090');
});
