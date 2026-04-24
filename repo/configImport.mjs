/**
 * XML Configuration Import Module
 *
 * Provides a POST /api/config/import endpoint that accepts an XML file upload
 * containing OAuth provider settings, parses it, validates well-formedness,
 * and returns the extracted configuration.
 *
 * Uses only built-in Node.js modules — no external XML parser dependency required.
 */

import { Router } from 'express';

const router = Router();

// ---------------------------------------------------------------------------
// Lightweight XML-to-JS parser (handles the OAuth config subset we need)
// ---------------------------------------------------------------------------

/**
 * Parse a well-formed XML string into a nested JS object.
 *
 * Throws an Error with a descriptive message when the XML is malformed.
 *
 * Supports:
 *  - Nested elements
 *  - Text content
 *  - Self-closing tags
 *  - XML declaration (<?xml ... ?>)
 *  - Attributes (captured but not the primary focus)
 *
 * Does NOT support:
 *  - CDATA sections, processing instructions (beyond <?xml?>), DTDs, namespaces
 *    (these are out of scope for the OAuth config use-case)
 */
function parseXml(xmlString) {
  if (typeof xmlString !== 'string' || xmlString.trim().length === 0) {
    throw new Error('XML input is empty');
  }

  let xml = xmlString.trim();

  // Strip XML declaration if present
  xml = xml.replace(/^<\?xml[^?]*\?>\s*/, '');

  // Strip XML comments
  xml = xml.replace(/<!--[\s\S]*?-->/g, '');

  xml = xml.trim();

  if (xml.length === 0) {
    throw new Error('XML input contains no elements');
  }

  const tokens = tokenize(xml);
  const result = buildTree(tokens);
  return result;
}

/**
 * Tokenize an XML string into an array of token objects.
 */
function tokenize(xml) {
  const tokens = [];
  let pos = 0;

  while (pos < xml.length) {
    if (xml[pos] === '<') {
      // Find the end of this tag
      const closeIdx = xml.indexOf('>', pos);
      if (closeIdx === -1) {
        throw new Error(`Malformed XML: unclosed tag starting at position ${pos}`);
      }

      const tagContent = xml.substring(pos + 1, closeIdx).trim();

      if (tagContent.startsWith('/')) {
        // Closing tag
        const tagName = tagContent.substring(1).trim();
        if (!tagName || !isValidTagName(tagName)) {
          throw new Error(`Malformed XML: invalid closing tag name "${tagName}" at position ${pos}`);
        }
        tokens.push({ type: 'close', name: tagName });
      } else if (tagContent.endsWith('/')) {
        // Self-closing tag
        const parts = tagContent.substring(0, tagContent.length - 1).trim();
        const tagName = extractTagName(parts);
        if (!tagName || !isValidTagName(tagName)) {
          throw new Error(`Malformed XML: invalid self-closing tag at position ${pos}`);
        }
        const attributes = extractAttributes(parts.substring(tagName.length));
        tokens.push({ type: 'self-closing', name: tagName, attributes });
      } else {
        // Opening tag
        const tagName = extractTagName(tagContent);
        if (!tagName || !isValidTagName(tagName)) {
          throw new Error(`Malformed XML: invalid opening tag at position ${pos}`);
        }
        const attributes = extractAttributes(tagContent.substring(tagName.length));
        tokens.push({ type: 'open', name: tagName, attributes });
      }

      pos = closeIdx + 1;
    } else {
      // Text content
      const nextTag = xml.indexOf('<', pos);
      const text = nextTag === -1 ? xml.substring(pos) : xml.substring(pos, nextTag);
      const trimmed = text.trim();
      if (trimmed.length > 0) {
        tokens.push({ type: 'text', value: decodeXmlEntities(trimmed) });
      }
      pos = nextTag === -1 ? xml.length : nextTag;
    }
  }

  return tokens;
}

/**
 * Extract the tag name from the beginning of tag content.
 */
function extractTagName(content) {
  const match = content.match(/^([a-zA-Z_][\w.\-]*)/);
  return match ? match[1] : null;
}

/**
 * Validate that a tag name is well-formed.
 */
function isValidTagName(name) {
  return /^[a-zA-Z_][\w.\-]*$/.test(name);
}

/**
 * Extract attributes from the attribute portion of a tag.
 */
function extractAttributes(attrString) {
  const attrs = {};
  const attrRegex = /([a-zA-Z_][\w.\-]*)=(?:"([^"]*)"|'([^']*)')/g;
  let match;
  while ((match = attrRegex.exec(attrString)) !== null) {
    attrs[match[1]] = decodeXmlEntities(match[2] ?? match[3]);
  }
  return attrs;
}

/**
 * Decode common XML entities.
 */
function decodeXmlEntities(str) {
  return str
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'");
}

/**
 * Build a nested JS object tree from the token array.
 */
function buildTree(tokens) {
  const stack = [];
  let root = null;

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];

    if (token.type === 'open') {
      const node = { _name: token.name, _attributes: token.attributes, _children: [] };
      if (stack.length > 0) {
        stack[stack.length - 1]._children.push(node);
      }
      stack.push(node);
    } else if (token.type === 'close') {
      if (stack.length === 0) {
        throw new Error(`Malformed XML: unexpected closing tag </${token.name}> with no matching opening tag`);
      }
      const current = stack[stack.length - 1];
      if (current._name !== token.name) {
        throw new Error(
          `Malformed XML: mismatched tags — expected </${current._name}> but found </${token.name}>`
        );
      }
      const finished = stack.pop();
      if (stack.length === 0) {
        root = finished;
      }
    } else if (token.type === 'self-closing') {
      const node = { _name: token.name, _attributes: token.attributes, _children: [] };
      if (stack.length > 0) {
        stack[stack.length - 1]._children.push(node);
      } else {
        root = node;
      }
    } else if (token.type === 'text') {
      if (stack.length > 0) {
        stack[stack.length - 1]._text = token.value;
      }
    }
  }

  if (stack.length > 0) {
    throw new Error(
      `Malformed XML: unclosed tag <${stack[stack.length - 1]._name}>`
    );
  }

  if (!root) {
    throw new Error('Malformed XML: no root element found');
  }

  return root;
}

// ---------------------------------------------------------------------------
// Convert parsed XML tree into a clean OAuth providers structure
// ---------------------------------------------------------------------------

/**
 * Simplify the raw XML tree into a plain JS object.
 * Leaf nodes become key: textValue pairs; branch nodes become nested objects.
 * Repeated sibling names become arrays.
 */
function simplifyNode(node) {
  // Leaf node — has text content and no child elements
  if (node._children.length === 0) {
    return node._text ?? '';
  }

  const obj = {};
  for (const child of node._children) {
    const value = simplifyNode(child);
    if (obj[child._name] !== undefined) {
      // Convert to array for repeated elements
      if (!Array.isArray(obj[child._name])) {
        obj[child._name] = [obj[child._name]];
      }
      obj[child._name].push(value);
    } else {
      obj[child._name] = value;
    }
  }
  return obj;
}

/**
 * Extract OAuth provider settings from the parsed XML tree.
 */
function extractOAuthProviders(tree) {
  const simplified = simplifyNode(tree);

  // The root element name is the tree's _name — we return the content beneath it
  return {
    rootElement: tree._name,
    providers: simplified,
  };
}

// ---------------------------------------------------------------------------
// Multipart form-data file upload handling (minimal, no external dependency)
// ---------------------------------------------------------------------------

/**
 * Parse a multipart/form-data request body and extract the first file part.
 *
 * Returns { filename, contentType, data } where data is a Buffer.
 */
function parseMultipart(buffer, boundary) {
  const boundaryStr = `--${boundary}`;
  const body = buffer.toString('binary');
  const parts = body.split(boundaryStr).filter((p) => p.trim() !== '' && p.trim() !== '--');

  for (const part of parts) {
    const headerEnd = part.indexOf('\r\n\r\n');
    if (headerEnd === -1) continue;

    const headerSection = part.substring(0, headerEnd);
    const dataSection = part.substring(headerEnd + 4);

    // Remove trailing \r\n before next boundary
    const cleanData = dataSection.replace(/\r\n$/, '');

    const filenameMatch = headerSection.match(/filename="([^"]+)"/);
    const contentTypeMatch = headerSection.match(/Content-Type:\s*(.+)/i);

    if (filenameMatch) {
      return {
        filename: filenameMatch[1],
        contentType: contentTypeMatch ? contentTypeMatch[1].trim() : 'application/octet-stream',
        data: Buffer.from(cleanData, 'binary'),
      };
    }
  }

  return null;
}

// ---------------------------------------------------------------------------
// POST /api/config/import endpoint
// ---------------------------------------------------------------------------

router.post('/api/config/import', (req, res) => {
  const contentType = req.headers['content-type'] || '';

  // ---- Handle multipart/form-data (file upload) ----
  if (contentType.includes('multipart/form-data')) {
    const boundaryMatch = contentType.match(/boundary=(.+)/);
    if (!boundaryMatch) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Missing multipart boundary in Content-Type header',
      });
    }

    const boundary = boundaryMatch[1].replace(/;.*$/, '').trim();
    const chunks = [];

    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const buffer = Buffer.concat(chunks);
      const file = parseMultipart(buffer, boundary);

      if (!file) {
        return res.status(400).json({
          error: 'Bad Request',
          message: 'No file found in the upload. Please send an XML file in the "file" field.',
        });
      }

      const xmlString = file.data.toString('utf-8');
      return processXml(xmlString, file.filename, res);
    });

    req.on('error', (err) => {
      return res.status(500).json({
        error: 'Internal Server Error',
        message: `Failed to read upload: ${err.message}`,
      });
    });

    return; // response handled in callbacks
  }

  // ---- Handle raw XML body (application/xml or text/xml) ----
  if (contentType.includes('xml')) {
    const chunks = [];

    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      const xmlString = Buffer.concat(chunks).toString('utf-8');
      return processXml(xmlString, null, res);
    });

    req.on('error', (err) => {
      return res.status(500).json({
        error: 'Internal Server Error',
        message: `Failed to read request body: ${err.message}`,
      });
    });

    return;
  }

  // ---- Unsupported content type ----
  return res.status(400).json({
    error: 'Bad Request',
    message:
      'Unsupported Content-Type. Please upload an XML file via multipart/form-data or send raw XML with Content-Type: application/xml.',
  });
});

/**
 * Process an XML string: parse, extract OAuth providers, and respond.
 */
function processXml(xmlString, filename, res) {
  if (!xmlString || xmlString.trim().length === 0) {
    return res.status(400).json({
      error: 'Bad Request',
      message: 'The uploaded file is empty. Please provide a valid XML configuration file.',
    });
  }

  try {
    const tree = parseXml(xmlString);
    const { rootElement, providers } = extractOAuthProviders(tree);

    return res.status(200).json({
      message: 'XML configuration parsed successfully',
      filename: filename || null,
      rootElement,
      providers,
    });
  } catch (err) {
    return res.status(400).json({
      error: 'Bad Request',
      message: `Failed to parse XML: ${err.message}`,
    });
  }
}

export default router;
export { parseXml, extractOAuthProviders, simplifyNode };
