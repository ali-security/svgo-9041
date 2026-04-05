import SAX from 'sax';
import { textElems } from '../plugins/_collections.js';

export class SvgoParserError extends Error {
  /**
   * @param {string} message
   * @param {number} line
   * @param {number} column
   * @param {string} source
   * @param {string=} file
   */
  constructor(message, line, column, source, file) {
    super(message);
    this.name = 'SvgoParserError';
    this.message = `${file || '<input>'}:${line}:${column}: ${message}`;
    this.reason = message;
    this.line = line;
    this.column = column;
    this.source = source;
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, SvgoParserError);
    }
  }

  toString() {
    const lines = this.source.split(/\r?\n/);
    const startLine = Math.max(this.line - 3, 0);
    const endLine = Math.min(this.line + 2, lines.length);
    const lineNumberWidth = String(endLine).length;
    const startColumn = Math.max(this.column - 54, 0);
    const endColumn = Math.max(this.column + 20, 80);
    const code = lines
      .slice(startLine, endLine)
      .map((line, index) => {
        const lineSlice = line.slice(startColumn, endColumn);
        let ellipsisPrefix = '';
        let ellipsisSuffix = '';
        if (startColumn !== 0) {
          ellipsisPrefix = startColumn > line.length - 1 ? ' ' : '…';
        }
        if (endColumn < line.length - 1) {
          ellipsisSuffix = '…';
        }
        const number = startLine + 1 + index;
        const gutter = ` ${number.toString().padStart(lineNumberWidth)} | `;
        if (number === this.line) {
          const gutterSpacing = gutter.replace(/[^|]/g, ' ');
          const lineSpacing = (
            ellipsisPrefix + line.slice(startColumn, this.column - 1)
          ).replace(/[^\t]/g, ' ');
          const spacing = gutterSpacing + lineSpacing;
          return `>${gutter}${ellipsisPrefix}${lineSlice}${ellipsisSuffix}\n ${spacing}^`;
        }
        return ` ${gutter}${ellipsisPrefix}${lineSlice}${ellipsisSuffix}`;
      })
      .join('\n');
    return `${this.name}: ${this.message}\n\n${code}\n`;
  }
}

const entityDeclaration = /<!ENTITY\s+(\S+)\s+(?:'([^']+)'|"([^"]+)")\s*>/g;

const ENTITY_REF_PATTERN = /&([^;]+);/g;
const MAX_ENTITY_DEPTH = 4;
const MAX_ENTITY_COUNT = 512;

/**
 * Statically validate that DOCTYPE entity definitions cannot cause exponential
 * expansion (Billion Laughs / CVE-2026-29074). Checks both nesting depth and
 * total expansion count against conservative limits.
 *
 * @param {Record<string, string>} entities
 */
const validateEntityExpansion = (entities) => {
  /** @param {string} value */
  const getDirectEntityRefs = (value) => {
    const refs = [];
    let match;
    ENTITY_REF_PATTERN.lastIndex = 0;
    while ((match = ENTITY_REF_PATTERN.exec(value)) !== null) {
      if (Object.prototype.hasOwnProperty.call(entities, match[1])) {
        refs.push(match[1]);
      }
    }
    return refs;
  };

  /** @type {Map<string, number>} */
  const depthCache = new Map();
  /** @type {Map<string, number>} */
  const countCache = new Map();

  /**
   * Maximum entity nesting depth produced when resolving this entity.
   * @param {string} name
   * @param {Set<string>} visiting
   * @returns {number}
   */
  const getMaxDepth = (name, visiting = new Set()) => {
    if (depthCache.has(name)) return /** @type {number} */ (depthCache.get(name));
    if (visiting.has(name)) return 0;
    visiting.add(name);
    const refs = getDirectEntityRefs(entities[name]);
    let maxChild = 0;
    for (const ref of refs) {
      maxChild = Math.max(maxChild, getMaxDepth(ref, visiting));
    }
    visiting.delete(name);
    const depth = 1 + maxChild;
    depthCache.set(name, depth);
    return depth;
  };

  /**
   * Total number of entity expansions when fully resolving this entity.
   * @param {string} name
   * @param {Set<string>} visiting
   * @returns {number}
   */
  const getExpansionCount = (name, visiting = new Set()) => {
    if (countCache.has(name)) return /** @type {number} */ (countCache.get(name));
    if (visiting.has(name)) return 1;
    visiting.add(name);
    const refs = getDirectEntityRefs(entities[name]);
    let count = 1;
    for (const ref of refs) {
      count += getExpansionCount(ref, visiting);
    }
    visiting.delete(name);
    countCache.set(name, count);
    return count;
  };

  for (const name of Object.keys(entities)) {
    if (getMaxDepth(name) > MAX_ENTITY_DEPTH) {
      throw new Error('Parsed entity depth exceeds max entity depth');
    }
  }
  for (const name of Object.keys(entities)) {
    if (getExpansionCount(name) > MAX_ENTITY_COUNT) {
      throw new Error('Parsed entity count exceeds max entity count');
    }
  }
};

const config = {
  strict: true,
  trim: false,
  normalize: false,
  lowercase: true,
  xmlns: true,
  position: true,
  unparsedEntities: true,
};

/**
 * Convert SVG (XML) string to SVG-as-JS object.
 *
 * @param {string} data
 * @param {string=} from
 * @returns {import('./types.js').XastRoot}
 */
export const parseSvg = (data, from) => {
  const sax = SAX.parser(config.strict, config);
  /** @type {import('./types.js').XastRoot} */
  const root = { type: 'root', children: [] };
  /** @type {import('./types.js').XastParent} */
  let current = root;
  /** @type {import('./types.js').XastParent[]} */
  const stack = [root];

  /**
   * @param {import('./types.js').XastChild} node
   */
  const pushToContent = (node) => {
    current.children.push(node);
  };

  sax.ondoctype = (doctype) => {
    /** @type {import('./types.js').XastDoctype} */
    const node = {
      type: 'doctype',
      // TODO parse doctype for name, public and system to match xast
      name: 'svg',
      data: {
        doctype,
      },
    };
    pushToContent(node);
    const subsetStart = doctype.indexOf('[');
    if (subsetStart >= 0) {
      /** @type {Record<string, string>} */
      const customEntities = {};
      entityDeclaration.lastIndex = subsetStart;
      let entityMatch = entityDeclaration.exec(data);
      while (entityMatch != null) {
        const entityName = entityMatch[1];
        const entityValue = entityMatch[2] || entityMatch[3];
        sax.ENTITIES[entityName] = entityValue;
        customEntities[entityName] = entityValue;
        entityMatch = entityDeclaration.exec(data);
      }
      validateEntityExpansion(customEntities);
    }
  };

  sax.onprocessinginstruction = (data) => {
    /** @type {import('./types.js').XastInstruction} */
    const node = {
      type: 'instruction',
      name: data.name,
      value: data.body,
    };
    pushToContent(node);
  };

  sax.oncomment = (comment) => {
    /** @type {import('./types.js').XastComment} */
    const node = {
      type: 'comment',
      value: comment.trim(),
    };
    pushToContent(node);
  };

  sax.oncdata = (cdata) => {
    /** @type {import('./types.js').XastCdata} */
    const node = {
      type: 'cdata',
      value: cdata,
    };
    pushToContent(node);
  };

  sax.onopentag = (data) => {
    /** @type {import('./types.js').XastElement} */
    const element = {
      type: 'element',
      name: data.name,
      attributes: {},
      children: [],
    };
    for (const [name, attr] of Object.entries(data.attributes)) {
      element.attributes[name] = attr.value;
    }
    pushToContent(element);
    current = element;
    stack.push(element);
  };

  sax.ontext = (text) => {
    if (current.type === 'element') {
      // prevent trimming of meaningful whitespace inside textual tags
      if (textElems.has(current.name)) {
        /** @type {import('./types.js').XastText} */
        const node = {
          type: 'text',
          value: text,
        };
        pushToContent(node);
      } else {
        const value = text.trim();

        if (value !== '') {
          /** @type {import('./types.js').XastText} */
          const node = {
            type: 'text',
            value,
          };
          pushToContent(node);
        }
      }
    }
  };

  sax.onclosetag = () => {
    stack.pop();
    current = stack[stack.length - 1];
  };

  sax.onerror = (e) => {
    const reason = e.message.split('\n')[0];
    const error = new SvgoParserError(
      reason,
      sax.line + 1,
      sax.column,
      data,
      from,
    );
    if (e.message.indexOf('Unexpected end') === -1) {
      throw error;
    }
  };

  sax.write(data).close();
  return root;
};
