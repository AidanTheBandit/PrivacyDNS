'use strict';

const dgram = require('dgram');
const dns = require('dns');
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------
const [UPSTREAM_HOST, UPSTREAM_PORT] = (process.env.UPSTREAM || '1.1.1.1:53').split(':');
const UPSTREAM_DNS_PORT = parseInt(UPSTREAM_PORT || '53', 10);
const LISTEN_ADDR = process.env.LISTEN_ADDR || '127.0.0.1';
const LISTEN_PORT = parseInt(process.env.LISTEN_PORT || '53', 10);
const LOG_FILE = process.env.LOG_FILE || 'dns.log';
const PAC_TUNNEL_HOST = process.env.PAC_TUNNEL_HOST || null;

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------
const logStream = fs.createWriteStream(LOG_FILE, { flags: 'a' });

function log(type, host, extra) {
  const line = `${new Date().toISOString()} [${type}] ${host} ${extra || ''}`;
  console.log(line);
  logStream.write(line + '\n');
}

// ---------------------------------------------------------------------------
// Securly IP range helpers
// ---------------------------------------------------------------------------
// Known Securly IP ranges (CIDR notation)
const SECURLY_RANGES = [
  { base: ipToInt('204.110.220.0'), mask: cidrMask(22) },
  { base: ipToInt('67.226.220.0'),  mask: cidrMask(22) },
];

function ipToInt(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) | parseInt(octet, 10), 0) >>> 0;
}

function cidrMask(bits) {
  return (0xFFFFFFFF << (32 - bits)) >>> 0;
}

function isSecurlyIP(ip) {
  try {
    const n = ipToInt(ip);
    return SECURLY_RANGES.some(r => (n & r.mask) === (r.base & r.mask));
  } catch (_) {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Proxy map: override specific proxy hosts (can be extended)
// ---------------------------------------------------------------------------
const PROXY_MAP = new Map([
  // Example: redirect Securly's proxy to localhost to blackhole connections
  // ['useast2-dp.securly.com', '127.0.0.1'],
]);

// ---------------------------------------------------------------------------
// Static records: load hosts.json + zone files
// ---------------------------------------------------------------------------
const records = {};

function loadHostsFile() {
  const hostsPath = path.join(__dirname, 'hosts.json');
  if (fs.existsSync(hostsPath)) {
    try {
      const data = JSON.parse(fs.readFileSync(hostsPath, 'utf8'));
      Object.assign(records, data);
      log('STARTUP', 'hosts.json', `loaded ${Object.keys(data).length} records`);
    } catch (err) {
      log('ERROR', 'hosts.json', `failed to parse: ${err.message}`);
    }
  }
}

function loadZoneFiles() {
  const zonesDir = path.join(__dirname, 'zones');
  if (!fs.existsSync(zonesDir)) return;
  const files = fs.readdirSync(zonesDir).filter(f => f.endsWith('.zone'));
  for (const file of files) {
    const filePath = path.join(zonesDir, file);
    try {
      const lines = fs.readFileSync(filePath, 'utf8').split('\n');
      let count = 0;
      for (const raw of lines) {
        const line = raw.trim();
        // Skip comments and blank lines
        if (!line || line.startsWith(';') || line.startsWith('#')) continue;
        // Parse simple BIND A record: <name> <ttl> IN A <ip>
        const m = line.match(/^(\S+)\s+\d+\s+IN\s+A\s+([\d.]+)/i);
        if (m) {
          // Strip trailing dot from zone name
          const name = m[1].replace(/\.$/, '').toLowerCase();
          records[name] = m[2];
          count++;
        }
      }
      log('STARTUP', file, `loaded ${count} records`);
    } catch (err) {
      log('ERROR', file, `failed to parse: ${err.message}`);
    }
  }
}

loadHostsFile();
loadZoneFiles();

// Apply PAC_TUNNEL_HOST override if provided and if it looks like an IP
if (PAC_TUNNEL_HOST) {
  const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(PAC_TUNNEL_HOST);
  if (isIP) {
    records['useast2-www.securly.com'] = PAC_TUNNEL_HOST;
    log('STARTUP', 'PAC_TUNNEL_HOST', `overriding useast2-www.securly.com -> ${PAC_TUNNEL_HOST}`);
  } else {
    log('STARTUP', 'PAC_TUNNEL_HOST', `${PAC_TUNNEL_HOST} is a hostname; resolve via upstream or hosts.json`);
  }
}

// ---------------------------------------------------------------------------
// Record lookup helpers
// ---------------------------------------------------------------------------
function resolveRecord(host) {
  // Exact match
  if (records[host]) return records[host];
  // Wildcard match: *.example.com
  const parts = host.split('.');
  for (let i = 1; i < parts.length; i++) {
    const wildcard = '*.' + parts.slice(i).join('.');
    if (records[wildcard]) return records[wildcard];
  }
  return null;
}

// ---------------------------------------------------------------------------
// Securly API domain patterns
// ---------------------------------------------------------------------------
const SECURLY_API_PATTERNS = [
  /\.prx\.useast2\.v1api\.securly\.com$/,
  /\.pacrpc\.useast2\.v1api\.securly\.com$/,
];

function matchesSecurlyApiPatterns(host) {
  return SECURLY_API_PATTERNS.some(re => re.test(host));
}

// ---------------------------------------------------------------------------
// In-memory TTL cache
// ---------------------------------------------------------------------------
const cache = new Map();

function checkCache(host) {
  const entry = cache.get(host);
  if (!entry) return null;
  if (Date.now() > entry.expires) {
    cache.delete(host);
    return null;
  }
  return entry.ip;
}

function cacheResponse(host, ip, ttl) {
  cache.set(host, { ip, expires: Date.now() + ttl * 1000 });
}

// ---------------------------------------------------------------------------
// DNS packet helpers
// ---------------------------------------------------------------------------

/**
 * Parse the question section of a DNS message and return the FQDN (lowercase).
 * @param {Buffer} msg
 * @param {number} [offset=12]  starting offset (after header)
 * @returns {string}
 */
function parseHost(msg, offset) {
  offset = offset === undefined ? 12 : offset;
  const labels = [];
  let i = offset;
  while (i < msg.length) {
    const len = msg[i];
    if (len === 0) break;
    // Pointer (0xC0xx) – not expected in queries but handle gracefully
    if ((len & 0xC0) === 0xC0) {
      const ptrOffset = ((len & 0x3F) << 8) | msg[i + 1];
      labels.push(parseHost(msg, ptrOffset));
      break;
    }
    i++;
    labels.push(msg.slice(i, i + len).toString('ascii'));
    i += len;
  }
  return labels.join('.').toLowerCase();
}

/**
 * Build a DNS response with a single A record.
 * @param {Buffer} msg  original query buffer
 * @param {string} ip   IPv4 address to return
 * @param {number} [ttl=300]
 * @returns {Buffer}
 */
function buildAResponse(msg, ip, ttl) {
  ttl = ttl === undefined ? 300 : ttl;
  const ipParts = ip.split('.').map(Number);

  // Header (12 bytes) + original question section
  // Question section length: from byte 12 to end of question
  // We re-use the original question bytes from the query.
  const questionEnd = findQuestionEnd(msg);
  const questionSection = msg.slice(12, questionEnd);

  const header = Buffer.alloc(12);
  msg.copy(header, 0, 0, 12); // copy ID + original header

  // Set QR=1 (response), keep OPCODE, set AA=0, TC=0, RD copy, RA=1
  const flags = (msg.readUInt16BE(2) | 0x8000) & 0x8780; // QR=1, OPCODE, AA=0, TC=0
  header.writeUInt16BE(flags | 0x0080, 2); // also set RA bit
  header.writeUInt16BE(1, 4);  // QDCOUNT=1
  header.writeUInt16BE(1, 6);  // ANCOUNT=1
  header.writeUInt16BE(0, 8);  // NSCOUNT=0
  header.writeUInt16BE(0, 10); // ARCOUNT=0

  // Answer RR:
  //   Name: pointer to question name (0xC00C = pointer to offset 12)
  //   Type: A (0x0001)
  //   Class: IN (0x0001)
  //   TTL: 4 bytes
  //   RDLENGTH: 4
  //   RDATA: 4 bytes IPv4
  const answer = Buffer.alloc(16);
  answer.writeUInt16BE(0xC00C, 0); // name pointer
  answer.writeUInt16BE(1, 2);      // type A
  answer.writeUInt16BE(1, 4);      // class IN
  answer.writeUInt32BE(ttl, 6);    // TTL
  answer.writeUInt16BE(4, 10);     // RDLENGTH
  answer[12] = ipParts[0];
  answer[13] = ipParts[1];
  answer[14] = ipParts[2];
  answer[15] = ipParts[3];

  return Buffer.concat([header, questionSection, answer]);
}

/**
 * Build a DNS NXDOMAIN response (RCODE=3, no answers).
 * @param {Buffer} msg  original query buffer
 * @returns {Buffer}
 */
function buildNXResponse(msg) {
  const questionEnd = findQuestionEnd(msg);
  const questionSection = msg.slice(12, questionEnd);

  const header = Buffer.alloc(12);
  msg.copy(header, 0, 0, 12);

  const flags = (msg.readUInt16BE(2) | 0x8000) & 0x8780;
  // Set QR=1, RA=1, RCODE=3 (NXDOMAIN)
  header.writeUInt16BE((flags | 0x0080) | 0x0003, 2);
  header.writeUInt16BE(1, 4);  // QDCOUNT=1
  header.writeUInt16BE(0, 6);  // ANCOUNT=0
  header.writeUInt16BE(0, 8);  // NSCOUNT=0
  header.writeUInt16BE(0, 10); // ARCOUNT=0

  return Buffer.concat([header, questionSection]);
}

/**
 * Find the byte offset of the end of the question section (past QTYPE + QCLASS).
 * @param {Buffer} msg
 * @returns {number}
 */
function findQuestionEnd(msg) {
  let i = 12;
  while (i < msg.length) {
    const len = msg[i];
    if (len === 0) { i++; break; }
    if ((len & 0xC0) === 0xC0) { i += 2; break; }
    i += 1 + len;
  }
  // Skip QTYPE (2 bytes) and QCLASS (2 bytes)
  return i + 4;
}

// ---------------------------------------------------------------------------
// Upstream forwarder
// ---------------------------------------------------------------------------
function forwardQuery(msg, rinfo, host, server) {
  const client = dgram.createSocket('udp4');
  const timeout = setTimeout(() => {
    log('ERROR', host, 'upstream timeout');
    client.close();
  }, 5000);

  client.on('error', (err) => {
    clearTimeout(timeout);
    log('ERROR', host, `upstream error: ${err.message}`);
    client.close();
  });

  client.on('message', (response) => {
    clearTimeout(timeout);
    // Try to extract cached A record from response
    try {
      const ip = extractAnswerIP(response);
      if (ip) {
        cacheResponse(host, ip, 300);
        log('UPSTREAM', host, `-> ${ip} (cached)`);
      } else {
        log('UPSTREAM', host, 'no A record in response');
      }
    } catch (_) {}
    server.send(response, rinfo.port, rinfo.address, (err) => {
      if (err) log('ERROR', host, `send error: ${err.message}`);
    });
    client.close();
  });

  client.send(msg, UPSTREAM_DNS_PORT, UPSTREAM_HOST, (err) => {
    if (err) {
      clearTimeout(timeout);
      log('ERROR', host, `forward send error: ${err.message}`);
      client.close();
    }
  });
}

/**
 * Naively extract the first A record IP from a DNS response buffer.
 * @param {Buffer} msg
 * @returns {string|null}
 */
function extractAnswerIP(msg) {
  if (msg.length < 12) return null;
  const ancount = msg.readUInt16BE(6);
  if (ancount === 0) return null;

  // Skip past header and question section
  let i = findQuestionEnd(msg);

  for (let a = 0; a < ancount; a++) {
    if (i >= msg.length) break;
    // Name (pointer or label sequence)
    if ((msg[i] & 0xC0) === 0xC0) {
      i += 2;
    } else {
      while (i < msg.length && msg[i] !== 0) {
        i += 1 + msg[i];
      }
      i++; // null terminator
    }
    if (i + 10 > msg.length) break;
    const type = msg.readUInt16BE(i);
    // const cls = msg.readUInt16BE(i + 2);
    // const ttl = msg.readUInt32BE(i + 4);
    const rdlen = msg.readUInt16BE(i + 8);
    i += 10;
    if (type === 1 && rdlen === 4 && i + 4 <= msg.length) {
      return `${msg[i]}.${msg[i+1]}.${msg[i+2]}.${msg[i+3]}`;
    }
    i += rdlen;
  }
  return null;
}

// ---------------------------------------------------------------------------
// DNS server
// ---------------------------------------------------------------------------
const server = dgram.createSocket('udp4');

server.on('error', (err) => {
  log('ERROR', 'server', `socket error: ${err.message}`);
  server.close();
});

server.on('listening', () => {
  const addr = server.address();
  log('STARTUP', 'server', `listening on ${addr.address}:${addr.port}`);
});

server.on('message', (msg, rinfo) => {
  const src = `${rinfo.address}:${rinfo.port}`;

  // Minimum DNS message is 12 bytes (header)
  if (msg.length < 12) {
    log('ERROR', 'unknown', `message too short from ${src}`);
    return;
  }

  let host;
  try {
    host = parseHost(msg);
  } catch (err) {
    log('ERROR', 'unknown', `parse error from ${src}: ${err.message}`);
    return;
  }

  log('QUERY', host, src);

  // 1. WPAD protection
  if (host === 'wpad' || host === 'wpad.local') {
    server.send(buildNXResponse(msg), rinfo.port, rinfo.address);
    log('WPAD_BLOCK', host, src);
    return;
  }

  // 2. Local records (hosts.json + zones)
  const localIP = resolveRecord(host);
  if (localIP) {
    // If the local record maps to 0.0.0.0 or 127.0.0.1 for a block, send as-is
    server.send(buildAResponse(msg, localIP), rinfo.port, rinfo.address);
    log('OVERRIDE', host, `-> ${localIP}`);
    return;
  }

  // 3. Securly API domain sabotage
  if (matchesSecurlyApiPatterns(host)) {
    server.send(buildNXResponse(msg), rinfo.port, rinfo.address);
    log('SECURLY_API_BLOCK', host, 'NXDOMAIN');
    return;
  }

  // 4. Securly proxy host override
  if (PROXY_MAP.has(host)) {
    const ip = PROXY_MAP.get(host);
    server.send(buildAResponse(msg, ip), rinfo.port, rinfo.address);
    log('SECURLY_PROXY_OVERRIDE', host, `-> ${ip}`);
    return;
  }

  // 5. In-memory cache
  const cached = checkCache(host);
  if (cached) {
    server.send(buildAResponse(msg, cached), rinfo.port, rinfo.address);
    log('CACHE_HIT', host, `-> ${cached}`);
    return;
  }

  // 6. Forward to upstream
  forwardQuery(msg, rinfo, host, server);
});

server.bind(LISTEN_PORT, LISTEN_ADDR);
// Allow the process to exit naturally (e.g. during tests) when no other
// async operations are pending.
server.unref();

// ---------------------------------------------------------------------------
// Exports for testing
// ---------------------------------------------------------------------------
module.exports = {
  parseHost,
  buildAResponse,
  buildNXResponse,
  findQuestionEnd,
  resolveRecord,
  matchesSecurlyApiPatterns,
  checkCache,
  cacheResponse,
  isSecurlyIP,
  PROXY_MAP,
  extractAnswerIP,
};
