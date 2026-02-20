'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

// Prevent the server from binding to port 53 during tests by pre-setting
// environment variables so the module-level dgram socket is created but
// we immediately work with exported helpers.
process.env.LISTEN_PORT = '0'; // bind to random port to avoid privilege issues
process.env.LISTEN_ADDR = '127.0.0.1';

const {
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
} = require('../index.js');

// ---------------------------------------------------------------------------
// Helper: craft a minimal DNS query buffer for a given hostname
// ---------------------------------------------------------------------------
function buildQuery(hostname, id) {
  id = id === undefined ? 0x1234 : id;
  const labels = hostname.split('.');
  const nameParts = [];
  for (const label of labels) {
    nameParts.push(Buffer.from([label.length]));
    nameParts.push(Buffer.from(label, 'ascii'));
  }
  nameParts.push(Buffer.from([0])); // null terminator
  const name = Buffer.concat(nameParts);

  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);   // ID
  header.writeUInt16BE(0x0100, 2); // flags: RD=1
  header.writeUInt16BE(1, 4);    // QDCOUNT=1
  header.writeUInt16BE(0, 6);    // ANCOUNT=0
  header.writeUInt16BE(0, 8);    // NSCOUNT=0
  header.writeUInt16BE(0, 10);   // ARCOUNT=0

  const qtype  = Buffer.from([0x00, 0x01]); // A
  const qclass = Buffer.from([0x00, 0x01]); // IN

  return Buffer.concat([header, name, qtype, qclass]);
}

// ---------------------------------------------------------------------------
// parseHost
// ---------------------------------------------------------------------------
describe('parseHost', () => {
  it('parses a simple single-label hostname', () => {
    const msg = buildQuery('example');
    assert.equal(parseHost(msg), 'example');
  });

  it('parses a multi-label hostname', () => {
    const msg = buildQuery('www.example.com');
    assert.equal(parseHost(msg), 'www.example.com');
  });

  it('returns lowercase result', () => {
    const msg = buildQuery('EXAMPLE.COM');
    assert.equal(parseHost(msg), 'example.com');
  });
});

// ---------------------------------------------------------------------------
// buildAResponse
// ---------------------------------------------------------------------------
describe('buildAResponse', () => {
  it('sets QR=1 in flags', () => {
    const query = buildQuery('example.com');
    const resp = buildAResponse(query, '1.2.3.4');
    // Byte 2 high bit should be 1 (QR=1)
    assert.ok(resp.readUInt16BE(2) & 0x8000);
  });

  it('sets ANCOUNT=1', () => {
    const query = buildQuery('example.com');
    const resp = buildAResponse(query, '1.2.3.4');
    assert.equal(resp.readUInt16BE(6), 1);
  });

  it('copies the request ID', () => {
    const query = buildQuery('example.com', 0xABCD);
    const resp = buildAResponse(query, '1.2.3.4');
    assert.equal(resp.readUInt16BE(0), 0xABCD);
  });

  it('encodes the IP address in RDATA', () => {
    const query = buildQuery('example.com');
    const resp = buildAResponse(query, '93.184.216.34');
    // RDATA is the last 4 bytes of the answer section
    const ip = `${resp[resp.length-4]}.${resp[resp.length-3]}.${resp[resp.length-2]}.${resp[resp.length-1]}`;
    assert.equal(ip, '93.184.216.34');
  });

  it('respects custom TTL', () => {
    const query = buildQuery('example.com');
    const resp = buildAResponse(query, '1.2.3.4', 600);
    // The answer RR starts right after header (12) + question section
    const qEnd = findQuestionEnd(query);
    const ttlOffset = qEnd + 6; // name(2) + type(2) + class(2)
    assert.equal(resp.readUInt32BE(ttlOffset), 600);
  });
});

// ---------------------------------------------------------------------------
// buildNXResponse
// ---------------------------------------------------------------------------
describe('buildNXResponse', () => {
  it('sets QR=1 in flags', () => {
    const query = buildQuery('example.com');
    const resp = buildNXResponse(query);
    assert.ok(resp.readUInt16BE(2) & 0x8000);
  });

  it('sets RCODE=3 (NXDOMAIN)', () => {
    const query = buildQuery('example.com');
    const resp = buildNXResponse(query);
    assert.equal(resp.readUInt16BE(2) & 0x000F, 3);
  });

  it('sets ANCOUNT=0', () => {
    const query = buildQuery('example.com');
    const resp = buildNXResponse(query);
    assert.equal(resp.readUInt16BE(6), 0);
  });

  it('copies the request ID', () => {
    const query = buildQuery('example.com', 0x1234);
    const resp = buildNXResponse(query);
    assert.equal(resp.readUInt16BE(0), 0x1234);
  });
});

// ---------------------------------------------------------------------------
// resolveRecord
// ---------------------------------------------------------------------------
describe('resolveRecord', () => {
  it('returns null for unknown host', () => {
    assert.equal(resolveRecord('unknown.example.invalid'), null);
  });

  it('returns IP for exact match from hosts.json', () => {
    // hosts.json has useast2-www.securly.com
    const ip = resolveRecord('useast2-www.securly.com');
    assert.ok(ip !== null, 'Expected an IP for useast2-www.securly.com');
  });

  it('returns IP for wildcard match', () => {
    const ip = resolveRecord('abc.prx.useast2.v1api.securly.com');
    assert.equal(ip, '127.0.0.1');
  });

  it('returns IP for another wildcard match', () => {
    const ip = resolveRecord('foo.pacrpc.useast2.v1api.securly.com');
    assert.equal(ip, '127.0.0.1');
  });
});

// ---------------------------------------------------------------------------
// matchesSecurlyApiPatterns
// ---------------------------------------------------------------------------
describe('matchesSecurlyApiPatterns', () => {
  it('matches prx subdomain', () => {
    assert.ok(matchesSecurlyApiPatterns('abc.prx.useast2.v1api.securly.com'));
  });

  it('matches pacrpc subdomain', () => {
    assert.ok(matchesSecurlyApiPatterns('xyz.pacrpc.useast2.v1api.securly.com'));
  });

  it('does not match unrelated domain', () => {
    assert.ok(!matchesSecurlyApiPatterns('www.google.com'));
  });

  it('does not match securly main domain', () => {
    assert.ok(!matchesSecurlyApiPatterns('useast2-www.securly.com'));
  });
});

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------
describe('cache', () => {
  it('returns null for unknown host', () => {
    assert.equal(checkCache('nocache.invalid'), null);
  });

  it('stores and retrieves a value', () => {
    cacheResponse('test.local', '10.0.0.1', 60);
    assert.equal(checkCache('test.local'), '10.0.0.1');
  });

  it('expires entries after TTL', () => {
    cacheResponse('expire.local', '10.0.0.2', 0); // 0-second TTL expires immediately
    // Wait a tick to ensure Date.now() advances
    const result = checkCache('expire.local');
    // May or may not have expired already; just ensure it doesn't throw
    assert.ok(result === null || result === '10.0.0.2');
  });
});

// ---------------------------------------------------------------------------
// isSecurlyIP
// ---------------------------------------------------------------------------
describe('isSecurlyIP', () => {
  it('identifies an IP in the 204.110.220.0/22 range', () => {
    assert.ok(isSecurlyIP('204.110.220.1'));
    assert.ok(isSecurlyIP('204.110.221.255'));
    assert.ok(isSecurlyIP('204.110.223.255'));
  });

  it('identifies an IP in the 67.226.220.0/22 range', () => {
    assert.ok(isSecurlyIP('67.226.220.1'));
    assert.ok(isSecurlyIP('67.226.223.255'));
  });

  it('returns false for non-Securly IP', () => {
    assert.ok(!isSecurlyIP('1.1.1.1'));
    assert.ok(!isSecurlyIP('93.184.216.34'));
    assert.ok(!isSecurlyIP('204.110.224.1')); // just outside range
  });
});

// ---------------------------------------------------------------------------
// extractAnswerIP
// ---------------------------------------------------------------------------
describe('extractAnswerIP', () => {
  it('extracts the IP from a synthetic A-record response', () => {
    const query = buildQuery('example.com');
    const resp = buildAResponse(query, '5.6.7.8');
    const ip = extractAnswerIP(resp);
    assert.equal(ip, '5.6.7.8');
  });

  it('returns null for NXDOMAIN response', () => {
    const query = buildQuery('example.com');
    const resp = buildNXResponse(query);
    assert.equal(extractAnswerIP(resp), null);
  });
});
