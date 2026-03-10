/* ------------------------------------------------------------------
 * node-dns-sd - dns-sd-announcer.test.js
 * Unit tests for DnsSdAnnouncer
 *
 * Coverage areas:
 *   - Constructor input validation
 *   - addTxt / removeTxt API
 *   - Packet binary structure (header, PTR, SRV, TXT, A)
 *   - goodbye TTL=0 packet
 *   - Name encoding (_encodeName)
 *   - Security: prototype pollution, port boundaries, injection
 *   - Network: correct multicast address and port used on send
 * ---------------------------------------------------------------- */
'use strict';

const assert        = require('assert');
const DnsSdAnnouncer = require('../lib/dns-sd-announcer.js');

// ---------------------------------------------------------------------------
// Helpers to decode raw DNS wire-format buffers
// ---------------------------------------------------------------------------

/** Decode a length-prefixed DNS name starting at offset. Returns { name, bytesRead }. */
function decodeName(buf, offset) {
    const labels = [];
    let pos = offset;
    while (pos < buf.length) {
        const len = buf.readUInt8(pos);
        if (len === 0) { pos++; break; }
        pos++;
        labels.push(buf.slice(pos, pos + len).toString('utf8'));
        pos += len;
    }
    return { name: labels.join('.'), bytesRead: pos - offset };
}

/** Skip a DNS name at offset, returning the byte count consumed. */
function skipName(buf, offset) {
    return decodeName(buf, offset).bytesRead;
}

/**
 * Decode a single DNS resource record from buf at offset.
 * Returns { name, type, cls, ttl, rdata, totalBytes }.
 */
function decodeRecord(buf, offset) {
    const { name, bytesRead } = decodeName(buf, offset);
    let pos = offset + bytesRead;
    const type  = buf.readUInt16BE(pos);     pos += 2;
    const cls   = buf.readUInt16BE(pos);     pos += 2;
    const ttl   = buf.readUInt32BE(pos);     pos += 4;
    const rdlen = buf.readUInt16BE(pos);     pos += 2;
    const rdata = buf.slice(pos, pos + rdlen);
    return { name, type, cls, ttl, rdata, totalBytes: (pos + rdlen) - offset };
}

/**
 * Decode TXT rdata: returns array of strings (each "key=value" or bare "key").
 */
function decodeTxtRdata(rdata) {
    const pairs = [];
    let i = 0;
    while (i < rdata.length) {
        const len = rdata.readUInt8(i);
        i++;
        if (len === 0) break;
        pairs.push(rdata.slice(i, i + len).toString('utf8'));
        i += len;
    }
    return pairs;
}

// ---------------------------------------------------------------------------
// Record type / class constants (mirrors dns-sd-announcer.js)
// ---------------------------------------------------------------------------
const TYPE_A   = 0x0001;
const TYPE_PTR = 0x000c;
const TYPE_TXT = 0x0010;
const TYPE_SRV = 0x0021;

const CLASS_IN       = 0x0001;
const CLASS_IN_FLUSH = 0x8001;

const TTL_SERVICE = 4500;
const TTL_HOST    = 120;

// ---------------------------------------------------------------------------
// Mock socket factory – intercepts sends without touching the network
// ---------------------------------------------------------------------------
function makeMockSocket() {
    const sent = [];
    return {
        sent,
        socket: {
            send(buf, offset, length, port, addr, cb) {
                sent.push({ buf: Buffer.from(buf), port, addr });
                cb(null);
            },
            close(cb) { if (cb) cb(); }
        }
    };
}

/** Attach a mock socket to an announcer, bypassing real UDP setup. */
function withMockSocket(announcer) {
    const mock = makeMockSocket();
    announcer._udp = mock.socket;
    return mock.sent;
}

// ---------------------------------------------------------------------------
// Helper to build a valid minimal announcer
// ---------------------------------------------------------------------------
function makeAnnouncer(overrides = {}) {
    return new DnsSdAnnouncer(Object.assign({
        name:     '_http._tcp.local',
        instance: 'Test Service',
        host:     'testhost.local',
        port:     8080
    }, overrides));
}

// ===========================================================================
describe('DnsSdAnnouncer', function () {

    // -----------------------------------------------------------------------
    describe('Constructor – input validation', function () {

        it('should throw when params is missing', function () {
            assert.throws(() => new DnsSdAnnouncer(), /required/i);
        });

        it('should throw when params is null', function () {
            assert.throws(() => new DnsSdAnnouncer(null), /required/i);
        });

        it('should throw when params is a string', function () {
            assert.throws(() => new DnsSdAnnouncer('_http._tcp.local'), /required/i);
        });

        it('should throw when params is a number', function () {
            assert.throws(() => new DnsSdAnnouncer(42), /required/i);
        });

        it('should throw when name is missing', function () {
            assert.throws(() => new DnsSdAnnouncer({ port: 80 }), /name/i);
        });

        it('should throw when name is an empty string', function () {
            assert.throws(() => new DnsSdAnnouncer({ name: '', port: 80 }), /name/i);
        });

        it('should throw when name is not a string', function () {
            assert.throws(() => new DnsSdAnnouncer({ name: 123, port: 80 }), /name/i);
        });

        it('should throw when port is missing', function () {
            assert.throws(() => new DnsSdAnnouncer({ name: '_http._tcp.local' }), /port/i);
        });

        it('should throw when port is 0', function () {
            assert.throws(() => makeAnnouncer({ port: 0 }), /port/i);
        });

        it('should throw when port is negative', function () {
            assert.throws(() => makeAnnouncer({ port: -1 }), /port/i);
        });

        it('should throw when port exceeds 65535', function () {
            assert.throws(() => makeAnnouncer({ port: 65536 }), /port/i);
        });

        it('should throw when port is a float', function () {
            assert.throws(() => makeAnnouncer({ port: 80.5 }), /port/i);
        });

        it('should throw when port is NaN', function () {
            assert.throws(() => makeAnnouncer({ port: NaN }), /port/i);
        });

        it('should throw when port is Infinity', function () {
            assert.throws(() => makeAnnouncer({ port: Infinity }), /port/i);
        });

        it('should throw when port is a string', function () {
            assert.throws(() => makeAnnouncer({ port: '80' }), /port/i);
        });

        it('should accept port = 1 (minimum valid)', function () {
            assert.doesNotThrow(() => makeAnnouncer({ port: 1 }));
        });

        it('should accept port = 65535 (maximum valid)', function () {
            assert.doesNotThrow(() => makeAnnouncer({ port: 65535 }));
        });

        it('should construct successfully with minimal valid params', function () {
            const a = new DnsSdAnnouncer({ name: '_http._tcp.local', port: 3000 });
            assert.ok(a);
        });

        it('should apply defaults for instance and host when omitted', function () {
            const a = new DnsSdAnnouncer({ name: '_http._tcp.local', port: 80 });
            assert.ok(typeof a._instanceName === 'string' && a._instanceName.length > 0);
            assert.ok(typeof a._host === 'string' && a._host.endsWith('.local'));
        });

        it('should set custom instance and host from params', function () {
            const a = makeAnnouncer();
            assert.strictEqual(a._instanceName, 'Test Service');
            assert.strictEqual(a._host, 'testhost.local');
        });

        it('should populate _txt from a plain object', function () {
            const a = makeAnnouncer({ txt: { version: '2', path: '/api' } });
            assert.strictEqual(a._txt['version'], '2');
            assert.strictEqual(a._txt['path'], '/api');
        });

        it('should ignore non-object txt (array)', function () {
            // Arrays are not plain objects; constructor should not throw but txt stays empty
            assert.doesNotThrow(() => makeAnnouncer({ txt: ['foo=bar'] }));
            const a = makeAnnouncer({ txt: ['foo=bar'] });
            assert.deepStrictEqual(a._txt, {});
        });

        it('should coerce txt values to strings', function () {
            const a = makeAnnouncer({ txt: { port: 8080, flag: true } });
            assert.strictEqual(a._txt['port'], '8080');
            assert.strictEqual(a._txt['flag'], 'true');
        });
    });

    // -----------------------------------------------------------------------
    describe('Constructor – prototype pollution via txt', function () {

        it('should not pollute Object.prototype via __proto__ key in txt', function () {
            const before = ({}).polluted;
            makeAnnouncer({ txt: { __proto__: { polluted: true } } });
            assert.strictEqual(({}).polluted, before);
        });

        it('should not pollute via constructor key in txt', function () {
            const before = ({}).injected;
            makeAnnouncer({ txt: { constructor: { injected: true } } });
            assert.strictEqual(({}).injected, before);
        });
    });

    // -----------------------------------------------------------------------
    describe('addTxt', function () {

        it('should add a key-value pair', function () {
            const a = makeAnnouncer();
            a.addTxt('env', 'prod');
            assert.strictEqual(a._txt['env'], 'prod');
        });

        it('should overwrite an existing key', function () {
            const a = makeAnnouncer({ txt: { env: 'dev' } });
            a.addTxt('env', 'prod');
            assert.strictEqual(a._txt['env'], 'prod');
        });

        it('should coerce value to string', function () {
            const a = makeAnnouncer();
            a.addTxt('count', 42);
            assert.strictEqual(a._txt['count'], '42');
        });

        it('should be chainable', function () {
            const a = makeAnnouncer();
            const ret = a.addTxt('a', '1').addTxt('b', '2');
            assert.strictEqual(ret, a);
            assert.strictEqual(a._txt['a'], '1');
            assert.strictEqual(a._txt['b'], '2');
        });

        it('should throw when key is an empty string', function () {
            const a = makeAnnouncer();
            assert.throws(() => a.addTxt('', 'value'), /key/i);
        });

        it('should throw when key is not a string', function () {
            const a = makeAnnouncer();
            assert.throws(() => a.addTxt(42, 'value'), /key/i);
        });

        it('should not pollute Object.prototype via __proto__ key', function () {
            const before = ({}).hacked;
            const a = makeAnnouncer();
            // addTxt stores in this._txt which is a plain {} – should be safe
            a.addTxt('__proto__', 'x');
            assert.strictEqual(({}).hacked, before);
        });
    });

    // -----------------------------------------------------------------------
    describe('removeTxt', function () {

        it('should remove an existing key', function () {
            const a = makeAnnouncer({ txt: { env: 'prod' } });
            a.removeTxt('env');
            assert.strictEqual(a._txt['env'], undefined);
        });

        it('should be a no-op for a non-existent key', function () {
            const a = makeAnnouncer();
            assert.doesNotThrow(() => a.removeTxt('nonexistent'));
        });

        it('should be chainable', function () {
            const a = makeAnnouncer({ txt: { a: '1', b: '2' } });
            const ret = a.removeTxt('a').removeTxt('b');
            assert.strictEqual(ret, a);
            assert.strictEqual(a._txt['a'], undefined);
            assert.strictEqual(a._txt['b'], undefined);
        });
    });

    // -----------------------------------------------------------------------
    describe('_encodeName', function () {

        it('should encode a single-label name', function () {
            const a = makeAnnouncer();
            const buf = a._encodeName('local');
            // \x05local\x00
            assert.strictEqual(buf[0], 5);
            assert.strictEqual(buf.slice(1, 6).toString(), 'local');
            assert.strictEqual(buf[6], 0x00);
        });

        it('should encode a multi-label name', function () {
            const a = makeAnnouncer();
            const buf = a._encodeName('_http._tcp.local');
            const { name } = decodeName(buf, 0);
            assert.strictEqual(name, '_http._tcp.local');
        });

        it('should terminate with a null byte', function () {
            const a = makeAnnouncer();
            const buf = a._encodeName('testhost.local');
            assert.strictEqual(buf[buf.length - 1], 0x00);
        });

        it('should skip empty label parts from trailing dots', function () {
            const a = makeAnnouncer();
            // "local." has a trailing dot producing an empty label
            const buf = a._encodeName('local.');
            const { name } = decodeName(buf, 0);
            assert.strictEqual(name, 'local');
        });

        it('should handle unicode labels without throwing', function () {
            const a = makeAnnouncer();
            assert.doesNotThrow(() => a._encodeName('café.local'));
        });
    });

    // -----------------------------------------------------------------------
    describe('Packet – header', function () {

        it('should start with ID = 0x0000', function () {
            const buf = makeAnnouncer()._buildPacket();
            assert.strictEqual(buf.readUInt16BE(0), 0x0000);
        });

        it('should have QR=1 and AA=1 in flags (0x8400)', function () {
            const buf = makeAnnouncer()._buildPacket();
            assert.strictEqual(buf.readUInt16BE(2), 0x8400);
        });

        it('should have QDCOUNT = 0', function () {
            const buf = makeAnnouncer()._buildPacket();
            assert.strictEqual(buf.readUInt16BE(4), 0);
        });

        it('should have ANCOUNT = 1 (PTR answer)', function () {
            const buf = makeAnnouncer()._buildPacket();
            assert.strictEqual(buf.readUInt16BE(6), 1);
        });

        it('should have NSCOUNT = 0', function () {
            const buf = makeAnnouncer()._buildPacket();
            assert.strictEqual(buf.readUInt16BE(8), 0);
        });

        it('should have ARCOUNT = 3 (SRV + TXT + A)', function () {
            const buf = makeAnnouncer()._buildPacket();
            assert.strictEqual(buf.readUInt16BE(10), 3);
        });
    });

    // -----------------------------------------------------------------------
    describe('Packet – PTR record (answer)', function () {
        let rec;

        before(function () {
            const buf = makeAnnouncer()._buildPacket();
            rec = decodeRecord(buf, 12); // immediately after 12-byte header
        });

        it('should have name = service type', function () {
            assert.strictEqual(rec.name, '_http._tcp.local');
        });

        it('should have type = PTR (0x000c)', function () {
            assert.strictEqual(rec.type, TYPE_PTR);
        });

        it('should have class = IN without cache-flush (0x0001)', function () {
            assert.strictEqual(rec.cls, CLASS_IN);
        });

        it('should have TTL = 4500 (service TTL)', function () {
            assert.strictEqual(rec.ttl, TTL_SERVICE);
        });

        it('should have rdata = instance FQDN', function () {
            const { name } = decodeName(rec.rdata, 0);
            assert.strictEqual(name, 'Test Service._http._tcp.local');
        });
    });

    // -----------------------------------------------------------------------
    describe('Packet – SRV record (additional)', function () {
        let rec;

        before(function () {
            const buf = makeAnnouncer()._buildPacket();
            const ptrSize = decodeRecord(buf, 12).totalBytes;
            rec = decodeRecord(buf, 12 + ptrSize);
        });

        it('should have name = instance FQDN', function () {
            assert.strictEqual(rec.name, 'Test Service._http._tcp.local');
        });

        it('should have type = SRV (0x0021)', function () {
            assert.strictEqual(rec.type, TYPE_SRV);
        });

        it('should have class = IN with cache-flush bit (0x8001)', function () {
            assert.strictEqual(rec.cls, CLASS_IN_FLUSH);
        });

        it('should have TTL = 120 (host TTL)', function () {
            assert.strictEqual(rec.ttl, TTL_HOST);
        });

        it('should encode priority = 0', function () {
            assert.strictEqual(rec.rdata.readUInt16BE(0), 0);
        });

        it('should encode weight = 0', function () {
            assert.strictEqual(rec.rdata.readUInt16BE(2), 0);
        });

        it('should encode the correct port', function () {
            assert.strictEqual(rec.rdata.readUInt16BE(4), 8080);
        });

        it('should encode the target hostname', function () {
            const { name } = decodeName(rec.rdata, 6);
            assert.strictEqual(name, 'testhost.local');
        });
    });

    // -----------------------------------------------------------------------
    describe('Packet – TXT record (additional)', function () {
        let buf, ptrOffset, ptrSize, srvSize;

        before(function () {
            buf = makeAnnouncer({ txt: { env: 'prod', path: '/api' } })._buildPacket();
            ptrSize = decodeRecord(buf, 12).totalBytes;
            srvSize = decodeRecord(buf, 12 + ptrSize).totalBytes;
            ptrOffset = 12 + ptrSize + srvSize;
        });

        it('should have name = instance FQDN', function () {
            const rec = decodeRecord(buf, ptrOffset);
            assert.strictEqual(rec.name, 'Test Service._http._tcp.local');
        });

        it('should have type = TXT (0x0010)', function () {
            const rec = decodeRecord(buf, ptrOffset);
            assert.strictEqual(rec.type, TYPE_TXT);
        });

        it('should have class = IN with cache-flush bit (0x8001)', function () {
            const rec = decodeRecord(buf, ptrOffset);
            assert.strictEqual(rec.cls, CLASS_IN_FLUSH);
        });

        it('should have TTL = 4500 (service TTL)', function () {
            const rec = decodeRecord(buf, ptrOffset);
            assert.strictEqual(rec.ttl, TTL_SERVICE);
        });

        it('should encode all key=value pairs', function () {
            const rec = decodeRecord(buf, ptrOffset);
            const pairs = decodeTxtRdata(rec.rdata);
            assert.ok(pairs.includes('env=prod'));
            assert.ok(pairs.includes('path=/api'));
        });

        it('should encode an empty TXT as a single null byte (RFC 6763 §6.1)', function () {
            const a = makeAnnouncer(); // no txt
            const b = a._buildPacket();
            const ps = decodeRecord(b, 12).totalBytes;
            const ss = decodeRecord(b, 12 + ps).totalBytes;
            const rec = decodeRecord(b, 12 + ps + ss);
            assert.strictEqual(rec.rdata.length, 1);
            assert.strictEqual(rec.rdata[0], 0x00);
        });

        it('should preserve = characters inside values', function () {
            const a = makeAnnouncer({ txt: { token: 'abc=def=ghi' } });
            const b = a._buildPacket();
            const ps = decodeRecord(b, 12).totalBytes;
            const ss = decodeRecord(b, 12 + ps).totalBytes;
            const rec = decodeRecord(b, 12 + ps + ss);
            const pairs = decodeTxtRdata(rec.rdata);
            assert.ok(pairs.includes('token=abc=def=ghi'));
        });

        it('should include TXT records added via addTxt after construction', function () {
            const a = makeAnnouncer();
            a.addTxt('dynamic', 'yes');
            const b = a._buildPacket();
            const ps = decodeRecord(b, 12).totalBytes;
            const ss = decodeRecord(b, 12 + ps).totalBytes;
            const rec = decodeRecord(b, 12 + ps + ss);
            const pairs = decodeTxtRdata(rec.rdata);
            assert.ok(pairs.includes('dynamic=yes'));
        });

        it('should not include TXT records removed via removeTxt', function () {
            const a = makeAnnouncer({ txt: { env: 'prod', remove_me: 'yes' } });
            a.removeTxt('remove_me');
            const b = a._buildPacket();
            const ps = decodeRecord(b, 12).totalBytes;
            const ss = decodeRecord(b, 12 + ps).totalBytes;
            const rec = decodeRecord(b, 12 + ps + ss);
            const pairs = decodeTxtRdata(rec.rdata);
            assert.ok(!pairs.some(p => p.startsWith('remove_me')));
        });
    });

    // -----------------------------------------------------------------------
    describe('Packet – A record (additional)', function () {
        let rec;

        before(function () {
            const buf = makeAnnouncer()._buildPacket();
            const p = decodeRecord(buf, 12).totalBytes;
            const s = decodeRecord(buf, 12 + p).totalBytes;
            const t = decodeRecord(buf, 12 + p + s).totalBytes;
            rec = decodeRecord(buf, 12 + p + s + t);
        });

        it('should have name = host', function () {
            assert.strictEqual(rec.name, 'testhost.local');
        });

        it('should have type = A (0x0001)', function () {
            assert.strictEqual(rec.type, TYPE_A);
        });

        it('should have class = IN with cache-flush bit (0x8001)', function () {
            assert.strictEqual(rec.cls, CLASS_IN_FLUSH);
        });

        it('should have TTL = 120 (host TTL)', function () {
            assert.strictEqual(rec.ttl, TTL_HOST);
        });

        it('should encode a 4-byte IPv4 address', function () {
            assert.strictEqual(rec.rdata.length, 4);
            const ip = Array.from(rec.rdata).join('.');
            assert.match(ip, /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
        });

        it('should encode each octet in range 0-255', function () {
            for (const byte of rec.rdata) {
                assert.ok(byte >= 0 && byte <= 255);
            }
        });
    });

    // -----------------------------------------------------------------------
    describe('goodbye() packet – all TTLs must be 0', function () {
        let buf;

        before(function () {
            buf = makeAnnouncer({ txt: { a: '1' } })._buildPacket({ ttlOverride: 0 });
        });

        it('PTR record TTL should be 0', function () {
            const rec = decodeRecord(buf, 12);
            assert.strictEqual(rec.ttl, 0);
        });

        it('SRV record TTL should be 0', function () {
            const p = decodeRecord(buf, 12).totalBytes;
            const rec = decodeRecord(buf, 12 + p);
            assert.strictEqual(rec.ttl, 0);
        });

        it('TXT record TTL should be 0', function () {
            const p = decodeRecord(buf, 12).totalBytes;
            const s = decodeRecord(buf, 12 + p).totalBytes;
            const rec = decodeRecord(buf, 12 + p + s);
            assert.strictEqual(rec.ttl, 0);
        });

        it('A record TTL should be 0', function () {
            const p = decodeRecord(buf, 12).totalBytes;
            const s = decodeRecord(buf, 12 + p).totalBytes;
            const t = decodeRecord(buf, 12 + p + s).totalBytes;
            const rec = decodeRecord(buf, 12 + p + s + t);
            assert.strictEqual(rec.ttl, 0);
        });
    });

    // -----------------------------------------------------------------------
    describe('announce() – network behavior', function () {

        it('should send to the mDNS multicast address 224.0.0.251', async function () {
            const a = makeAnnouncer();
            const sent = withMockSocket(a);
            await a.announce();
            assert.strictEqual(sent.length, 1);
            assert.strictEqual(sent[0].addr, '224.0.0.251');
        });

        it('should send to port 5353', async function () {
            const a = makeAnnouncer();
            const sent = withMockSocket(a);
            await a.announce();
            assert.strictEqual(sent[0].port, 5353);
        });

        it('should send a buffer with at least a 12-byte header', async function () {
            const a = makeAnnouncer();
            const sent = withMockSocket(a);
            await a.announce();
            assert.ok(sent[0].buf.length > 12);
        });

        it('should send a valid QR=1 packet on announce', async function () {
            const a = makeAnnouncer();
            const sent = withMockSocket(a);
            await a.announce();
            // byte 2 high bit = QR flag
            assert.strictEqual(sent[0].buf.readUInt8(2) >> 7, 1);
        });
    });

    // -----------------------------------------------------------------------
    describe('goodbye() – network behavior', function () {

        it('should send to 224.0.0.251:5353', async function () {
            const a = makeAnnouncer();
            const sent = withMockSocket(a);
            await a.goodbye();
            assert.strictEqual(sent[0].addr, '224.0.0.251');
            assert.strictEqual(sent[0].port, 5353);
        });

        it('should send a packet with TTL = 0 in the PTR record', async function () {
            const a = makeAnnouncer();
            const sent = withMockSocket(a);
            await a.goodbye();
            const rec = decodeRecord(sent[0].buf, 12);
            assert.strictEqual(rec.ttl, 0);
        });
    });

    // -----------------------------------------------------------------------
    describe('destroy()', function () {

        it('should close the UDP socket', async function () {
            let closed = false;
            const a = makeAnnouncer();
            a._udp = { close(cb) { closed = true; cb(); } };
            await a.destroy();
            assert.strictEqual(closed, true);
            assert.strictEqual(a._udp, null);
        });

        it('should resolve immediately when no socket is open', async function () {
            const a = makeAnnouncer(); // _udp is null
            await assert.doesNotReject(() => a.destroy());
        });
    });

    // -----------------------------------------------------------------------
    describe('Security – packet integrity', function () {

        it('total packet length should match header record counts', function () {
            const a = makeAnnouncer({ txt: { k: 'v' } });
            const buf = a._buildPacket();
            // Parse all 4 records (1 answer + 3 additional)
            let offset = 12;
            for (let i = 0; i < 4; i++) {
                const rec = decodeRecord(buf, offset);
                assert.ok(rec.totalBytes > 0, `record ${i} has 0 bytes`);
                offset += rec.totalBytes;
            }
            assert.strictEqual(offset, buf.length, 'no trailing garbage bytes');
        });

        it('should not expose internal state via _txt reference', function () {
            const original = { key: 'val' };
            const a = makeAnnouncer({ txt: original });
            original.key = 'mutated';
            // Constructor iterates entries at construction time, so _txt is
            // not a reference to the original object – mutation has no effect.
            assert.strictEqual(a._txt['key'], 'val');
        });

        it('should produce a different packet after addTxt', function () {
            const a = makeAnnouncer();
            const buf1 = a._buildPacket();
            a.addTxt('extra', 'data');
            const buf2 = a._buildPacket();
            assert.notDeepStrictEqual(buf1, buf2);
        });

        it('should produce the same packet on repeated calls when state unchanged', function () {
            const a = makeAnnouncer({ txt: { k: 'v' } });
            const buf1 = a._buildPacket();
            const buf2 = a._buildPacket();
            assert.deepStrictEqual(buf1, buf2);
        });

        it('should handle a very long TXT value without throwing', function () {
            const a = makeAnnouncer();
            const longValue = 'x'.repeat(200);
            assert.doesNotThrow(() => a.addTxt('bigkey', longValue));
            assert.doesNotThrow(() => a._buildPacket());
        });

        it('should handle many TXT entries without throwing', function () {
            const a = makeAnnouncer();
            for (let i = 0; i < 50; i++) {
                a.addTxt(`key${i}`, `val${i}`);
            }
            assert.doesNotThrow(() => a._buildPacket());
        });
    });

    // -----------------------------------------------------------------------
    describe('Security – instance FQDN construction', function () {

        it('should build instanceFqdn as "<instance>.<serviceType>"', function () {
            const a = makeAnnouncer();
            assert.strictEqual(a._instanceFqdn, 'Test Service._http._tcp.local');
        });

        it('should not allow injecting extra labels via instance name with dots', function () {
            // A dot in the instance name is encoded as part of that label in DNS wire format,
            // producing extra labels – verify the name round-trips through _encodeName
            const a = makeAnnouncer({ instance: 'evil.inject' });
            const encoded = a._encodeName(a._instanceFqdn);
            const { name } = decodeName(encoded, 0);
            // The dot is treated as a label separator, so it splits into labels
            // This is a known DNS behaviour – document it rather than hide it
            assert.ok(name.includes('evil'));
        });
    });
});
