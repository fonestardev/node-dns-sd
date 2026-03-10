/* ------------------------------------------------------------------
 * node-dns-sd - dns-sd-announcer.js
 *
 * Announces a DNS-SD service on the local network via mDNS multicast.
 *
 * Packet structure (RFC 6762 / RFC 6763):
 *   Header  : QR=1 (response), AA=1 (authoritative), no questions
 *   Answers : PTR  service-type -> instance FQDN
 *   Additional:
 *             SRV  instance FQDN -> host:port
 *             TXT  instance FQDN -> key=value pairs
 *             A    host -> IPv4 address
 * ---------------------------------------------------------------- */
'use strict';
const mDgram = require('node:dgram');
const mOs   = require('node:os');

const MDNS_ADDR = '224.0.0.251';
const MDNS_PORT = 5353;

// Record types
const TYPE_A   = 0x0001;
const TYPE_PTR = 0x000c;
const TYPE_TXT = 0x0010;
const TYPE_SRV = 0x0021;

// Classes
const CLASS_IN       = 0x0001; // standard
const CLASS_IN_FLUSH = 0x8001; // cache-flush bit set (unicast-response)

// TTLs (seconds)
const TTL_SERVICE = 4500; // PTR / TXT
const TTL_HOST    = 120;  // SRV / A

class DnsSdAnnouncer {
    /* ------------------------------------------------------------------
     * Constructor: DnsSdAnnouncer(params)
     * - params:
     *   - name     | String | Required | Service type  e.g. "_http._tcp.local"
     *   - instance | String | Optional | Instance name e.g. "My Server"
     *              |        |          | Defaults to os.hostname()
     *   - host     | String | Optional | Hostname      e.g. "myserver.local"
     *              |        |          | Defaults to "<hostname>.local"
     *   - port     | Number | Required | Service port  e.g. 8080
     *   - txt      | Object | Optional | Initial TXT records  { key: 'value', ... }
     * ---------------------------------------------------------------- */
    constructor(params) {
        if (!params || typeof params !== 'object') {
            throw new Error('params object is required.');
        }
        if (typeof params.name !== 'string' || !params.name) {
            throw new Error('params.name (service type, e.g. "_http._tcp.local") is required.');
        }
        if (typeof params.port !== 'number' || !Number.isInteger(params.port) || params.port <= 0 || params.port > 65535) {
            throw new Error('params.port must be an integer between 1 and 65535.');
        }

        this._serviceType   = params.name;
        this._instanceName  = params.instance || mOs.hostname();
        this._host          = params.host || `${mOs.hostname()}.local`;
        this._port          = params.port;
        this._txt           = {};

        // Build the instance FQDN: "My Server._http._tcp.local"
        this._instanceFqdn  = `${this._instanceName}.${this._serviceType}`;

        if (params.txt && typeof params.txt === 'object' && !Array.isArray(params.txt)) {
            for (const [k, v] of Object.entries(params.txt)) {
                this._txt[k] = String(v);
            }
        }

        this._udp = null;
    }

    /* ------------------------------------------------------------------
     * Method: addTxt(key, value)
     *   Adds or updates a TXT record entry. Chainable.
     * ---------------------------------------------------------------- */
    addTxt(key, value) {
        if (typeof key !== 'string' || !key) {
            throw new Error('TXT key must be a non-empty string.');
        }
        this._txt[key] = String(value);
        return this;
    }

    /* ------------------------------------------------------------------
     * Method: removeTxt(key)
     *   Removes a TXT record entry. Chainable.
     * ---------------------------------------------------------------- */
    removeTxt(key) {
        delete this._txt[key];
        return this;
    }

    /* ------------------------------------------------------------------
     * Method: announce()
     *   Builds and sends the mDNS announcement to the multicast network.
     *   Per RFC 6762 §8.3, callers may invoke this multiple times with
     *   short delays (1s apart) for reliability.
     * ---------------------------------------------------------------- */
    async announce() {
        await this._ensureSocket();
        const buf = this._buildPacket();
        await this._send(buf);
    }

    /* ------------------------------------------------------------------
     * Method: goodbye()
     *   Sends a goodbye packet (TTL=0) to remove the service from the
     *   network caches per RFC 6762 §11.
     * ---------------------------------------------------------------- */
    async goodbye() {
        await this._ensureSocket();
        const buf = this._buildPacket({ ttlOverride: 0 });
        await this._send(buf);
    }

    /* ------------------------------------------------------------------
     * Method: destroy()
     *   Closes the UDP socket and releases resources.
     * ---------------------------------------------------------------- */
    destroy() {
        return new Promise((resolve) => {
            if (!this._udp) {
                resolve();
                return;
            }
            this._udp.close(() => {
                this._udp = null;
                resolve();
            });
        });
    }

    // ----------------------------------------------------------------
    // Private helpers
    // ----------------------------------------------------------------

    _ensureSocket() {
        if (this._udp) {
            return Promise.resolve();
        }
        return new Promise((resolve, reject) => {
            const udp = mDgram.createSocket({ type: 'udp4', reuseAddr: true });
            udp.once('error', reject);
            udp.bind(MDNS_PORT, () => {
                udp.removeAllListeners('error');
                udp.setMulticastTTL(255);
                udp.setMulticastLoopback(true);
                this._udp = udp;
                resolve();
            });
        });
    }

    _send(buf) {
        return new Promise((resolve, reject) => {
            this._udp.send(buf, 0, buf.length, MDNS_PORT, MDNS_ADDR, (err) => {
                if (err) {
                    reject(err);
                } else {
                    resolve();
                }
            });
        });
    }

    _buildPacket({ ttlOverride } = {}) {
        const ttlService = ttlOverride !== undefined ? ttlOverride : TTL_SERVICE;
        const ttlHost    = ttlOverride !== undefined ? ttlOverride : TTL_HOST;

        const ptrRec = this._buildPtrRecord(ttlService);
        const srvRec = this._buildSrvRecord(ttlHost);
        const txtRec = this._buildTxtRecord(ttlService);
        const aRec   = this._buildARecord(ttlHost);

        const header = Buffer.from([
            0x00, 0x00,  // ID (always 0 for mDNS)
            0x84, 0x00,  // Flags: QR=1 Response, AA=1 Authoritative
            0x00, 0x00,  // QDCOUNT: 0
            0x00, 0x01,  // ANCOUNT: 1 (PTR)
            0x00, 0x00,  // NSCOUNT: 0
            0x00, 0x03   // ARCOUNT: 3 (SRV + TXT + A)
        ]);

        return Buffer.concat([header, ptrRec, srvRec, txtRec, aRec]);
    }

    _buildPtrRecord(ttl) {
        // PTR: _service._tcp.local  ->  Instance._service._tcp.local
        const rdata = this._encodeName(this._instanceFqdn);
        return this._encodeRecord(this._serviceType, TYPE_PTR, CLASS_IN, ttl, rdata);
    }

    _buildSrvRecord(ttl) {
        // SRV: Instance._service._tcp.local  ->  priority + weight + port + host
        const targetBuf = this._encodeName(this._host);
        const rdata = Buffer.alloc(6 + targetBuf.length);
        rdata.writeUInt16BE(0, 0);           // priority
        rdata.writeUInt16BE(0, 2);           // weight
        rdata.writeUInt16BE(this._port, 4);  // port
        targetBuf.copy(rdata, 6);
        return this._encodeRecord(this._instanceFqdn, TYPE_SRV, CLASS_IN_FLUSH, ttl, rdata);
    }

    _buildTxtRecord(ttl) {
        // TXT: Instance._service._tcp.local  ->  [<len>key=value ...]
        const entries = Object.entries(this._txt);
        let rdata;
        if (entries.length === 0) {
            rdata = Buffer.from([0x00]); // RFC 6763 §6.1: empty TXT = single null byte
        } else {
            const bufs = [];
            for (const [key, value] of entries) {
                const pair = Buffer.from(`${key}=${value}`, 'utf8');
                bufs.push(Buffer.from([pair.length]));
                bufs.push(pair);
            }
            rdata = Buffer.concat(bufs);
        }
        return this._encodeRecord(this._instanceFqdn, TYPE_TXT, CLASS_IN_FLUSH, ttl, rdata);
    }

    _buildARecord(ttl) {
        // A: host.local  ->  IPv4 address (4 bytes)
        const ip = this._getLocalIPv4();
        const rdata = Buffer.from(ip.split('.').map(Number));
        return this._encodeRecord(this._host, TYPE_A, CLASS_IN_FLUSH, ttl, rdata);
    }

    _encodeRecord(name, type, cls, ttl, rdata) {
        const nameBuf = this._encodeName(name);
        const meta = Buffer.alloc(8);
        meta.writeUInt16BE(type, 0);
        meta.writeUInt16BE(cls,  2);
        meta.writeUInt32BE(ttl,  4);
        const rdlen = Buffer.alloc(2);
        rdlen.writeUInt16BE(rdata.length, 0);
        return Buffer.concat([nameBuf, meta, rdlen, rdata]);
    }

    _encodeName(name) {
        // Encode a domain name as length-prefixed labels per RFC 1035
        const bufs = [];
        for (const label of name.split('.')) {
            if (label === '') continue;
            const labelBuf = Buffer.from(label, 'utf8');
            bufs.push(Buffer.from([labelBuf.length]));
            bufs.push(labelBuf);
        }
        bufs.push(Buffer.from([0x00])); // root label
        return Buffer.concat(bufs);
    }

    _getLocalIPv4() {
        const netifs = mOs.networkInterfaces();
        for (const iflist of Object.values(netifs)) {
            for (const info of iflist) {
                if (!info.internal && info.family === 'IPv4' && !info.address.startsWith('169.254.')) {
                    return info.address;
                }
            }
        }
        return '127.0.0.1';
    }
}

module.exports = DnsSdAnnouncer;
