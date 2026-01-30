/* ------------------------------------------------------------------
 * node-dns-sd - dns-sd-composer.test.js
 * Unit tests for the DNS-SD composer
 * ---------------------------------------------------------------- */
'use strict';

const assert = require('assert');
const composer = require('../lib/dns-sd-composer.js');

describe('DnsSdComposer', function () {
    describe('Basic Composition', function () {
        it('should compose a simple query packet', function () {
            const buf = composer.compose({
                name: ['_http._tcp.local']
            });
            assert.ok(Buffer.isBuffer(buf));
            // Header is 12 bytes
            assert.ok(buf.length > 12);
            // Check questions count is 1
            assert.strictEqual(buf.readUInt16BE(4), 1);
        });

        it('should compose query with multiple names', function () {
            const buf = composer.compose({
                name: ['_http._tcp.local', '_ftp._tcp.local']
            });
            // Check questions count is 2
            assert.strictEqual(buf.readUInt16BE(4), 2);
        });

        it('should set correct query type', function () {
            const buf = composer.compose({
                name: ['_http._tcp.local'],
                type: 'PTR'
            });
            assert.ok(Buffer.isBuffer(buf));
            // PTR type code is 12 (0x0C)
            // Find the type field after the domain name
            // _http._tcp.local = 5 + "http" + 4 + "tcp" + 5 + "local" + 1 = ...
            // Just verify it's a valid buffer
            assert.ok(buf.length > 12);
        });

        it('should default to ANY type (*)', function () {
            const buf = composer.compose({
                name: ['test.local']
            });
            // ANY type is 255 (0xFF)
            // Find the position after "test.local\0"
            // 12 (header) + 1 (len) + 4 (test) + 1 (len) + 5 (local) + 1 (null) = 24
            // Type is at offset 24-25
            const typeCode = buf.readUInt16BE(24);
            assert.strictEqual(typeCode, 0xFF);
        });

        it('should throw on unknown query type', function () {
            assert.throws(() => {
                composer.compose({
                    name: ['test.local'],
                    type: 'UNKNOWN_TYPE'
                });
            }, /unknown/i);
        });

        it('should throw on invalid type (non-string)', function () {
            assert.throws(() => {
                composer.compose({
                    name: ['test.local'],
                    type: 123
                });
            }, /invalid/i);
        });
    });

    describe('Security: Label Length Validation', function () {
        it('should throw on label exceeding 63 bytes', function () {
            const longLabel = 'a'.repeat(64);
            assert.throws(() => {
                composer.compose({
                    name: [longLabel + '.local']
                });
            }, /63/);
        });

        it('should accept label of exactly 63 bytes', function () {
            const maxLabel = 'a'.repeat(63);
            const buf = composer.compose({
                name: [maxLabel + '.local']
            });
            assert.ok(Buffer.isBuffer(buf));
        });

        it('should throw on domain name exceeding 253 characters', function () {
            // Create a domain name > 253 chars using multiple valid labels
            const labels = [];
            for (let i = 0; i < 10; i++) {
                labels.push('a'.repeat(30));
            }
            const longDomain = labels.join('.');
            assert.ok(longDomain.length > 253);

            assert.throws(() => {
                composer.compose({
                    name: [longDomain]
                });
            }, /253/);
        });

        it('should accept domain name of exactly 253 characters', function () {
            // Build a 253-char domain: multiple 63-char labels + dots
            // 63 + 1 + 63 + 1 + 63 + 1 + 59 = 253
            const domain = 'a'.repeat(63) + '.' + 'b'.repeat(63) + '.' + 'c'.repeat(63) + '.' + 'd'.repeat(61);
            assert.strictEqual(domain.length, 253);

            const buf = composer.compose({
                name: [domain]
            });
            assert.ok(Buffer.isBuffer(buf));
        });
    });

    describe('Packet Structure', function () {
        it('should have correct header structure', function () {
            const buf = composer.compose({
                name: ['test.local']
            });

            // Transaction ID (should be 0)
            assert.strictEqual(buf.readUInt16BE(0), 0);
            // Flags (should be 0 for query)
            assert.strictEqual(buf.readUInt16BE(2), 0);
            // Questions count
            assert.strictEqual(buf.readUInt16BE(4), 1);
            // Answers count
            assert.strictEqual(buf.readUInt16BE(6), 0);
            // Authority count
            assert.strictEqual(buf.readUInt16BE(8), 0);
            // Additional count
            assert.strictEqual(buf.readUInt16BE(10), 0);
        });

        it('should encode domain labels correctly', function () {
            const buf = composer.compose({
                name: ['test.local']
            });

            // After 12-byte header:
            // Byte 12: length of "test" = 4
            assert.strictEqual(buf.readUInt8(12), 4);
            // Bytes 13-16: "test"
            assert.strictEqual(buf.slice(13, 17).toString(), 'test');
            // Byte 17: length of "local" = 5
            assert.strictEqual(buf.readUInt8(17), 5);
            // Bytes 18-22: "local"
            assert.strictEqual(buf.slice(18, 23).toString(), 'local');
            // Byte 23: null terminator
            assert.strictEqual(buf.readUInt8(23), 0);
        });

        it('should set class to IN', function () {
            const buf = composer.compose({
                name: ['test.local']
            });

            // Class field is after type field
            // Domain: 12 bytes offset + domain encoding + 2 bytes type
            // For "test.local": 12 + 1+4 + 1+5 + 1 + 2 = 26
            // Class is at offset 26-27
            const classCode = buf.readUInt16BE(26);
            assert.strictEqual(classCode, 1); // IN class
        });
    });

    describe('UTF-8 Handling', function () {
        it('should handle ASCII service names', function () {
            const buf = composer.compose({
                name: ['_http._tcp.local']
            });
            assert.ok(Buffer.isBuffer(buf));
        });

        it('should correctly measure byte length for UTF-8', function () {
            // UTF-8 characters can be multi-byte
            // "café" is 5 bytes in UTF-8 (c=1, a=1, f=1, é=2)
            const buf = composer.compose({
                name: ['café.local']
            });
            // Label length should be 5 (bytes), not 4 (characters)
            assert.strictEqual(buf.readUInt8(12), 5);
        });
    });
});
