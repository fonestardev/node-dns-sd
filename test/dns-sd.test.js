/* ------------------------------------------------------------------
 * node-dns-sd - dns-sd.test.js
 * Unit tests for the main dns-sd module
 * ---------------------------------------------------------------- */
'use strict';

const assert = require('assert');
const DnsSd = require('../lib/dns-sd.js');

describe('DnsSd', function () {
    describe('Parameter Validation', function () {
        describe('discover() parameters', function () {
            it('should reject missing params', function () {
                const result = DnsSd._checkDiscoveryParameters();
                assert.ok(result.error instanceof Error);
                assert.match(result.error.message, /required/);
            });

            it('should reject non-object params', function () {
                const result = DnsSd._checkDiscoveryParameters('invalid');
                assert.ok(result.error instanceof Error);
            });

            it('should reject missing name', function () {
                const result = DnsSd._checkDiscoveryParameters({});
                assert.ok(result.error instanceof Error);
                assert.match(result.error.message, /name.*required/i);
            });

            it('should reject empty name string', function () {
                const result = DnsSd._checkDiscoveryParameters({ name: '' });
                assert.ok(result.error instanceof Error);
            });

            it('should reject empty name array', function () {
                const result = DnsSd._checkDiscoveryParameters({ name: [] });
                assert.ok(result.error instanceof Error);
            });

            it('should accept valid name string', function () {
                const result = DnsSd._checkDiscoveryParameters({ name: '_http._tcp.local' });
                assert.ok(!result.error);
                assert.deepStrictEqual(result.params.name, ['_http._tcp.local']);
            });

            it('should accept valid name array', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: ['_http._tcp.local', '_ftp._tcp.local']
                });
                assert.ok(!result.error);
                assert.deepStrictEqual(result.params.name, ['_http._tcp.local', '_ftp._tcp.local']);
            });

            it('should reject name array with more than 255 elements', function () {
                const names = Array(256).fill('_test._tcp.local');
                const result = DnsSd._checkDiscoveryParameters({ name: names });
                assert.ok(result.error instanceof Error);
                assert.match(result.error.message, /255/);
            });

            it('should reject invalid type', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local',
                    type: 123
                });
                assert.ok(result.error instanceof Error);
            });

            it('should accept valid type', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local',
                    type: 'PTR'
                });
                assert.ok(!result.error);
                assert.strictEqual(result.params.type, 'PTR');
            });

            it('should reject invalid key', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local',
                    key: 'invalid'
                });
                assert.ok(result.error instanceof Error);
            });

            it('should accept key="address"', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local',
                    key: 'address'
                });
                assert.ok(!result.error);
                assert.strictEqual(result.params.key, 'address');
            });

            it('should accept key="fqdn"', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local',
                    key: 'fqdn'
                });
                assert.ok(!result.error);
                assert.strictEqual(result.params.key, 'fqdn');
            });

            it('should reject invalid wait', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local',
                    wait: -1
                });
                assert.ok(result.error instanceof Error);
            });

            it('should reject non-integer wait', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local',
                    wait: 1.5
                });
                assert.ok(result.error instanceof Error);
            });

            it('should accept valid wait', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local',
                    wait: 5
                });
                assert.ok(!result.error);
                assert.strictEqual(result.params.wait, 5);
            });

            it('should reject non-boolean quick', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local',
                    quick: 'true'
                });
                assert.ok(result.error instanceof Error);
            });

            it('should accept boolean quick', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local',
                    quick: true
                });
                assert.ok(!result.error);
                assert.strictEqual(result.params.quick, true);
            });

            it('should default quick to false', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local'
                });
                assert.ok(!result.error);
                assert.strictEqual(result.params.quick, false);
            });

            it('should accept string filter', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local',
                    filter: 'mydevice'
                });
                assert.ok(!result.error);
                assert.strictEqual(result.params.filter, 'mydevice');
            });

            it('should accept function filter', function () {
                const filterFn = (device) => device.address === '192.168.1.1';
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local',
                    filter: filterFn
                });
                assert.ok(!result.error);
                assert.strictEqual(result.params.filter, filterFn);
            });

            it('should reject invalid filter type', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local',
                    filter: 123
                });
                assert.ok(result.error instanceof Error);
            });
        });

        describe('localhost parameter', function () {
            it('should default localhost to false', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local'
                });
                assert.ok(!result.error);
                assert.strictEqual(result.params.localhost, false);
            });

            it('should accept localhost=true', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local',
                    localhost: true
                });
                assert.ok(!result.error);
                assert.strictEqual(result.params.localhost, true);
            });

            it('should accept localhost=false', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local',
                    localhost: false
                });
                assert.ok(!result.error);
                assert.strictEqual(result.params.localhost, false);
            });

            it('should reject non-boolean localhost', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local',
                    localhost: 'true'
                });
                assert.ok(result.error instanceof Error);
                assert.match(result.error.message, /localhost.*boolean/i);
            });

            it('should reject number localhost', function () {
                const result = DnsSd._checkDiscoveryParameters({
                    name: '_http._tcp.local',
                    localhost: 1
                });
                assert.ok(result.error instanceof Error);
            });
        });
    });

    describe('Network Interface List', function () {
        it('should return an array', function () {
            const list = DnsSd._getNetifAddressList();
            assert.ok(Array.isArray(list));
        });

        it('should contain only IPv4 addresses', function () {
            const list = DnsSd._getNetifAddressList();
            for (const addr of list) {
                assert.match(addr, /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
            }
        });

        it('should not contain loopback addresses', function () {
            const list = DnsSd._getNetifAddressList();
            for (const addr of list) {
                assert.ok(!addr.startsWith('127.'));
            }
        });

        it('should not contain link-local addresses', function () {
            const list = DnsSd._getNetifAddressList();
            for (const addr of list) {
                assert.ok(!addr.startsWith('169.254.'));
            }
        });
    });

    describe('Device Filter Evaluation', function () {
        const mockDevice = {
            fqdn: 'My Device._http._tcp.local',
            address: '192.168.1.100',
            modelName: 'TestModel',
            familyName: 'TestFamily'
        };

        it('should return true when no filter specified', function () {
            const result = DnsSd._evaluateDeviceFilter(mockDevice, null);
            assert.strictEqual(result, true);
        });

        it('should match fqdn with string filter', function () {
            const result = DnsSd._evaluateDeviceFilter(mockDevice, 'My Device');
            assert.strictEqual(result, true);
        });

        it('should match address with string filter', function () {
            const result = DnsSd._evaluateDeviceFilter(mockDevice, '192.168.1');
            assert.strictEqual(result, true);
        });

        it('should match modelName with string filter', function () {
            const result = DnsSd._evaluateDeviceFilter(mockDevice, 'TestModel');
            assert.strictEqual(result, true);
        });

        it('should match familyName with string filter', function () {
            const result = DnsSd._evaluateDeviceFilter(mockDevice, 'TestFamily');
            assert.strictEqual(result, true);
        });

        it('should not match when string filter not found', function () {
            const result = DnsSd._evaluateDeviceFilter(mockDevice, 'NotFound');
            assert.strictEqual(result, false);
        });

        it('should work with function filter returning true', function () {
            const filter = (device) => device.address === '192.168.1.100';
            const result = DnsSd._evaluateDeviceFilter(mockDevice, filter);
            assert.strictEqual(result, true);
        });

        it('should work with function filter returning false', function () {
            const filter = (device) => device.address === '10.0.0.1';
            const result = DnsSd._evaluateDeviceFilter(mockDevice, filter);
            assert.strictEqual(result, false);
        });

        it('should handle filter function throwing error', function () {
            const filter = () => { throw new Error('Filter error'); };
            const result = DnsSd._evaluateDeviceFilter(mockDevice, filter);
            assert.strictEqual(result, false);
        });
    });

    describe('Answer Packet Validation', function () {
        const validPacket = {
            header: { qr: 1, op: 0 }
        };

        const queryPacket = {
            header: { qr: 0, op: 0 }
        };

        beforeEach(function () {
            DnsSd._netif_address_list = ['192.168.1.10', '10.0.0.5'];
            DnsSd._allow_localhost = false;
        });

        it('should accept valid answer packet from external address', function () {
            const result = DnsSd._isAnswerPacket(validPacket, '192.168.1.100');
            assert.strictEqual(result, true);
        });

        it('should reject packet from local address by default', function () {
            const result = DnsSd._isAnswerPacket(validPacket, '192.168.1.10');
            assert.strictEqual(result, false);
        });

        it('should accept packet from local address when localhost=true', function () {
            DnsSd._allow_localhost = true;
            const result = DnsSd._isAnswerPacket(validPacket, '192.168.1.10');
            assert.strictEqual(result, true);
        });

        it('should reject query packets', function () {
            const result = DnsSd._isAnswerPacket(queryPacket, '192.168.1.100');
            assert.strictEqual(result, false);
        });

        it('should reject packets with non-zero opcode', function () {
            const packet = { header: { qr: 1, op: 1 } };
            const result = DnsSd._isAnswerPacket(packet, '192.168.1.100');
            assert.strictEqual(result, false);
        });
    });
});
