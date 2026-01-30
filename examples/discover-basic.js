/* ------------------------------------------------------------------
 * node-dns-sd - Example: Basic Service Discovery
 *
 * This example shows how to discover services on the local network
 * using mDNS/DNS-SD (Bonjour compatible).
 * ---------------------------------------------------------------- */
'use strict';

const dnssd = require('../lib/dns-sd.js');

// Common service types to discover:
// - _http._tcp.local        - HTTP servers
// - _https._tcp.local       - HTTPS servers
// - _googlecast._tcp.local  - Chromecast devices
// - _airplay._tcp.local     - AirPlay devices
// - _printer._tcp.local     - Printers
// - _ipp._tcp.local         - IPP Printers
// - _ssh._tcp.local         - SSH servers
// - _smb._tcp.local         - SMB/Windows shares
// - _ftp._tcp.local         - FTP servers

async function discoverServices() {
    console.log('Discovering HTTP services on the network...\n');

    try {
        const devices = await dnssd.discover({
            name: '_http._tcp.local',
            wait: 5  // Wait 5 seconds for responses
        });

        if (devices.length === 0) {
            console.log('No devices found.');
        } else {
            console.log(`Found ${devices.length} device(s):\n`);
            devices.forEach((device, index) => {
                console.log(`--- Device ${index + 1} ---`);
                console.log(`  Address:     ${device.address}`);
                console.log(`  FQDN:        ${device.fqdn || 'N/A'}`);
                console.log(`  Model:       ${device.modelName || 'N/A'}`);
                console.log(`  Family:      ${device.familyName || 'N/A'}`);
                if (device.service) {
                    console.log(`  Service:`);
                    console.log(`    Type:      ${device.service.type}`);
                    console.log(`    Protocol:  ${device.service.protocol}`);
                    console.log(`    Port:      ${device.service.port}`);
                }
                console.log('');
            });
        }
    } catch (error) {
        console.error('Discovery failed:', error.message);
    }
}

// Run the example
discoverServices();
