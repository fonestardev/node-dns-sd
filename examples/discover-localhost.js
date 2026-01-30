/* ------------------------------------------------------------------
 * node-dns-sd - Example: Localhost Service Discovery
 *
 * This example shows how to discover services running on the same
 * machine (localhost) using the `localhost: true` option.
 *
 * By default, the library filters out responses from the local machine's
 * IP addresses to avoid self-discovery. Setting `localhost: true` allows
 * discovering services advertised by the same machine.
 * ---------------------------------------------------------------- */
'use strict';

const dnssd = require('../lib/dns-sd.js');

async function discoverLocalServices() {
    console.log('Discovering services including localhost...\n');

    try {
        // Discover with localhost enabled
        const devices = await dnssd.discover({
            name: '_http._tcp.local',
            localhost: true,  // <-- Enable localhost discovery
            wait: 3
        });

        if (devices.length === 0) {
            console.log('No devices found.');
            console.log('\nNote: For this example to find localhost services,');
            console.log('you need a service advertising via mDNS on this machine.');
            console.log('Try running Avahi, Bonjour, or an mDNS-enabled application.');
        } else {
            console.log(`Found ${devices.length} device(s):\n`);

            // Separate local and remote devices
            const localAddresses = getLocalAddresses();

            devices.forEach((device) => {
                const isLocal = localAddresses.includes(device.address);
                const tag = isLocal ? '[LOCAL]' : '[REMOTE]';

                console.log(`${tag} ${device.address}`);
                console.log(`  FQDN:   ${device.fqdn || 'N/A'}`);
                console.log(`  Model:  ${device.modelName || 'N/A'}`);
                if (device.service) {
                    console.log(`  Port:   ${device.service.port}`);
                }
                console.log('');
            });
        }
    } catch (error) {
        console.error('Discovery failed:', error.message);
    }
}

// Helper to get local IP addresses
function getLocalAddresses() {
    const os = require('os');
    const addresses = [];
    const netifs = os.networkInterfaces();

    for (const iflist of Object.values(netifs)) {
        for (const info of iflist) {
            if (info.family === 'IPv4' && !info.internal) {
                addresses.push(info.address);
            }
        }
    }
    return addresses;
}

// Comparison: discover without localhost (default behavior)
async function compareDiscovery() {
    console.log('='.repeat(60));
    console.log('COMPARISON: With vs Without localhost option');
    console.log('='.repeat(60));

    console.log('\n1. Discovery WITHOUT localhost (default):');
    console.log('-'.repeat(40));

    const withoutLocalhost = await dnssd.discover({
        name: '_http._tcp.local',
        localhost: false,  // This is the default
        wait: 2
    });
    console.log(`   Found ${withoutLocalhost.length} device(s)`);

    console.log('\n2. Discovery WITH localhost enabled:');
    console.log('-'.repeat(40));

    const withLocalhost = await dnssd.discover({
        name: '_http._tcp.local',
        localhost: true,
        wait: 2
    });
    console.log(`   Found ${withLocalhost.length} device(s)`);

    if (withLocalhost.length > withoutLocalhost.length) {
        console.log('\n   Note: localhost option found additional local services!');
    }
}

// Run examples
(async () => {
    await discoverLocalServices();
    console.log('\n');
    await compareDiscovery();
})();
