/* ------------------------------------------------------------------
 * node-dns-sd - Example: Filtered Service Discovery
 *
 * This example shows how to use filters to narrow down discovered
 * devices by name, address, model, or custom criteria.
 * ---------------------------------------------------------------- */
'use strict';

const dnssd = require('../lib/dns-sd.js');

async function discoverWithStringFilter() {
    console.log('Example 1: String Filter');
    console.log('=' .repeat(50));
    console.log('Searching for devices with "192.168" in their address...\n');

    try {
        const devices = await dnssd.discover({
            name: '_http._tcp.local',
            filter: '192.168',  // String filter matches against fqdn, address, modelName, familyName
            wait: 3
        });

        console.log(`Found ${devices.length} matching device(s)`);
        devices.forEach((d) => {
            console.log(`  - ${d.address}: ${d.fqdn || 'N/A'}`);
        });
    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function discoverWithFunctionFilter() {
    console.log('\n\nExample 2: Function Filter');
    console.log('='.repeat(50));
    console.log('Searching for devices with port 80...\n');

    try {
        const devices = await dnssd.discover({
            name: '_http._tcp.local',
            filter: (device) => {
                // Custom filter function
                // Return true to include the device, false to exclude
                return device.service && device.service.port === 80;
            },
            wait: 3
        });

        console.log(`Found ${devices.length} device(s) on port 80`);
        devices.forEach((d) => {
            console.log(`  - ${d.address}: ${d.fqdn || 'N/A'}`);
        });
    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function discoverWithModelFilter() {
    console.log('\n\nExample 3: Filter by Model Name');
    console.log('='.repeat(50));
    console.log('Searching for Apple TV devices...\n');

    try {
        const devices = await dnssd.discover({
            name: '_airplay._tcp.local',
            filter: 'Apple TV',
            wait: 5
        });

        console.log(`Found ${devices.length} Apple TV device(s)`);
        devices.forEach((d) => {
            console.log(`  - ${d.address}: ${d.modelName || 'N/A'}`);
        });
    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function discoverQuickMode() {
    console.log('\n\nExample 4: Quick Mode (return on first match)');
    console.log('='.repeat(50));
    console.log('Finding first available HTTP service...\n');

    const startTime = Date.now();

    try {
        const devices = await dnssd.discover({
            name: '_http._tcp.local',
            quick: true,  // Return immediately when first device found
            wait: 10      // Max wait if no devices found
        });

        const elapsed = Date.now() - startTime;
        console.log(`Found in ${elapsed}ms`);

        if (devices.length > 0) {
            console.log(`  First device: ${devices[0].address}`);
        } else {
            console.log('  No devices found within timeout');
        }
    } catch (error) {
        console.error('Error:', error.message);
    }
}

async function discoverMultipleServices() {
    console.log('\n\nExample 5: Discover Multiple Service Types');
    console.log('='.repeat(50));
    console.log('Searching for HTTP and HTTPS services...\n');

    try {
        const devices = await dnssd.discover({
            name: ['_http._tcp.local', '_https._tcp.local'],
            wait: 3
        });

        console.log(`Found ${devices.length} device(s) total`);
        devices.forEach((d) => {
            const protocol = d.service ? d.service.type : 'unknown';
            console.log(`  - ${d.address}: ${protocol} (${d.fqdn || 'N/A'})`);
        });
    } catch (error) {
        console.error('Error:', error.message);
    }
}

// Run all examples
(async () => {
    await discoverWithStringFilter();
    await discoverWithFunctionFilter();
    await discoverWithModelFilter();
    await discoverQuickMode();
    await discoverMultipleServices();
})();
