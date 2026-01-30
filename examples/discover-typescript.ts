/* ------------------------------------------------------------------
 * node-dns-sd - Example: TypeScript Usage
 *
 * This example demonstrates how to use node-dns-sd with TypeScript.
 *
 * To run this example:
 *   npm install -D typescript ts-node
 *   npx ts-node examples/discover-typescript.ts
 * ---------------------------------------------------------------- */

import dnssd, {
    DiscoverParams,
    DiscoveredDevice,
    DnsPacket,
    ServiceInfo
} from 'node-dns-sd';

async function discoverWithTypes(): Promise<void> {
    console.log('TypeScript mDNS Discovery Example\n');

    // Define discovery parameters with full type support
    const params: DiscoverParams = {
        name: '_http._tcp.local',
        wait: 3,
        localhost: true,  // Include local services
        quick: false,
        key: 'address'
    };

    try {
        // Discover returns Promise<DiscoveredDevice[]>
        const devices: DiscoveredDevice[] = await dnssd.discover(params);

        console.log(`Found ${devices.length} device(s):\n`);

        devices.forEach((device: DiscoveredDevice, index: number) => {
            console.log(`Device ${index + 1}:`);
            console.log(`  Address: ${device.address}`);
            console.log(`  FQDN: ${device.fqdn}`);
            console.log(`  Model: ${device.modelName}`);

            // Service info is typed
            const service: ServiceInfo | null = device.service;
            if (service) {
                console.log(`  Service:`);
                console.log(`    Type: ${service.type}`);
                console.log(`    Protocol: ${service.protocol}`);
                console.log(`    Port: ${service.port}`);
            }

            // Access raw packet data
            const packet: DnsPacket = device.packet;
            console.log(`  Answers: ${packet.answers.length}`);
            console.log('');
        });
    } catch (error) {
        console.error('Discovery failed:', (error as Error).message);
    }
}

async function monitorWithTypes(): Promise<void> {
    console.log('Starting typed monitor...\n');

    // ondata callback is typed
    dnssd.ondata = (packet: DnsPacket): void => {
        const isResponse = packet.header.qr === 1;
        console.log(`[${isResponse ? 'RESPONSE' : 'QUERY'}] from ${packet.address}`);

        // Iterate typed records
        packet.answers.forEach((record) => {
            console.log(`  ${record.name} ${record.type} (TTL: ${record.ttl})`);
        });
    };

    await dnssd.startMonitoring();

    // Stop after 5 seconds
    setTimeout(async () => {
        await dnssd.stopMonitoring();
        console.log('\nMonitor stopped.');
    }, 5000);
}

// Using filter with function (typed)
async function discoverWithFilter(): Promise<void> {
    const devices = await dnssd.discover({
        name: '_http._tcp.local',
        wait: 3,
        // Filter function receives DiscoveredDevice and returns boolean
        filter: (device: DiscoveredDevice): boolean => {
            return device.service !== null && device.service.port === 80;
        }
    });

    console.log(`Found ${devices.length} device(s) on port 80`);
}

// Run example
discoverWithTypes();
