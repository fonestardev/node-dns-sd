/* ------------------------------------------------------------------
 * node-dns-sd - Example: Monitor mDNS Traffic
 *
 * This example shows how to monitor all mDNS/DNS-SD packets on the
 * network. This is useful for debugging or building service browsers.
 * ---------------------------------------------------------------- */
'use strict';

const dnssd = require('../lib/dns-sd.js');

async function monitorMdns() {
    console.log('Starting mDNS packet monitor...');
    console.log('Press Ctrl+C to stop.\n');
    console.log('='.repeat(60));

    // Set up the packet handler
    dnssd.ondata = (packet) => {
        const timestamp = new Date().toISOString();
        const addr = packet.address || 'unknown';
        const isQuery = packet.header.qr === 0;

        console.log(`\n[${timestamp}] ${isQuery ? 'QUERY' : 'RESPONSE'} from ${addr}`);

        // Print questions
        if (packet.questions && packet.questions.length > 0) {
            console.log('  Questions:');
            packet.questions.forEach((q) => {
                console.log(`    - ${q.name} (${q.type}/${q.class})`);
            });
        }

        // Print answers
        if (packet.answers && packet.answers.length > 0) {
            console.log('  Answers:');
            packet.answers.forEach((a) => {
                let rdata = a.rdata;
                if (typeof rdata === 'object') {
                    rdata = JSON.stringify(rdata);
                }
                console.log(`    - ${a.name} ${a.type} ${rdata} (TTL: ${a.ttl})`);
            });
        }

        // Print additionals (often contains useful service info)
        if (packet.additionals && packet.additionals.length > 0) {
            console.log('  Additionals:');
            packet.additionals.forEach((a) => {
                let rdata = a.rdata;
                if (typeof rdata === 'object') {
                    rdata = JSON.stringify(rdata);
                }
                console.log(`    - ${a.name} ${a.type} ${rdata}`);
            });
        }
    };

    try {
        // Start monitoring
        await dnssd.startMonitoring();
        console.log('Monitoring started. Waiting for packets...');

        // Handle graceful shutdown
        process.on('SIGINT', async () => {
            console.log('\n\nStopping monitor...');
            await dnssd.stopMonitoring();
            console.log('Monitor stopped.');
            process.exit(0);
        });
    } catch (error) {
        console.error('Failed to start monitoring:', error.message);
        process.exit(1);
    }
}

// Run the monitor
monitorMdns();
