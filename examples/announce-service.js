/* ------------------------------------------------------------------
 * node-dns-sd - Example: Announce a Service
 *
 * Advertises a local service on the mDNS/DNS-SD multicast network
 * so that other devices can discover it.
 * ---------------------------------------------------------------- */
'use strict';

const DnsSdAnnouncer = require('../lib/dns-sd-announcer.js');

async function main() {
    // Create an announcer for an HTTP service on port 3000
    const announcer = new DnsSdAnnouncer({
        name:     '_http._tcp.local',  // service type
        instance: 'My Node Server',    // how it appears in discovery
        port:     3000,
        txt: {
            version: '1.0',
            path:    '/'
        }
    });

    // Dynamically add more TXT records before announcing
    announcer
        .addTxt('env',  'production')
        .addTxt('lang', 'node');

    console.log('Announcing service every 2 seconds. Press Ctrl+C to stop.\n');

    let count = 0;

    const interval = setInterval(async () => {
        try {
            await announcer.announce();
            count++;
            console.log(`[${new Date().toISOString()}] Announcement #${count} sent`);
        } catch (err) {
            console.error('Announce error:', err.message);
        }
    }, 2000);

    // Send the first announcement immediately without waiting 2 seconds
    await announcer.announce();
    count++;
    console.log(`[${new Date().toISOString()}] Announcement #${count} sent`);

    // On exit send a goodbye packet (TTL=0) to remove from network caches
    process.on('SIGINT', async () => {
        console.log('\nSending goodbye...');
        clearInterval(interval);
        await announcer.goodbye();
        await announcer.destroy();
        process.exit(0);
    });
}

main().catch(console.error);
