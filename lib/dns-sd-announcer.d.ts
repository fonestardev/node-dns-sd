/* ------------------------------------------------------------------
 * node-dns-sd - dns-sd-announcer.d.ts
 * TypeScript type declarations for DnsSdAnnouncer
 * ---------------------------------------------------------------- */

/// <reference types="node" />

/**
 * Parameters for the DnsSdAnnouncer constructor.
 */
export interface AnnouncerParams {
    /**
     * Service type to announce.
     * @example "_http._tcp.local"
     * @example "_googlecast._tcp.local"
     */
    name: string;

    /**
     * Human-readable instance name shown during discovery.
     * Defaults to `os.hostname()`.
     * @example "My Node Server"
     */
    instance?: string;

    /**
     * Hostname advertised in the SRV and A records.
     * Defaults to `"<os.hostname()>.local"`.
     * @example "myserver.local"
     */
    host?: string;

    /**
     * Port number the service listens on. Must be an integer in [1, 65535].
     * @example 8080
     */
    port: number;

    /**
     * Initial TXT record key-value pairs.
     * Values are coerced to strings.
     * @example { version: "1.0", path: "/" }
     */
    txt?: Record<string, string | number | boolean>;
}

/**
 * Announces a DNS-SD service on the local network via mDNS multicast.
 *
 * Sends an authoritative mDNS response (RFC 6762 / RFC 6763) containing:
 * - PTR answer:      service-type  → instance FQDN
 * - SRV additional: instance FQDN → host:port
 * - TXT additional: instance FQDN → key=value pairs
 * - A   additional: host          → IPv4 address
 *
 * @example
 * ```typescript
 * import DnsSdAnnouncer from './lib/dns-sd-announcer';
 *
 * const announcer = new DnsSdAnnouncer({
 *     name:     '_http._tcp.local',
 *     instance: 'My Server',
 *     port:     3000,
 *     txt:      { version: '1.0' }
 * });
 *
 * announcer.addTxt('env', 'production');
 *
 * await announcer.announce();
 *
 * process.on('SIGINT', async () => {
 *     await announcer.goodbye();
 *     await announcer.destroy();
 * });
 * ```
 */
declare class DnsSdAnnouncer {
    constructor(params: AnnouncerParams);

    /**
     * Adds or updates a TXT record entry.
     * The value is coerced to a string.
     * Chainable.
     *
     * @param key   - Non-empty string key.
     * @param value - Value coerced to string.
     * @throws {Error} When key is empty or not a string.
     *
     * @example
     * ```typescript
     * announcer
     *     .addTxt('env', 'production')
     *     .addTxt('version', 2);
     * ```
     */
    addTxt(key: string, value: string | number | boolean): this;

    /**
     * Removes a TXT record entry.
     * No-op if the key does not exist.
     * Chainable.
     *
     * @param key - Key to remove.
     *
     * @example
     * ```typescript
     * announcer.removeTxt('debug');
     * ```
     */
    removeTxt(key: string): this;

    /**
     * Builds and sends the mDNS announcement to the multicast network.
     *
     * Per RFC 6762 §8.3, calling this twice with a 1-second delay between
     * calls improves reliability on lossy networks.
     *
     * @example
     * ```typescript
     * await announcer.announce();
     * await new Promise(r => setTimeout(r, 1000));
     * await announcer.announce();
     * ```
     */
    announce(): Promise<void>;

    /**
     * Sends a goodbye packet (all TTLs = 0) to remove this service from
     * the caches of other devices on the network (RFC 6762 §11).
     *
     * Should be called before `destroy()` when shutting down gracefully.
     */
    goodbye(): Promise<void>;

    /**
     * Closes the underlying UDP socket and releases all resources.
     * The announcer cannot be used after this call.
     */
    destroy(): Promise<void>;
}

export default DnsSdAnnouncer;
