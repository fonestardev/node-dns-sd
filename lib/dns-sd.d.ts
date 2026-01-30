/* ------------------------------------------------------------------
 * node-dns-sd - TypeScript Type Declarations
 *
 * Copyright (c) 2018 - 2023, Futomi Hatano, All rights reserved.
 * Released under the MIT license
 * ---------------------------------------------------------------- */

/// <reference types="node" />

/**
 * Parameters for the discover() method
 */
export interface DiscoverParams {
    /**
     * Service name(s) to discover.
     * @example "_http._tcp.local"
     * @example ["_http._tcp.local", "_https._tcp.local"]
     */
    name: string | string[];

    /**
     * Query type (e.g., "PTR", "A", "AAAA", "SRV", "TXT").
     * Default is "*" (ANY).
     */
    type?: string;

    /**
     * Deduplication key mode.
     * - "address": IP address based discovery (default)
     * - "fqdn": FQDN (service) based discovery
     */
    key?: 'address' | 'fqdn';

    /**
     * Duration of discovery in seconds.
     * Default is 3 seconds.
     */
    wait?: number;

    /**
     * If true, returns immediately after the first device is found.
     * Default is false.
     */
    quick?: boolean;

    /**
     * Filter for discovered devices.
     * - String: matches against fqdn, address, modelName, or familyName
     * - Function: custom filter returning true to include device
     */
    filter?: string | ((device: DiscoveredDevice) => boolean);

    /**
     * If true, also discovers services running on the local machine.
     * Default is false.
     */
    localhost?: boolean;
}

/**
 * Service information extracted from mDNS response
 */
export interface ServiceInfo {
    /** Service port number */
    port: number;
    /** Service protocol (e.g., "tcp", "udp") */
    protocol: string;
    /** Service type (e.g., "http", "https") */
    type: string;
}

/**
 * SRV record data
 */
export interface SrvRdata {
    /** Priority of this target host */
    priority: number;
    /** Weight for load balancing */
    weight: number;
    /** Port number */
    port: number;
    /** Target hostname */
    target: string | null;
}

/**
 * HINFO record data
 */
export interface HinfoRdata {
    /** CPU type */
    cpu?: string;
    /** Operating system */
    os?: string;
}

/**
 * DNS resource record from mDNS packet
 */
export interface DnsRecord {
    /** Domain name */
    name: string;
    /** Record type (A, AAAA, PTR, TXT, SRV, etc.) */
    type: string;
    /** Record class (usually "IN") */
    class: string;
    /** Cache flush flag */
    flash?: boolean;
    /** Time to live in seconds */
    ttl?: number;
    /**
     * Record data - type depends on record type:
     * - A: IPv4 address string (e.g., "192.168.1.1")
     * - AAAA: IPv6 address string
     * - PTR: domain name string
     * - TXT: key-value object
     * - SRV: SrvRdata object
     * - HINFO: HinfoRdata object
     * - Other: hex string
     */
    rdata?: string | Record<string, string> | SrvRdata | HinfoRdata;
    /** Raw TXT record data as Buffer (when available) */
    rdata_buffer?: Record<string, Buffer>;
}

/**
 * DNS packet header
 */
export interface DnsHeader {
    /** Transaction ID */
    id: number;
    /** Query/Response flag: 0 = Query, 1 = Response */
    qr: number;
    /** Opcode: 0 = Standard query */
    op: number;
    /** Authoritative Answer flag */
    aa: number;
    /** Truncation flag */
    tc: number;
    /** Recursion Desired flag */
    rd: number;
    /** Recursion Available flag */
    ra: number;
    /** Reserved (zero) */
    z: number;
    /** Authenticated Data flag */
    ad: number;
    /** Checking Disabled flag */
    cd: number;
    /** Response code */
    rc: number;
    /** Number of questions */
    questions: number;
    /** Number of answer records */
    answers: number;
    /** Number of authority records */
    authorities: number;
    /** Number of additional records */
    additionals: number;
}

/**
 * Raw mDNS packet structure
 */
export interface DnsPacket {
    /** Packet header */
    header: DnsHeader;
    /** Question records */
    questions: DnsRecord[];
    /** Answer records */
    answers: DnsRecord[];
    /** Authority records */
    authorities: DnsRecord[];
    /** Additional records */
    additionals: DnsRecord[];
    /** Source IP address of the packet */
    address?: string;
}

/**
 * Device discovered via mDNS/DNS-SD
 */
export interface DiscoveredDevice {
    /** IPv4 address of the device */
    address: string | null;
    /** Fully Qualified Domain Name */
    fqdn: string | null;
    /** Model name (e.g., "Apple TV", "Chromecast") */
    modelName: string | null;
    /** Family/friendly name */
    familyName: string | null;
    /** Service information (port, protocol, type) */
    service: ServiceInfo | null;
    /** Raw mDNS packet */
    packet: DnsPacket;
}

/**
 * DNS-SD (mDNS) service discovery module
 */
interface DnsSd {
    /**
     * Callback function for monitoring mode.
     * Called when an mDNS packet is received.
     */
    ondata: (packet: DnsPacket) => void;

    /**
     * Discover devices/services on the local network using mDNS/DNS-SD.
     *
     * @param params - Discovery parameters
     * @returns Promise resolving to array of discovered devices
     *
     * @example
     * ```typescript
     * const devices = await dnssd.discover({
     *     name: '_http._tcp.local',
     *     wait: 5,
     *     localhost: true
     * });
     * ```
     */
    discover(params: DiscoverParams): Promise<DiscoveredDevice[]>;

    /**
     * Start monitoring all mDNS traffic on the network.
     * Packets will be delivered via the ondata callback.
     *
     * @example
     * ```typescript
     * dnssd.ondata = (packet) => {
     *     console.log('Received packet from:', packet.address);
     * };
     * await dnssd.startMonitoring();
     * ```
     */
    startMonitoring(): Promise<void>;

    /**
     * Stop monitoring mDNS traffic.
     */
    stopMonitoring(): Promise<void>;
}

declare const dnssd: DnsSd;
export default dnssd;
