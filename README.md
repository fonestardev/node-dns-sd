# 📡 node-dns-sd

[![CI](https://github.com/fonestardev/node-dns-sd/actions/workflows/ci.yml/badge.svg)](https://github.com/fonestardev/node-dns-sd/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@fonestardev/node-dns-sd.svg)](https://github.com/fonestardev/node-dns-sd/packages)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org/)

> 🔍 A pure JavaScript implementation of mDNS/DNS-SD (Apple Bonjour) browser and packet parser for Node.js

The **node-dns-sd** module allows you to discover devices and services on your local network using mDNS/DNS-SD protocol. Specify a service name like `_http._tcp.local` and find all matching devices with their IPv4 addresses.

## ✨ Features

- 🔎 **Service Discovery** - Find devices by service name (Chromecast, AirPlay, printers, etc.)
- 🏠 **Localhost Discovery** - Discover services running on the same machine
- 📊 **Packet Monitoring** - Watch and parse all mDNS/DNS-SD traffic
- 🔒 **Security Hardened** - Protection against DNS pointer loops and buffer overflows
- 📝 **TypeScript Support** - Full type definitions included
- ⚡ **Promise-based API** - Modern async/await support
- 🎯 **Filtering** - String or function-based device filtering

---

## 📦 Installation

### From GitHub Packages

```bash
npm install @fonestardev/node-dns-sd
```

### From Source

```bash
git clone https://github.com/fonestardev/node-dns-sd.git
cd node-dns-sd
npm install
```

---

## 📋 Requirements

- 📌 **Node.js** 18.x or higher
- 🖥️ Network interface with multicast support

---

## 📚 Table of Contents

- [🚀 Quick Start](#-quick-start)
  - [Discover Devices](#discover-devices)
  - [Discover Localhost Services](#discover-localhost-services)
  - [Monitor Packets](#monitor-packets)
- [📖 API Reference](#-api-reference)
  - [discover()](#discover-method)
  - [startMonitoring()](#startmonitoring-method)
  - [stopMonitoring()](#stopmonitoring-method)
  - [ondata Event](#ondata-event-handler)
- [📦 DnsSdPacket Object](#-dnspacket-object)
- [🔷 TypeScript](#-typescript)
- [🧪 Testing](#-testing)
- [📝 Release Notes](#-release-notes)
- [📚 References](#-references)
- [📄 License](#-license)

---

## 🚀 Quick Start

### Discover Devices

```javascript
const dnssd = require('@fonestardev/node-dns-sd');

// Discover Google Cast devices
dnssd.discover({
  name: '_googlecast._tcp.local'
}).then((devices) => {
  console.log(JSON.stringify(devices, null, 2));
}).catch((error) => {
  console.error(error);
});
```

**Output:**
```json
[
  {
    "address": "192.168.1.20",
    "fqdn": "Chromecast-abc123._googlecast._tcp.local",
    "modelName": "Chromecast",
    "familyName": "Living Room TV",
    "service": {
      "port": 8009,
      "protocol": "tcp",
      "type": "googlecast"
    },
    "packet": {...}
  }
]
```

### Discover Localhost Services

🆕 **New Feature!** Discover services running on the same machine:

```javascript
const dnssd = require('@fonestardev/node-dns-sd');

// Enable localhost discovery
dnssd.discover({
  name: '_http._tcp.local',
  localhost: true  // 👈 Enable local machine discovery
}).then((devices) => {
  console.log('Found devices (including localhost):');
  devices.forEach(device => {
    console.log(`  ${device.address}: ${device.fqdn}`);
  });
});
```

### Monitor Packets

```javascript
const dnssd = require('@fonestardev/node-dns-sd');

// Set up packet handler
dnssd.ondata = (packet) => {
  const type = packet.header.qr === 0 ? '❓ Query' : '✅ Response';
  console.log(`${type} from ${packet.address}`);
};

// Start monitoring
dnssd.startMonitoring().then(() => {
  console.log('🎧 Monitoring mDNS traffic...');
});

// Stop with: dnssd.stopMonitoring()
```

---

## 📖 API Reference

### `discover()` method

Discovers devices/services on the local network. Returns a `Promise<DiscoveredDevice[]>`.

```javascript
dnssd.discover(params)
```

#### Parameters

| Property | Type | Required | Description |
|:---------|:-----|:---------|:------------|
| `name` | String \| String[] | ✅ | Service name(s). Example: `"_http._tcp.local"` |
| `type` | String | ❌ | Query type (`"PTR"`, `"A"`, etc.). Default: `"*"` |
| `key` | String | ❌ | Deduplication key: `"address"` (default) or `"fqdn"` |
| `wait` | Integer | ❌ | Discovery duration in seconds. Default: `3` |
| `quick` | Boolean | ❌ | Return immediately on first match. Default: `false` |
| `filter` | String \| Function | ❌ | Filter devices by string match or custom function |
| `localhost` | Boolean | ❌ | 🆕 Include services on local machine. Default: `false` |

#### Common Service Names

| Service | Name |
|:--------|:-----|
| 🎬 Chromecast | `_googlecast._tcp.local` |
| 📺 AirPlay | `_airplay._tcp.local` |
| 🖨️ Printers | `_printer._tcp.local` |
| 🌐 HTTP Servers | `_http._tcp.local` |
| 🔐 SSH | `_ssh._tcp.local` |
| 🏠 HomeKit | `_hap._tcp.local` |
| 📁 SMB Shares | `_smb._tcp.local` |

#### Examples

**Filter by string:**
```javascript
dnssd.discover({
  name: '_googlecast._tcp.local',
  filter: 'Living Room'
});
```

**Filter by function:**
```javascript
dnssd.discover({
  name: '_http._tcp.local',
  filter: (device) => device.service?.port === 80
});
```

**Discover multiple services:**
```javascript
dnssd.discover({
  name: ['_http._tcp.local', '_https._tcp.local'],
  wait: 5
});
```

**Quick discovery (return first match):**
```javascript
dnssd.discover({
  name: '_airplay._tcp.local',
  quick: true
});
```

#### Response Object

| Property | Type | Description |
|:---------|:-----|:------------|
| `address` | String | IPv4 address |
| `fqdn` | String | Fully Qualified Domain Name |
| `modelName` | String | Device model name |
| `familyName` | String | Device friendly name |
| `service` | Object | Service info (`port`, `protocol`, `type`) |
| `packet` | DnsSdPacket | Raw mDNS packet |

---

### `startMonitoring()` method

Starts listening to all mDNS/DNS-SD packets on the network.

```javascript
dnssd.ondata = (packet) => {
  console.log('Received packet from:', packet.address);
};

await dnssd.startMonitoring();
```

---

### `stopMonitoring()` method

Stops the monitoring mode.

```javascript
await dnssd.stopMonitoring();
```

---

### `ondata` event handler

Callback function invoked for each received mDNS packet during monitoring.

```javascript
dnssd.ondata = (packet) => {
  // packet is a DnsSdPacket object
  console.log(packet.header);
  console.log(packet.answers);
};
```

---

## 📦 DnsSdPacket Object

The packet object contains parsed mDNS/DNS-SD data:

```javascript
{
  "header": {
    "id": 0,
    "qr": 1,        // 0 = Query, 1 = Response
    "op": 0,
    "aa": 1,
    "tc": 0,
    "rd": 0,
    "ra": 0,
    "questions": 0,
    "answers": 1,
    "authorities": 0,
    "additionals": 3
  },
  "questions": [...],
  "answers": [
    {
      "name": "_googlecast._tcp.local",
      "type": "PTR",
      "class": "IN",
      "flash": false,
      "ttl": 120,
      "rdata": "Device-Name._googlecast._tcp.local"
    }
  ],
  "authorities": [...],
  "additionals": [...],
  "address": "192.168.1.100"
}
```

---

## 🔷 TypeScript

Full TypeScript support is included. Import types directly:

```typescript
import dnssd, {
  DiscoverParams,
  DiscoveredDevice,
  DnsPacket,
  ServiceInfo
} from '@fonestardev/node-dns-sd';

const params: DiscoverParams = {
  name: '_http._tcp.local',
  localhost: true,
  wait: 5
};

const devices: DiscoveredDevice[] = await dnssd.discover(params);

devices.forEach((device: DiscoveredDevice) => {
  console.log(`Found: ${device.address}`);
});
```

---

## 🧪 Testing

```bash
# Run all tests
npm test

# Watch mode
npm run test:watch

# Run examples
npm run example:basic
npm run example:localhost
npm run example:filter
npm run example:monitor
```

---

## 📝 Release Notes

### v2.0.1 (2024)
- 🆕 Added `localhost` parameter to discover services on local machine
- 🔒 Security fixes for DNS pointer loop attacks
- 🔒 Buffer bounds checking to prevent overflows
- 🔒 Label length validation (RFC 1035 compliance)
- 📝 Added TypeScript type definitions
- 🧪 Added comprehensive unit tests (76 tests)
- 📚 Added usage examples

### v1.0.1 (2023-04-05)
- Fixed the constant variable issue

### v1.0.0 (2023-03-11)
- Rewrote all codes in modern style using `class`, `async`, `await`
- Supported multi-homed environment

### v0.4.2 (2020-09-30)
- Catch dropMembership error

### v0.4.1 (2020-04-09)
- Fix address already in use on udp.addMembership

### v0.4.0 (2019-02-24)
- Added `rdata_buffer` property for TXT records

### v0.3.0 (2018-10-25)
- Added `key` and `type` parameters to discover()

<details>
<summary>📜 Older versions</summary>

### v0.2.1 (2018-10-24)
- Improved device discovery with multi-interface support

### v0.2.0 (2018-08-02)
- Added function-based filtering

### v0.1.2 (2018-01-06)
- Fixed filter exception bug

### v0.1.0 (2018-01-06)
- Added `quick` and `filter` parameters

### v0.0.1 (2018-01-05)
- First public release

</details>

---

## 📚 References

- 📄 [RFC 1035 - Domain Names Implementation](https://tools.ietf.org/html/rfc1035)
- 📄 [RFC 6762 - Multicast DNS](https://tools.ietf.org/html/rfc6762)
- 📄 [RFC 6763 - DNS-Based Service Discovery](https://tools.ietf.org/html/rfc6763)
- 📄 [RFC 2782 - DNS SRV Records](https://tools.ietf.org/html/rfc2782)

---

## 📄 License

The MIT License (MIT)

Copyright (c) 2018-2023 Futomi Hatano
Copyright (c) 2024 Fonestar Dev

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
