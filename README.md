# F5 iRules for JA4+ Network Fingerprinting

F5 iRules for generating JA4+ fingerprints.  iRules for JA4, JA4S, JA4X, JA4H, JA4L, and JA4T are provided (JA4X is produced together with JA4S by the combined `ja4s_x.irule` — see [iRules in this repository](#irules-in-this-repository)).  More JA4+ fingerprint iRules *MAY* be added in the future.

> [!WARNING]
>DISCLAIMER: These iRules are provided as-is with no guarantee of performance or functionality.  Use at your own risk.
>These iRules have been tested on F5 BIGIPs running TMOS versions 16.1 and 17.1.
 

## iRules in this repository

| iRule | Fingerprint(s) | TLS/HTTP data used | BIG-IP event(s) |
|---|---|---|---|
| `ja4.irule` | JA4 | TLS ClientHello | `CLIENT_DATA` |
| `ja4s.irule` | JA4S | TLS ServerHello | `SERVER_DATA` |
| `ja4s_x.irule` | JA4S **and** JA4X | TLS ServerHello + server X.509 certificate | `SERVER_DATA` |
| `ja4h.irule` | JA4H | HTTP request | `HTTP_REQUEST` |
| `ja4l.irule` | JA4L (light distance) | TLS handshake timing | `FLOW_INIT`, `CLIENTSSL_*` |
| `ja4t.irule` | JA4T | TCP SYN options | `FLOW_INIT` (`DATAGRAM::tcp`) |

Each `.irule` file is self-contained and deployed directly to a BIG-IP virtual server (Local Traffic > iRules, or via the iControl REST API).  There is no build step.

### Why JA4S and JA4X are combined into a single iRule

JA4S (computed from the ServerHello) and JA4X (computed from the server's X.509 certificate) are both derived from the server side of the TLS handshake, and both rely on `TCP::collect` in the `SERVER_CONNECTED` event to buffer the raw server payload for parsing.

On BIG-IP, a `TCP::collect` issued in `SERVER_CONNECTED` only takes effect for **whichever iRule calls it last**.  If two separate iRules on the same virtual server each call `TCP::collect` in `SERVER_CONNECTED`, they clobber one another and only one of them receives the buffered `SERVER_DATA` — so running independent JA4S and JA4X rules together does not work.

`ja4s_x.irule` resolves this by performing a **single** `TCP::collect` and parsing **both** handshake messages out of the one buffered payload: the ServerHello record yields JA4S, and the Certificate record yields JA4X (JA4X is computed from the leaf certificate; it is not produced on resumed sessions, which send no certificate).

- Use **`ja4s.irule`** if you only need JA4S.
- Use **`ja4s_x.irule`** if you need JA4S *and* JA4X.
- Do **not** attach both `ja4s.irule` and `ja4s_x.irule` to the same virtual server.

## What is JA4+ Network Fingerprinting?

From the [FoxIO JA4+ Repo](https://github.com/FoxIO-LLC/ja4):
>JA4+ is a suite of network fingerprinting methods that are easy to use and easy to share. These methods are both human >and machine readable to facilitate more effective threat-hunting and analysis. The use-cases for these fingerprints >include scanning for threat actors, malware detection, session hijacking prevention, compliance automation, location >tracking, DDoS detection, grouping of threat actors, reverse shell detection, and many more.

Please read this blog post for more details: [JA4+ Network Fingerprinting](https://medium.com/foxio/ja4-network-fingerprinting-9376fe9ca637)

To understand how to read JA4+ fingerprints, see [Technical Details](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/README.md)

## JA4+ Licensing

> [!IMPORTANT]
>**JA4 TLS Client Fingerprinting is licensed under BSD 3-Clause**
>
>_Copyright (c) 2024, FoxIO_
>_All rights reserved.
>JA4 TLS Client Fingerprinting is Open-Source, Licensed under BSD 3-Clause.
>For full license text and more details, see the repo root https://github.com/FoxIO-LLC/ja4_
>
>
>**All other JA4+ Fingerprints are under the FoxIO License 1.1**
>
>_Copyright (c) 2024, FoxIO, LLC.
>All rights reserved.
>Licensed under FoxIO License 1.1
>For full license text and more details, see the repo root https://github.com/FoxIO-LLC/ja4_

## How to Use

**Coming Soon**