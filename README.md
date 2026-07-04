# F5 iRules for JA4+ Network Fingerprinting

F5 iRules for generating JA4+ fingerprints.  iRules for JA4, JA4S, JA4X, JA4H, JA4L, and JA4T are provided (JA4X is produced together with JA4S by the combined `ja4s_x.irule` — see [iRules in this repository](#irules-in-this-repository)).  More JA4+ fingerprint iRules *MAY* be added in the future.

> [!WARNING]
>DISCLAIMER: These iRules are provided as-is with no guarantee of performance or functionality.  Use at your own risk.
>These iRules have been tested on F5 BIGIPs running TMOS versions 16.1, 17.1, 17.5, and 21.1.
 

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

## Security considerations

These points are about how JA4+ fingerprints can and cannot be used safely as a security control. They are properties of the JA4+ methods (and of the BIG-IP TCP/TLS stack), not defects in these iRules.

### Treat JA4/JA4S/JA4T as a reputation signal, not an authenticator

Every field of JA4 (from the ClientHello), JA4S (from the ServerHello) and JA4T (from the TCP SYN) is derived entirely from bytes the remote peer controls. Consequently:

- **A denylist is evadable.** A peer that fully controls its handshake can add or drop a real cipher/extension, add a TCP NOP option, reorder options, or nudge its advertised window — changing its fingerprint while keeping a working connection — to move off an exact-match blocklist entry. (These iRules already neutralise the *cheap* evasions JA4 is designed to resist: JA4 sorts ciphers/extensions and filters GREASE, so mere reordering or GREASE injection does **not** change the fingerprint.)
- **An allowlist / authenticator is impersonatable.** Because each fingerprint is a deterministic function of peer-controlled bytes, an attacker can replay a target client's cipher/extension set (or a target stack's SYN options) and reproduce that JA4/JA4T byte-for-byte.

Use these fingerprints for correlation, threat-hunting, and reputation/risk scoring in combination with other signals — **not** as a standalone allow/deny decision or as proof of identity.

### JA4T blocking and blocklist sourcing

`ja4t.irule` can optionally drop connections whose JA4T matches a BIG-IP data group (`ja4t_blocking` is **off by default**; blocking uses an exact `class match ... equals`). Two things to know before relying on it:

- **Source the blocklist from this iRule's own JA4T output.** `[DATAGRAM::tcp option]` on BIG-IP does not return TCP option kind `0` (End-of-Option-List / EOL), so for a SYN that carries an explicit EOL this iRule computes a JA4T that differs from one produced by a spec-compliant, EOL-counting tool (FoxIO/Wireshark/Zeek/tcpdump-based tooling). A blocklist entry taken from such a tool may therefore never match (the block silently fails open for that entry). Build the blocklist from values these iRules log, or from a parser that also omits EOL. (The same class of cross-tool difference applies to duplicate MSS/window-scale options and to the 32-option cap.)
- **Blocking fails open by design.** If `ja4t_blocking` is enabled but the data group is missing, connections are forwarded (an unavailable blocklist should not black-hole all traffic). Ensure the data group exists and is a *string* class populated with JA4T values.

### Anti-spoofing of `X-JA4*` headers

`ja4h.irule` and `ja4_http_header_injector.irule` strip any client-supplied `X-JA4*` request header (prefix match) before (re)inserting the values computed on the BIG-IP, so a client cannot spoof the fingerprint a backend sees. If you consume these headers on the pool member, make sure the traffic reaches the backend **through** the injector (or the fingerprint rules), and do not trust `X-JA4*` headers arriving from any path that bypasses them.

## How to Use

**Coming Soon**