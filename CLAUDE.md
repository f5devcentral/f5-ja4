# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Repo Is

F5 BIG-IP iRules (written in TCL) that compute JA4+ network fingerprints. Each `.irule` file is a self-contained, standalone rule deployed directly to a BIG-IP virtual server — there is no build system, package manager, or test framework.

Tested on TMOS 16.1 and 17.1.

## Deployment

iRules are deployed via the BIG-IP management UI (Local Traffic > iRules) or via iControl REST API. There is no local build or deploy command.

## Fingerprint Files

| File | Fingerprint | Event model |
|---|---|---|
| `ja4.irule` | JA4 — TLS Client | Raw TCP (`CLIENT_DATA`), manual `binary scan` of ClientHello |
| `ja4s.irule` | JA4S — TLS Server | Raw TCP (`SERVER_DATA`) + `proc parseServerHello` |
| `ja4h.irule` | JA4H — HTTP Request | `HTTP_REQUEST` event; outputs `X-JA4H` / `X-JA4H_r` headers |
| `ja4l.irule` | JA4L — Light Distance | Timing via `clock clicks` across `FLOW_INIT`, `CLIENTSSL_*`; outputs `X-JA4L` header |
| `ja4t.irule` | JA4T — TCP Fingerprint | `FLOW_INIT` + `DATAGRAM::tcp`; optional blocking via data group |

## Architecture Patterns

**Event lifecycle per iRule:**
- `RULE_INIT` — sets `static::` vars (caps, limits, defaults)
- `FLOW_INIT` / `CLIENT_ACCEPTED` / `SERVER_CONNECTED` — unset stale vars, begin collection
- Data events — parse payload, compute fingerprint
- `HTTP_REQUEST` — strip client-supplied `X-JA4*` headers (anti-spoofing), insert computed header

**Raw TLS parsing (`ja4.irule`, `ja4s.irule`):**
- `TCP::collect` buffers the full record before parsing
- `binary scan` with explicit offsets (`@${off}`) reads fields
- All lengths masked to unsigned: `& 0xff` (byte), `& 0xffff` (short)
- Iteration limits (`ja4_max_iter 256`) and record size limits (`ja4_max_record 17408`) guard every loop
- GREASE values filtered by pattern: `($val & 0x0f0f) == 0x0a0a && high_byte == low_byte`

**Fingerprint output:**
- `ja4.irule` / `ja4s.irule`: `log local0.` only (no HTTP header insertion)
- `ja4h.irule`, `ja4l.irule`, `ja4t.irule`: insert `X-JA4*` HTTP headers; strip any client-supplied headers of the same name first
- JA4H exposes a `ja4h_raw` flag (set in `CLIENT_ACCEPTED`) to enable the `X-JA4H_r` raw header; cookie key=value pairs are intentionally excluded from the raw header to avoid leaking session tokens

**Hashing:** BIG-IP's built-in `sha256` command is used; first 12 hex chars of the hash form each fingerprint segment.

**JA4T blocking:** `ja4t.irule` supports connection dropping via a BIG-IP data group named in `$ja4t_blocklist`. Blocking is off by default (`ja4t_blocking 0`).
