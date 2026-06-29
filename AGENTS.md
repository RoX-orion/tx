# Agent Context

## Language

- Use Chinese when answering the user.

## Project Overview

- This repository is a C++14 proxy/tunnel project.
- It builds two main applications:
  - `tx_client`: local client that starts HTTP and SOCKS5 proxy listeners.
  - `tx_server`: remote server that receives encrypted client tunnel connections and proxies traffic.
- The client and server exchange traffic over TCP.
- Client/server connections are not multiplexed; each proxied connection uses a separate tunnel connection.
- The server proxies all traffic received from the client.

## Routing Requirements

- The client routes requests by GeoIP and GeoSite rules.
- LAN and mainland China traffic should go direct.
- Other traffic should go through the remote proxy.
- GeoIP matching is intended to use a compressed Radix Tree.
- GeoSite matching is intended to use Reverse Trie + Aho-Corasick and Double Array Trie where appropriate.
- Geo data files should be loaded with `mmap` where feasible.

## Transport Security Model

- The old shared `password` deployment model has been replaced as the primary path.
- The current tunnel authentication and key agreement model is:
  - High-entropy shared PSK from config `secret`.
  - X25519/ECDHE handshake for forward secrecy.
  - HKDF-SHA256 to derive per-connection traffic keys.
  - Separate client-to-server and server-to-client AEAD keys.
  - Per-direction nonce prefixes plus monotonically increasing sequence numbers.
  - AEAD AAD includes sequence, direction, version, cipher, and frame length.
- Handshake protocol version is the newer `TXH2` path.
- Authentication failures should close silently without verbose protocol hints.

## Cipher Support

- Supported AEAD ciphers:
  - `aes-256-gcm`
  - `chacha20-poly1305`
- `aes-256-gcm` remains the default.
- `chacha20-poly1305` is available for Android or systems without efficient AES acceleration.

## Configuration Requirements

- Client and server should use `secret`, not `password`.
- Supported `secret` encodings:
  - `base64:...`
  - `hex:...`
  - `uuid-v4:...`
- Preferred deployment format is a 32-byte randomly generated `base64:` secret.
- Client config also supports `server.cipher`; server config supports `cipher`.
- The client and server must use the same `secret` and `cipher`.
- `tx_client --gen-secret` and `tx_server --gen-secret` both generate the same kind of 32-byte random base64 PSK. Either binary can be used to generate the secret once; both sides must then share that same generated value.

## Build Requirements

- The project uses CMake.
- Minimum CMake version is `3.25.1`.
- Dependencies should be linked statically where practical.
- Target platforms:
  - Linux executables.
  - Windows executables.
  - Android library.
- Android builds should produce a shared library suitable for app/JNI integration while statically linking third-party dependencies where practical.

## Current Repository Notes

- Current top-level build files already use CMake minimum version `3.25.1`.
- The repository contains `geoip.dat` and `geosite.dat` data files.
- Be careful with existing working tree changes. Early initialization noted these files as already changed or untracked:
  - `config/client.json.example`
  - `CMakePresets.json`
  - `geoip.dat`
  - `geosite.dat`
- A later security update introduced local, still-uncommitted changes in tunnel/config/test files and new crypto helper files. Do not revert them unless explicitly asked.

## Verification Notes

- The updated transport security model was validated in the local dynamic build tree:
  - `cmake --build build-local-dyn -j8`
  - `ctest --test-dir build-local-dyn --output-on-failure`
- The static Linux preset may still depend on availability of static OpenSSL libraries in the host environment.

## Engineering Preferences

- Prefer existing project patterns and interfaces.
- Keep changes focused on the requested behavior.
- Do not revert user changes unless explicitly asked.
- Use `rg` for code search where possible.
- Use C++14-compatible code.
- Maintain cross-platform behavior for Linux, Windows, and Android when touching shared code.
