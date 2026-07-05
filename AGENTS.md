# Repository Guidelines

## Project Overview
- `tx` is a C++14 proxy/tunnel project built with CMake.
- Main binaries are `tx_client` and `tx_server`.
- Core code is organized under `src/` with public headers under `include/tx/`.
- Major modules:
  - `crypto`: AES-GCM encryption and key derivation.
  - `protocol`: SOCKS5, HTTP proxy, and tunnel protocol handling.
  - `router`: routing decisions.
  - `geo`: GeoIP/GeoSite parsing and lookup structures.
  - `net`: TCP server and buffer utilities.
  - `client` / `server`: executable apps and config parsing.

## Build And Run
Use an out-of-tree build:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Run examples:

```sh
./build/bin/tx_server -c config/server.json.example
./build/bin/tx_client -c config/client.json.example
```

Tests are enabled by default when not building for Android:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DTX_BUILD_TESTS=ON
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
```

## Dependencies
- CMake 3.25.1+
- C++14 compiler
- OpenSSL
- libuv
- nlohmann_json

The top-level `CMakeLists.txt` expects helper modules `cmake/TxUtils.cmake` and `cmake/FetchDeps.cmake`. At initialization time this repository did not contain a `cmake/` directory, so a clean CMake configure may fail until those files are restored or the dependency setup is adjusted.

## Tests
- Test files live in `tests/` and use simple `assert`-based executables.
- `tests/CMakeLists.txt` currently registers `crypto`, `geoip`, `geosite`, `socks5`, `http_proxy`, `router`, and `tunnel`.
- At initialization time `tests/test_tunnel.cpp` was not present, while `tests/CMakeLists.txt` still referenced it. Expect configure/build failures unless that test is added or the registration is removed.

## Coding Conventions
- Keep public APIs in `include/tx/...` and implementations in matching `src/...` modules.
- Code is namespaced under `tx`.
- Prefer the existing small, direct C++14 style. Avoid broad refactors unless the task requires them.
- Existing tests use `printf` and `assert`; match that style for focused unit coverage.
- Preserve platform conditionals already present in CMake and source code.

## Workflow Notes
- Use `rg` / `rg --files` for search.
- Do not edit generated build output under `build/` or `cmake-build-debug/` unless explicitly requested.
- Treat `config/*.example` as examples; avoid putting real secrets in them.

## Current Architecture Notes
- The client configuration has moved to an `outbounds` + `routing.rules` model.
- `routing.rules` is evaluated from top to bottom. The last rule is the fallback when no prior matcher applies.
- `routing.rules[*].outboundTag` is only a reference to an outbound tag. Do not collapse it into a direct/proxy/block decision inside the router.
- Actual behavior is defined by `outbounds[*]`:
  - `type: "direct"` connects directly.
  - `type: "tx"` connects through a TX encrypted tunnel using that outbound's `server` settings.
  - `type: "block"` rejects TCP connections or drops UDP packets.
- Old client config fields such as top-level `server`, `geo.direct_geoip`, and `geo.direct_geosite` are intentionally unsupported.
- Default Android routing should keep private IPs first, for example `{"ip":["geoip:private"],"outboundTag":"direct-out"}`, so LAN targets such as `192.168.0.1` do not go through the remote tunnel.
- In Android TUN mode, traffic currently flows through tun2socks into the local SOCKS5 inbound. Domain rules only work when the SOCKS5 request carries a domain or when future fake-IP reverse mapping is added; otherwise routing falls back to IP rules.

## UDP / QUIC Status
- SOCKS5 `UDP ASSOCIATE` is supported.
- The tunnel protocol includes `TunnelCmd::UdpPacket`.
- `tx_client` forwards SOCKS5 UDP packets through a shared UDP TX tunnel.
- `tx_server` sends UDP packets to targets and returns responses through the tunnel.
- UDP routed to a `tx` outbound is proxied. UDP routed to `block` is dropped. Direct UDP relay is not implemented yet, so UDP routed to `direct` is currently dropped with a warning.

## Android Build Context
- Android project path: `/mnt/f/program/android/txz`.
- Android NDK path: `/home/andre/Android/android-ndk-r29`.
- Android OpenSSL path: `/mnt/f/DevEnv/AndroidSDK/android_openssl/ssl_3`.
- Existing Android CMake build directory: `build-android-arm64-r29`.
- Build the Android native library with:

```sh
cmake --build build-android-arm64-r29 -j$(nproc)
```

- Copy the library into the Android project with:

```sh
cp build-android-arm64-r29/lib/libtx.so \
  /mnt/f/program/android/txz/app/src/main/jniLibs/arm64-v8a/libtx.so
```

- If writing to `/mnt/f/...` is blocked by sandboxing, request escalation rather than using generated build output as a workaround.
