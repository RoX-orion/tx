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
  - `net`: TCP stream abstraction、DNS/fake-IP、lwIP TUN 和流量回收设施。
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
- OpenSSL and the C++ runtime are intentionally linked dynamically on all platforms.
- `OPENSSL_ROOT_DIR` is optional and should only be passed when OpenSSL is installed outside the platform's normal search paths.

The top-level `CMakeLists.txt` uses `cmake/TxUtils.cmake` and `cmake/FetchDeps.cmake`; a clean configure can fetch libuv、nlohmann_json 和 HEV lwIP into `.deps/` when `TX_FETCH_DEPS=ON`.

## Tests
- Test files live in `tests/` and use simple `assert`-based executables.
- `tests/CMakeLists.txt` currently registers 17 个测试：`crypto`、`geoip`、`geosite`、`socks5`、`http_proxy`、`router`、`tunnel`、`tun_packet`、`lwip_udp_stack`、`lwip_tcp_stack`、`fake_ip_dns`、`dns_resolver`、`tls_sni`、`socket_protector`、`tcp_session_callbacks`、`udp_flow_timeout` 和 `client_config`。

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
- 原生 lwIP TUN 路径会用 fake-IP 反向映射和 TLS SNI 恢复域名，再按 `AsIs` 规则路由。HTTP/SOCKS5 监听器在 `tun.auto_redirect=false` 时仍会保留，因此 tun2socks 是可选兼容路径，而不是 Android 的唯一数据面。

## Native TUN Status
- Client config now has a `tun` section with fields such as `enabled`, `fd`, `name`, `address` / `addresses`, `mtu`, `auto_config`, `auto_route`, `auto_redirect`, `redirect_port`, `redirect_mark`, `bypass_mark`, `route_table`, `rule_priority`, `routes`, `mode`, `tcp_stack`, and `udp_stack`.
- `tun.mode` is deprecated. The default native mode is `tcp_stack: "lwip"` plus `udp_stack: "lwip"`; `udp_stack` currently must be `lwip`. `tcp_stack: "system"` is Linux-only and is intended for the transparent-redirect path.
- `tx_client_start_with_tun_fd()` exists for Android `VpnService` integration. Android supplies the TUN fd externally; Android native code does not open `/dev/net/tun`.
- `include/tx/net/tun_packet.h` and `src/net/tun_packet.cpp` parse IPv4/IPv6 TUN packets; `LwipUdpStack` additionally exposes the lwIP TCP stream bridge. `tests/test_tun_packet.cpp` covers IPv4/IPv6 UDP roundtrips, while `test_lwip_tcp_stack` / `test_lwip_udp_stack` cover the data plane.
- Native TUN TCP and UDP are both routed through the same direct / TX tunnel / block decision model as HTTP/SOCKS. TCP bridging preserves half-close and applies bounded write backpressure.
- fake-IP DNS handles UDP/TCP A and AAAA locally, retains bounded stable forward/reverse mappings, emits HTTPS/SVCB NODATA, and forwards other DNS types to configured upstreams. For a non-fake TCP/443 flow, TLS ClientHello SNI can restore the original domain before routing.

## Linux TUN / auto_redirect Notes
- Linux has a `PlatformTunDevice` backend that can open `/dev/net/tun`, set `IFF_TUN | IFF_NO_PI`, configure IPv4 address/netmask/MTU, bring the interface up, and add IPv4 CIDR routes.
- In lwIP mode, `tun.auto_route=true` installs a dedicated policy-routing table. With empty `tun.routes`, it adds IPv4 (`0.0.0.0/1`, `128.0.0.0/1`) and IPv6 (`::/1`, `8000::/1`) split-default routes, with `tun.bypass_mark` returning TX egress to the main table.
- In Linux `tcp_stack=system` mode, normal TUN route installation is IPv4-only; do not describe it as a gateway IPv6 route implementation.
- When `tun.auto_redirect=true`, Linux starts a transparent TCP listener on `0.0.0.0:<tun.redirect_port>` and installs nftables rules in table `inet tx_auto_redirect`.
- The current Linux redirect implementation targets local IPv4 TCP `OUTPUT` traffic. It is not yet a full gateway/side-router `PREROUTING TPROXY` implementation.
- lwIP TUN direct/TX egress sockets use `tun.bypass_mark`; ordinary HTTP/SOCKS DNS sockets deliberately use mark 0. In `auto_redirect` mode, TCP egress uses `tun.redirect_mark`, which the nftables rule skips to avoid redirect loops.
- Transparent listener sockets must be explicitly opened before setting `IP_TRANSPARENT`; outbound sockets must be explicitly opened before applying `SO_MARK`. Do not move these socket options back before libuv creates/opens the OS socket.
- `stop_tun_listener()` removes the nftables auto_redirect table and stops the transparent listener.
- Linux TUN and redirect setup usually require root or `CAP_NET_ADMIN`; `SO_MARK` may require elevated privileges as well.

## Android Runtime Notes
- Android's native data path is:

```text
VpnService TUN fd -> HEV lwIP TCP/UDP -> tx router -> direct / tx tunnel / block
```

- Android rejects `tcp_stack=system`; use `tcp_stack=lwip` and let `VpnService` provide the fd. The native layer owns that fd after startup, including failure paths.
- The current code keeps proxy listeners in TUN mode when `tun.auto_redirect=false`; this preserves optional tun2socks compatibility without making it a requirement.
- Linux `tun.auto_redirect` is not available on Android; do not assume Android can use nftables/IP_TRANSPARENT.
- Native direct/tunnel and controlled DNS sockets support a protector callback. The JNI layer must call `VpnService.protect(fd)` and, when necessary, bind the fd to the selected physical `Network`.
- `tx_client_start_android()` requires a non-empty `dns.upstreams` configuration. For app-provided host and DNS resolution, call `tx_client_start_android_ex()` with both DNS hooks.

## UDP / QUIC Status
- SOCKS5 `UDP ASSOCIATE` is supported.
- The tunnel protocol includes `TunnelCmd::UdpPacket`.
- `tx_client` forwards SOCKS5 UDP packets through a shared UDP TX tunnel.
- `tx_server` sends UDP packets to targets and returns responses through the tunnel.
- UDP routed to a `tx` outbound is proxied through the encrypted tunnel. UDP routed to `direct` is relayed locally by `tx_client`. UDP routed to `block` is dropped.
- Server UDP flow sockets are created for the first target address family, so IPv6 literals and AAAA-only UDP domains are supported.
- A TUN UDP/443 destination with no fake-IP domain mapping is intentionally dropped to encourage TCP fallback, where TLS SNI can preserve domain routing.
- Client and server UDP flows are removed after an idle timeout. Configure `udp.idle_timeout` in seconds; the default is 300 seconds.

## Android Build Context
- Android project path: `/mnt/f/program/android/txz`.
- Android NDK path: `/home/andre/Android/android-ndk-r29`.
- Android OpenSSL path: `/mnt/f/DevEnv/AndroidSDK/android_openssl/ssl_3`.
- Android builds should use the dynamic C++ runtime (`ANDROID_STL=c++_shared`).
- Default Android CMake build directory: `build-android-arm64`; it has been configured with `ANDROID_STL=c++_shared`.
- Configure the Android native build with:

```sh
cmake -S . -B build-android-arm64 \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=/home/andre/Android/android-ndk-r29/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-24 \
  -DANDROID_STL=c++_shared \
  -DOPENSSL_ROOT_DIR=/mnt/f/DevEnv/AndroidSDK/android_openssl/ssl_3
```

- Build the Android native library with:

```sh
cmake --build build-android-arm64 -j$(nproc)
```

- Copy the library into the Android project with:

```sh
cp build-android-arm64/lib/libtx.so \
  /mnt/f/program/android/txz/app/src/main/jniLibs/arm64-v8a/libtx.so
```

- `libc++_shared.so` comes from the NDK and should be present in the Android project when using `c++_shared`:

```sh
/home/andre/Android/android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/libc++_shared.so
```

- The Android project's WSL Gradle build may not understand `local.properties` when it contains a Windows `sdk.dir=F\:\\...` path. Building via Windows `cmd.exe` from `F:\program\android\txz` works:

```sh
/mnt/c/Windows/System32/cmd.exe /c "cd /d F:\program\android\txz && gradlew.bat assembleDebug"
```

- Windows-side adb path:

```sh
/mnt/c/Windows/System32/cmd.exe /c "F:\DevEnv\AndroidSDK\platform-tools\adb.exe devices"
```

- If writing to `/mnt/f/...` is blocked by sandboxing, request escalation rather than using generated build output as a workaround.

## Current Branch Verification Notes
- Recent local verification passed:

```sh
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
cmake --build build-android-arm64 -j$(nproc)
```

- The Android native build currently passes with `ANDROID_STL=c++_shared`. It may still emit unused lambda capture warnings in `src/client/client_app.cpp`.
- Runtime Linux auto_redirect has not been fully validated with root/CAP_NET_ADMIN in this session; test it with real nftables privileges before treating it as production-ready.
- Current known future work: full Linux gateway `PREROUTING TPROXY`, stronger outbound bypass/policy routing, DNS/fake-IP with domain preservation, Android JNI `VpnService.protect(fd)` and DNS bypass, Windows Wintun compile/runtime validation, and a Windows TCP system-stack mechanism such as WFP or WinDivert.
