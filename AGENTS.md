# 仓库协作指南

## 项目概览

- `tx` 是使用 CMake 构建的 C++14 代理 / 隧道项目。
- 主要可执行程序为 `tx_client` 和 `tx_server`；Android 构建产物为共享库 `libtx.so`。
- 核心实现位于 `src/`，公共头文件位于 `include/tx/`。
- 主要模块：
  - `crypto`：AES-GCM 加密和密钥派生。
  - `protocol`：SOCKS5、HTTP 代理、隧道协议、TLS/QUIC SNI 解析。
  - `router`：路由匹配与出站选择。
  - `geo`：GeoIP / GeoSite 解析和查找结构。
  - `net`：TCP 流抽象、DNS/fake-IP、lwIP TUN 和流量回收设施。
  - `client` / `server`：应用入口和配置解析。

## 构建与运行

使用 out-of-tree 构建：

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

运行示例：

```sh
./build/bin/tx_server -c config/server.json.example
./build/bin/tx_client -c config/client.json.example
```

非 Android 平台默认启用测试：

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DTX_BUILD_TESTS=ON
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
```

## 依赖

- CMake 3.25.1 或更高版本。
- 支持 C++14 的编译器。
- OpenSSL、libuv 和 nlohmann_json。
- OpenSSL 与 C++ 运行时在所有平台都刻意采用动态链接。
- `OPENSSL_ROOT_DIR` 是可选项；仅当 OpenSSL 不在平台默认搜索路径时传入。

顶层 `CMakeLists.txt` 使用 `cmake/TxUtils.cmake` 和 `cmake/FetchDeps.cmake`。启用
`TX_FETCH_DEPS=ON` 时，干净配置可将 libuv、nlohmann_json 和 HEV lwIP 下载到 `.deps/`。

## 测试

- 测试文件位于 `tests/`，使用简单的 `printf` 和 `assert` 风格。
- `tests/CMakeLists.txt` 当前注册 21 个测试：`crypto`、`geoip`、`geosite`、`socks5`、
  `http_proxy`、`router`、`tunnel`、`tun_packet`、`lwip_udp_stack`、
  `socket_protector`、`udp_flow_timeout`、`fake_ip_dns`、`lwip_tcp_stack`、
  `tcp_session_callbacks`、`dns_resolver`、`tls_sni`、`quic_sni`、`client_config`、
  `server_config`、`client_tunnel_dns` 和 `client_quic_routing`。

## 编码约定

- 公共 API 放在 `include/tx/...`，实现放在对应的 `src/...` 模块。
- 代码使用 `tx` 命名空间。
- 保持现有直接、轻量的 C++14 风格；除非任务需要，避免大范围重构。
- 新增聚焦测试时沿用现有 `printf` / `assert` 风格。
- 保留 CMake 和源文件中已有的平台条件编译。

## 工作流约定
- 未明确要求时，不要修改 `build/` 或 `cmake-build-debug/` 中的生成产物。
- `config/*.example` 仅为示例，不能写入真实密钥。
- 不要自动执行破坏性 Git 命令；保留工作树中与当前任务无关的改动。

## 当前配置与路由模型

- 客户端配置使用 `outbounds` 加 `routing.rules` 模型。
- `routing.rules` 按从上到下顺序匹配；最后一条规则是所有前序匹配失败时的兜底。
- `routing.rules[*].outboundTag` 只引用出站标签，不能在路由器中将它折叠成
  direct / proxy / block 决策。
- 实际行为由 `outbounds[*]` 决定：
  - `type: "direct"`：直接连接。
  - `type: "tx"`：按该出站的 `server` 配置建立 TX 加密隧道。
  - `type: "block"`：拒绝 TCP 或丢弃 UDP。
- 旧的顶层 `server`、`geo.direct_geoip` 和 `geo.direct_geosite` 已刻意不再支持。
- Android 默认路由必须把私网 IP 放在首位，例如
  `{"ip":["geoip:private"],"outboundTag":"direct-out"}`，确保 `192.168.0.1` 等
  局域网目标不会进入远端隧道。
- 原生 lwIP TUN 路径会使用 fake-IP 反向映射、TLS SNI 和 QUIC Initial SNI 恢复域名，
  再按 `AsIs` 规则路由。`tun.auto_redirect=false` 时仍会保留 HTTP/SOCKS5 监听器，
  因而 tun2socks 只是兼容选项，不是 Android 的唯一数据面。

## 原生 TUN 状态

- 客户端的 `tun` 配置包括 `enabled`、`fd`、`name`、`address` / `addresses`、`mtu`、
  `auto_config`、`auto_route`、`auto_redirect`、`redirect_port`、`redirect_mark`、
  `bypass_mark`、`route_table`、`rule_priority`、`routes`、`mode`、`tcp_stack` 和
  `udp_stack` 等字段。
- `tun.mode` 已弃用。默认原生模式为 `tcp_stack: "lwip"` 和
  `udp_stack: "lwip"`；`udp_stack` 当前只能为 `lwip`。`tcp_stack: "system"` 仅
  Linux 支持，且只用于透明重定向路径。
- `tx_client_start_with_tun_fd()` 用于 Android `VpnService` 集成。Android 提供 TUN fd，
  原生代码不会打开 `/dev/net/tun`。
- `include/tx/net/tun_packet.h` 与 `src/net/tun_packet.cpp` 解析 IPv4/IPv6 TUN 数据包；
  `LwipUdpStack` 还提供 lwIP TCP 流桥接。`test_tun_packet` 覆盖 IPv4/IPv6 UDP 往返，
  `test_lwip_tcp_stack` 和 `test_lwip_udp_stack` 覆盖数据面。
- 原生 TUN TCP 和 UDP 与 HTTP/SOCKS 使用相同的 direct / TX / block 路由模型。TCP
  桥接保留半关闭语义并实施有界写入背压。
- fake-IP DNS 在本地处理 UDP/TCP A 和 AAAA，维护有界稳定正反映射，对 HTTPS/SVCB
  返回 NODATA，并将其他 DNS 类型转发至配置的上游。没有 fake-IP 映射的 TCP/443
  流会尝试通过 TLS ClientHello SNI 恢复域名后再路由。

## Linux TUN 与 auto_redirect

- Linux 的 `PlatformTunDevice` 可以打开 `/dev/net/tun`，设置 `IFF_TUN | IFF_NO_PI`，
  配置 IPv4 地址/掩码/MTU、启用接口并添加 IPv4 CIDR 路由。
- 在 lwIP 模式下，`tun.auto_route=true` 会安装独立策略路由表。`tun.routes` 为空时，
  添加 IPv4（`0.0.0.0/1`、`128.0.0.0/1`）和 IPv6（`::/1`、`8000::/1`）分段默认路由，
  并通过 `tun.bypass_mark` 让 TX 出站返回主路由表。
- Linux `tcp_stack=system` 模式的普通 TUN 路由仅支持 IPv4；不要把它描述为 IPv6
  网关路由实现。
- `tun.auto_redirect=true` 时，Linux 会在 `0.0.0.0:<tun.redirect_port>` 启动透明 TCP
  监听器，并创建 nftables 表 `inet tx_auto_redirect`。
- 当前 Linux 重定向只作用于本机 IPv4 TCP `OUTPUT` 流量，不是完整的网关/旁路由
  `PREROUTING TPROXY` 实现。
- lwIP TUN 的 direct/TX 出站 socket 使用 `tun.bypass_mark`；普通 HTTP/SOCKS DNS
  socket 刻意使用 mark 0。`auto_redirect` 模式中，TCP 出站使用
  `tun.redirect_mark`，由 nftables 规则跳过以避免重定向循环。
- 必须先让 libuv 创建/打开透明监听 socket，再设置 `IP_TRANSPARENT`；必须先创建/打开
  出站 socket，再设置 `SO_MARK`。不要把这些选项移回 libuv 创建 socket 之前。
- `stop_tun_listener()` 会删除 nftables 自动重定向表并停止透明监听器。
- Linux TUN 与重定向通常需要 root 或 `CAP_NET_ADMIN`；`SO_MARK` 也可能需要额外权限。

## Android 运行时约定

Android 原生数据路径：

```text
VpnService TUN fd -> HEV lwIP TCP/UDP -> tx router -> direct / tx tunnel / block
```

- Android 不支持 `tcp_stack=system`；必须使用 `tcp_stack=lwip`，并由 `VpnService`
  提供 fd。原生层在启动成功和失败路径中均拥有并关闭该 fd。
- `tun.auto_redirect` 是 Linux 功能，Android 不支持 nftables 或 `IP_TRANSPARENT`。
- 原生 direct、TX 和受控 DNS socket 都支持 protector 回调。JNI 层必须调用
  `VpnService.protect(fd)`，必要时再将 fd 绑定至选定的物理 `Network`；失败必须让该
  流失败，不能冒险造成 VPN 路由环路。
- `tx_client_start_android()` 要求非空的数值 `dns.upstreams`，DNS 查询经已配置的 TX
  出站转发到远端，不得回退到物理网络 DNS。
- `tx_client_start_android_ex()` 的 `resolve_host` 与 `query_dns` 字段仅为 ABI 兼容而
  保留；Android 上不会调用它们，只有 `protect_socket` 生效。需要在 Android 启动前
  解析服务器主机名时，应用应通过选定的物理网络自行解析，再把数值地址写入配置。

## UDP 与 QUIC 状态

- 已支持 SOCKS5 `UDP ASSOCIATE`。
- 隧道协议包含 `TunnelCmd::UdpPacket`。
- `tx_client` 通过共享 UDP TX 隧道转发 SOCKS5 UDP；`tx_server` 将 UDP 发往目标并把
  响应通过隧道返回。
- 路由到 `tx` 的 UDP 通过加密隧道代理，路由到 `direct` 的 UDP 在客户端本地中继，
  路由到 `block` 的 UDP 被丢弃。
- 服务端 UDP flow 按首个目标地址族创建 socket，因此支持 IPv6 字面量和仅 AAAA 的域名。
- 对没有 fake-IP 域名映射的 TUN UDP/443，默认开启的 `udp.quic_sniff` 尝试从 QUIC
  Initial 中恢复 SNI 以用于路由；实际 UDP 仍发往原始数值目标。SNI 不可用、关闭嗅探
  或触及资源上限时，回退到普通按 IP 路由，不再主动丢弃该流。
- 客户端和服务端 UDP flow 按空闲超时回收。`udp.idle_timeout` 单位为秒，默认 300。

## Android 构建与打包

- Android 项目路径为 `/home/andre/code/android/txz`。
- NDK 路径为 `/home/andre/Android/android-ndk-r29`；OpenSSL 路径为
  `/home/andre/Android/android_openssl/ssl_3`。
- 必须使用动态 C++ 运行时：`ANDROID_STL=c++_shared`。
- 默认 Android 构建目录为 `build-android-arm64`。

```sh
cmake -S . -B build-android-arm64 \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_TOOLCHAIN_FILE=/home/andre/Android/android-ndk-r29/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-24 \
  -DANDROID_STL=c++_shared \
  -DOPENSSL_ROOT_DIR=/home/andre/Android/android_openssl/ssl_3
cmake --build build-android-arm64 -j$(nproc)
```

- `libtx.so` 动态依赖 OpenSSL 与 `libc++_shared.so`。每个 ABI 的 Android APK 必须同时
  打包 `libtx.so`、`libssl_3.so`、`libcrypto_3.so` 和 `libc++_shared.so`；以
  `readelf -d libtx.so` 中的 `NEEDED` 条目为准。
- 若 Android 工程以 `app/src/main/jniLibs/<ABI>/` 提供这些库，它们都应提交到版本库，
  以确保干净检出可以构建并运行；不要用宽泛的 `*.so` 忽略规则排除它们。
- 构建完成后至少复制 `build-android-arm64/lib/libtx.so` 到 Android 工程对应 ABI 目录，
  并从所用 NDK/OpenSSL 发行包同步匹配 ABI 的其余三个动态库。
- Android 项目的 WSL Gradle 构建可能无法解析 Windows 格式的 `local.properties`；必要时
  在 Windows 环境从 Android 工程目录执行 `gradlew.bat assembleDebug`。

## 验证与已知限制

- 提交前至少运行主机测试套件；涉及 Android 原生代码时，再运行 Android NDK 构建。

```sh
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
cmake --build build-android-arm64 -j$(nproc)
```

- Linux `auto_redirect` 尚未以 root/CAP_NET_ADMIN 在真实环境完成全面运行验证，不能视为
  已达到生产就绪。
- 后续工作包括完整 Linux 网关 `PREROUTING TPROXY`、更强的出站绕过/策略路由、
  Windows Wintun 的编译与运行验证，以及 Windows system-stack 方案（WFP 或 WinDivert）。
