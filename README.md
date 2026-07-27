# tx

`tx` 是一个基于 C++14 的代理 / 隧道程序，提供本地 HTTP 代理、SOCKS5 代理和远端加密隧道服务。项目使用 CMake 构建，核心网络事件由 libuv 驱动，传输层使用高熵 PSK 认证、X25519/ECDHE 前向安全握手和 AEAD 加密，并支持通过 GeoIP / GeoSite 数据进行直连与代理路由判断。

项目会生成两个主要可执行文件：

- `tx_server`：部署在远端服务器，监听客户端隧道连接。
- `tx_client`：运行在本地，提供 HTTP 和 SOCKS5 代理入口，并根据规则转发到直连或远端隧道。

## 功能概览

- 本地 HTTP 代理入口。
- 本地 SOCKS5 代理入口。
- SOCKS5 UDP ASSOCIATE、UDP 直连和 TX 隧道转发。
- 客户端与服务端之间的自定义隧道协议。
- AES-GCM / ChaCha20-Poly1305 AEAD 加密。
- 高熵 PSK 认证和 X25519/ECDHE 会话密钥派生。
- 基于 GeoIP / GeoSite 的有序路由规则，以及 direct / tx / block 出站。
- IPv4 / IPv6 原生 TUN TCP / UDP 数据面（HEV lwIP）。
- fake-IP DNS、TLS SNI 域名恢复，以及按域名优先的 `AsIs` 路由。
- Linux TUN 自动配置、policy route 和本机 TCP 透明重定向。
- Android `VpnService` TUN fd、socket protector 与 DNS hook C API。
- 有界的连接、流、握手、连接超时、速率和写入背压控制。
- 简单的 assert 风格单元测试。

## 目录结构

```text
.
├── CMakeLists.txt          # 顶层构建脚本
├── cmake/                  # CMake 辅助模块和依赖查找逻辑
├── config/                 # 客户端 / 服务端配置示例
├── include/tx/             # 公共头文件
├── src/
│   ├── client/             # tx_client 入口、配置和应用逻辑
│   ├── server/             # tx_server 入口、配置和应用逻辑
│   ├── common/             # 日志、基础类型等公共代码
│   ├── crypto/             # AEAD、secret 解析和密钥派生
│   ├── geo/                # GeoIP / GeoSite 数据结构和解析
│   ├── net/                # TCP server、buffer 等网络基础设施
│   ├── protocol/           # SOCKS5、HTTP 代理、隧道协议
│   └── router/             # 路由决策
└── tests/                  # 单元测试
```

## 依赖

构建前需要准备：

- CMake 3.25.1 或更新版本
- 支持 C++14 的编译器
- OpenSSL 开发库
- libuv 开发库，或允许 CMake 下载到项目 `.deps/`
- nlohmann_json，或允许 CMake 下载到项目 `.deps/`

默认构建策略：

- `tx_core` 本身始终构建为静态库。
- OpenSSL 在所有平台都使用动态库链接。
- 所有平台强制动态链接 C++ 运行库。
- `TX_FETCH_DEPS=ON` 时，缺失的 libuv 和 nlohmann_json 会下载到项目 `.deps/` 目录。
- Linux / Windows 可继续构建 `tx_client` 和 `tx_server` 可执行文件。
- Android 默认关闭命令行程序，转而构建 `libtx.so` 共享库，并使用动态 C++ 运行库。

Debian / Ubuntu 示例：

```sh
sudo apt update
sudo apt install -y build-essential cmake libssl-dev
```

Fedora 示例：

```sh
sudo dnf install -y gcc gcc-c++ cmake make openssl-devel
```

如果依赖安装在非标准路径，可以通过 CMake 变量指定，例如：

```sh
cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DLIBUV_INCLUDE_DIR=/path/to/libuv/include \
  -DLIBUV_LIBRARY=/path/to/libuv/lib/libuv.a \
  -DNLOHMANN_JSON_INCLUDE_DIR=/path/to/nlohmann-json/include
```

- `OpenSSL` 通过 `find_package(OpenSSL)` 查找，并强制使用动态库；系统路径可找到 OpenSSL 时不需要传 `OPENSSL_ROOT_DIR`。
- 只有 OpenSSL 安装在非标准路径时，才需要额外传 `-DOPENSSL_ROOT_DIR=/path/to/openssl`。
- `libuv` 可以显式指向静态库文件，例如 `libuv.a`、`uv_a.lib`；未指定且 `TX_FETCH_DEPS=ON` 时会下载到 `.deps/`。
- `nlohmann_json` 是 header-only；未指定且 `TX_FETCH_DEPS=ON` 时会下载到 `.deps/`。
- 原生 TUN TCP / UDP 数据面使用固定提交的 HEV lwIP，并由 CMake FetchContent 下载到 `.deps/` 后静态链接。

## 构建

推荐使用 out-of-tree 构建：

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

构建完成后，可执行文件位于：

```text
build/bin/tx_client
build/bin/tx_server
```

常用 CMake 选项：

- `-DTX_BUILD_APPS=ON|OFF`：是否构建 `tx_client` 和 `tx_server`。
- `-DTX_BUILD_TESTS=ON|OFF`：是否构建测试，非 Android 平台默认开启。
- `-DTX_BUILD_SHARED=ON|OFF`：是否构建共享库，主要用于 Android 场景，默认关闭。
- `-DTX_FETCH_DEPS=ON|OFF`：是否把缺失的 libuv / nlohmann_json 下载到项目 `.deps/`，默认开启。
- `-DCMAKE_BUILD_TYPE=Debug|Release`：选择调试或发布构建。

### Linux Release 构建

```sh
cmake -B build-linux \
  -DCMAKE_BUILD_TYPE=Release \
  -DTX_FETCH_DEPS=ON
cmake --build build-linux -j$(nproc)
```

也可以使用 preset：

```sh
cmake --preset linux-release
cmake --build --preset linux-release
```

### Windows 构建

MSVC 示例：

```powershell
cmake -B build-win `
  -G "Visual Studio 17 2022" `
  -A x64 `
  -DCMAKE_BUILD_TYPE=Release `
  -DTX_FETCH_DEPS=ON `
  -DOPENSSL_ROOT_DIR=C:/deps/openssl
cmake --build build-win --config Release
```

建议：

- OpenSSL 准备动态库版本，并通过 `OPENSSL_ROOT_DIR` 指向安装根目录。
- `libuv` 和 `nlohmann_json` 可以由 `TX_FETCH_DEPS=ON` 下载到 `.deps/`，也可以手工指定本地路径。

### Android 共享库构建

Android 默认行为：

- 强制 `TX_BUILD_APPS=OFF`
- 强制 `TX_BUILD_SHARED=ON`
- 强制 `TX_BUILD_TESTS=OFF`

也就是只构建共享库 `libtx.so`，适合 JNI / SDK 集成。

示例：

```sh
cmake -B build-android \
  -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-24 \
  -DCMAKE_BUILD_TYPE=Release \
  -DANDROID_STL=c++_shared \
  -DTX_FETCH_DEPS=ON \
  -DOPENSSL_ROOT_DIR=/path/to/android/openssl
cmake --build build-android -j$(nproc)
```

生成产物位于：

```text
build-android/lib/libtx.so
```

Android 模式下使用动态 OpenSSL 和 NDK 的 `c++_shared` 动态 C++ 运行库。

## 测试

Debug 构建并运行测试：

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DTX_BUILD_TESTS=ON
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
```

当前共有 19 个测试目标，覆盖 crypto、GeoIP、GeoSite、SOCKS5、HTTP proxy、router、
tunnel、TUN packet、HEV lwIP TCP / UDP、fake-IP DNS、DNS resolver、TX 隧道 DNS、
客户端/服务端配置、TLS SNI、socket protector、TCP 回调和 UDP flow timeout。

## 配置

仓库提供了两个配置示例：

- `config/server.json.example`
- `config/client.json.example`

建议复制后再修改，避免直接把真实 secret、服务器地址等信息写入示例文件：

```sh
cp config/server.json.example server.json
cp config/client.json.example client.json
```

生成推荐的 32 字节 base64 PSK：

```sh
./build/bin/tx_server --gen-secret
```

把输出的 `base64:...` 同时填入服务端 `secret` 和客户端 TX 出站的
`outbounds[*].server.secret`。

### 服务端配置

示例：

```json
{
    "listen": {
        "host": "0.0.0.0",
        "port": 443
    },
    "udp": {
        "idle_timeout": 300
    },
    "limits": {
        "max_clients": 1024,
        "max_unauthenticated_per_ip": 32,
        "max_new_clients_per_second": 128,
        "max_tcp_outbounds_per_client": 1024,
        "max_udp_flows_per_client": 4096,
        "handshake_timeout": 8,
        "connect_timeout": 10,
        "max_client_rate_mbps": 64
    },
    "secret": "base64:REPLACE_WITH_GEN_SECRET_OUTPUT",
    "log_level": "info"
}
```

字段说明：

- `listen.host`：服务端监听地址。
- `listen.port`：服务端监听端口。
- `secret`：客户端与服务端共享的高熵 PSK，支持 `base64:`、`hex:`、`uuid-v4:` 前缀；推荐使用 `--gen-secret` 生成 `base64:`。
- AEAD 算法由客户端各 TX 出站的 `server.cipher` 在握手时选择，服务端无需重复配置。
- `udp.idle_timeout`：UDP 出站空闲回收时间，单位秒，默认 300，范围 1～86400。
- `limits.max_clients`：同时连接的隧道客户端上限。
- `limits.max_unauthenticated_per_ip` / `max_new_clients_per_second`：握手前连接的每 IP 上限与新连接速率上限。
- `limits.max_tcp_outbounds_per_client` / `max_udp_flows_per_client`：单个隧道客户端的 TCP / UDP 出站上限。
- `limits.handshake_timeout` / `connect_timeout`：握手与目标连接超时，单位秒。
- `limits.max_client_rate_mbps`：每个隧道客户端的单秒入口速率上限。
- `log_level`：日志级别，可选 `debug`、`info`、`warn`、`error`。

### 客户端配置

示例：

```json
{
    "listen": {
        "http": {"host": "127.0.0.1", "port": 8080},
        "socks5": {"host": "127.0.0.1", "port": 1080}
    },
    "udp": {
        "idle_timeout": 300,
        "max_flows": 4096
    },
    "limits": {
        "max_proxy_connections": 4096
    },
    "tun": {
        "enabled": false,
        "name": "tx0",
        "mtu": 1500,
        "addresses": ["10.10.0.1/24", "fd00:2024::1/64"],
        "auto_config": true,
        "auto_route": true,
        "auto_redirect": false,
        "redirect_port": 54321,
        "redirect_mark": 8228,
        "routes": [],
        "bypass_mark": 8228,
        "route_table": 20220,
        "rule_priority": 10000,
        "tcp_stack": "lwip",
        "udp_stack": "lwip"
    },
    "dns": {
        "mode": "fake-ip",
        "fake_ipv4_range": "198.18.0.0/16",
        "fake_ipv6_range": "fd00:198:18::/96",
        "upstreams": [],
        "cache_ttl": 60,
        "cache_capacity": 4096
    },
    "outbounds": [
        {
            "tag": "direct-out",
            "type": "direct"
        },
        {
            "tag": "block",
            "type": "block"
        },
        {
            "tag": "proxy-out-tx",
            "type": "tx",
            "server": {
                "host": "your-server.example.com",
                "port": 443,
                "secret": "base64:REPLACE_WITH_GEN_SECRET_OUTPUT",
                "cipher": "aes-256-gcm"
            }
        }
    ],
    "routing": {
        "domainStrategy": "AsIs",
        "geoip_path": "geoip.dat",
        "geosite_path": "geosite.dat",
        "rules": [
            {"ip": ["geoip:private"], "outboundTag": "direct-out"},
            {"domain": ["geosite:category-ads-all"], "outboundTag": "block"},
            {"domain": ["geosite:cn"], "outboundTag": "direct-out"},
            {"ip": ["geoip:cn"], "outboundTag": "direct-out"},
            {"outboundTag": "proxy-out-tx"}
        ]
    },
    "log_level": "info"
}
```

字段说明：

- `listen.http`：本地 HTTP 代理监听地址和端口。
- `listen.socks5`：本地 SOCKS5 代理监听地址和端口。
- `udp.idle_timeout`：UDP flow 空闲回收时间，单位秒，默认 300，范围 1～86400。
- `udp.max_flows`：客户端 UDP flow 上限，范围 1～1000000。
- `limits.max_proxy_connections`：本地 HTTP / SOCKS / TUN TCP 连接总上限，范围 1～1000000。
- `tun`：原生 TUN 配置；启用时 `tcp_stack` 可为 `lwip` 或 Linux 专用的 `system`，`udp_stack` 当前必须为 `lwip`。
- `dns`：当前仅支持 `mode: "fake-ip"`；`upstreams` 为数值 DNS 上游地址列表，`cache_ttl` 和 `cache_capacity` 分别控制映射存活时间和 LRU 容量。
- `outbounds`：具名出站列表。每个 `tag` 必须唯一，`type` 可选 `direct`、`tx` 或 `block`。
- `outbounds[*].server`：仅 `tx` 出站使用，指定远端地址、端口、PSK 和 AEAD 算法。
- `routing.geoip_path`：GeoIP 数据文件路径。
- `routing.geosite_path`：GeoSite 数据文件路径。
- `routing.rules`：从上到下匹配；规则的 `outboundTag` 仅引用某个出站，不直接表示处理方式。
- `routing.rules[*].ip`：IP/CIDR 或 `geoip:<tag>` 匹配项。
- `routing.rules[*].domain`：域名或 `geosite:<tag>` 匹配项。
- `routing.domainStrategy`：必须为 `AsIs`；域名只走 domain 规则，IP 字面量只走 IP 规则，不会二次解析后混合匹配。
- `routing.rules` 的最后一条应作为无 matcher 的默认出站。私网 IP 规则应放在最前，避免 LAN 流量进入远端隧道。
- `log_level`：日志级别，可选 `debug`、`info`、`warn`、`error`。

旧版顶层 `server`、`geo.direct_geoip` 和 `geo.direct_geosite` 配置已不再支持。

### TUN 模式

默认原生数据面为 `tcp_stack: "lwip"`、`udp_stack: "lwip"`。同一个 HEV lwIP
netif 终结 TUN 侧 TCP/UDP，随后进入统一的 direct / tx / block 路由；TCP 支持
半关闭与有界背压。`tun.mode` 仅是弃用兼容字段；`tcp_stack: "system"` 仅在 Linux
可用，且仅适用于透明重定向路径；要处理原生 TUN TCP 必须使用 `lwip`。`udp_stack`
当前只能为 `lwip`。

- `tun.addresses` 接受 IPv4/IPv6 CIDR；旧 `tun.address` 仍作为 IPv4 别名。
- Linux lwIP + `auto_route=true` 使用独立路由表（默认 `20220`）、bypass mark（默认 `0x2024`）和有序 policy rules；未指定 `routes` 时安装 IPv4 / IPv6 split-default。
- Linux 普通 HTTP/SOCKS 客户端不会为 DNS socket 设置 `SO_MARK`；该 mark 仅用于 lwIP TUN 的 policy-routing 路径。
- Linux `tun.auto_redirect` 使用 nftables 表 `inet tx_auto_redirect` 重定向本机 IPv4 TCP `OUTPUT` 流量，并通过 `tun.redirect_mark` 排除 TX 出站 socket，避免重定向循环。
- `auto_redirect=true` 只能和 Linux `tcp_stack=system` 一起使用；lwIP 模式会在配置校验阶段拒绝该组合。
- 当前 Linux redirect 不是网关/旁路由的 `PREROUTING TPROXY` 实现；TUN 和 nftables 配置通常需要 root 或 `CAP_NET_ADMIN`。
- Windows 使用 Wintun 后端；其编译与运行验证仍应在真实 Windows 环境进行。
- Android 由 `VpnService` 提供真实 TUN fd，txlib 接管 fd 所有权并直接运行 lwIP。未启用 Linux `auto_redirect` 时，HTTP / SOCKS5 监听器会保留，因而仍可选用 tun2socks 兼容路径。所有 native 出站 socket 都必须通过 `VpnService.protect(fd)`。
- 内置 fake-IP DNS 支持 UDP/TCP A、AAAA、HTTPS/SVCB NODATA、稳定正反映射和 LRU 容量控制；其他 DNS 类型转发至上游。默认池为 `198.18.0.0/16` 与 `fd00:198:18::/96`。
- 对 fake-IP 映射缺失的 TCP/443，客户端会尝试从 TLS ClientHello 提取 SNI 以恢复域名；非 fake-IP 的 UDP/443 会被丢弃以促使应用回退到可恢复域名的 TCP 路径。ICMP 当前丢弃，DoH/DoT 仍只能按目标 IP 路由。

Android 共享库提供以下启动接口：

- `tx_client_start_with_tun_fd()`：使用 `VpnService` 提供的 TUN fd 启动客户端。
- `tx_client_start_android()`：额外接受 socket protector 回调；JNI 层应在回调中调用 `VpnService.protect(fd)`，防止直连和 TX 出站 socket 再次进入 VPN。Android 配置必须提供至少一个数值 `dns.upstreams`；查询由 TX 隧道送到远端服务器后再访问该 DNS，不能回退到物理网络 DNS。TX 服务器地址在 Android 上必须使用 IP 字面量，避免启动前的 DNS 引导泄漏。

Android 隧道 DNS 按 `dns.upstreams` 顺序尝试，每个 UDP/TCP 阶段的超时为 2 秒；
收到 UDP TC 响应时会在同一 TX 加密连接上改用标准 DNS-over-TCP。

TX 客户端与服务端隧道帧协议已升级为 v2，并通过 `HalfClose` 命令传播双向 TCP
FIN。v1 帧会明确作为版本不匹配拒绝，升级时必须同步部署客户端和服务端。

## 运行

先在远端服务器启动服务端：

```sh
./build/bin/tx_server -c server.json
```

再在本地启动客户端：

```sh
./build/bin/tx_client -c client.json
```

也可以直接使用仓库中的示例配置做本地验证：

```sh
./build/bin/tx_server -c config/server.json.example
./build/bin/tx_client -c config/client.json.example
```

命令行参数：

```text
-c, --config <path>   指定配置文件路径
-l, --log <level>     覆盖配置文件中的日志级别，支持 debug/info/warn/error
-h, --help            显示帮助
```

客户端启动后，应用程序可以使用以下本地代理入口：

- HTTP 代理：`127.0.0.1:8080`
- SOCKS5 代理：`127.0.0.1:1080`

端口以 `client.json` 中的配置为准。

## 安装

可选安装到指定前缀：

```sh
cmake --install build --prefix /usr/local
```

安装内容包括：

- `bin/tx_client`
- `bin/tx_server`
- `lib/libtx.so`（启用共享库构建时）
- `include/tx/tx_api.h`（启用共享库构建时）
- `include/tx/`

## 常见问题

### 找不到 libuv

安装开发包：

```sh
sudo apt install libuv1-dev
```

或者在配置 CMake 时指定：

```sh
cmake -B build -DLIBUV_INCLUDE_DIR=/path/to/include -DLIBUV_LIBRARY=/path/to/libuv.a
```

Windows 下一般传入 `uv_a.lib`，Android 下一般传入交叉编译得到的 `libuv.a`。

### 找不到 nlohmann_json

安装开发包：

```sh
sudo apt install nlohmann-json3-dev
```

或者指定头文件目录：

```sh
cmake -B build -DNLOHMANN_JSON_INCLUDE_DIR=/path/to/include
```

### OpenSSL 查找失败

确认已安装 OpenSSL 开发包，或通过 `OPENSSL_ROOT_DIR` 指向动态 OpenSSL 的安装根目录。

### 端口监听失败

检查端口是否被占用，或当前用户是否有权限监听该端口。Linux 上监听 1024 以下端口通常需要 root 权限或额外 capability。开发调试时可以先改用 8443、18080、11080 等高端口。

## 开发说明

- 公共 API 放在 `include/tx/`。
- 实现代码按模块放在 `src/`。
- 新测试放在 `tests/test_<name>.cpp`，并在 `tests/CMakeLists.txt` 中通过 `tx_add_test(<name>)` 注册。
- 保持 C++14 兼容，优先沿用现有直接、轻量的代码风格。
