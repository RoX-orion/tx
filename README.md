# tx

`tx` 是一个基于 C++14 的代理 / 隧道程序，提供本地 HTTP 代理、SOCKS5 代理和远端加密隧道服务。项目使用 CMake 构建，核心网络事件由 libuv 驱动，传输层使用高熵 PSK 认证、X25519/ECDHE 前向安全握手和 AEAD 加密，并支持通过 GeoIP / GeoSite 数据进行直连与代理路由判断。

项目会生成两个主要可执行文件：

- `tx_server`：部署在远端服务器，监听客户端隧道连接。
- `tx_client`：运行在本地，提供 HTTP 和 SOCKS5 代理入口，并根据规则转发到直连或远端隧道。

## 功能概览

- 本地 HTTP 代理入口。
- 本地 SOCKS5 代理入口。
- 客户端与服务端之间的自定义隧道协议。
- AES-GCM / ChaCha20-Poly1305 AEAD 加密。
- 高熵 PSK 认证和 X25519/ECDHE 会话密钥派生。
- 基于 GeoIP / GeoSite 的路由规则。
- Linux / Windows / Android 相关平台条件支持。
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
- OpenSSL 开发库和静态库
- Linux 静态 C++ 运行库（启用 `TX_STATIC_CXX_RUNTIME=ON` 时）
- libuv 开发库，或允许 CMake 下载到项目 `.deps/`
- nlohmann_json，或允许 CMake 下载到项目 `.deps/`

默认构建策略：

- `tx_core` 本身始终构建为静态库。
- `TX_LINK_STATIC_DEPS=ON` 时，优先静态链接第三方依赖，默认开启。
- `TX_FETCH_DEPS=ON` 时，缺失的 libuv 和 nlohmann_json 会下载到项目 `.deps/` 目录。
- Linux / Windows 可继续构建 `tx_client` 和 `tx_server` 可执行文件。
- Android 默认关闭命令行程序，转而构建 `libtx.so` 共享库，并将第三方依赖静态打入该库。

Debian / Ubuntu 示例：

```sh
sudo apt update
sudo apt install -y build-essential cmake libssl-dev
```

Fedora 示例：

```sh
sudo dnf install -y gcc gcc-c++ cmake make openssl-devel openssl-static libstdc++-static zlib-static zstd-static
```

如果 OpenSSL 或其它依赖安装在非标准路径，可以通过 CMake 变量指定，例如：

```sh
cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DLIBUV_INCLUDE_DIR=/path/to/libuv/include \
  -DLIBUV_LIBRARY=/path/to/libuv/lib/libuv.a \
  -DNLOHMANN_JSON_INCLUDE_DIR=/path/to/nlohmann-json/include \
  -DOPENSSL_ROOT_DIR=/path/to/openssl
```

说明：

- `OpenSSL` 通过 `find_package(OpenSSL)` 查找；静态模式下会优先选择静态库。
- Linux 上静态 OpenSSL 常见传递依赖是 `zlib`、`zstd`，构建会自动尝试补齐对应静态库。
- `libuv` 可以显式指向静态库文件，例如 `libuv.a`、`uv_a.lib`；未指定且 `TX_FETCH_DEPS=ON` 时会下载到 `.deps/`。
- `nlohmann_json` 是 header-only；未指定且 `TX_FETCH_DEPS=ON` 时会下载到 `.deps/`。

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
- `-DTX_LINK_STATIC_DEPS=ON|OFF`：是否优先静态链接第三方依赖，默认开启。
- `-DTX_FETCH_DEPS=ON|OFF`：是否把缺失的 libuv / nlohmann_json 下载到项目 `.deps/`，默认开启。
- `-DTX_STATIC_CXX_RUNTIME=ON|OFF`：在 GCC / Clang 下尽量静态链接 `libgcc` / `libstdc++`，默认开启。
- `-DTX_STATIC_MSVC_RUNTIME=ON|OFF`：在 MSVC 下使用静态运行时 `/MT` 或 `/MTd`，默认开启。
- `-DCMAKE_BUILD_TYPE=Debug|Release`：选择调试或发布构建。

### Linux 静态依赖构建

```sh
cmake -B build-linux \
  -DCMAKE_BUILD_TYPE=Release \
  -DTX_FETCH_DEPS=ON \
  -DTX_LINK_STATIC_DEPS=ON \
  -DTX_STATIC_CXX_RUNTIME=ON \
  -DOPENSSL_ROOT_DIR=/path/to/openssl
cmake --build build-linux -j$(nproc)
```

如果系统同时安装了动态版和静态版 OpenSSL，`TX_LINK_STATIC_DEPS=ON` 会优先查找静态库。
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
  -DTX_LINK_STATIC_DEPS=ON `
  -DTX_STATIC_MSVC_RUNTIME=ON `
  -DOPENSSL_ROOT_DIR=C:/deps/openssl
cmake --build build-win --config Release
```

建议：

- OpenSSL 准备静态库版本，并通过 `OPENSSL_ROOT_DIR` 指向安装根目录。
- `libuv` 和 `nlohmann_json` 可以由 `TX_FETCH_DEPS=ON` 下载到 `.deps/`，也可以手工指定本地路径。
- 如果你用的是 MinGW，也可以保留 `TX_STATIC_CXX_RUNTIME=ON`，让 `libgcc/libstdc++` 尽量静态链接。

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
  -DANDROID_STL=c++_static \
  -DTX_FETCH_DEPS=ON \
  -DTX_LINK_STATIC_DEPS=ON \
  -DOPENSSL_ROOT_DIR=/path/to/android/openssl
cmake --build build-android -j$(nproc)
```

生成产物位于：

```text
build-android/lib/libtx.so
```

Android 模式下，第三方依赖会优先静态链接进 `libtx.so`，并使用 NDK 的 `c++_static`。

## 测试

Debug 构建并运行测试：

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DTX_BUILD_TESTS=ON
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
```

当前测试覆盖 crypto、GeoIP、GeoSite、SOCKS5、HTTP proxy、router 和 tunnel 等模块。

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

把输出的 `base64:...` 同时填入服务端 `secret` 和客户端 `server.secret`。

### 服务端配置

示例：

```json
{
    "listen": {
        "host": "0.0.0.0",
        "port": 443
    },
    "secret": "base64:REPLACE_WITH_GEN_SECRET_OUTPUT",
    "cipher": "aes-256-gcm",
    "log_level": "info"
}
```

字段说明：

- `listen.host`：服务端监听地址。
- `listen.port`：服务端监听端口。
- `secret`：客户端与服务端共享的高熵 PSK，支持 `base64:`、`hex:`、`uuid-v4:` 前缀；推荐使用 `--gen-secret` 生成 `base64:`。
- `cipher`：隧道 AEAD 算法，可选 `aes-256-gcm` 或 `chacha20-poly1305`。
- `log_level`：日志级别，可选 `debug`、`info`、`warn`、`error`。

### 客户端配置

示例：

```json
{
    "listen": {
        "http": {"host": "127.0.0.1", "port": 8080},
        "socks5": {"host": "127.0.0.1", "port": 1080}
    },
    "server": {
        "host": "your-server.example.com",
        "port": 443,
        "secret": "base64:REPLACE_WITH_GEN_SECRET_OUTPUT",
        "cipher": "aes-256-gcm"
    },
    "geo": {
        "geoip_path": "geoip.dat",
        "geosite_path": "geosite.dat",
        "direct_geoip": ["cn", "private"],
        "direct_geosite": ["cn"]
    },
    "log_level": "info"
}
```

字段说明：

- `listen.http`：本地 HTTP 代理监听地址和端口。
- `listen.socks5`：本地 SOCKS5 代理监听地址和端口。
- `server.host`：远端 `tx_server` 地址。
- `server.port`：远端 `tx_server` 端口。
- `server.secret`：与服务端一致的高熵 PSK。
- `server.cipher`：与服务端一致的 AEAD 算法，可选 `aes-256-gcm` 或 `chacha20-poly1305`。
- `geo.geoip_path`：GeoIP 数据文件路径。
- `geo.geosite_path`：GeoSite 数据文件路径。
- `geo.direct_geoip`：命中后直连的 GeoIP 标签。
- `geo.direct_geosite`：命中后直连的 GeoSite 标签。
- `log_level`：日志级别，可选 `debug`、`info`、`warn`、`error`。

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

### OpenSSL 被链接成动态库

确认以下条件：

- `TX_LINK_STATIC_DEPS=ON`
- 提供的是静态版 OpenSSL 安装目录
- `OPENSSL_ROOT_DIR` 指向包含静态库的根目录

例如：

```sh
cmake -B build -DTX_LINK_STATIC_DEPS=ON -DOPENSSL_ROOT_DIR=/path/to/openssl
```

### 静态 OpenSSL 链接时报缺少 zlib / zstd

当前构建会自动尝试补齐这两个常见传递依赖；如果仍然失败，通常说明你的 OpenSSL 是用额外压缩后端构建的，但这些静态库没有安装到可搜索路径。此时需要：

- 安装对应静态库；
- 或把它们放到工具链默认搜索路径；
- 或关闭 `TX_LINK_STATIC_DEPS`，退回动态依赖。

### 端口监听失败

检查端口是否被占用，或当前用户是否有权限监听该端口。Linux 上监听 1024 以下端口通常需要 root 权限或额外 capability。开发调试时可以先改用 8443、18080、11080 等高端口。

## 开发说明

- 公共 API 放在 `include/tx/`。
- 实现代码按模块放在 `src/`。
- 新测试放在 `tests/test_<name>.cpp`，并在 `tests/CMakeLists.txt` 中通过 `tx_add_test(<name>)` 注册。
- 保持 C++14 兼容，优先沿用现有直接、轻量的代码风格。
