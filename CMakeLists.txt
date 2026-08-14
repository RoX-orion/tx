cmake_minimum_required(VERSION 3.25.1)
project(tx VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Position independent code for shared library (Android)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Options
option(TX_BUILD_APPS "Build tx_client and tx_server executables" ON)
option(TX_BUILD_TESTS "Build unit tests" ON)
option(TX_BUILD_SHARED "Build shared library (for Android)" OFF)

if(ANDROID)
    set(TX_BUILD_APPS OFF CACHE BOOL "Build tx_client and tx_server executables" FORCE)
    set(TX_BUILD_SHARED ON CACHE BOOL "Build shared library (for Android)" FORCE)
    set(TX_BUILD_TESTS OFF CACHE BOOL "Build unit tests" FORCE)
endif()

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif()

# Platform detection. Keep these branches mutually exclusive: Apple and other
# POSIX platforms must never compile Linux-only TUN/nftables code.
if(ANDROID)
    add_compile_definitions(TX_PLATFORM_ANDROID TX_PLATFORM_POSIX)
elseif(WIN32)
    add_compile_definitions(TX_PLATFORM_WINDOWS)
elseif(APPLE)
    add_compile_definitions(TX_PLATFORM_APPLE TX_PLATFORM_POSIX)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_compile_definitions(TX_PLATFORM_LINUX TX_PLATFORM_POSIX)
endif()

# Compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-O2 -DNDEBUG)
    endif()
elseif(MSVC)
    add_compile_options(/W3)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(/O2)
        add_compile_definitions(NDEBUG)
    endif()
elseif(MINGW)
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-O2)
        add_compile_definitions(NDEBUG)
    endif()
endif()

# Include utility modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(TxUtils)
include(FetchDeps)

# Find OpenSSL
tx_find_openssl()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
set(TX_GENERATED_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${TX_GENERATED_INCLUDE_DIR}/tx)
configure_file(cmake/tx_version.h.in
               ${TX_GENERATED_INCLUDE_DIR}/tx/version.h @ONLY)
include_directories(${TX_GENERATED_INCLUDE_DIR})

# Collect common sources
file(GLOB COMMON_SOURCES CONFIGURE_DEPENDS src/common/*.cpp)
file(GLOB NET_SOURCES CONFIGURE_DEPENDS src/net/*.cpp)
file(GLOB LWIP_NET_SOURCES CONFIGURE_DEPENDS src/net/lwip/*.cpp)
file(GLOB CRYPTO_SOURCES CONFIGURE_DEPENDS src/crypto/*.cpp)
file(GLOB PROTOCOL_SOURCES CONFIGURE_DEPENDS src/protocol/*.cpp)
file(GLOB GEO_SOURCES CONFIGURE_DEPENDS src/geo/*.cpp)
file(GLOB ROUTER_SOURCES CONFIGURE_DEPENDS src/router/*.cpp)

set(ALL_LIB_SOURCES
    ${COMMON_SOURCES}
    ${NET_SOURCES}
    ${LWIP_NET_SOURCES}
    ${CRYPTO_SOURCES}
    ${PROTOCOL_SOURCES}
    ${GEO_SOURCES}
    ${ROUTER_SOURCES}
)

set(TX_CLIENT_APP_SOURCES
    src/client/client_app.cpp
    src/client/config.cpp
    src/client/platform_tun.cpp
)

set(TX_SERVER_APP_SOURCES
    src/server/server_app.cpp
    src/server/config.cpp
)

# Core static library
add_library(tx_core STATIC ${ALL_LIB_SOURCES})
target_link_libraries(tx_core PUBLIC
    tx::libuv
    tx::hev_lwip
    OpenSSL::SSL OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)
target_include_directories(tx_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Platform-specific link libraries
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT ANDROID)
    target_link_libraries(tx_core PUBLIC pthread dl)
elseif(ANDROID)
    target_link_libraries(tx_core PUBLIC log c++_shared)
elseif(WIN32 OR MINGW)
    target_link_libraries(tx_core PUBLIC ws2_32 shlwapi userenv advapi32 iphlpapi psapi shell32 crypt32 bcrypt)
endif()

# Client executable
if(TX_BUILD_APPS)
    add_executable(tx_client src/client/main.cpp ${TX_CLIENT_APP_SOURCES})
    target_link_libraries(tx_client PRIVATE tx_core)
    target_include_directories(tx_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/client)

    add_executable(tx_server src/server/main.cpp ${TX_SERVER_APP_SOURCES})
    target_link_libraries(tx_server PRIVATE tx_core)
    target_include_directories(tx_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/server)
endif()

# Android shared library
if(TX_BUILD_SHARED OR ANDROID)
    add_library(tx_shared SHARED
        src/lib/tx_api.cpp
        ${TX_CLIENT_APP_SOURCES}
        ${TX_SERVER_APP_SOURCES}
    )
    target_link_libraries(tx_shared PRIVATE tx_core)
    target_compile_definitions(tx_shared PRIVATE TX_EXPORTS)
    target_include_directories(tx_shared PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib
        ${CMAKE_CURRENT_SOURCE_DIR}/src/client
        ${CMAKE_CURRENT_SOURCE_DIR}/src/server
    )
    set_target_properties(tx_shared PROPERTIES
        OUTPUT_NAME "tx"
        C_VISIBILITY_PRESET hidden
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES
    )
    if(ANDROID OR CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # Keep implementation symbols pulled from static archives local to
        # libtx.so. Android also loads tun2socks, which embeds a differently
        # configured lwIP; exporting both copies lets the dynamic linker bind
        # tun2socks calls to TX's incompatible lwIP ABI.
        target_link_options(tx_shared PRIVATE "LINKER:--exclude-libs,ALL")
    endif()
endif()

# Tests
if(TX_BUILD_TESTS AND NOT ANDROID)
    enable_testing()
    add_subdirectory(tests)
endif()

# Install
if(TX_BUILD_APPS)
    install(TARGETS tx_client tx_server RUNTIME DESTINATION bin)
endif()
if(TX_BUILD_SHARED OR ANDROID)
    install(TARGETS tx_shared LIBRARY DESTINATION lib)
    install(FILES src/lib/tx_api.h DESTINATION include/tx)
    install(FILES ${TX_GENERATED_INCLUDE_DIR}/tx/version.h DESTINATION include/tx)
endif()
install(DIRECTORY include/tx DESTINATION include)

# Print build info
tx_print_build_info()
