cmake_minimum_required(VERSION 3.25.1)
project(tx VERSION 1.0.0 LANGUAGES C CXX)

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
option(TX_LINK_STATIC_DEPS "Prefer static third-party dependencies" ON)
option(TX_STATIC_CXX_RUNTIME "Link libgcc/libstdc++ statically when supported" ON)
option(TX_STATIC_MSVC_RUNTIME "Link the static MSVC runtime when building with MSVC" ON)

if(ANDROID)
    set(TX_BUILD_APPS OFF CACHE BOOL "Build tx_client and tx_server executables" FORCE)
    set(TX_BUILD_SHARED ON CACHE BOOL "Build shared library (for Android)" FORCE)
    set(TX_BUILD_TESTS OFF CACHE BOOL "Build unit tests" FORCE)
endif()

if(MSVC AND TX_STATIC_MSVC_RUNTIME)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Platform detection
if(WIN32)
    add_definitions(-DTX_PLATFORM_WINDOWS)
elseif(ANDROID)
    add_definitions(-DTX_PLATFORM_ANDROID)
elseif(UNIX)
    add_definitions(-DTX_PLATFORM_LINUX)
endif()

# Compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-O2 -DNDEBUG)
    endif()
elseif(MSVC OR MINGW)
    add_compile_options(-W3)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(-O2 -DNDEBUG)
    endif()
endif()

# Include utility modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(TxUtils)
include(FetchDeps)

# Find OpenSSL
if(TX_LINK_STATIC_DEPS)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()
find_package(OpenSSL REQUIRED)
tx_find_static_openssl_deps()

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Collect common sources
file(GLOB COMMON_SOURCES src/common/*.cpp)
file(GLOB NET_SOURCES src/net/*.cpp)
file(GLOB CRYPTO_SOURCES src/crypto/*.cpp)
file(GLOB PROTOCOL_SOURCES src/protocol/*.cpp)
file(GLOB GEO_SOURCES src/geo/*.cpp)
file(GLOB ROUTER_SOURCES src/router/*.cpp)

set(ALL_LIB_SOURCES
    ${COMMON_SOURCES}
    ${NET_SOURCES}
    ${CRYPTO_SOURCES}
    ${PROTOCOL_SOURCES}
    ${GEO_SOURCES}
    ${ROUTER_SOURCES}
)

set(TX_CLIENT_APP_SOURCES
    src/client/client_app.cpp
    src/client/config.cpp
)

set(TX_SERVER_APP_SOURCES
    src/server/server_app.cpp
    src/server/config.cpp
)

# Core static library
add_library(tx_core STATIC ${ALL_LIB_SOURCES})
target_link_libraries(tx_core PUBLIC
    tx::libuv
    OpenSSL::SSL OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    ${TX_OPENSSL_STATIC_EXTRA_LIBS}
)
target_include_directories(tx_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Platform-specific link libraries
if(UNIX AND NOT ANDROID)
    target_link_libraries(tx_core PUBLIC pthread dl)
elseif(ANDROID)
    target_link_libraries(tx_core PUBLIC log)
elseif(WIN32 OR MINGW)
    target_link_libraries(tx_core PUBLIC ws2_32 shlwapi userenv advapi32 iphlpapi psapi shell32 crypt32 bcrypt)
endif()

if(TX_STATIC_CXX_RUNTIME AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang" AND NOT ANDROID)
    target_link_options(tx_core PUBLIC -static-libgcc -static-libstdc++)
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
    target_include_directories(tx_shared PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/lib
        ${CMAKE_CURRENT_SOURCE_DIR}/src/client
        ${CMAKE_CURRENT_SOURCE_DIR}/src/server
    )
    set_target_properties(tx_shared PROPERTIES OUTPUT_NAME "tx")
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
endif()
install(DIRECTORY include/tx DESTINATION include)

# Print build info
tx_print_build_info()
