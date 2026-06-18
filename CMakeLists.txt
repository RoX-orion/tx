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
option(TX_BUILD_TESTS "Build unit tests" ON)
option(TX_BUILD_SHARED "Build shared library (for Android)" OFF)

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
find_package(OpenSSL REQUIRED)

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

# Core static library
add_library(tx_core STATIC ${ALL_LIB_SOURCES})
target_link_libraries(tx_core PUBLIC
    uv_a        # libuv static
    OpenSSL::SSL OpenSSL::Crypto
    nlohmann_json::nlohmann_json
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
    target_link_libraries(tx_core PUBLIC ws2_32 shlwapi userenv advapi32 iphlpapi psapi shell32)
endif()

# Client executable
add_executable(tx_client src/client/main.cpp src/client/client_app.cpp src/client/config.cpp)
target_link_libraries(tx_client PRIVATE tx_core)
target_include_directories(tx_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/client)

# Server executable
add_executable(tx_server src/server/main.cpp src/server/server_app.cpp src/server/config.cpp)
target_link_libraries(tx_server PRIVATE tx_core)
target_include_directories(tx_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/server)

# Android shared library
if(TX_BUILD_SHARED OR ANDROID)
    add_library(tx_shared SHARED src/lib/tx_api.cpp)
    target_link_libraries(tx_shared PRIVATE tx_core)
    target_include_directories(tx_shared PRIVATE
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
install(TARGETS tx_client tx_server RUNTIME DESTINATION bin)
if(TX_BUILD_SHARED OR ANDROID)
    install(TARGETS tx_shared LIBRARY DESTINATION lib)
endif()
install(DIRECTORY include/tx DESTINATION include)

# Print build info
tx_print_build_info()
