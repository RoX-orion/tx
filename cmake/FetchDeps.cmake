include_guard(GLOBAL)

include(FetchContent)

option(TX_FETCH_DEPS "Download missing third-party dependencies during configure" ON)
set(TX_DEPS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.deps" CACHE PATH "Directory for locally downloaded third-party dependencies")
set(TX_HEV_LWIP_SOURCE_DIR "" CACHE PATH
    "Local HEV lwIP source tree (must contain src/core, src/include and src/ports/include)")

if(ANDROID)
    set(TX_DEPS_TRIPLET "${CMAKE_SYSTEM_NAME}-${ANDROID_ABI}")
else()
    set(TX_DEPS_TRIPLET "${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
endif()
set(_tx_deps_generator "${CMAKE_GENERATOR}")
string(REPLACE " " "-" _tx_deps_generator "${_tx_deps_generator}")
string(REPLACE "/" "-" _tx_deps_generator "${_tx_deps_generator}")
set(FETCHCONTENT_BASE_DIR "${TX_DEPS_ROOT}/${TX_DEPS_TRIPLET}/${_tx_deps_generator}/fetchcontent" CACHE PATH "FetchContent dependency directory" FORCE)

function(tx_find_openssl)
    set(OPENSSL_USE_STATIC_LIBS FALSE)
    find_package(OpenSSL REQUIRED)
    message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")
endfunction()

function(tx_find_libuv)
    find_path(LIBUV_INCLUDE_DIR uv.h)
    find_library(LIBUV_LIBRARY NAMES uv_a libuv_a uv libuv)

    if(NOT LIBUV_INCLUDE_DIR OR NOT LIBUV_LIBRARY)
        find_package(libuv CONFIG QUIET)
        if(TARGET uv_a)
            add_library(tx::libuv ALIAS uv_a)
            message(STATUS "Found libuv: uv_a target")
            return()
        elseif(TARGET libuv::uv_a)
            add_library(tx::libuv ALIAS libuv::uv_a)
            message(STATUS "Found libuv: libuv::uv_a target")
            return()
        elseif(TARGET uv)
            add_library(tx::libuv ALIAS uv)
            message(STATUS "Found libuv: uv target")
            return()
        elseif(TARGET libuv::uv)
            add_library(tx::libuv ALIAS libuv::uv)
            message(STATUS "Found libuv: libuv::uv target")
            return()
        endif()
    endif()

    if((NOT LIBUV_INCLUDE_DIR OR NOT LIBUV_LIBRARY) AND TX_FETCH_DEPS)
        message(STATUS "libuv not found; fetching it")
        set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
        set(LIBUV_BUILD_TESTS OFF CACHE BOOL "" FORCE)
        set(LIBUV_BUILD_BENCH OFF CACHE BOOL "" FORCE)
        set(LIBUV_BUILD_SHARED OFF CACHE BOOL "" FORCE)
        FetchContent_Declare(
            libuv
            URL https://github.com/libuv/libuv/archive/refs/tags/v1.48.0.tar.gz
            URL_HASH SHA256=8c253adb0f800926a6cbd1c6576abae0bc8eb86a4f891049b72f9e5b7dc58f33
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )
        FetchContent_MakeAvailable(libuv)

        if(TARGET uv_a)
            add_library(tx::libuv ALIAS uv_a)
            message(STATUS "Fetched libuv: uv_a target")
            return()
        elseif(TARGET libuv::uv_a)
            add_library(tx::libuv ALIAS libuv::uv_a)
            message(STATUS "Fetched libuv: libuv::uv_a target")
            return()
        endif()
    endif()

    if(NOT LIBUV_INCLUDE_DIR OR NOT LIBUV_LIBRARY)
        message(FATAL_ERROR
            "libuv development files were not found. Install libuv headers and "
            "library files, provide LIBUV_INCLUDE_DIR and LIBUV_LIBRARY to CMake, "
            "or configure with TX_FETCH_DEPS=ON.")
    endif()

    if(NOT TARGET tx::libuv)
        add_library(tx::libuv UNKNOWN IMPORTED)
        set_target_properties(tx::libuv PROPERTIES
            IMPORTED_LOCATION "${LIBUV_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${LIBUV_INCLUDE_DIR}"
        )
    endif()

    message(STATUS "Found libuv: ${LIBUV_LIBRARY}")
endfunction()

function(tx_find_nlohmann_json)
    find_package(nlohmann_json CONFIG QUIET)
    if(TARGET nlohmann_json::nlohmann_json)
        message(STATUS "Found nlohmann_json: package config")
        return()
    endif()

    find_path(NLOHMANN_JSON_INCLUDE_DIR nlohmann/json.hpp)
    if(NLOHMANN_JSON_INCLUDE_DIR)
        if(NOT TARGET nlohmann_json::nlohmann_json)
            add_library(nlohmann_json::nlohmann_json INTERFACE IMPORTED)
            set_target_properties(nlohmann_json::nlohmann_json PROPERTIES
                INTERFACE_INCLUDE_DIRECTORIES "${NLOHMANN_JSON_INCLUDE_DIR}"
            )
        endif()
        message(STATUS "Found nlohmann_json: ${NLOHMANN_JSON_INCLUDE_DIR}")
        return()
    endif()

    if(TX_FETCH_DEPS)
        message(STATUS "nlohmann_json not found; fetching it")
        FetchContent_Declare(
            nlohmann_json
            URL https://github.com/nlohmann/json/archive/refs/tags/v3.11.3.tar.gz
            URL_HASH SHA256=0d8ef5af7f9794e3263480193c491549b2ba6cc74bb018906202ada498a79406
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )
        FetchContent_MakeAvailable(nlohmann_json)
        return()
    endif()

    message(FATAL_ERROR
        "nlohmann_json development files were not found. Install nlohmann_json "
        "(for example: sudo apt install nlohmann-json3-dev) or provide "
        "NLOHMANN_JSON_INCLUDE_DIR to CMake, or configure with TX_FETCH_DEPS=ON.")
endfunction()

function(tx_find_hev_lwip)
    if(TARGET tx::hev_lwip)
        message(STATUS "Using caller-provided tx::hev_lwip target")
        return()
    endif()

    if(TX_HEV_LWIP_SOURCE_DIR)
        get_filename_component(_tx_hev_source_dir
            "${TX_HEV_LWIP_SOURCE_DIR}" ABSOLUTE BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
        foreach(_tx_required_dir src/core src/include src/ports/include)
            if(NOT IS_DIRECTORY "${_tx_hev_source_dir}/${_tx_required_dir}")
                message(FATAL_ERROR
                    "TX_HEV_LWIP_SOURCE_DIR='${_tx_hev_source_dir}' is not a usable "
                    "HEV lwIP source tree: missing ${_tx_required_dir}.")
            endif()
        endforeach()
        message(STATUS "Using local HEV lwIP: ${_tx_hev_source_dir}")
    elseif(TX_FETCH_DEPS)
        FetchContent_Declare(
            hev_lwip
            URL https://github.com/heiher/lwip/archive/cd3007df7047555399a04e6e40214accfae0d324.tar.gz
            URL_HASH SHA256=83a7154efaf0a441d79bf208613943bc9f013c5250dcd3794a043dd76de5b8fe
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )
        FetchContent_MakeAvailable(hev_lwip)
        set(_tx_hev_source_dir "${hev_lwip_SOURCE_DIR}")
    else()
        message(FATAL_ERROR
            "HEV lwIP was not provided. Define a tx::hev_lwip target, set "
            "TX_HEV_LWIP_SOURCE_DIR to a local source tree, or configure with "
            "TX_FETCH_DEPS=ON.")
    endif()

    file(GLOB HEV_LWIP_CORE_SOURCES CONFIGURE_DEPENDS
        "${_tx_hev_source_dir}/src/core/*.c"
        "${_tx_hev_source_dir}/src/core/ipv4/*.c"
        "${_tx_hev_source_dir}/src/core/ipv6/*.c"
    )
    # altcp is not used; raw tcp*.c is required by the unified TUN frontend.
    list(FILTER HEV_LWIP_CORE_SOURCES EXCLUDE REGEX "/altcp.*\\.c$")
    add_library(tx_hev_lwip STATIC ${HEV_LWIP_CORE_SOURCES})
    add_library(tx::hev_lwip ALIAS tx_hev_lwip)
    target_include_directories(tx_hev_lwip
        PUBLIC
            "${CMAKE_CURRENT_SOURCE_DIR}/src/net/lwip/port"
            "${_tx_hev_source_dir}/src/include"
            "${_tx_hev_source_dir}/src/ports/include"
    )
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(tx_hev_lwip PRIVATE -w)
    endif()
    if(ANDROID)
        # Match HEV lwIP's Android.mk and avoid NDK libc type redefinitions.
        target_compile_definitions(tx_hev_lwip PUBLIC
            FD_SET_DEFINED SOCKLEN_T_DEFINED)
    endif()
endfunction()

tx_find_libuv()
tx_find_nlohmann_json()
tx_find_hev_lwip()
