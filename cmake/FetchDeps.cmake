include_guard(GLOBAL)

include(FetchContent)

option(TX_FETCH_DEPS "Download missing third-party dependencies during configure" ON)
set(TX_DEPS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.deps" CACHE PATH "Directory for locally downloaded third-party dependencies")

if(ANDROID)
    set(TX_DEPS_TRIPLET "${CMAKE_SYSTEM_NAME}-${ANDROID_ABI}")
else()
    set(TX_DEPS_TRIPLET "${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR}")
endif()
set(_tx_deps_generator "${CMAKE_GENERATOR}")
string(REPLACE " " "-" _tx_deps_generator "${_tx_deps_generator}")
string(REPLACE "/" "-" _tx_deps_generator "${_tx_deps_generator}")
set(FETCHCONTENT_BASE_DIR "${TX_DEPS_ROOT}/${TX_DEPS_TRIPLET}/${_tx_deps_generator}/fetchcontent" CACHE PATH "FetchContent dependency directory" FORCE)

function(tx_library_suffixes out_var)
    if(WIN32)
        set(static_suffixes .lib .a)
        set(shared_suffixes .dll.a .lib)
    elseif(APPLE)
        set(static_suffixes .a)
        set(shared_suffixes .dylib .so)
    else()
        set(static_suffixes .a)
        set(shared_suffixes .so)
    endif()

    if(TX_LINK_STATIC_DEPS)
        set(${out_var} ${static_suffixes} PARENT_SCOPE)
    else()
        set(${out_var} ${CMAKE_FIND_LIBRARY_SUFFIXES} PARENT_SCOPE)
    endif()
endfunction()

function(tx_find_openssl)
    if(TX_LINK_STATIC_DEPS)
        set(OPENSSL_USE_STATIC_LIBS TRUE)
    endif()

    find_package(OpenSSL REQUIRED)
    message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")
endfunction()

function(tx_find_libuv)
    tx_library_suffixes(TX_DEP_LIBRARY_SUFFIXES)
    set(_saved_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
    set(CMAKE_FIND_LIBRARY_SUFFIXES ${TX_DEP_LIBRARY_SUFFIXES})

    find_path(LIBUV_INCLUDE_DIR uv.h)
    find_library(LIBUV_LIBRARY NAMES uv_a libuv_a uv libuv)

    set(CMAKE_FIND_LIBRARY_SUFFIXES ${_saved_suffixes})

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
        elseif(NOT TX_LINK_STATIC_DEPS AND TARGET uv)
            add_library(tx::libuv ALIAS uv)
            message(STATUS "Found libuv: uv target")
            return()
        elseif(NOT TX_LINK_STATIC_DEPS AND TARGET libuv::uv)
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
            "${TX_DEP_LIBRARY_SUFFIXES} library files, provide LIBUV_INCLUDE_DIR "
            "and LIBUV_LIBRARY to CMake, or configure with TX_FETCH_DEPS=ON.")
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

function(tx_find_optional_static_library target_name library_var)
    if(NOT TX_LINK_STATIC_DEPS)
        return()
    endif()

    if(TARGET ${target_name})
        return()
    endif()

    tx_library_suffixes(TX_DEP_LIBRARY_SUFFIXES)
    set(_saved_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
    set(CMAKE_FIND_LIBRARY_SUFFIXES ${TX_DEP_LIBRARY_SUFFIXES})
    find_library(${library_var} NAMES ${ARGN})
    set(CMAKE_FIND_LIBRARY_SUFFIXES ${_saved_suffixes})

    if(${library_var})
        add_library(${target_name} UNKNOWN IMPORTED)
        set_target_properties(${target_name} PROPERTIES
            IMPORTED_LOCATION "${${library_var}}"
        )
        message(STATUS "Found ${target_name}: ${${library_var}}")
    endif()
endfunction()

function(tx_find_static_openssl_deps)
    if(NOT TX_LINK_STATIC_DEPS)
        return()
    endif()

    set(TX_OPENSSL_STATIC_EXTRA_LIBS "")

    set(ZLIB_USE_STATIC_LIBS ON)
    find_package(ZLIB QUIET)
    if(ZLIB_FOUND)
        list(APPEND TX_OPENSSL_STATIC_EXTRA_LIBS ZLIB::ZLIB)
    endif()

    tx_find_optional_static_library(tx::zstd ZSTD_LIBRARY zstd libzstd)
    if(TARGET tx::zstd)
        list(APPEND TX_OPENSSL_STATIC_EXTRA_LIBS tx::zstd)
    endif()

    set(TX_OPENSSL_STATIC_EXTRA_LIBS "${TX_OPENSSL_STATIC_EXTRA_LIBS}" PARENT_SCOPE)
endfunction()

tx_find_libuv()
tx_find_nlohmann_json()
