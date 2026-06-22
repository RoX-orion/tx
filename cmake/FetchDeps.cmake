include_guard(GLOBAL)

include(FetchContent)

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

function(tx_find_libuv)
    tx_library_suffixes(TX_DEP_LIBRARY_SUFFIXES)
    set(_saved_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
    set(CMAKE_FIND_LIBRARY_SUFFIXES ${TX_DEP_LIBRARY_SUFFIXES})

    find_path(LIBUV_INCLUDE_DIR uv.h)
    find_library(LIBUV_LIBRARY NAMES uv_a libuv_a uv libuv)

    set(CMAKE_FIND_LIBRARY_SUFFIXES ${_saved_suffixes})

    if(NOT LIBUV_INCLUDE_DIR OR NOT LIBUV_LIBRARY)
        message(FATAL_ERROR
            "libuv development files were not found. Install libuv headers and "
            "${TX_DEP_LIBRARY_SUFFIXES} library files, or provide LIBUV_INCLUDE_DIR "
            "and LIBUV_LIBRARY to CMake.")
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
    find_package(nlohmann_json QUIET)
    if(nlohmann_json_FOUND)
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

    message(FATAL_ERROR
        "nlohmann_json development files were not found. Install nlohmann_json "
        "(for example: sudo apt install nlohmann-json3-dev) or provide "
        "NLOHMANN_JSON_INCLUDE_DIR to CMake.")
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
