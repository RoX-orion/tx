enable_testing()

# Test helper: create a test executable
function(tx_add_test name)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_${name}.cpp")
        message(WARNING "Skipping missing test source: test_${name}.cpp")
        return()
    endif()

    add_executable(test_${name} test_${name}.cpp)
    target_link_libraries(test_${name} PRIVATE tx_core)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(test_${name} PRIVATE -UNDEBUG)
    elseif(MSVC)
        target_compile_options(test_${name} PRIVATE /UNDEBUG)
    endif()
    add_test(NAME test_${name} COMMAND test_${name})
endfunction()

tx_add_test(crypto)
tx_add_test(geoip)
tx_add_test(geosite)
tx_add_test(socks5)
tx_add_test(http_proxy)
tx_add_test(router)
tx_add_test(tunnel)
tx_add_test(tun_packet)
tx_add_test(lwip_udp_stack)
tx_add_test(socket_protector)
tx_add_test(udp_flow_timeout)
tx_add_test(fake_ip_dns)
tx_add_test(lwip_tcp_stack)
tx_add_test(tcp_session_callbacks)
tx_add_test(dns_resolver)
tx_add_test(tls_sni)
tx_add_test(quic_sni)
tx_add_test(client_config)
target_sources(test_client_config PRIVATE ../src/client/config.cpp)
target_include_directories(test_client_config PRIVATE ../src/client)
tx_add_test(server_config)
target_sources(test_server_config PRIVATE ../src/server/config.cpp)
target_include_directories(test_server_config PRIVATE ../src/server)
tx_add_test(server_udp)
target_sources(test_server_udp PRIVATE
    ../src/server/server_app.cpp
    ../src/server/config.cpp)
target_include_directories(test_server_udp PRIVATE ../src/server)
tx_add_test(client_tunnel_dns)
target_sources(test_client_tunnel_dns PRIVATE
    ../src/client/client_app.cpp
    ../src/client/config.cpp
    ../src/client/platform_tun.cpp
    ../src/server/server_app.cpp
    ../src/server/config.cpp)
target_include_directories(test_client_tunnel_dns PRIVATE
    ../src/client
    ../src/server)
target_compile_definitions(test_client_tunnel_dns PRIVATE TX_PLATFORM_ANDROID=1)
set_tests_properties(test_client_tunnel_dns PROPERTIES TIMEOUT 20)
tx_add_test(client_quic_routing)
target_sources(test_client_quic_routing PRIVATE
    ../src/client/client_app.cpp
    ../src/client/config.cpp
    ../src/client/platform_tun.cpp)
target_include_directories(test_client_quic_routing PRIVATE ../src/client)
