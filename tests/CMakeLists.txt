enable_testing()

# Test helper: create a test executable
function(tx_add_test name)
    add_executable(test_${name} test_${name}.cpp)
    target_link_libraries(test_${name} PRIVATE tx_core)
    add_test(NAME test_${name} COMMAND test_${name})
endfunction()

tx_add_test(crypto)
tx_add_test(geoip)
tx_add_test(geosite)
tx_add_test(socks5)
tx_add_test(http_proxy)
tx_add_test(router)
tx_add_test(tunnel)
