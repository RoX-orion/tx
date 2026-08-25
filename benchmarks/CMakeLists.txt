function(tx_add_benchmark name)
    add_executable(bench_${name} bench_${name}.cpp)
    target_link_libraries(bench_${name} PRIVATE tx_core)
endfunction()

tx_add_benchmark(fake_ip_dns)
tx_add_benchmark(tunnel_codec)
tx_add_benchmark(tun_hotpath)
