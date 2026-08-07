#pragma once

#include "tx/net/dns_network_provider.h"

#include <uv.h>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace tx {

class DnsResolver {
public:
    using ProtectCallback = std::function<bool(int)>;
    using ResolveCallback = std::function<void(std::vector<uint8_t>)>;
    using HostResolveHook = std::function<std::vector<std::string>(const std::string&, int)>;
    using QueryHook = std::function<std::vector<uint8_t>(const uint8_t*, size_t)>;
    // Returns true for an address that must not be exposed by this resolver.
    // It is applied to upstream addresses, A/AAAA records and numeric hosts.
    using AddressFilterHook = std::function<bool(const std::string&)>;
    // Runs on the owning loop and must eventually invoke the callback.  This
    // is used when DNS itself has to travel through an already-established
    // proxy rather than being sent by a local UDP socket.
    using AsyncQueryHook = std::function<void(std::vector<uint8_t>, ResolveCallback)>;
    using HostResolveCallback = std::function<void(std::vector<std::string>)>;

    explicit DnsResolver(uv_loop_t* loop);
    void configure(std::vector<std::string> upstreams,
                   ProtectCallback protector, uint32_t bypass_mark,
                   HostResolveHook host_resolver = HostResolveHook(),
                   QueryHook query_hook = QueryHook(),
                   AsyncQueryHook async_query_hook = AsyncQueryHook(),
                   std::shared_ptr<DnsNetworkProvider> network_provider = nullptr,
                   AddressFilterHook address_filter = AddressFilterHook());
    void resolve(const uint8_t* query, size_t query_len, ResolveCallback callback);
    void resolve_host(const std::string& host, int family, HostResolveCallback callback);
    // Shared by alternate transports (for example Android's TX tunnel DNS
    // path) so they apply the same response authentication as socket DNS.
    static bool response_matches_query(const std::vector<uint8_t>& query,
                                       const std::vector<uint8_t>& response);
    static bool response_is_truncated(const std::vector<uint8_t>& response);
    bool can_query() const {
        return static_cast<bool>(async_query_hook_) || static_cast<bool>(query_hook_) ||
               static_cast<bool>(network_provider_) || !upstreams_.empty();
    }
    bool has_host_hook() const { return static_cast<bool>(host_resolver_); }
    void cancel_pending();

private:
    struct Request;
    struct HostRequest;
    static void on_work(uv_work_t* work);
    static void after_work(uv_work_t* work, int status);
    static void on_host_work(uv_work_t* work);
    static void after_host_work(uv_work_t* work, int status);
    uv_loop_t* loop_;
    std::vector<std::string> upstreams_;
    ProtectCallback protector_;
    HostResolveHook host_resolver_;
    QueryHook query_hook_;
    AsyncQueryHook async_query_hook_;
    std::shared_ptr<DnsNetworkProvider> network_provider_;
    DnsSocketBinding static_socket_binding_;
    AddressFilterHook address_filter_;
    uint64_t generation_ = 1;
};

} // namespace tx
