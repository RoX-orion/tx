#include "tx/net/lwip_udp_stack.h"

#include <atomic>
#include <chrono>
#include <openssl/rand.h>

extern "C" {
#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/ip4_addr.h"
#include "lwip/ip6_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
#include "lwip/udp.h"
}

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

extern "C" u32_t sys_now(void) {
    using namespace std::chrono;
    return static_cast<u32_t>(duration_cast<milliseconds>(
        steady_clock::now().time_since_epoch()).count());
}

extern "C" unsigned int lwip_port_rand(void) {
    unsigned int value = 0;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) == 1) {
        return value;
    }
    // OpenSSL entropy failure is exceptional. Keep a thread-safe fallback so
    // lwIP never reuses the old fixed process-wide seed.
    static std::atomic<unsigned int> state{
        static_cast<unsigned int>(std::chrono::steady_clock::now()
                                      .time_since_epoch().count())};
    unsigned int previous = state.load(std::memory_order_relaxed);
    unsigned int next = 0;
    do {
        next = previous;
        next ^= next << 13;
        next ^= next >> 17;
        next ^= next << 5;
    } while (!state.compare_exchange_weak(previous, next,
                                          std::memory_order_relaxed,
                                          std::memory_order_relaxed));
    return next;
}

namespace tx {
namespace {

constexpr size_t kMaxTcpPendingWrite = 16 * 1024 * 1024;
constexpr size_t kMaxTcpPendingRead = 4 * 1024 * 1024;
std::once_flag g_lwip_init_once;
// HEV lwIP keeps global protocol state and is not safe to drive from two
// independent ClientApp loops. Fail initialization explicitly instead of
// allowing a second TUN instance to corrupt the first one's state.
std::atomic<LwipUdpStack*> g_active_lwip_stack{nullptr};

uint8_t ip_protocol(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0;
    const uint8_t version = data[0] >> 4;
    if (version == 4) {
        if (len < 20) return 0;
        const size_t header_len = static_cast<size_t>(data[0] & 0x0f) * 4;
        return header_len >= 20 && header_len <= len ? data[9] : 0;
    }
    if (version != 6 || len < 40) return 0;
    uint8_t next = data[6];
    size_t offset = 40;
    while (next != IP6_NEXTH_TCP && next != IP6_NEXTH_UDP) {
        if (next == IP6_NEXTH_NONE || offset + 2 > len) return 0;
        const uint8_t following = data[offset];
        size_t extension_len = 0;
        switch (next) {
            case IP6_NEXTH_HOPBYHOP:
            case IP6_NEXTH_ROUTING:
            case IP6_NEXTH_DESTOPTS:
                extension_len = (static_cast<size_t>(data[offset + 1]) + 1) * 8;
                break;
            case IP6_NEXTH_FRAGMENT:
                extension_len = 8;
                break;
            case 51:
                extension_len = (static_cast<size_t>(data[offset + 1]) + 2) * 4;
                break;
            default:
                return 0;
        }
        if (extension_len == 0 || offset + extension_len > len) return 0;
        next = following;
        offset += extension_len;
    }
    return next;
}

ip_addr_t to_lwip_ip(const IpAddr& address) {
    ip_addr_t result;
    std::memset(&result, 0, sizeof(result));
    if (address.family == IpAddr::IPv6) {
        IP_SET_TYPE_VAL(result, IPADDR_TYPE_V6);
        std::memcpy(ip_2_ip6(&result)->addr, address.data.v6, 16);
    } else {
        IP_SET_TYPE_VAL(result, IPADDR_TYPE_V4);
        std::memcpy(&ip_2_ip4(&result)->addr, address.data.v4, 4);
    }
    return result;
}

IpAddr from_lwip_ip(const ip_addr_t& address, uint16_t port) {
    if (IP_IS_V6_VAL(address)) {
        uint8_t bytes[16];
        std::memcpy(bytes, ip_2_ip6(&address)->addr, sizeof(bytes));
        return IpAddr::from_ipv6(bytes, port);
    }
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&ip_2_ip4(&address)->addr);
    return IpAddr::from_ipv4(bytes[0], bytes[1], bytes[2], bytes[3], port);
}

TargetAddr to_target(const ip_addr_t& address, uint16_t port) {
    IpAddr ip = from_lwip_ip(address, port);
    TargetAddr target;
    target.type = ip.family == IpAddr::IPv6 ? AddrType::IPv6 : AddrType::IPv4;
    ip.port = 0;
    target.host = ip.to_string();
    target.port = port;
    return target;
}

void acknowledge(tcp_pcb* pcb, size_t amount) {
    while (amount > 0) {
        const u16_t chunk = static_cast<u16_t>(std::min<size_t>(amount, 65535));
        tcp_recved(pcb, chunk);
        amount -= chunk;
    }
}

} // namespace

struct LwipTcpStream::Impl {
    tcp_pcb* pcb = nullptr;
    tcp_pcb* identity = nullptr;
    bool paused = false;
    bool closed = false;
    bool read_eof = false;
    bool write_shutdown = false;
    bool fin_pending = false;
    bool in_lwip_callback = false;
    size_t unacknowledged_receive = 0;
    std::deque<std::vector<uint8_t>> read_queue;
    size_t queued_bytes = 0;
    std::deque<std::vector<uint8_t>> write_queue;
    DataCallback data_callback;
    EventCallback writable_callback;
    EventCallback eof_callback;
    EventCallback close_callback;
    ErrorCallback error_callback;
    std::function<void(tcp_pcb*)> detach;

    bool flush() {
        if (!pcb || closed) return false;
        while (!write_queue.empty()) {
            auto& front = write_queue.front();
            const size_t available = tcp_sndbuf(pcb);
            if (available == 0) break;
            const u16_t amount = static_cast<u16_t>(
                std::min<size_t>(std::min<size_t>(front.size(), available), 65535));
            if (amount == 0) break;
            err_t result = tcp_write(pcb, front.data(), amount, TCP_WRITE_FLAG_COPY);
            if (result == ERR_MEM) break;
            if (result != ERR_OK) return false;
            queued_bytes -= amount;
            if (amount == front.size()) {
                write_queue.pop_front();
            } else {
                front.erase(front.begin(), front.begin() + amount);
            }
        }
        tcp_output(pcb);
        if (write_queue.empty() && fin_pending) {
            err_t result = tcp_shutdown(pcb, 0, 1);
            if (result == ERR_OK) {
                fin_pending = false;
                write_shutdown = true;
            } else if (result != ERR_MEM) {
                return false;
            }
        }
        return true;
    }

    static err_t on_receive(void* arg, tcp_pcb* pcb, pbuf* packet, err_t error) {
        auto* self = static_cast<Impl*>(arg);
        if (!self || self->closed) {
            if (packet) pbuf_free(packet);
            return ERR_OK;
        }
        if (error != ERR_OK) {
            if (packet) pbuf_free(packet);
            auto callback = self->error_callback;
            self->in_lwip_callback = true;
            if (callback) callback(error);
            if (self->closed) return ERR_ABRT;
            self->in_lwip_callback = false;
            return error;
        }
        if (!packet) {
            self->read_eof = true;
            auto callback = self->eof_callback;
            self->in_lwip_callback = true;
            if (callback) callback();
            if (self->closed) return ERR_ABRT;
            self->in_lwip_callback = false;
            return ERR_OK;
        }
        std::vector<uint8_t> bytes(packet->tot_len);
        const bool copied = pbuf_copy_partial(packet, bytes.data(), packet->tot_len, 0) ==
                            packet->tot_len;
        pbuf_free(packet);
        if (!copied) return ERR_BUF;
        if (self->paused) {
            const size_t limit = std::min<size_t>(kMaxTcpPendingRead, TCP_WND);
            if (self->unacknowledged_receive + bytes.size() > limit) {
                self->in_lwip_callback = true;
                tcp_abort(pcb);
                self->pcb = nullptr;
                self->closed = true;
                auto close_callback = self->close_callback;
                auto detach = self->detach;
                tcp_pcb* identity = self->identity;
                if (close_callback) close_callback();
                if (detach) detach(identity);
                return ERR_ABRT;
            }
            self->unacknowledged_receive += bytes.size();
            self->read_queue.emplace_back(std::move(bytes));
            return ERR_OK;
        }
        Buffer data(bytes.size());
        data.append(bytes.data(), bytes.size());
        auto callback = self->data_callback;
        self->in_lwip_callback = true;
        if (callback) callback(data);
        if (self->closed) return ERR_ABRT;
        self->in_lwip_callback = false;
        acknowledge(pcb, bytes.size());
        return ERR_OK;
    }

    static err_t on_sent(void* arg, tcp_pcb*, u16_t) {
        auto* self = static_cast<Impl*>(arg);
        if (!self || self->closed) return ERR_OK;
        if (!self->flush()) return ERR_ABRT;
        auto callback = self->writable_callback;
        self->in_lwip_callback = true;
        if (callback) callback();
        if (self->closed) return ERR_ABRT;
        self->in_lwip_callback = false;
        return ERR_OK;
    }

    static err_t on_poll(void* arg, tcp_pcb*) {
        auto* self = static_cast<Impl*>(arg);
        if (!self || self->closed) return ERR_OK;
        return self->flush() ? ERR_OK : ERR_ABRT;
    }

    static void on_error(void* arg, err_t error) {
        auto* self = static_cast<Impl*>(arg);
        if (!self || self->closed) return;
        tcp_pcb* identity = self->identity;
        auto error_callback = self->error_callback;
        auto close_callback = self->close_callback;
        auto detach = self->detach;
        self->pcb = nullptr;
        self->closed = true;
        if (error_callback) error_callback(error);
        if (close_callback) close_callback();
        // Detaching can release the last owner of this Impl. Do it last and
        // never access self afterwards.
        if (detach) detach(identity);
    }
};

struct LwipUdpStack::Impl {
    struct UdpFlow { uint64_t id; udp_pcb* pcb; };
    netif interface;
    udp_pcb* udp_listener = nullptr;
    tcp_pcb* tcp_listener = nullptr;
    uint64_t next_flow_id = 1;
    bool initialized = false;
    bool owns_global_stack = false;
    DatagramCallback datagram_callback;
    TcpAcceptCallback tcp_accept_callback;
    PacketOutputCallback output_callback;
    std::unordered_map<uint64_t, UdpFlow> udp_flows;
    std::unordered_map<udp_pcb*, uint64_t> udp_pcb_flows;
    std::unordered_map<tcp_pcb*, std::shared_ptr<LwipTcpStream>> tcp_flows;

    static err_t initialize_netif(netif* interface) {
        auto* self = static_cast<Impl*>(interface->state);
        interface->name[0] = 't';
        interface->name[1] = 'x';
        interface->output = output_ipv4;
        interface->output_ip6 = output_ipv6;
        interface->flags = NETIF_FLAG_PRETEND_TCP | NETIF_FLAG_PRETEND_UDP;
        return self ? ERR_OK : ERR_ARG;
    }
    static err_t output_ipv4(netif* interface, pbuf* packet, const ip4_addr_t*) {
        return output_packet(interface, packet);
    }
    static err_t output_ipv6(netif* interface, pbuf* packet, const ip6_addr_t*) {
        return output_packet(interface, packet);
    }
    static err_t output_packet(netif* interface, pbuf* packet) {
        auto* self = static_cast<Impl*>(interface->state);
        if (!self || !self->output_callback || !packet) return ERR_IF;
        std::vector<uint8_t> bytes(packet->tot_len);
        if (pbuf_copy_partial(packet, bytes.data(), packet->tot_len, 0) != packet->tot_len)
            return ERR_BUF;
        return self->output_callback(bytes.data(), bytes.size()) ? ERR_OK : ERR_IF;
    }
    static void accept_udp(void* arg, udp_pcb* pcb, pbuf*, const ip_addr_t*, u16_t) {
        auto* self = static_cast<Impl*>(arg);
        if (!self || !pcb) return;
        const uint64_t id = self->next_flow_id++;
        self->udp_flows.emplace(id, UdpFlow{id, pcb});
        self->udp_pcb_flows.emplace(pcb, id);
        // HEV Pretend UDP documents this accept callback's p/addr/port as
        // unused. The first actual datagram is delivered to receive_udp().
        udp_recv(pcb, receive_udp, self);
    }
    static void receive_udp(void* arg, udp_pcb* pcb, pbuf* packet,
                            const ip_addr_t*, u16_t) {
        auto* self = static_cast<Impl*>(arg);
        if (!self || !pcb || !packet) { if (packet) pbuf_free(packet); return; }
        auto flow = self->udp_pcb_flows.find(pcb);
        if (flow == self->udp_pcb_flows.end()) { pbuf_free(packet); return; }
        std::vector<uint8_t> payload(packet->tot_len);
        if (pbuf_copy_partial(packet, payload.data(), packet->tot_len, 0) == packet->tot_len &&
            self->datagram_callback) {
            self->datagram_callback(flow->second,
                from_lwip_ip(pcb->remote_ip, pcb->remote_port),
                from_lwip_ip(pcb->local_ip, pcb->local_port),
                payload.data(), payload.size());
        }
        pbuf_free(packet);
    }
    static err_t accept_tcp(void* arg, tcp_pcb* pcb, err_t error) {
        auto* self = static_cast<Impl*>(arg);
        if (!self || !pcb || error != ERR_OK || self->tcp_flows.size() >= 4096) {
            if (pcb) tcp_abort(pcb);
            return ERR_ABRT;
        }
        std::unique_ptr<LwipTcpStream::Impl> state(new LwipTcpStream::Impl);
        state->pcb = pcb;
        state->identity = pcb;
        state->detach = [self](tcp_pcb* key) { self->tcp_flows.erase(key); };
        auto stream = std::shared_ptr<LwipTcpStream>(new LwipTcpStream(std::move(state)));
        self->tcp_flows.emplace(pcb, stream);
        tcp_arg(pcb, stream->impl_.get());
        tcp_recv(pcb, LwipTcpStream::Impl::on_receive);
        tcp_sent(pcb, LwipTcpStream::Impl::on_sent);
        tcp_poll(pcb, LwipTcpStream::Impl::on_poll, 2);
        tcp_err(pcb, LwipTcpStream::Impl::on_error);
        tcp_nagle_disable(pcb);
        if (self->tcp_accept_callback) {
            stream->impl_->in_lwip_callback = true;
            self->tcp_accept_callback(stream,
                from_lwip_ip(pcb->remote_ip, pcb->remote_port),
                to_target(pcb->local_ip, pcb->local_port));
            if (stream->is_closed()) return ERR_ABRT;
            stream->impl_->in_lwip_callback = false;
        }
        return ERR_OK;
    }
};

LwipUdpStack::LwipUdpStack() : impl_(new Impl) {}
LwipUdpStack::~LwipUdpStack() { shutdown(); }

bool LwipUdpStack::initialize(const std::string& ipv4_cidr, int mtu,
                              DatagramCallback datagram_callback,
                              PacketOutputCallback output_callback,
                              std::string& error) {
    return initialize(std::vector<std::string>{ipv4_cidr}, mtu,
                      std::move(datagram_callback), TcpAcceptCallback(),
                      std::move(output_callback), error);
}

bool LwipUdpStack::initialize(const std::vector<std::string>& addresses, int mtu,
                              DatagramCallback datagram_callback,
                              TcpAcceptCallback tcp_accept_callback,
                              PacketOutputCallback output_callback,
                              std::string& error) {
    shutdown();
    if (mtu <= 0 || mtu > 65535 || addresses.empty()) {
        error = "lwIP TUN requires addresses and an MTU between 1 and 65535";
        return false;
    }
    LwipUdpStack* expected = nullptr;
    if (!g_active_lwip_stack.compare_exchange_strong(
            expected, this, std::memory_order_acq_rel, std::memory_order_acquire)) {
        error = "only one native lwIP TUN instance can run in this process";
        return false;
    }
    impl_->owns_global_stack = true;
    ip4_addr_t address;
    ip4_addr_set_zero(&address);
    ip4_addr_t netmask;
    ip4_addr_set_zero(&netmask);
    ip4_addr_t gateway;
    ip4_addr_set_zero(&gateway);
    bool have_ipv4 = false;
    for (const auto& cidr : addresses) {
        const size_t slash = cidr.find('/');
        if (slash == std::string::npos) { error = "TUN address must use CIDR notation"; return false; }
        const std::string host = cidr.substr(0, slash);
        if (host.find(':') == std::string::npos && !have_ipv4) {
            char* end = nullptr;
            long prefix = std::strtol(cidr.substr(slash + 1).c_str(), &end, 10);
            if (!end || *end || prefix < 0 || prefix > 32 || !ip4addr_aton(host.c_str(), &address)) {
                error = "invalid IPv4 TUN CIDR"; return false;
            }
            ip4_addr_set_u32(&netmask, lwip_htonl(prefix == 0 ? 0u : 0xffffffffu << (32 - prefix)));
            have_ipv4 = true;
        }
    }
    std::call_once(g_lwip_init_once, [] { lwip_init(); });
    std::memset(&impl_->interface, 0, sizeof(impl_->interface));
    impl_->datagram_callback = std::move(datagram_callback);
    impl_->tcp_accept_callback = std::move(tcp_accept_callback);
    impl_->output_callback = std::move(output_callback);
    if (!netif_add(&impl_->interface, &address, &netmask, &gateway, impl_.get(),
                   Impl::initialize_netif, ip_input)) {
        error = "failed to create lwIP TUN netif"; shutdown(); return false;
    }
    impl_->initialized = true;
    impl_->interface.mtu = static_cast<u16_t>(mtu);
    for (const auto& cidr : addresses) {
        const std::string host = cidr.substr(0, cidr.find('/'));
        if (host.find(':') != std::string::npos) {
            ip6_addr_t address6;
            if (!ip6addr_aton(host.c_str(), &address6)) {
                error = "invalid IPv6 TUN CIDR"; shutdown(); return false;
            }
            s8_t index = -1;
            if (netif_add_ip6_address(&impl_->interface, &address6, &index) != ERR_OK) {
                error = "failed to add lwIP IPv6 address"; shutdown(); return false;
            }
            netif_ip6_addr_set_state(&impl_->interface, index, IP6_ADDR_PREFERRED);
        }
    }
    netif_set_default(&impl_->interface);
    netif_set_up(&impl_->interface);
    netif_set_link_up(&impl_->interface);

    impl_->udp_listener = udp_new_ip_type(IPADDR_TYPE_ANY);
    if (!impl_->udp_listener) { error = "failed to allocate UDP listener"; shutdown(); return false; }
    udp_bind_netif(impl_->udp_listener, &impl_->interface);
    if (udp_bind(impl_->udp_listener, nullptr, 0) != ERR_OK) {
        error = "failed to bind Pretend UDP listener"; shutdown(); return false;
    }
    udp_recv(impl_->udp_listener, Impl::accept_udp, impl_.get());

    impl_->tcp_listener = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!impl_->tcp_listener) { error = "failed to allocate TCP listener"; shutdown(); return false; }
    tcp_bind_netif(impl_->tcp_listener, &impl_->interface);
    if (tcp_bind(impl_->tcp_listener, nullptr, 0) != ERR_OK) {
        error = "failed to bind Pretend TCP listener"; shutdown(); return false;
    }
    tcp_pcb* listener = tcp_listen(impl_->tcp_listener);
    if (!listener) { error = "failed to listen for Pretend TCP"; impl_->tcp_listener = nullptr; shutdown(); return false; }
    impl_->tcp_listener = listener;
    tcp_arg(listener, impl_.get());
    tcp_accept(listener, Impl::accept_tcp);
    return true;
}

void LwipUdpStack::shutdown() {
    if (!impl_) return;
    auto tcp_flows = std::move(impl_->tcp_flows);
    impl_->tcp_flows.clear();
    for (auto& item : tcp_flows) item.second->reset();
    for (auto& entry : impl_->udp_flows) udp_remove(entry.second.pcb);
    impl_->udp_flows.clear();
    impl_->udp_pcb_flows.clear();
    if (impl_->tcp_listener) { tcp_close(impl_->tcp_listener); impl_->tcp_listener = nullptr; }
    if (impl_->udp_listener) { udp_remove(impl_->udp_listener); impl_->udp_listener = nullptr; }
    if (impl_->initialized) netif_remove(&impl_->interface);
    impl_->initialized = false;
    impl_->datagram_callback = DatagramCallback();
    impl_->tcp_accept_callback = TcpAcceptCallback();
    impl_->output_callback = PacketOutputCallback();
    if (impl_->owns_global_stack) {
        LwipUdpStack* expected = this;
        g_active_lwip_stack.compare_exchange_strong(
            expected, nullptr, std::memory_order_acq_rel, std::memory_order_acquire);
        impl_->owns_global_stack = false;
    }
}

bool LwipUdpStack::input(const uint8_t* packet, size_t packet_len) {
    const uint8_t protocol = ip_protocol(packet, packet_len);
    if (!impl_->initialized || (protocol != IP_PROTO_TCP && protocol != IP_PROTO_UDP) ||
        packet_len > 65535) return false;
    pbuf* buffer = pbuf_alloc(PBUF_RAW, static_cast<u16_t>(packet_len), PBUF_RAM);
    if (!buffer) return false;
    if (pbuf_take(buffer, packet, packet_len) != ERR_OK) { pbuf_free(buffer); return false; }
    const err_t result = impl_->interface.input(buffer, &impl_->interface);
    if (result != ERR_OK) pbuf_free(buffer);
    return result == ERR_OK;
}

bool LwipUdpStack::send_response(uint64_t flow_id, const IpAddr& source,
                                 const uint8_t* payload, size_t payload_len) {
    auto flow = impl_->udp_flows.find(flow_id);
    if (!impl_->initialized || flow == impl_->udp_flows.end() || payload_len > 65535) return false;
    pbuf* buffer = pbuf_alloc(PBUF_TRANSPORT, static_cast<u16_t>(payload_len), PBUF_RAM);
    if (!buffer) return false;
    if (payload_len && pbuf_take(buffer, payload, payload_len) != ERR_OK) { pbuf_free(buffer); return false; }
    const ip_addr_t lwip_source = to_lwip_ip(source);
    const err_t result = udp_sendfrom(flow->second.pcb, buffer, &lwip_source, source.port);
    pbuf_free(buffer);
    return result == ERR_OK;
}

void LwipUdpStack::close_flow(uint64_t flow_id) {
    auto flow = impl_->udp_flows.find(flow_id);
    if (flow == impl_->udp_flows.end()) return;
    impl_->udp_pcb_flows.erase(flow->second.pcb);
    udp_remove(flow->second.pcb);
    impl_->udp_flows.erase(flow);
}

void LwipUdpStack::poll_timers() { if (impl_->initialized) sys_check_timeouts(); }
uint32_t LwipUdpStack::next_timeout_ms() const {
    if (!impl_->initialized) return 1000;
    u32_t delay = sys_timeouts_sleeptime();
    return delay == SYS_TIMEOUTS_SLEEPTIME_INFINITE ? 1000 : std::max<u32_t>(1, delay);
}

LwipTcpStream::LwipTcpStream(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
LwipTcpStream::~LwipTcpStream() { if (impl_ && !impl_->closed) reset(); }
bool LwipTcpStream::write(const uint8_t* data, size_t len) {
    if (!impl_ || impl_->closed || impl_->write_shutdown || impl_->fin_pending ||
        (!data && len)) return false;
    if (impl_->queued_bytes + len > kMaxTcpPendingWrite) { reset(); return false; }
    if (len) {
        impl_->write_queue.emplace_back(data, data + len);
        impl_->queued_bytes += len;
    }
    if (!impl_->flush()) { reset(); return false; }
    return true;
}
bool LwipTcpStream::write(Buffer& data) {
    if (data.empty()) return false;
    if (!write(data.data(), data.readable())) return false;
    data.clear(); return true;
}
void LwipTcpStream::pause_read() { if (impl_ && !impl_->closed) impl_->paused = true; }
void LwipTcpStream::resume_read() {
    if (!impl_ || impl_->closed) return;
    impl_->paused = false;
    while (impl_->pcb && !impl_->closed && !impl_->paused && !impl_->read_queue.empty()) {
        std::vector<uint8_t> bytes = std::move(impl_->read_queue.front());
        impl_->read_queue.pop_front();
        Buffer data(bytes.size());
        data.append(bytes.data(), bytes.size());
        auto callback = impl_->data_callback;
        if (callback) callback(data);
        if (impl_->closed) return;
        acknowledge(impl_->pcb, bytes.size());
        impl_->unacknowledged_receive -= bytes.size();
    }
}
void LwipTcpStream::shutdown_write() {
    if (!impl_ || impl_->closed || impl_->write_shutdown) return;
    impl_->fin_pending = true;
    if (!impl_->flush()) reset();
}
void LwipTcpStream::close() {
    if (!impl_ || impl_->closed) return;
    tcp_pcb* pcb = impl_->pcb;
    auto close_callback = impl_->close_callback;
    auto detach = impl_->detach;
    tcp_pcb* identity = impl_->identity;
    impl_->closed = true; impl_->pcb = nullptr;
    tcp_arg(pcb, nullptr); tcp_recv(pcb, nullptr); tcp_sent(pcb, nullptr); tcp_err(pcb, nullptr);
    if (impl_->in_lwip_callback || tcp_close(pcb) != ERR_OK) tcp_abort(pcb);
    if (close_callback) close_callback();
    if (detach) detach(identity);
}
void LwipTcpStream::reset() {
    if (!impl_ || impl_->closed) return;
    tcp_pcb* pcb = impl_->pcb;
    auto close_callback = impl_->close_callback;
    auto detach = impl_->detach;
    tcp_pcb* identity = impl_->identity;
    impl_->closed = true; impl_->pcb = nullptr;
    tcp_arg(pcb, nullptr); tcp_recv(pcb, nullptr); tcp_sent(pcb, nullptr); tcp_err(pcb, nullptr);
    tcp_abort(pcb);
    if (close_callback) close_callback();
    if (detach) detach(identity);
}
size_t LwipTcpStream::pending_write_bytes() const { return impl_ ? impl_->queued_bytes : 0; }
bool LwipTcpStream::is_closed() const { return !impl_ || impl_->closed; }
bool LwipTcpStream::is_read_eof() const { return impl_ && impl_->read_eof; }
bool LwipTcpStream::is_write_shutdown() const { return impl_ && impl_->write_shutdown; }
void LwipTcpStream::set_data_callback(DataCallback cb) { impl_->data_callback = std::move(cb); }
void LwipTcpStream::set_writable_callback(EventCallback cb) { impl_->writable_callback = std::move(cb); }
void LwipTcpStream::set_eof_callback(EventCallback cb) { impl_->eof_callback = std::move(cb); }
void LwipTcpStream::set_close_callback(EventCallback cb) { impl_->close_callback = std::move(cb); }
void LwipTcpStream::set_error_callback(ErrorCallback cb) { impl_->error_callback = std::move(cb); }

} // namespace tx
