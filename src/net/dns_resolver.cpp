#include "tx/net/dns_resolver.h"
#include "tx/common/endian.h"
#include "tx/common/log.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstring>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

namespace tx {

struct DnsResolver::Request {
    uv_work_t work;
    std::vector<std::string> upstreams;
    ProtectCallback protector;
    uint32_t mark = 0;
    std::vector<uint8_t> query;
    std::vector<uint8_t> response;
    ResolveCallback callback;
    QueryHook query_hook;
    uint64_t generation = 0;
    DnsResolver* owner = nullptr;
};

struct DnsResolver::HostRequest {
    uv_work_t work;
    std::string host;
    int family = AF_UNSPEC;
    HostResolveHook resolver;
    std::vector<std::string> addresses;
    HostResolveCallback callback;
    uint64_t generation = 0;
    DnsResolver* owner = nullptr;
};

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
namespace {

bool configure_socket(int fd, const DnsResolver::ProtectCallback& protector,
                      uint32_t mark) {
    if (protector && !protector(fd)) {
        TX_ERROR("Socket protector rejected DNS fd %d", fd);
        return false;
    }
#if defined(TX_PLATFORM_LINUX)
    if (mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0)
        return false;
#else
    (void)mark;
#endif
    timeval timeout{2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    return true;
}

bool upstream_address(const std::string& host, int socktype,
                      sockaddr_storage& storage, socklen_t& length) {
    std::string numeric_host = host;
    std::string service = "53";
    if (!host.empty() && host.front() == '[') {
        const size_t closing = host.find(']');
        if (closing != std::string::npos) {
            numeric_host = host.substr(1, closing - 1);
            if (closing + 2 < host.size() && host[closing + 1] == ':')
                service = host.substr(closing + 2);
        }
    } else {
        const size_t colon = host.rfind(':');
        if (colon != std::string::npos && host.find(':') == colon) {
            numeric_host = host.substr(0, colon);
            service = host.substr(colon + 1);
        }
    }
    if (numeric_host.empty() || service.empty()) return false;

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    addrinfo* result = nullptr;
    if (getaddrinfo(numeric_host.c_str(), service.c_str(), &hints, &result) != 0 ||
        !result) {
        return false;
    }
    std::memcpy(&storage, result->ai_addr, result->ai_addrlen);
    length = static_cast<socklen_t>(result->ai_addrlen);
    freeaddrinfo(result);
    return true;
}

bool operation_cancelled(const std::atomic<bool>* cancelled) {
    return cancelled && cancelled->load(std::memory_order_acquire);
}

bool write_all(int fd, const uint8_t* data, size_t len,
               const std::atomic<bool>* cancelled) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(1);
    while (len) {
        if (operation_cancelled(cancelled)) {
            errno = ECANCELED;
            return false;
        }
#ifdef MSG_NOSIGNAL
        constexpr int send_flags = MSG_NOSIGNAL;
#else
        constexpr int send_flags = 0;
#endif
        ssize_t n = send(fd, data, len, send_flags);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) &&
            std::chrono::steady_clock::now() < deadline) {
            continue;
        }
        if (n <= 0) return false;
        data += n; len -= static_cast<size_t>(n);
    }
    return true;
}

bool read_all(int fd, uint8_t* data, size_t len,
              const std::atomic<bool>* cancelled) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(1);
    while (len) {
        if (operation_cancelled(cancelled)) {
            errno = ECANCELED;
            return false;
        }
        ssize_t n = recv(fd, data, len, 0);
        if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) &&
            std::chrono::steady_clock::now() < deadline) {
            continue;
        }
        if (n <= 0) return false;
        data += n; len -= static_cast<size_t>(n);
    }
    return true;
}

bool connect_with_timeout(int fd, const sockaddr* address, socklen_t address_len,
                          int timeout_ms, const std::atomic<bool>* cancelled) {
    const int original_flags = fcntl(fd, F_GETFL, 0);
    if (original_flags < 0 || fcntl(fd, F_SETFL, original_flags | O_NONBLOCK) != 0)
        return false;
    int result = connect(fd, address, address_len);
    if (result != 0 && errno == EINPROGRESS) {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        result = 0;
        while (result == 0 && std::chrono::steady_clock::now() < deadline &&
               !operation_cancelled(cancelled)) {
            pollfd event{fd, POLLOUT, 0};
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now()).count();
            result = poll(&event, 1,
                          static_cast<int>(std::max<int64_t>(
                              1, std::min<int64_t>(50, remaining))));
            if (result < 0 && errno == EINTR) result = 0;
        }
        if (operation_cancelled(cancelled)) {
            errno = ECANCELED;
            result = -1;
        } else if (result > 0) {
            int socket_error = 0;
            socklen_t error_len = sizeof(socket_error);
            result = getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_len);
            if (result == 0 && socket_error != 0) {
                errno = socket_error;
                result = -1;
            }
        } else {
            if (result == 0) errno = ETIMEDOUT;
            result = -1;
        }
    }
    const int saved_errno = errno;
    fcntl(fd, F_SETFL, original_flags);
    errno = saved_errno;
    return result == 0;
}

struct DnsQuestion {
    std::vector<uint8_t> name;
    uint16_t type = 0;
    uint16_t qclass = 0;

    bool operator==(const DnsQuestion& other) const {
        return name == other.name && type == other.type && qclass == other.qclass;
    }
};

bool read_dns_name(const uint8_t* message, size_t message_len, size_t& offset,
                   std::vector<uint8_t>& normalized) {
    if (!message || offset >= message_len) return false;

    size_t cursor = offset;
    size_t next_offset = offset;
    size_t expanded_len = 0;
    unsigned jumps = 0;
    bool jumped = false;
    normalized.clear();

    for (;;) {
        if (cursor >= message_len) return false;
        const uint8_t length = message[cursor];
        if ((length & 0xc0u) == 0xc0u) {
            if (cursor + 1 >= message_len || ++jumps > 128) return false;
            const size_t pointer =
                static_cast<size_t>((length & 0x3fu) << 8) | message[cursor + 1];
            if (pointer >= message_len) return false;
            if (!jumped) next_offset = cursor + 2;
            cursor = pointer;
            jumped = true;
            continue;
        }
        if ((length & 0xc0u) != 0) return false;

        ++cursor;
        if (length == 0) {
            if (!jumped) next_offset = cursor;
            normalized.push_back(0);
            offset = next_offset;
            return true;
        }
        if (cursor + length > message_len ||
            expanded_len + static_cast<size_t>(length) + 1 > 255) {
            return false;
        }
        normalized.push_back(length);
        for (size_t i = 0; i < length; ++i) {
            normalized.push_back(static_cast<uint8_t>(
                std::tolower(static_cast<unsigned char>(message[cursor + i]))));
        }
        expanded_len += static_cast<size_t>(length) + 1;
        cursor += length;
        if (!jumped) next_offset = cursor;
    }
}

bool read_dns_questions(const std::vector<uint8_t>& message,
                        std::vector<DnsQuestion>& questions) {
    if (message.size() < 12) return false;
    const uint16_t count = load_be16(message.data() + 4);
    if (count > 64) return false;

    size_t offset = 12;
    questions.clear();
    questions.reserve(count);
    for (uint16_t i = 0; i < count; ++i) {
        DnsQuestion question;
        if (!read_dns_name(message.data(), message.size(), offset, question.name) ||
            offset + 4 > message.size()) {
            return false;
        }
        question.type = load_be16(message.data() + offset);
        question.qclass = load_be16(message.data() + offset + 2);
        offset += 4;
        questions.push_back(std::move(question));
    }
    return true;
}

bool dns_response_matches_query(const std::vector<uint8_t>& query,
                                const std::vector<uint8_t>& response) {
    if (query.size() < 12 || response.size() < 12 ||
        load_be16(query.data()) != load_be16(response.data())) {
        return false;
    }

    const uint16_t query_flags = load_be16(query.data() + 2);
    const uint16_t response_flags = load_be16(response.data() + 2);
    if ((query_flags & 0x8000u) != 0 || (response_flags & 0x8000u) == 0 ||
        (query_flags & 0x7800u) != (response_flags & 0x7800u) ||
        load_be16(query.data() + 4) != load_be16(response.data() + 4)) {
        return false;
    }

    std::vector<DnsQuestion> query_questions;
    std::vector<DnsQuestion> response_questions;
    return read_dns_questions(query, query_questions) &&
           read_dns_questions(response, response_questions) &&
           query_questions == response_questions;
}

bool resolve_tcp(const std::string& upstream, const std::vector<uint8_t>& query,
                 const DnsResolver::ProtectCallback& protector, uint32_t mark,
                 std::vector<uint8_t>& response,
                 const std::atomic<bool>* cancelled) {
    if (operation_cancelled(cancelled)) return false;
    sockaddr_storage address{}; socklen_t address_len = 0;
    if (!upstream_address(upstream, SOCK_STREAM, address, address_len)) {
        TX_WARN("Invalid DNS upstream address %s", upstream.c_str());
        return false;
    }
    int fd = socket(address.ss_family, SOCK_STREAM, 0);
    if (fd < 0) {
        TX_WARN("DNS TCP socket for %s failed: %s", upstream.c_str(), strerror(errno));
        return false;
    }
    bool ok = configure_socket(fd, protector, mark);
    timeval tcp_timeout{0, 100000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tcp_timeout, sizeof(tcp_timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tcp_timeout, sizeof(tcp_timeout));
    if (ok && !connect_with_timeout(fd, reinterpret_cast<sockaddr*>(&address),
                                    address_len, 1000, cancelled)) {
        TX_DEBUG("DNS TCP connect to %s failed: %s", upstream.c_str(), strerror(errno));
        ok = false;
    }
    uint8_t length[2]; store_be16(length, static_cast<uint16_t>(query.size()));
    ok = ok && write_all(fd, length, 2, cancelled) &&
         write_all(fd, query.data(), query.size(), cancelled) &&
         read_all(fd, length, 2, cancelled);
    const uint16_t response_len = ok ? load_be16(length) : 0;
    if (response_len < 12) ok = false;
    if (ok) {
        response.resize(response_len);
        ok = read_all(fd, response.data(), response.size(), cancelled);
    }
    close(fd);
    if (ok && !dns_response_matches_query(query, response)) {
        TX_DEBUG("DNS TCP response from %s did not match the query", upstream.c_str());
        ok = false;
    }
    if (!ok) {
        TX_DEBUG("DNS TCP exchange with %s failed: %s", upstream.c_str(),
                 strerror(errno));
        response.clear();
    }
    return ok;
}

bool resolve_udp(const std::string& upstream, const std::vector<uint8_t>& query,
                 const DnsResolver::ProtectCallback& protector, uint32_t mark,
                 std::vector<uint8_t>& response,
                 const std::atomic<bool>* cancelled) {
    if (operation_cancelled(cancelled)) return false;
    sockaddr_storage address{}; socklen_t address_len = 0;
    if (!upstream_address(upstream, SOCK_DGRAM, address, address_len)) {
        TX_WARN("Invalid DNS upstream address %s", upstream.c_str());
        return false;
    }
    int fd = socket(address.ss_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        TX_WARN("DNS UDP socket for %s failed: %s", upstream.c_str(), strerror(errno));
        return false;
    }
    bool ok = configure_socket(fd, protector, mark);
    timeval udp_timeout{0, 100000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &udp_timeout, sizeof(udp_timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &udp_timeout, sizeof(udp_timeout));
    if (ok && connect(fd, reinterpret_cast<sockaddr*>(&address), address_len) != 0) {
        TX_DEBUG("DNS UDP connect to %s failed: %s", upstream.c_str(), strerror(errno));
        ok = false;
    }
    if (ok) {
#ifdef MSG_NOSIGNAL
        constexpr int send_flags = MSG_NOSIGNAL;
#else
        constexpr int send_flags = 0;
#endif
        ssize_t sent = send(fd, query.data(), query.size(), send_flags);
        ok = sent == static_cast<ssize_t>(query.size());
        if (!ok) TX_DEBUG("DNS UDP send to %s failed: %s", upstream.c_str(),
                         strerror(errno));
    }
    uint8_t buffer[65535];
    ssize_t received = -1;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(2);
    while (ok && !operation_cancelled(cancelled) &&
           std::chrono::steady_clock::now() < deadline) {
        received = recv(fd, buffer, sizeof(buffer), 0);
        if (received >= 0) break;
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) break;
    }
    if (operation_cancelled(cancelled)) errno = ECANCELED;
    const int receive_errno = errno;
    close(fd);
    if (received < 12) {
        TX_DEBUG("DNS UDP receive from %s failed: %s", upstream.c_str(),
                strerror(receive_errno));
        return false;
    }
    response.assign(buffer, buffer + received);
    if (!dns_response_matches_query(query, response)) {
        TX_DEBUG("DNS UDP response from %s did not match the query", upstream.c_str());
        response.clear();
        return false;
    }
    if ((load_be16(response.data() + 2) & 0x0200u) != 0)
        return resolve_tcp(upstream, query, protector, mark, response, cancelled);
    return true;
}

} // namespace
#endif

DnsResolver::DnsResolver(uv_loop_t* loop) : loop_(loop) {}

void DnsResolver::configure(std::vector<std::string> upstreams,
                            ProtectCallback protector, uint32_t bypass_mark,
                            HostResolveHook host_resolver, QueryHook query_hook) {
#if !defined(TX_PLATFORM_WINDOWS)
    if (upstreams.empty()) {
        std::ifstream resolv("/etc/resolv.conf");
        std::string line;
        while (std::getline(resolv, line)) {
            std::istringstream fields(line);
            std::string keyword;
            std::string address;
            if (fields >> keyword >> address && keyword == "nameserver")
                upstreams.push_back(address);
        }
    }
#endif
    upstreams_ = std::move(upstreams);
    protector_ = std::move(protector);
    bypass_mark_ = bypass_mark;
    host_resolver_ = std::move(host_resolver);
    query_hook_ = std::move(query_hook);
}

void DnsResolver::resolve(const uint8_t* query, size_t query_len,
                          ResolveCallback callback) {
    if (!callback) return;
    if (!query || query_len < 12 || query_len > 65535 ||
        (!query_hook_ && upstreams_.empty())) {
        callback(std::vector<uint8_t>());
        return;
    }
    auto* request = new Request;
    request->work.data = request;
    request->upstreams = upstreams_;
    request->protector = protector_;
    request->mark = bypass_mark_;
    request->query.assign(query, query + query_len);
    request->callback = std::move(callback);
    request->query_hook = query_hook_;
    request->generation = generation_;
    request->owner = this;
    if (uv_queue_work(loop_, &request->work, on_work, after_work) != 0) {
        auto cb = std::move(request->callback);
        delete request;
        cb(std::vector<uint8_t>());
    }
}

void DnsResolver::on_work(uv_work_t* work) {
    auto* request = static_cast<Request*>(work->data);
    if (request->query_hook) {
        request->response = request->query_hook(request->query.data(), request->query.size());
        return;
    }
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
    // Android's resolver gives VPN DNS queries only a short time to complete.
    // Trying IPv6 and IPv4 upstreams serially can exceed that deadline when an
    // upstream is unreachable, even though a later server is healthy. Race the
    // configured servers and keep the first valid response instead.
    struct RaceState {
        std::mutex mutex;
        std::vector<uint8_t> query;
        ProtectCallback protector;
        uint32_t mark = 0;
        std::vector<uint8_t> response;
        std::atomic<bool> cancelled{false};
        bool resolved = false;
    };
    auto state = std::make_shared<RaceState>();
    state->query = request->query;
    state->protector = request->protector;
    state->mark = request->mark;

    std::vector<std::thread> workers;
    workers.reserve(request->upstreams.size() * 2);
    for (const auto& upstream : request->upstreams) {
        auto start_worker = [state, upstream, &workers](bool tcp) {
            try {
                workers.emplace_back([state, upstream, tcp]() {
                    std::vector<uint8_t> candidate;
                    const bool ok = tcp
                        ? resolve_tcp(upstream, state->query, state->protector,
                                      state->mark, candidate, &state->cancelled)
                        : resolve_udp(upstream, state->query, state->protector,
                                      state->mark, candidate, &state->cancelled);
                    if (!ok && !operation_cancelled(&state->cancelled)) {
                        TX_DEBUG("DNS upstream %s failed over %s", upstream.c_str(),
                                 tcp ? "TCP" : "UDP");
                    }
                    std::lock_guard<std::mutex> lock(state->mutex);
                    if (ok && !state->resolved) {
                        state->response = std::move(candidate);
                        state->resolved = true;
                        state->cancelled.store(true, std::memory_order_release);
                    }
                });
            } catch (const std::system_error& error) {
                TX_WARN("Could not start DNS %s worker for %s: %s",
                        tcp ? "TCP" : "UDP", upstream.c_str(), error.what());
            }
        };
        // Some Android networks silently filter application UDP/53 while
        // allowing TCP/53. Race both transports so fallback does not add a
        // second timeout interval.
        start_worker(false);
        start_worker(true);
    }
    for (auto& worker : workers) worker.join();
    {
        std::lock_guard<std::mutex> lock(state->mutex);
        if (state->resolved) request->response = state->response;
    }
    if (request->response.empty())
        TX_WARN("All %zu DNS upstreams failed", request->upstreams.size());
#else
    (void)request;
#endif
}

void DnsResolver::after_work(uv_work_t* work, int status) {
    auto* request = static_cast<Request*>(work->data);
    auto callback = std::move(request->callback);
    const bool stale = !request->owner || request->generation != request->owner->generation_;
    auto response = status == UV_ECANCELED || stale ? std::vector<uint8_t>()
                                                     : std::move(request->response);
    delete request;
    callback(std::move(response));
}

void DnsResolver::resolve_host(const std::string& host, int family,
                               HostResolveCallback callback) {
    if (!callback || host.empty()) return;
    in_addr address4{};
    in6_addr address6{};
    if (inet_pton(AF_INET, host.c_str(), &address4) == 1 ||
        inet_pton(AF_INET6, host.c_str(), &address6) == 1) {
        callback(std::vector<std::string>{host});
        return;
    }
    auto* request = new HostRequest;
    request->work.data = request;
    request->host = host;
    request->family = family;
    request->resolver = host_resolver_;
    request->callback = std::move(callback);
    request->generation = generation_;
    request->owner = this;
    if (uv_queue_work(loop_, &request->work, on_host_work, after_host_work) != 0) {
        auto cb = std::move(request->callback);
        delete request;
        cb(std::vector<std::string>());
    }
}

void DnsResolver::on_host_work(uv_work_t* work) {
    auto* request = static_cast<HostRequest*>(work->data);
    if (request->resolver) {
        request->addresses = request->resolver(request->host, request->family);
        return;
    }
    addrinfo hints{};
    hints.ai_family = request->family;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* result = nullptr;
    if (getaddrinfo(request->host.c_str(), nullptr, &hints, &result) != 0) return;
    for (auto* ai = result; ai && request->addresses.size() < 16; ai = ai->ai_next) {
        char text[INET6_ADDRSTRLEN]{};
        const void* source = ai->ai_family == AF_INET
            ? static_cast<const void*>(&reinterpret_cast<sockaddr_in*>(ai->ai_addr)->sin_addr)
            : ai->ai_family == AF_INET6
                ? static_cast<const void*>(&reinterpret_cast<sockaddr_in6*>(ai->ai_addr)->sin6_addr)
                : nullptr;
        if (source && inet_ntop(ai->ai_family, source, text, sizeof(text)))
            request->addresses.emplace_back(text);
    }
    freeaddrinfo(result);
}

void DnsResolver::after_host_work(uv_work_t* work, int status) {
    auto* request = static_cast<HostRequest*>(work->data);
    auto callback = std::move(request->callback);
    const bool stale = !request->owner || request->generation != request->owner->generation_;
    auto addresses = status == UV_ECANCELED || stale
        ? std::vector<std::string>() : std::move(request->addresses);
    delete request;
    callback(std::move(addresses));
}

void DnsResolver::cancel_pending() {
    ++generation_;
}

} // namespace tx
