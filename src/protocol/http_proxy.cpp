#include "tx/protocol/http_proxy.h"
#include "tx/common/log.h"
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <algorithm>
#include "tx/common/network.h"

namespace tx {

namespace {

static bool starts_with_ci(const std::string& s, const char* prefix) {
    size_t prefix_len = strlen(prefix);
    if (s.size() < prefix_len) return false;
    for (size_t i = 0; i < prefix_len; ++i) {
        if (std::tolower(static_cast<unsigned char>(s[i])) !=
            std::tolower(static_cast<unsigned char>(prefix[i]))) {
            return false;
        }
    }
    return true;
}

static void set_addr_type(TargetAddr& target) {
    struct in_addr v4;
    struct in6_addr v6;
    if (inet_pton(AF_INET, target.host.c_str(), &v4) == 1) {
        target.type = AddrType::IPv4;
    } else if (inet_pton(AF_INET6, target.host.c_str(), &v6) == 1) {
        target.type = AddrType::IPv6;
    } else {
        target.type = AddrType::Domain;
    }
}

static bool parse_port(const std::string& text, uint16_t& port) {
    if (text.empty()) return false;
    char* end = nullptr;
    errno = 0;
    const unsigned long value = std::strtoul(text.c_str(), &end, 10);
    if (errno != 0 || !end || *end != '\0' || value == 0 || value > 65535) {
        return false;
    }
    port = static_cast<uint16_t>(value);
    return true;
}

} // namespace

HttpProxyHandler::HttpProxyHandler()
    : state_(State::Request), header_end_(0), mode_(Mode::Connect) {}

size_t HttpProxyHandler::feed(const uint8_t* data, size_t len) {
    if (state_ == State::Connected) {
        // Already in tunnel mode — data should be forwarded directly
        return 0;
    }

    if (state_ == State::Error) return len;

    if (try_parse_request(data, len)) {
        // Return bytes consumed = header end position
        // Any remaining data in caller buffer is the start of tunnel data
        return header_end_;
    }

    // Not enough data yet
    return 0;
}

bool HttpProxyHandler::try_parse_request(const uint8_t* data, size_t len) {
    // Look for \r\n\r\n in buffer
    const uint8_t* d = data;

    for (size_t i = 0; i + 3 < len; i++) {
        if (d[i] == '\r' && d[i+1] == '\n' && d[i+2] == '\r' && d[i+3] == '\n') {
            // Found end of headers
            std::string headers(reinterpret_cast<const char*>(d), i);
            header_end_ = i + 4; // position after \r\n\r\n

            // Parse "CONNECT host:port HTTP/1.1"
            // Find first line
            size_t first_line_end = headers.find("\r\n");
            if (first_line_end == std::string::npos) {
                first_line_end = headers.size();
            }
            std::string request_line = headers.substr(0, first_line_end);

            size_t method_end = request_line.find(' ');
            size_t target_end = method_end == std::string::npos
                                    ? std::string::npos
                                    : request_line.find(' ', method_end + 1);
            if (method_end == std::string::npos || target_end == std::string::npos) {
                TX_ERROR("HTTP proxy: malformed request line: %s", request_line.c_str());
                state_ = State::Error;
                return true;
            }

            std::string method = request_line.substr(0, method_end);
            std::string request_target =
                request_line.substr(method_end + 1, target_end - method_end - 1);
            std::string version = request_line.substr(target_end + 1);

            std::string host_port;
            size_t consumed = i + 4;
            if (method == "CONNECT") {
                mode_ = Mode::Connect;
                host_port = request_target;
            } else if (starts_with_ci(request_target, "http://")) {
                mode_ = Mode::Plain;
                size_t authority_start = 7;
                size_t path_start = request_target.find('/', authority_start);
                host_port = request_target.substr(
                    authority_start,
                    path_start == std::string::npos
                        ? std::string::npos
                        : path_start - authority_start);

                std::string path = path_start == std::string::npos
                                       ? "/"
                                       : request_target.substr(path_start);
                std::string rewritten = method + " " + path + " " + version + "\r\n" +
                                        headers.substr(first_line_end + 2) + "\r\n\r\n";
                initial_payload_.clear();
                initial_payload_.append(rewritten);
                if (len > consumed) {
                    initial_payload_.append(data + consumed, len - consumed);
                }
            } else {
                TX_ERROR("HTTP proxy: unsupported request target: %s",
                         request_target.substr(0, 80).c_str());
                state_ = State::Error;
                return true;
            }

            // Split host and port. IPv6 literals in CONNECT are bracketed.
            if (!host_port.empty() && host_port[0] == '[') {
                size_t close = host_port.find(']');
                if (close == std::string::npos) {
                    TX_ERROR("HTTP proxy: malformed IPv6 target: %s", host_port.c_str());
                    state_ = State::Error;
                    return true;
                }
                target_.host = host_port.substr(1, close - 1);
                if (close + 1 < host_port.size() && host_port[close + 1] == ':') {
                    if (!parse_port(host_port.substr(close + 2), target_.port)) {
                        state_ = State::Error;
                        return true;
                    }
                } else {
                    target_.port = method == "CONNECT" ? 443 : 80;
                }
            } else {
                size_t colon_pos = host_port.rfind(':');
                if (colon_pos != std::string::npos) {
                    target_.host = host_port.substr(0, colon_pos);
                    if (!parse_port(host_port.substr(colon_pos + 1), target_.port)) {
                        state_ = State::Error;
                        return true;
                    }
                } else {
                    target_.host = host_port;
                    target_.port = method == "CONNECT" ? 443 : 80;
                }
            }

            if (target_.host.empty() || target_.port == 0) {
                TX_ERROR("HTTP proxy: invalid target: %s", host_port.c_str());
                state_ = State::Error;
                return true;
            }

            set_addr_type(target_);
            header_end_ = mode_ == Mode::Plain ? len : consumed;

            state_ = State::Connected;
            TX_INFO("HTTP %s %s:%u",
                    mode_ == Mode::Connect ? "CONNECT" : "PLAIN",
                    target_.host.c_str(), target_.port);

            if (target_cb_) {
                target_cb_(target_);
            }

            return true;
        }
    }

    // Header too large? (>64KB)
    if (len > 65536) {
        TX_ERROR("HTTP proxy: request headers too large");
        state_ = State::Error;
        return true;
    }

    return false;
}

void HttpProxyHandler::build_connect_response(Buffer& out) {
    const char* resp = "HTTP/1.1 200 Connection Established\r\n\r\n";
    out.append(reinterpret_cast<const uint8_t*>(resp), strlen(resp));
}

void HttpProxyHandler::build_error_response(int status_code, Buffer& out) {
    std::string resp = "HTTP/1.1 " + std::to_string(status_code) +
                       " Error\r\nContent-Length: 0\r\n\r\n";
    out.append(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
}

} // namespace tx
