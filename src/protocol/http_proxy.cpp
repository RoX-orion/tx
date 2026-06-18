#include "tx/protocol/http_proxy.h"
#include "tx/common/log.h"
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <arpa/inet.h>

namespace tx {

HttpProxyHandler::HttpProxyHandler() : state_(State::Request), header_end_(0) {}

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

            // Must start with CONNECT
            if (request_line.substr(0, 8) != "CONNECT ") {
                TX_ERROR("HTTP proxy: only CONNECT method supported, got: %s",
                         request_line.substr(0, 20).c_str());
                state_ = State::Error;
                return true;
            }

            // Extract host:port
            size_t space_pos = request_line.find(' ', 8);
            std::string host_port;
            if (space_pos != std::string::npos) {
                host_port = request_line.substr(8, space_pos - 8);
            } else {
                host_port = request_line.substr(8);
            }

            // Split host and port. IPv6 literals in CONNECT are bracketed:
            // CONNECT [2001:db8::1]:443 HTTP/1.1
            if (!host_port.empty() && host_port[0] == '[') {
                size_t close = host_port.find(']');
                if (close == std::string::npos) {
                    TX_ERROR("HTTP proxy: malformed IPv6 target: %s", host_port.c_str());
                    state_ = State::Error;
                    return true;
                }
                target_.host = host_port.substr(1, close - 1);
                if (close + 1 < host_port.size() && host_port[close + 1] == ':') {
                    target_.port = static_cast<uint16_t>(atoi(host_port.substr(close + 2).c_str()));
                } else {
                    target_.port = 443;
                }
            } else {
                size_t colon_pos = host_port.rfind(':');
                if (colon_pos != std::string::npos) {
                    target_.host = host_port.substr(0, colon_pos);
                    target_.port = static_cast<uint16_t>(atoi(host_port.substr(colon_pos + 1).c_str()));
                } else {
                    target_.host = host_port;
                    target_.port = 80;
                }
            }

            if (target_.host.empty() || target_.port == 0) {
                TX_ERROR("HTTP proxy: invalid target: %s", host_port.c_str());
                state_ = State::Error;
                return true;
            }

            // Determine address type
            struct in_addr v4;
            struct in6_addr v6;
            if (inet_pton(AF_INET, target_.host.c_str(), &v4) == 1) {
                target_.type = AddrType::IPv4;
            } else if (inet_pton(AF_INET6, target_.host.c_str(), &v6) == 1) {
                target_.type = AddrType::IPv6;
            } else {
                target_.type = AddrType::Domain;
            }

            state_ = State::Connected;
            TX_INFO("HTTP CONNECT %s:%u", target_.host.c_str(), target_.port);

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
