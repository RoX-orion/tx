#include "tx/net/lwip_udp_stack.h"

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

static uint16_t checksum(const uint8_t* data, size_t len, uint32_t sum = 0) {
    while (len > 1) {
        sum += static_cast<uint16_t>((data[0] << 8) | data[1]);
        data += 2; len -= 2;
    }
    if (len) sum += static_cast<uint16_t>(data[0] << 8);
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

static void put16(uint8_t* p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
static void put32(uint8_t* p, uint32_t v) {
    p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

static std::vector<uint8_t> tcp_packet(uint32_t seq, uint32_t ack,
                                       uint8_t flags,
                                       const uint8_t* payload = nullptr,
                                       size_t payload_len = 0) {
    std::vector<uint8_t> p(40 + payload_len, 0);
    p[0] = 0x45; put16(&p[2], static_cast<uint16_t>(p.size()));
    p[8] = 64; p[9] = 6;
    p[12] = 10; p[13] = 0; p[14] = 0; p[15] = 2;
    p[16] = 1; p[17] = 1; p[18] = 1; p[19] = 1;
    put16(&p[20], 12345); put16(&p[22], 80);
    put32(&p[24], seq); put32(&p[28], ack);
    p[32] = 0x50; p[33] = flags; put16(&p[34], 65535);
    if (payload_len) std::memcpy(&p[40], payload, payload_len);
    uint32_t pseudo = 0;
    pseudo += (10u << 8); pseudo += 2;
    pseudo += (1u << 8) | 1u; pseudo += (1u << 8) | 1u;
    pseudo += 6; pseudo += static_cast<uint16_t>(20 + payload_len);
    put16(&p[36], checksum(&p[20], 20 + payload_len, pseudo));
    put16(&p[10], checksum(p.data(), 20));
    return p;
}

static uint32_t get32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8) | p[3];
}

int main() {
    tx::LwipTunStack stack;
    std::vector<std::vector<uint8_t>> output;
    std::shared_ptr<tx::LwipTcpStream> stream;
    tx::TargetAddr accepted_target;
    std::string received;
    std::string error;
    assert(stack.initialize({"10.10.0.1/24", "fd00:2024::1/64"}, 1500,
        tx::LwipTunStack::DatagramCallback(),
        [&](const std::shared_ptr<tx::LwipTcpStream>& accepted,
            const tx::IpAddr&, const tx::TargetAddr& target) {
            stream = accepted;
            accepted_target = target;
            stream->set_data_callback([&](tx::Buffer& data) {
                received.append(reinterpret_cast<const char*>(data.data()), data.readable());
                data.clear();
            });
        },
        [&](const uint8_t* packet, size_t len) {
            output.emplace_back(packet, packet + len); return true;
        }, error));

    auto syn = tcp_packet(100, 0, 0x02);
    assert(stack.input(syn.data(), syn.size()));
    assert(!output.empty());
    const auto syn_ack = output.back();
    assert((syn_ack[33] & 0x12) == 0x12);
    const uint32_t server_seq = get32(&syn_ack[24]);

    auto ack = tcp_packet(101, server_seq + 1, 0x10);
    assert(stack.input(ack.data(), ack.size()));
    assert(stream);
    assert(accepted_target.host == "1.1.1.1");
    assert(accepted_target.port == 80);

    const char hello[] = "hello";
    stream->pause_read();
    auto data = tcp_packet(101, server_seq + 1, 0x18,
                           reinterpret_cast<const uint8_t*>(hello), 5);
    assert(stack.input(data.data(), data.size()));
    assert(received.empty());
    stream->resume_read();
    assert(received == "hello");

    bool close_callback_called = false;
    stream->set_close_callback([&]() {
        close_callback_called = true;
        // Clearing a callback from inside itself must not invalidate the
        // active invocation.
        stream->set_close_callback(nullptr);
    });

    tx::Buffer reply;
    reply.append(reinterpret_cast<const uint8_t*>("world"), 5);
    assert(stream->write(reply));
    assert(!output.empty());
    stream->reset();
    assert(close_callback_called);
    stack.shutdown();

    for (int i = 0; i < 100; ++i) {
        tx::LwipTunStack repeated;
        std::string repeated_error;
        assert(repeated.initialize({"198.18.0.1/30", "fd00:198:18::1/126"}, 1500,
            tx::LwipTunStack::DatagramCallback(), tx::LwipTunStack::TcpAcceptCallback(),
            [](const uint8_t*, size_t) { return true; }, repeated_error));
        repeated.shutdown();
    }
    std::printf("lwip tcp stack tests passed\n");
    return 0;
}
