#include "tx/net/tcp_server.h"

#include <cassert>
#include <cstdio>

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace tx;

int main() {
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
    uv_loop_t loop;
    assert(uv_loop_init(&loop) == 0);

    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);

    bool protector_called = false;
    bool connect_called = false;
    auto session = std::make_shared<TcpSession>(
        &loop,
        [&protector_called](int fd) {
            protector_called = true;
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID)
            assert(fcntl(fd, F_GETFD) != -1);
#endif
            return false;
        });
    assert(uv_tcp_open(session->handle(), sockets[0]) == 0);
    close(sockets[1]);

    session->connect("127.0.0.1", 9, [&connect_called](bool success) {
        connect_called = true;
        assert(!success);
    });

    assert(protector_called);
    assert(connect_called);

    uv_run(&loop, UV_RUN_DEFAULT);
    session.reset();
    assert(uv_loop_close(&loop) == 0);
#endif

    std::printf("socket protector tests passed\n");
    return 0;
}
