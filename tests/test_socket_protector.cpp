#include "tx/net/tcp_server.h"

#include <cassert>
#include <cstdio>
#include <set>

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

    int protector_calls = 0;
    bool connect_called = false;
    auto session = std::make_shared<TcpSession>(
        &loop,
        [&protector_calls](int fd) {
            ++protector_calls;
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

    // A rejected socket is never passed to uv_tcp_connect(), and the hook is
    // invoked exactly once for that socket before the connect can begin.
    assert(protector_calls == 1);
    assert(connect_called);

    uv_run(&loop, UV_RUN_DEFAULT);
    session.reset();
    assert(uv_loop_close(&loop) == 0);

    // Each address candidate is represented by a fresh TcpSession/socket and
    // therefore invokes the prepare hook independently.
    uv_loop_t retry_loop;
    assert(uv_loop_init(&retry_loop) == 0);
    std::set<int> prepared_fds;
    int failed_callbacks = 0;
    auto reject = [&prepared_fds](int fd) {
        prepared_fds.insert(fd);
        return false;
    };
    int first_pair[2];
    int second_pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, first_pair) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, second_pair) == 0);
    auto first = std::make_shared<TcpSession>(&retry_loop, reject);
    auto second = std::make_shared<TcpSession>(&retry_loop, reject);
    assert(uv_tcp_open(first->handle(), first_pair[0]) == 0);
    assert(uv_tcp_open(second->handle(), second_pair[0]) == 0);
    close(first_pair[1]);
    close(second_pair[1]);
    first->connect("2001:db8::1", 443, 50, [&failed_callbacks](bool success) {
        assert(!success);
        ++failed_callbacks;
    });
    second->connect("192.0.2.1", 443, 50, [&failed_callbacks](bool success) {
        assert(!success);
        ++failed_callbacks;
    });
    uv_run(&retry_loop, UV_RUN_DEFAULT);
    assert(prepared_fds.size() == 2);
    assert(failed_callbacks == 2);
    first.reset();
    second.reset();
    assert(uv_loop_close(&retry_loop) == 0);

    // The timeout overload shares the single-completion/close behavior even
    // when the host rejects the connect before its timer fires.
    uv_loop_t timeout_loop;
    assert(uv_loop_init(&timeout_loop) == 0);
    int timeout_callbacks = 0;
    auto pending = std::make_shared<TcpSession>(&timeout_loop);
    int pending_pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pending_pair) == 0);
    assert(uv_tcp_open(pending->handle(), pending_pair[0]) == 0);
    close(pending_pair[1]);
    pending->connect("192.0.2.1", 65000, 20, [&timeout_callbacks](bool success) {
        assert(!success);
        ++timeout_callbacks;
    });
    uv_run(&timeout_loop, UV_RUN_DEFAULT);
    assert(timeout_callbacks == 1);
    assert(pending->is_closed());
    pending.reset();
    assert(uv_loop_close(&timeout_loop) == 0);
#endif

    std::printf("socket protector tests passed\n");
    return 0;
}
