#include "tx/net/tcp_server.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID) || defined(TX_PLATFORM_APPLE)
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace tx;

#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID) || defined(TX_PLATFORM_APPLE)
struct TestContext {
    uv_loop_t* loop = nullptr;
    int client_fd = -1;
    bool first_read = false;
    bool second_read = false;
    bool eof = false;
    bool closed = false;
    SessionPtr accepted;
};

static void configure_session(TestContext* context, const SessionPtr& session) {
    session->set_close_callback([context](SessionPtr) { context->closed = true; });
    session->set_eof_callback([context](SessionPtr stream) {
        context->eof = true;
        // Clearing the currently executing callback must be safe.
        stream->set_eof_callback(nullptr);
        stream->close();
    });
    session->start_read([context](SessionPtr stream, Buffer& data) {
        context->first_read = true;
        data.clear();

        // The tunnel handshake replaces its read callback from inside the
        // callback in exactly this way.
        stream->start_read([context](SessionPtr, Buffer& second) {
            context->second_read = true;
            second.clear();
            assert(close(context->client_fd) == 0);
            context->client_fd = -1;
        });

        const char second[] = "second";
        assert(write(context->client_fd, second, sizeof(second)) ==
               static_cast<ssize_t>(sizeof(second)));
    });
}

static void test_half_close_flushes_pending_response() {
    uv_loop_t loop;
    assert(uv_loop_init(&loop) == 0);
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);

    bool closed = false;
    auto session = std::make_shared<TcpSession>(&loop);
    assert(uv_tcp_open(session->handle(), sockets[0]) == 0);
    session->set_close_callback([&closed](SessionPtr) { closed = true; });
    session->set_eof_callback([](SessionPtr stream) {
        const char response[] = "response-after-fin";
        assert(stream->send(reinterpret_cast<const uint8_t*>(response),
                            sizeof(response) - 1));
        stream->shutdown_write();
    });
    session->start_read([](SessionPtr, Buffer& data) { data.clear(); });

    std::string received;
    std::thread peer([fd = sockets[1], &received]() {
        const char request[] = "request";
        assert(write(fd, request, sizeof(request) - 1) ==
               static_cast<ssize_t>(sizeof(request) - 1));
        assert(shutdown(fd, SHUT_WR) == 0);
        char buffer[64];
        for (;;) {
            const ssize_t count = read(fd, buffer, sizeof(buffer));
            if (count == 0) break;
            assert(count > 0);
            received.append(buffer, static_cast<size_t>(count));
        }
        close(fd);
    });

    uv_run(&loop, UV_RUN_DEFAULT);
    peer.join();
    assert(closed);
    assert(received == "response-after-fin");
    session.reset();
    assert(uv_loop_close(&loop) == 0);
}

static void test_unlistened_server_closes_its_handle() {
    uv_loop_t loop;
    assert(uv_loop_init(&loop) == 0);
    {
        TcpServer server(&loop);
    }
    uv_run(&loop, UV_RUN_DEFAULT);
    assert(uv_loop_close(&loop) == 0);
}
#endif

int main() {
#if defined(TX_PLATFORM_LINUX) || defined(TX_PLATFORM_ANDROID) || defined(TX_PLATFORM_APPLE)
    uv_loop_t loop;
    assert(uv_loop_init(&loop) == 0);

    TestContext context;
    context.loop = &loop;
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    auto session = std::make_shared<TcpSession>(&loop);
    assert(uv_tcp_open(session->handle(), sockets[0]) == 0);
    context.client_fd = sockets[1];
    context.accepted = session;
    configure_session(&context, session);
    const char first[] = "first";
    assert(write(context.client_fd, first, sizeof(first)) ==
           static_cast<ssize_t>(sizeof(first)));

    uv_run(&loop, UV_RUN_DEFAULT);

    assert(context.first_read);
    assert(context.second_read);
    assert(context.eof);
    assert(context.closed);
    if (context.client_fd >= 0) close(context.client_fd);
    context.accepted.reset();
    assert(uv_loop_close(&loop) == 0);
    test_half_close_flushes_pending_response();
    test_unlistened_server_closes_its_handle();
#endif

    std::printf("tcp session callback lifecycle tests passed\n");
    return 0;
}
