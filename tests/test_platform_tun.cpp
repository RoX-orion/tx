#include "platform_tun.h"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

#if defined(TX_PLATFORM_LINUX)
#include <unistd.h>

namespace {

std::string join(const std::vector<std::string>& command) {
    std::string result;
    for (const auto& part : command) {
        if (!result.empty()) result.push_back(' ');
        result += part;
    }
    return result;
}

tx::ClientConfig policy_config(int fd) {
    tx::ClientConfig config;
    config.tun_fd = fd;
    config.tun_name = "tx-test0";
    config.tun_auto_config = true;
    config.tun_addresses = {"198.18.0.1/30", "fd00:198:18::1/126"};
    config.tun_auto_route = true;
    config.tun_routes.clear();
    config.tun_tcp_stack = "lwip";
    config.tun_bypass_mark = 8228;
    config.tun_route_table = 20220;
    config.tun_rule_priority = 10000;
    return config;
}

size_t find_after(const std::vector<std::string>& commands,
                  const std::string& needle, size_t start = 0) {
    for (size_t i = start; i < commands.size(); ++i) {
        if (commands[i].find(needle) != std::string::npos) return i;
    }
    return commands.size();
}

void test_policy_order_and_cleanup() {
    int descriptors[2];
    assert(pipe(descriptors) == 0);
    std::vector<std::string> commands;
    tx::PlatformTunDevice::set_command_runner_for_testing(
        [&](const std::vector<std::string>& command) {
            commands.push_back(join(command));
            return tx::PlatformTunDevice::CommandResult{0, std::string()};
        });
    auto device = tx::PlatformTunDevice::create();
    std::string error;
    assert(device->open(policy_config(descriptors[0]), error));

    const size_t v4_route = find_after(commands,
        "-4 route add table 20220 0.0.0.0/1 dev tx-test0");
    const size_t v6_route = find_after(commands,
        "-6 route add table 20220 ::/1 dev tx-test0");
    const size_t mark_rule = find_after(commands,
        "-4 rule add priority 10000 fwmark 8228/0xffffffff lookup main");
    const size_t capture_rule = find_after(commands,
        "-4 rule add priority 10001 lookup 20220");
    assert(v4_route < mark_rule && v6_route < mark_rule && mark_rule < capture_rule);

    device->close();
    const size_t capture_del = find_after(commands,
        "-6 rule del priority 10001 lookup 20220");
    const size_t route_del = find_after(commands,
        "-6 route del table 20220 8000::/1 dev tx-test0", capture_del);
    const size_t address_del = find_after(commands,
        "-6 address del fd00:198:18::1/126 dev tx-test0", route_del);
    assert(capture_del < route_del && route_del < address_del);
    close(descriptors[1]);
}

void test_conflict_and_partial_rollback() {
    int descriptors[2];
    assert(pipe(descriptors) == 0);
    std::vector<std::string> commands;
    tx::PlatformTunDevice::set_command_runner_for_testing(
        [&](const std::vector<std::string>& command) {
            const std::string text = join(command);
            commands.push_back(text);
            if (text == "-4 rule show priority 10000")
                return tx::PlatformTunDevice::CommandResult{0, "10000: existing\n"};
            return tx::PlatformTunDevice::CommandResult{0, std::string()};
        });
    auto device = tx::PlatformTunDevice::create();
    std::string error;
    assert(!device->open(policy_config(descriptors[0]), error));
    assert(error.find("conflict") != std::string::npos);
    assert(find_after(commands, "route add table") == commands.size());
    assert(find_after(commands, "address del") != commands.size());
    close(descriptors[1]);

    assert(pipe(descriptors) == 0);
    commands.clear();
    tx::PlatformTunDevice::set_command_runner_for_testing(
        [&](const std::vector<std::string>& command) {
            const std::string text = join(command);
            commands.push_back(text);
            if (text.find("-6 route add table 20220 ::/1") != std::string::npos)
                return tx::PlatformTunDevice::CommandResult{1, "injected failure"};
            return tx::PlatformTunDevice::CommandResult{0, std::string()};
        });
    device = tx::PlatformTunDevice::create();
    error.clear();
    assert(!device->open(policy_config(descriptors[0]), error));
    assert(find_after(commands,
        "-4 route del table 20220 128.0.0.0/1 dev tx-test0") != commands.size());
    assert(find_after(commands, "address del") != commands.size());
    close(descriptors[1]);
}

void test_system_stack_explicit_routes_without_auto_config() {
    int descriptors[2];
    assert(pipe(descriptors) == 0);
    std::vector<std::string> commands;
    tx::PlatformTunDevice::set_command_runner_for_testing(
        [&](const std::vector<std::string>& command) {
            commands.push_back(join(command));
            return tx::PlatformTunDevice::CommandResult{0, std::string()};
        });

    tx::ClientConfig config = policy_config(descriptors[0]);
    config.tun_auto_config = false;
    config.tun_auto_route = false;
    config.tun_routes = {"10.0.0.0/8", "2001:db8::/32"};
    config.tun_tcp_stack = "system";
    config.tun_auto_redirect = true;
    config.tun_redirect_mark = 4660;

    auto device = tx::PlatformTunDevice::create();
    std::string error;
    assert(device->open(config, error));
    assert(find_after(commands, "address show") == commands.size());
    assert(find_after(commands, "link set") == commands.size());
    assert(find_after(commands,
        "-4 route add table 20220 10.0.0.0/8 dev tx-test0") != commands.size());
    assert(find_after(commands,
        "-6 route add table 20220 2001:db8::/32 dev tx-test0") != commands.size());
    assert(find_after(commands,
        "-4 rule add priority 10000 fwmark 4660/0xffffffff lookup main") !=
        commands.size());
    assert(find_after(commands, "0.0.0.0/1") == commands.size());

    device->close();
    assert(find_after(commands,
        "-6 route del table 20220 2001:db8::/32 dev tx-test0") != commands.size());
    assert(find_after(commands, "address del") == commands.size());
    close(descriptors[1]);
}

} // namespace
#endif

int main() {
#if defined(TX_PLATFORM_LINUX)
    test_policy_order_and_cleanup();
    test_conflict_and_partial_rollback();
    test_system_stack_explicit_routes_without_auto_config();
    tx::PlatformTunDevice::reset_command_runner_for_testing();
#endif
    std::printf("platform TUN policy tests passed\n");
    return 0;
}
