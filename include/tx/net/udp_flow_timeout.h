#pragma once

#include <algorithm>
#include <cstdint>

namespace tx {

constexpr uint64_t kDefaultUdpFlowIdleTimeoutMs = 300000;
constexpr uint64_t kMaxUdpFlowCleanupIntervalMs = 30000;

inline bool udp_flow_is_idle(uint64_t now_ms, uint64_t last_activity_ms,
                             uint64_t idle_timeout_ms) {
    return idle_timeout_ms > 0 && now_ms >= last_activity_ms &&
           now_ms - last_activity_ms >= idle_timeout_ms;
}

inline uint64_t udp_flow_cleanup_interval(uint64_t idle_timeout_ms) {
    return std::min(idle_timeout_ms, kMaxUdpFlowCleanupIntervalMs);
}

} // namespace tx
