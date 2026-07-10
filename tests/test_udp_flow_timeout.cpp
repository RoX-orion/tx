#include "tx/net/udp_flow_timeout.h"

#include <cassert>
#include <cstdio>

int main() {
    assert(!tx::udp_flow_is_idle(999, 0, 1000));
    assert(tx::udp_flow_is_idle(1000, 0, 1000));
    assert(tx::udp_flow_is_idle(1500, 500, 1000));
    assert(!tx::udp_flow_is_idle(499, 500, 1000));
    assert(!tx::udp_flow_is_idle(1000, 0, 0));

    assert(tx::udp_flow_cleanup_interval(1000) == 1000);
    assert(tx::udp_flow_cleanup_interval(300000) == 30000);

    std::printf("udp flow timeout tests passed\n");
    return 0;
}
