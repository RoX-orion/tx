#pragma once

// tx drives lwIP from one libuv loop and uses its raw TCP/UDP/IP path.
#define NO_SYS                      1
#define SYS_LIGHTWEIGHT_PROT        0
#define LWIP_TIMERS                 1

#define MEM_LIBC_MALLOC             1
#define MEMP_MEM_MALLOC             1
#define MEM_ALIGNMENT               8

#define LWIP_IPV4                   1
#define LWIP_IPV6                   1
#define LWIP_SINGLE_NETIF           1
#define LWIP_TCP                    1
#define LWIP_UDP                    1
#define LWIP_RAW                    0
#define LWIP_ICMP                   0
#define LWIP_ICMP6                  1

#define LWIP_ARP                    0
#define LWIP_ETHERNET               0
#define LWIP_DHCP                   0
#define LWIP_AUTOIP                 0
#define LWIP_DNS                    0
#define LWIP_IGMP                   0
#define LWIP_IPV6_MLD               0
#define LWIP_IPV6_DHCP6             0

#define IP_REASSEMBLY               1
#define IP_FRAG                     1
#define IP_REASS_MAX_PBUFS          16
#define LWIP_IPV6_REASS             1
#define LWIP_IPV6_FRAG              1
// On 64-bit platforms the IPv6 reassembly helper contains an 8-byte pointer
// and cannot fit inside the 8-byte fragment header. Preserve the overwritten
// header bytes separately as required by lwIP.
#define IPV6_FRAG_COPYHEADER        1

#define LWIP_NETCONN                0
#define LWIP_SOCKET                 0
#define LWIP_STATS                  0
#define LWIP_DEBUG                  0

#define MEMP_NUM_UDP_PCB            1024
#define MEMP_NUM_REASSDATA          16
#define PBUF_POOL_SIZE              64
#define PBUF_POOL_BUFSIZE           2048
#define PBUF_LINK_HLEN              0

#define CHECKSUM_CHECK_IP           1
#define CHECKSUM_CHECK_UDP          1
#define CHECKSUM_GEN_IP             1
#define CHECKSUM_GEN_UDP            1
#define LWIP_CHECKSUM_ON_COPY       1

#define LWIP_WND_SCALE              1
#define TCP_RCV_SCALE               3
#define TCP_WND                     (256 * 1024)
#define TCP_SND_BUF                 (256 * 1024)
#define TCP_SND_QUEUELEN            1024
#define TCP_SNDLOWAT                32768
#define TCP_SNDQUEUELOWAT           128
#define LWIP_TCP_SACK_OUT           1
#define TCP_QUEUE_OOSEQ             1
#define MEMP_NUM_TCP_PCB            4096
#define MEMP_NUM_TCP_PCB_LISTEN     4
#define MEMP_NUM_TCP_SEG            8192
