// net.hpp
#pragma once

#include <cstdint>

namespace agm {
namespace net {

    constexpr uint8_t ETHER_ADDR_LEN = 6u;

    /* Ethernet header */
    struct EthernetHeader
    {
        uint8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        uint8_t  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        uint16_t ether_type;                     /* IP? ARP? RARP? etc */
    };

    /* 4 bytes IP address */
    struct IpAddress
    {
        uint8_t byte1;
        uint8_t byte2;
        uint8_t byte3;
        uint8_t byte4;
    };

    /* IPv4 header */
    struct IPv4Header
    {
        uint8_t  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
        uint8_t  tos;            // Type of service 
        uint16_t tlen;           // Total length 
        uint16_t identification; // Identification
        uint16_t flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
        uint8_t  ttl;            // Time to live
        uint8_t  proto;          // Protocol
        uint16_t crc;            // Header checksum
        IpAddress  saddr;       // Source address
        IpAddress  daddr;       // Destination address
    };

    /* UDP header*/
    struct UdpHeader
    {
        uint16_t src_port;          // Source port
        uint16_t dst_port;          // Destination port
        uint16_t len;            // Datagram length
        uint16_t crc;            // Checksum
    };

} } // namespace agm::net
