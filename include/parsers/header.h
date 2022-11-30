/**
 * @file include/parsers/header.h
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief Parser for layer 3 and 4 headers (currently only IP, UDP and TCP)
 * 
 * Parser for layer 3 and 4 headers.
 * Currently supported protocols:
 *   - Layer 3:
 *     - IP
 *   - Layer 4:
 *     - UDP
 *     - TCP
 * 
 * @date 2022-09-09
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _IOTFIREWALL_HEADER_
#define _IOTFIREWALL_HEADER_

#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#define IPV6_HEADER_LENGTH 40
#define UDP_HEADER_LENGTH  8


/**
 * IP protocols assigned to their protocol number
 */
typedef enum {
    ICMP =  1,
    IGMP =  2,
    TCP  =  6,
    UDP  = 17
} ip_protocol_t;

/**
 * Retrieve the length of a packet's IPv4 header.
 *
 * @param data a pointer to the start of the packet's IPv4 header
 * @return the size, in bytes, of the IPv4 header
 */
size_t get_ipv4_header_length(uint8_t *data);

/**
 * Retrieve the length of a packet's IPv6 header.
 *
 * @param data a pointer to the start of the packet's IPv6 header
 * @return the size, in bytes, of the IPv6 header
 */
size_t get_ipv6_header_length(uint8_t *data);

/**
 * Retrieve the length of a packet's UDP header.
 *
 * @param data a pointer to the start of the packet's UDP (layer 4) header
 * @return the size, in bytes, of the UDP header
 */
size_t get_udp_header_length(uint8_t *data);

/**
 * Retrieve the length of a packet's TCP header.
 * 
 * @param data a pointer to the start of the packet's TCP (layer 4) header
 * @return the size, in bytes, of the UDP header
 */
size_t get_tcp_header_length(uint8_t *data);

/**
 * Retrieve the length of a packet's layer-3 and layer-4 headers.
 * 
 * @param data a pointer to the start of the packet's layer-3 header
 * @return the size, in bytes, of the UDP header
 */
size_t get_headers_length(uint8_t* data);

/**
 * @brief Retrieve the length of a UDP payload.
 * 
 * @param data pointer to the start of the UDP header
 * @return length of the UDP payload, in bytes
 */
uint16_t get_udp_payload_length(uint8_t *data);

/**
 * @brief Retrieve the source port from a layer 4 header.
 * 
 * @param data pointer to the start of the layer 4 header
 * @return destination port
 */
uint16_t get_dst_port(uint8_t* data);

/**
 * @brief Retrieve the destination address from an IPv4 header.
 *
 * @param data pointer to the start of the IPv4 header
 * @return destination IPv4 address, in network byte order
 */
uint32_t get_ipv4_dst_addr(uint8_t *data);


#endif /* _IOTFIREWALL_HEADER_ */
