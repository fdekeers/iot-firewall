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

#define UDP_HEADER_LENGTH 8


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
 * Retrieve the length of a packet's IP header.
 * 
 * @param data a pointer to the start of the packet's IP (layer 3) header
 * @return the size, in bytes, of the IP header
 */
size_t get_ip_header_length(uint8_t* data);

/**
 * Retrieve the length of a packet's UDP header.
 * 
 * @param data a pointer to the start of the packet's UDP (layer 4) header
 * @return the size, in bytes, of the UDP header
 */
size_t get_udp_header_length(uint8_t* data);

/**
 * Retrieve the length of a packet's TCP header.
 * 
 * @param data a pointer to the start of the packet's TCP (layer 4) header
 * @return the size, in bytes, of the UDP header
 */
size_t get_tcp_header_length(uint8_t* data);

/**
 * Retrieve the length of a packet's layer-3 and layer-4 headers.
 * 
 * @param data a pointer to the start of the packet's layer-3 header
 * @return the size, in bytes, of the UDP header
 */
size_t get_headers_length(uint8_t* data);

/**
 * @brief Retrieve the source port from a layer 4 header.
 * 
 * @param data pointer to the start of the layer 4 header
 * @return destination port
 */
uint16_t get_dst_port(uint8_t* data);

/**
 * @brief Retrieve the destination IPv4 address from a layer 3 header.
 *
 * @param data pointer to the start of the layer 3 header
 * @return destination IPv4 address, in network byte order
 */
uint32_t get_dst_addr(uint8_t *data);

#endif /* _IOTFIREWALL_HEADER_ */
