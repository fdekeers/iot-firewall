/**
 * @file src/parsers/header.c
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

#include "header.h"


/**
 * Retrieve the length of a packet's IP header.
 * 
 * @param data a pointer to the start of the packet's IP (layer 3) header
 * @return the size, in bytes, of the IP header
 */
size_t get_ip_header_length(uint8_t* data) {
    // 4-bit IP header length is encoded in the last 4 bits of byte 0.
    // It indicates the number of 32-bit words.
    // It must be multiplied by 4 to obtain the header size in bytes.
    uint8_t length = (*data & 0x0f) * 4;
    return length;
}

/**
 * Retrieve the length of a packet's UDP header.
 * 
 * @param data a pointer to the start of the packet's UDP (layer 4) header
 * @return the size, in bytes, of the UDP header
 */
size_t get_udp_header_length(uint8_t* data) {
    // A UDP header has a fixed length of 8 bytes
    return UDP_HEADER_LENGTH;
}

/**
 * Retrieve the length of a packet's TCP header.
 * 
 * @param data a pointer to the start of the packet's TCP (layer 4) header
 * @return the size, in bytes, of the UDP header
 */
size_t get_tcp_header_length(uint8_t* data) {
    // 4-bit TCP header data offset is encoded in the first 4 bits of byte 12.
    // It indicates the number of 32-bit words.
    // It must be multiplied by 4 to obtain the header size in bytes.
    uint8_t length = (*((data) + 12) >> 4) * 4;
    return length;
}

/**
 * Retrieve the length of a packet's layer-3 and layer-4 headers.
 * 
 * @param data a pointer to the start of the packet's layer-3 header
 * @return the size, in bytes, of the UDP header
 */
size_t get_headers_length(uint8_t* data) {
    // Retrieve the IP protocol number, which is encoded in byte 9 of the IP header.
    ip_protocol_t protocol = *((data) + 9);
    // Skip IP header (layer 3)
    size_t length = get_ip_header_length(data);
    // Skip layer 4 header (protocol-dependant)
    switch (protocol) {
        case TCP:
            length += get_tcp_header_length(data);
            break;
        case UDP:
            length += get_udp_header_length(data);
            break;
        default:
            break;
    }
    return length;
}
