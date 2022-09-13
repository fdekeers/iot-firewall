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
 * Skip a IP packet header.
 * 
 * @param data a double pointer to the start of the packet's IP (layer 3) header, which will be updated to point to the start of the layer-4 header
 * @return the number of bytes skipped
 */
size_t skip_ip_header(uint8_t** data) {
    // 4-bit IP header length is encoded in the last 4 bits of byte 0.
    // It indicates the number of 32-bit words.
    // It must be multiplied by 4 to obtain the header size in bytes.
    uint8_t length = (**data & 0x0f) * 4;
    *data += length;
    return length;
}

/**
 * Skip a UDP packet header.
 * 
 * @param data a double pointer to the start of the packet's UDP (layer 4) header, which will be updated to point to the start of the application payload
 * @return the number of bytes skipped
 */
size_t skip_udp_header(uint8_t** data) {
    // A UDP header has a fixed length of 8 bytes
    *data += UDP_HEADER_LENGTH;
    return UDP_HEADER_LENGTH;
}

/**
 * Skip a TCP packet header.
 * 
 * @param data a double pointer to the start of the packet's TCP (layer 4) header, which will be updated to point to the start of the application payload
 * @return the number of bytes skipped
 */
size_t skip_tcp_header(uint8_t** data) {
    // 4-bit TCP header data offset is encoded in the first 4 bits of byte 12.
    // It indicates the number of 32-bit words.
    // It must be multiplied by 4 to obtain the header size in bytes.
    uint8_t length = (*((*data) + 12) >> 4) * 4;
    *data += length;
    return length;
}

/**
 * Skip the layer-3 and layer-4 packet headers.
 * 
 * @param data a double pointer to the start of the packet's layer-3 header, which will be updated to point to the start of the application payload
 * @return the number of bytes skipped
 */
size_t skip_headers(uint8_t** data) {
    // Retrieve the IP protocol number, which is encoded in byte 9 of the IP header.
    ip_protocol protocol = *((*data) + 9);
    // Skip IP header (layer 3)
    size_t length = skip_ip_header(data);
    // Skip layer 4 header (protocol-dependant)
    switch (protocol) {
        case TCP:
            length += skip_tcp_header(data);
            break;
        case UDP:
            length += skip_udp_header(data);
            break;
        default:
            break;
    }
    return length;
}
