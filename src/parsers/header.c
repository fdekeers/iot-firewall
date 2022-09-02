#include "header.h"

/**
 * Skip a IP packet header.
 * 
 * @param data a pointer to the start of the packet's IP header
 * @return a pointer to the packet payload, offset after the skipped IP header
 */
unsigned char* skip_ip_header(unsigned char* data) {
    // 4-bit IP header length is encoded in the last 4 bits of byte 0.
    // It indicates the number of 32-bit words.
    // It must be multiplied by 4 to obtain the header size in bytes.
    uint8_t length = (*data & 0x0f) * 4;
    return data + length;
}

/**
 * Skip a UDP packet header.
 * 
 * @param data a pointer to the start of the packet's UDP header
 * @return a pointer to the packet payload, offset after the skipped UDP header
 */
unsigned char* skip_udp_header(unsigned char* data) {
    // A UDP header has a fixed length of 8 bytes
    return data + UDP_HEADER_LENGTH;
}

/**
 * Skip a TCP packet header.
 * 
 * @param data a pointer to the start of the packet's TCP header
 * @return a pointer to the packet payload, offset after the skipped TCP header
 */
unsigned char* skip_tcp_header(unsigned char* data) {
    // 4-bit TCP header data offset is encoded in the first 4 bits of byte 12.
    // It indicates the number of 32-bit words.
    // It must be multiplied by 4 to obtain the header size in bytes.
    uint8_t length = (*(data + 12) >> 4) * 4;
    return data + length;
}

/**
 * Skip the layer-3 and layer-4 packet headers.
 * 
 * @param data a pointer to the start of the packet's layer-3 header
 * @return a pointer to the packet payload, offset after the skipped layer-3 and layer-4 headers
 */
unsigned char* skip_headers(unsigned char* data) {
    // Retrieve the IP protocol number, which is encoded in byte 9 of the IP header.
    ip_protocol protocol = *(data + 9);
    // Skip IP header (layer 3)
    data = skip_ip_header(data);
    // Skip layer 4 header (protocol-dependant)
    switch (protocol) {
        case TCP:
            data = skip_tcp_header(data);
            break;
        case UDP:
            data = skip_udp_header(data);
            break;
        default:
            // Do not skip header
            return data;
    }
}
