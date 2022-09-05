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
} ip_protocol;

/**
 * Skip a IP packet header.
 * 
 * @param data a double pointer to the start of the packet's IP (layer 3) header, which will be updated to point to the start of the layer-4 header
 * @return the number of bytes skipped
 */
size_t skip_ip_header(unsigned char** data);

/**
 * Skip a UDP packet header.
 * 
 * @param data a double pointer to the start of the packet's UDP (layer 4) header, which will be updated to point to the start of the application payload
 * @return the number of bytes skipped
 */
size_t skip_udp_header(unsigned char** data);

/**
 * Skip a TCP packet header.
 * 
 * @param data a double pointer to the start of the packet's TCP (layer 4) header, which will be updated to point to the start of the application payload
 * @return the number of bytes skipped
 */
size_t skip_tcp_header(unsigned char** data);

/**
 * Skip the layer-3 and layer-4 packet headers.
 * 
 * @param data a double pointer to the start of the packet's layer-3 header, which will be updated to point to the start of the application payload
 * @return the number of bytes skipped
 */
size_t skip_headers(unsigned char** data);


#endif