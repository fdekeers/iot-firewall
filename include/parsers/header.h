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
 * Skip the layer-3 and layer-4 packet headers.
 * 
 * @param data a pointer to the start of the packet's layer-3 header
 * @return a pointer to the packet payload, offset after the skipped layer-3 and layer-4 headers
 */
unsigned char* skip_headers(unsigned char* data);

/**
 * Skip a IP packet header.
 * 
 * @param data a pointer to the start of the packet's IP header
 * @return a pointer to the packet payload, offset after the skipped IP header
 */
unsigned char* skip_ip_header(unsigned char* data);

/**
 * Skip a UDP packet header.
 * 
 * @param data a pointer to the start of the packet's UDP header
 * @return a pointer to the packet payload, offset after the skipped UDP header
 */
unsigned char* skip_udp_header(unsigned char* data);

/**
 * Skip a TCP packet header.
 * 
 * @param data a pointer to the start of the packet's TCP header
 * @return a pointer to the packet payload, offset after the skipped TCP header
 */
unsigned char* skip_tcp_header(unsigned char* data);


#endif