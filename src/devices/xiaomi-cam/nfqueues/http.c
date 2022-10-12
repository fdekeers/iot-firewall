/**
 * @file src/devices/xiaomi-cam/3-dns.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief 
 * @date 2022-10-03
 * 
 * @copyright Copyright (c) 2022
 * 
 */

// Standard libraries
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
// Custom libraries
#include "nfqueue.h"
#include "packet_utils.h"
// Parsers
#include "parsers/header.h"
#include "parsers/http.h"

#define NFQ_ID_BASE 3

/**
 * Current DHCP state
 */
typedef enum {
    INIT,
    REQUESTED
} http_state_t;

http_state_t state = INIT;

/**
 * @brief Basic callback function, called when a packet enters the queue.
 * 
 * @param pkt_id packet ID for netfilter queue
 * @param payload pointer to the packet payload
 * @param arg pointer to the argument passed to the callback function
 * @return the verdict for the packet
 */
uint32_t callback(int pkt_id, uint8_t *payload, void *arg) {
    printf("Received packet\n");
    // Skip layer 3 and 4 headers
    size_t skipped = get_ip_header_length(payload);
    uint16_t src_port = get_src_port(payload + skipped);
    skipped += get_tcp_header_length(payload + skipped);
    // Parse DNS message
    http_message_t message = http_parse_message(payload + skipped, src_port);
    http_print_message(message);

    // Match packet application layer
    printf("Actual: %s\n", message.uri);
    if (
        state == INIT &&
        message.method == GET &&
        strcmp(message.uri, "/gslb?tver=2&id=369215617&dm=ots.io.mi.com&timestamp=8&sign=j2zt3%2BpbAwcxrxovQUFtCyZ6DUmGplXNKr1i8jteRb4%3D") == 0
    ) {
        state = REQUESTED;
        printf("Received request.\n");
        return NF_ACCEPT;
    } else if (
        state == REQUESTED
    ) {
        state = INIT;
        printf("Received response.\n");
        return NF_ACCEPT;
    }

    return NF_ACCEPT;
}

/**
 * @brief Program entry point
 * 
 * @param argc number of command line arguments
 * @param argv list of command line arguments
 * @return exit code, 0 if success
 */
int main(int argc, char const *argv[]) {
    // Bind to netfilter queue
    bind_queue(NFQ_ID_BASE, &callback, NULL);

    return 0;
}
