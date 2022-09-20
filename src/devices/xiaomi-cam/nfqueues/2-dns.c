/**
 * @file src/devices/xiaomi-cam/2-dns.c
 * @author François De Keersmaeker (francois.dekeersmaeker@uclouvain.be)
 * @brief 
 * @date 2022-09-16
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
// Parsers
#include "parsers/header.h"
#include "parsers/dns.h"

#define NFQUEUE_ID 2

/**
 * Current DHCP state
 */
typedef enum {
    INIT,
    QUERIED,
    ANSWERED
} dns_state_t;

dns_state_t state = INIT;

/**
 * @brief Basic callback function, called when a packet enters the queue.
 * 
 * @param pkt_id packet ID for netfilter queue
 * @param payload pointer to the packet payload
 * @param arg pointer to the argument passed to the callback function
 * @return the verdict for the packet
 */
uint32_t callback(int pkt_id, uint8_t *payload, void *arg) {
    // Skip layer 3 and 4 headers
    size_t skipped = get_ip_header_length(payload);
    skipped += get_udp_header_length(payload + skipped);
    // Parse DNS message
    dns_message_t message = dns_parse_message(payload + skipped);
    dns_print_message(message);

    // Match packet application layer
    

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
    bind_queue(NFQUEUE_ID, &callback, NULL);

    return 0;
}